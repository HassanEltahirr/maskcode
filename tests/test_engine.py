"""Stdio engine checks use synthetic subprocesses and never call a cloud model.

Run the optional installed-Claude two-turn permission integration with:
MASKCODE_TEST_INSTALLED_ENGINE=1 python3 -m unittest discover -s tests -p test_engine.py -v
It uses dummy authentication, an empty temporary Claude config, and only a
synthetic local gateway transport under the real network restriction.
"""
import json
import os
from pathlib import Path
import platform
import queue
import shutil
import sys
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from privacy_gateway.client import (ClientConfigurationError, build_claude_engine_command,
                                    claude_environment, validate_claude_arguments)
from privacy_gateway.engine import ClaudeEngine, EngineError


FAKE_CHILD = r'''
import json, os, sys, time
def send(event):
    print(json.dumps(event), flush=True)
def result(text):
    send({"type":"result", "session_id":"synthetic-session", "result":text, "is_error":False})
for line in sys.stdin:
    event = json.loads(line)
    if event["type"] == "control_request":
        subtype = event["request"]["subtype"]
        if subtype == "initialize" and os.environ.get("SYNTHETIC_INIT") == "timeout":
            time.sleep(20)
            continue
        if subtype == "initialize" and os.environ.get("SYNTHETIC_INIT") == "error":
            send({"type":"control_response", "response":{"subtype":"error", "request_id":event["request_id"], "error":"private synthetic credential"}})
            continue
        send({"type":"control_response", "response":{"subtype":"success", "request_id":event["request_id"], "response":{"commands":[{"name":"synthetic"}], "echo": event["request"]}}})
        if subtype == "initialize":
            send({"type":"system", "subtype":"init", "session_id":"synthetic-session", "model":"synthetic-model"})
        elif subtype == "interrupt":
            result("interrupted")
    elif event["type"] == "user":
        prompt = event["message"]["content"]
        if prompt == "permission":
            send({"type":"control_request", "request_id":"synthetic-tool", "request":{"subtype":"can_use_tool", "tool_name":"Write", "input":{"file_path":"/synthetic/example.txt", "content":"original synthetic content"}}})
        elif prompt == "cancel_permission":
            send({"type":"control_request", "request_id":"synthetic-tool", "request":{"subtype":"can_use_tool", "tool_name":"Write", "input":{"content":"original"}}})
            send({"type":"control_cancel_request", "request_id":"synthetic-tool"})
            result("cancelled")
        elif prompt == "unknown_control":
            send({"type":"control_request", "request_id":"synthetic-unknown", "request":{"subtype":"hook_callback"}})
        elif prompt == "invalid_permission":
            send({"type":"control_request", "request_id":"synthetic-tool", "request":{"subtype":"can_use_tool", "tool_name":"Write", "input":"not an object"}})
        elif prompt == "wait":
            continue
        elif prompt == "malformed":
            print('{broken private synthetic credential', flush=True)
        elif prompt == "oversize":
            print('x' * 20000, flush=True)
        elif prompt == "stderr":
            print('private synthetic credential', file=sys.stderr, flush=True)
            sys.exit(3)
        else:
            send({"type":"stream_event", "event":{"type":"content_block_delta", "delta":{"type":"text_delta", "text":prompt}}})
            result(prompt)
    elif event["type"] == "control_response":
        response = event["response"]
        result(json.dumps(response))
'''


class EngineCommandTests(unittest.TestCase):
    def test_internal_transport_is_sandboxed_with_fixed_protocol_and_permissions(self):
        extra = ["--resume", "synthetic-session", "--model", "sonnet", "--tools", "Read,Write"]
        with patch("privacy_gateway.client.shutil.which", return_value="/synthetic/claude"), \
                patch("privacy_gateway.client.command", side_effect=lambda port, argv: ["sandbox", str(port), *argv]):
            argv = build_claude_engine_command(SimpleNamespace(server_port=41234), extra)
        self.assertEqual(argv[:3], ["sandbox", "41234", "/synthetic/claude"])
        for flag in ("--safe-mode", "--no-chrome", "--strict-mcp-config", "--print",
                     "--verbose", "--include-partial-messages"):
            self.assertIn(flag, argv)
        for flag, value in (("--input-format", "stream-json"), ("--output-format", "stream-json"),
                            ("--permission-prompt-tool", "stdio"), ("--permission-mode", "default")):
            self.assertEqual(argv[argv.index(flag) + 1], value)
        self.assertEqual(argv[-len(extra):], extra)
        self.assertNotIn("--dangerously-skip-permissions", argv)

    def test_external_permission_transport_stays_blocked(self):
        for args in (["--permission-prompt-tool", "stdio"], ["--permission-prompt-tool=stdio"]):
            with self.subTest(args=args), self.assertRaises(ClientConfigurationError):
                validate_claude_arguments(args)

    def test_protocol_overrides_native_commands_and_positionals_are_rejected(self):
        for args in (["--output-format", "text"], ["--input-format", "text"], ["-p"],
                     ["--", "literal"], ["auth", "status"], ["prompt"], ["--help"],
                     ["--dangerously-skip-permissions"], ["--permission-mode=bypassPermissions"]):
            with self.subTest(args=args), patch("privacy_gateway.client.shutil.which") as lookup, \
                    self.assertRaises(ClientConfigurationError):
                build_claude_engine_command(SimpleNamespace(server_port=41234), args)
            lookup.assert_not_called()


class EngineTransportTests(unittest.TestCase):
    def setUp(self):
        self.events = queue.Queue()
        self.patches = [
            patch("privacy_gateway.engine.build_claude_engine_command", return_value=[sys.executable, "-I", "-u", "-c", FAKE_CHILD]),
            patch("privacy_gateway.engine.claude_environment", return_value={"PATH": "/usr/bin:/bin"}),
        ]
        for patcher in self.patches:
            patcher.start()
            self.addCleanup(patcher.stop)
        self.engine = ClaudeEngine(SimpleNamespace(), [], None, self.events.put)
        self.addCleanup(self.engine.close)

    def wait_for(self, kind, timeout=3):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            event = self.events.get(timeout=max(.001, deadline - time.monotonic()))
            if event["type"] == kind:
                return event
        self.fail("Expected synthetic engine event was not received")

    def test_two_prompts_share_process_session_and_stream(self):
        initialization = self.engine.start()
        self.assertEqual(initialization["echo"], {"subtype": "initialize", "hooks": None})
        self.wait_for("system")
        process = self.engine._process
        for prompt in ("first synthetic turn", "second synthetic turn"):
            self.engine.send(prompt)
            stream = self.wait_for("stream_event")
            self.assertEqual(stream["event"]["delta"]["text"], prompt)
            self.assertEqual(self.wait_for("result")["result"], prompt)
            self.assertFalse(self.engine.busy)
            self.assertEqual(self.engine.session_id, "synthetic-session")
            self.assertIs(self.engine._process, process)
            self.assertIsNone(process.poll())

    def test_permission_approval_uses_original_input_even_if_ui_mutates_event(self):
        self.engine.start()
        self.engine.send("permission")
        request = self.wait_for("permission_request")
        request["input"]["content"] = "replacement must not execute"
        self.assertTrue(self.engine.decide_permission(request["id"], True))
        result = json.loads(self.wait_for("result")["result"])["response"]
        self.assertEqual(result["behavior"], "allow")
        self.assertEqual(result["updatedInput"]["content"], "original synthetic content")
        self.assertNotIn("updatedPermissions", result)
        self.assertFalse(self.engine.decide_permission(request["id"], True))

    def test_permission_denial_has_no_updated_input(self):
        self.engine.start()
        self.engine.send("permission")
        request = self.wait_for("permission_request")
        self.engine.decide_permission(request["id"], False)
        decision = json.loads(self.wait_for("result")["result"])["response"]
        self.assertEqual(decision["behavior"], "deny")
        self.assertNotIn("updatedInput", decision)

    def test_permission_requires_boolean_decision(self):
        with self.assertRaises(EngineError):
            self.engine.decide_permission("synthetic", "yes")

    def test_permission_cancel_cannot_be_approved_later(self):
        self.engine.start()
        self.engine.send("cancel_permission")
        request = self.wait_for("permission_request")
        self.assertEqual(self.wait_for("permission_cancelled")["id"], request["id"])
        self.assertFalse(self.engine.decide_permission(request["id"], True))

    def test_permission_timeout_denies_and_clears(self):
        self.engine.start()
        with patch("privacy_gateway.engine.PERMISSION_TIMEOUT", .03):
            self.engine.send("permission")
            request = self.wait_for("permission_request")
            self.wait_for("permission_cancelled")
        result = json.loads(self.wait_for("result")["result"])["response"]
        self.assertEqual(result["behavior"], "deny")
        self.assertFalse(self.engine.decide_permission(request["id"], True))

    def test_unknown_control_requests_are_rejected(self):
        self.engine.start()
        self.engine.send("unknown_control")
        response = json.loads(self.wait_for("result")["result"])
        self.assertEqual(response["subtype"], "error")
        self.assertNotIn("allow", json.dumps(response))

    def test_malformed_tool_input_is_denied(self):
        self.engine.start()
        self.engine.send("invalid_permission")
        response = json.loads(self.wait_for("result")["result"])["response"]
        self.assertEqual(response["behavior"], "deny")

    def test_interrupt_and_model_controls_keep_session_alive(self):
        self.engine.start()
        self.assertEqual(self.engine.set_model("synthetic-model")["echo"],
                         {"subtype": "set_model", "model": "synthetic-model"})
        self.engine.send("wait")
        self.engine.interrupt()
        self.assertEqual(self.wait_for("result")["result"], "interrupted")
        self.engine.send("after interruption")
        self.assertEqual(self.wait_for("result")["result"], "after interruption")

    def test_overlapping_turns_are_not_written(self):
        self.engine.start()
        self.engine.send("wait")
        with self.assertRaises(EngineError):
            self.engine.send("overlapping")

    def test_unstarted_and_closed_engine_reject_prompts(self):
        with self.assertRaises(EngineError):
            self.engine.send("before start")
        self.engine.close()
        with self.assertRaises(EngineError):
            self.engine.start()

    def test_initialization_error_is_fixed_safe_text(self):
        with patch("privacy_gateway.engine.claude_environment", return_value={"SYNTHETIC_INIT": "error"}), \
                self.assertRaises(EngineError) as error:
            self.engine.start()
        self.assertNotIn("private synthetic credential", str(error.exception))
        self.assertIsNotNone(self.engine._process.poll())

    def test_initialization_timeout_terminates_child(self):
        with patch("privacy_gateway.engine.claude_environment", return_value={"SYNTHETIC_INIT": "timeout"}), \
                patch("privacy_gateway.engine.INITIALIZE_TIMEOUT", .1), self.assertRaises(EngineError):
            self.engine.start()
        self.assertIsNotNone(self.engine._process.poll())

    def test_malformed_response_is_never_exposed(self):
        self.engine.start()
        self.engine.send("malformed")
        error = self.wait_for("engine_error")
        self.assertNotIn("private synthetic credential", json.dumps(error))
        self.wait_for("engine_exit")

    def test_response_line_is_bounded(self):
        self.engine.start()
        with patch("privacy_gateway.engine.MAX_LINE_BYTES", 4096):
            self.engine.send("oversize")
            self.wait_for("engine_error")
            self.wait_for("engine_exit")

    def test_stderr_is_discarded_and_exit_is_structured(self):
        self.engine.start()
        self.engine.send("stderr")
        self.assertEqual(self.wait_for("engine_exit"), {"type": "engine_exit", "code": 3})

    def test_close_terminates_process_and_clears_pending_approval(self):
        self.engine.start()
        self.engine.send("permission")
        request = self.wait_for("permission_request")
        self.engine.close()
        self.assertIsNotNone(self.engine._process.poll())
        self.assertFalse(self.engine.decide_permission(request["id"], True))
        self.assertFalse(self.engine.ready)
        self.assertFalse(self.engine.busy)
        self.assertTrue(all(not thread.is_alive() for thread in self.engine._threads))


@unittest.skipUnless(os.environ.get("MASKCODE_TEST_INSTALLED_ENGINE") == "1"
                     and platform.system() == "Darwin" and shutil.which("claude"),
                     "Opt-in installed CLI integration; all requests use a local fake transport")
class InstalledEngineIntegrationTests(unittest.TestCase):
    def test_two_turns_deny_then_approve_write_with_dummy_auth(self):
        from privacy_gateway.redaction import Policy
        from privacy_gateway.server import GatewayServer, GatewayState
        from claude_tools_smoke import response, find_tool_result

        email = "sample.person@example.com"
        events = queue.Queue()
        requests = []
        stream_events = []
        with tempfile.TemporaryDirectory(prefix="maskcode-engine-synthetic-") as work:
            denied_path = Path(work) / "denied.txt"
            allowed_path = Path(work) / "allowed.txt"
            config = Path(work) / "config"
            config.mkdir()
            state = GatewayState(mode="auto", policy=Policy.from_dict({"literals": [
                {"value": str(Path.home()), "label": "LOCAL_HOME"},
                {"value": work, "label": "SYNTHETIC_PATH"},
            ]}))
            email_token = state.redactor.redact_text(email)

            def fake(path, body, headers):
                self.assertNotIn(email.encode(), body)
                self.assertNotIn(work.encode(), body)
                self.assertEqual(headers.get("x-api-key"), "sk-ant-synthetic-local-test-only")
                data = json.loads(body)
                if path.startswith("/v1/messages/count_tokens"):
                    return 200, "application/json", b'{"input_tokens":100}'
                requests.append(data)
                step = len(requests)
                model = data.get("model", "synthetic-model")
                if step == 1:
                    return response(model, "Write", "toolu_denied", {
                        "file_path": state.redactor.redact_text(str(denied_path)), "content": email_token})
                if step == 2:
                    denied = find_tool_result(data, "toolu_denied")
                    self.assertIsNotNone(denied)
                    self.assertTrue(denied.get("is_error"))
                    return response(model)
                if step == 3:
                    self.assertIn("first synthetic turn", json.dumps(data))
                    self.assertIn("second synthetic turn", json.dumps(data))
                    return response(model, "Write", "toolu_allowed", {
                        "file_path": state.redactor.redact_text(str(allowed_path)), "content": email_token})
                if step == 4:
                    allowed = find_tool_result(data, "toolu_allowed")
                    self.assertIsNotNone(allowed)
                    self.assertFalse(allowed.get("is_error"))
                    return response(model)
                self.fail("Unexpected additional model request")

            state.transport = fake
            server = GatewayServer(state)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            env = claude_environment(server)
            for key in list(env):
                if key.startswith(("ANTHROPIC_", "CLAUDE_CODE_OAUTH_")):
                    env.pop(key)
            env.update({"ANTHROPIC_BASE_URL": server.proxy_url,
                        "ANTHROPIC_API_KEY": "sk-ant-synthetic-local-test-only",
                        "CLAUDE_CONFIG_DIR": str(config), "HOME": work})
            engine = ClaudeEngine(server, ["--tools", "Write", "--no-session-persistence",
                "--model", "sonnet", "--system-prompt", "Use the supplied tools for this synthetic local test."],
                work, events.put)

            def wait_for(kind):
                deadline = time.monotonic() + 35
                while time.monotonic() < deadline:
                    event = events.get(timeout=max(.001, deadline - time.monotonic()))
                    if event["type"] in {"engine_exit", "engine_error"}:
                        self.fail("Installed engine failed during the synthetic integration")
                    if event["type"] == "stream_event":
                        stream_events.append(event)
                    if event["type"] == kind:
                        return event
                self.fail("Installed engine event timed out")

            try:
                with patch("privacy_gateway.engine.claude_environment", return_value=env):
                    engine.start()
                process = engine._process
                engine.send("first synthetic turn: use Write for " + email)
                denied = wait_for("permission_request")
                self.assertEqual(denied["tool"], "Write")
                self.assertEqual(denied["input"]["content"], email)
                engine.decide_permission(denied["id"], False)
                self.assertFalse(wait_for("result").get("is_error"))
                self.assertFalse(denied_path.exists())
                engine.set_model("haiku")
                engine.send("second synthetic turn: use Write for " + email)
                allowed = wait_for("permission_request")
                self.assertEqual(allowed["tool"], "Write")
                engine.decide_permission(allowed["id"], True)
                self.assertFalse(wait_for("result").get("is_error"))
                self.assertEqual(allowed_path.read_text(), email)
                self.assertEqual(len(requests), 4)
                self.assertNotEqual(requests[0]["model"], requests[2]["model"])
                self.assertTrue(stream_events)
                self.assertEqual(state.blocked, 0)
                self.assertIs(engine._process, process)
                self.assertIsNone(process.poll())
                self.assertIsNotNone(engine.session_id)
            finally:
                engine.close()
                state.close()
                server.shutdown()
                server.server_close()
                thread.join(2)


if __name__ == "__main__":
    unittest.main()
