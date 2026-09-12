import base64
import copy
import json
import os
from pathlib import Path
import subprocess
import platform
import threading
import socket
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from privacy_gateway.codex_client import (
    CodexConfigurationError, codex_environment, protected_codex_launch,
    validate_codex_arguments, find_codex_binary,
)


class CodexDiscoveryTests(unittest.TestCase):
    def test_path_installation_takes_precedence_without_scanning_apps(self):
        with tempfile.TemporaryDirectory(prefix="maskcode-codex-discovery-") as temporary:
            binary = Path(temporary, "preferred-cli").resolve()
            binary.write_text("synthetic executable fixture")
            binary.chmod(0o700)
            with patch("privacy_gateway.codex_client.shutil.which", return_value=str(binary)) as lookup, \
                    patch("privacy_gateway.codex_client._macos_codex_paths") as candidates:
                self.assertEqual(find_codex_binary(), str(binary))
            lookup.assert_called_once_with("codex")
            candidates.assert_not_called()

    def test_executable_app_bundle_fallback_preserves_spaces_in_path(self):
        with tempfile.TemporaryDirectory(prefix="maskcode codex discovery ") as temporary:
            binary = Path(temporary, "Applications", "Codex.app", "Contents", "Resources", "codex")
            binary.parent.mkdir(parents=True)
            binary.write_text("synthetic executable fixture")
            binary.chmod(0o700)
            with patch("privacy_gateway.codex_client.shutil.which", return_value=None), \
                    patch("platform.system", return_value="Darwin"), \
                    patch("privacy_gateway.codex_client._macos_codex_paths", return_value=(binary,)):
                discovered = find_codex_binary()
            self.assertEqual(Path(discovered).resolve(), binary.resolve())
            self.assertTrue(Path(discovered).is_absolute())
            self.assertIn(" ", discovered)

    def test_fallback_skips_missing_directories_nonexecutables_and_broken_links(self):
        with tempfile.TemporaryDirectory(prefix="maskcode-codex-discovery-") as temporary:
            root = Path(temporary)
            missing = root / "missing"
            directory = root / "directory"
            directory.mkdir()
            nonexecutable = root / "nonexecutable"
            nonexecutable.write_text("synthetic nonexecutable fixture")
            nonexecutable.chmod(0o600)
            broken = root / "broken-link"
            broken.symlink_to(missing)
            valid = root / "valid"
            valid.write_text("synthetic executable fixture")
            valid.chmod(0o700)
            invalid = (missing, directory, nonexecutable, broken)
            with patch("privacy_gateway.codex_client.shutil.which", return_value=None), \
                    patch("platform.system", return_value="Darwin"):
                for candidate in invalid:
                    with self.subTest(candidate=candidate.name), \
                            patch("privacy_gateway.codex_client._macos_codex_paths",
                                  return_value=(candidate, valid)):
                        self.assertEqual(Path(find_codex_binary()).resolve(), valid.resolve())
                with patch("privacy_gateway.codex_client._macos_codex_paths", return_value=invalid):
                    self.assertIsNone(find_codex_binary())

    def test_nothing_installed_returns_none(self):
        with patch("privacy_gateway.codex_client.shutil.which", return_value=None), \
                patch("platform.system", return_value="Darwin"), \
                patch("privacy_gateway.codex_client._macos_codex_paths", return_value=()):
            self.assertIsNone(find_codex_binary())

    def test_other_platforms_do_not_scan_macos_bundles(self):
        for operating_system in ("Linux", "Windows"):
            with self.subTest(platform=operating_system), \
                    patch("privacy_gateway.codex_client.shutil.which", return_value=None), \
                    patch("platform.system", return_value=operating_system), \
                    patch("privacy_gateway.codex_client._macos_codex_paths") as candidates:
                self.assertIsNone(find_codex_binary())
                candidates.assert_not_called()


class CodexLaunchTests(unittest.TestCase):
    def setUp(self):
        from privacy_gateway.server import GatewayState
        self.server = SimpleNamespace(server_port=40123, proxy_url="http://127.0.0.1:40123/proxy/synthetic",
                                      state=GatewayState(provider="codex", mode="auto"))
        self.catalog = {"models": [{
            "slug": "gpt-6-astra", "base_instructions": "Official synthetic instructions", "context_window": 272000,
            "model_messages": {"instructions_template": "Official synthetic instructions",
                               "persistent_instructions": "Persistent official context",
                               "approvals": {"on_request": "Official approval context"}},
            "use_responses_lite": True, "tool_mode": "code_mode_only", "apply_patch_tool_type": "freeform",
        }, {"slug": "other-model", "base_instructions": "Other official instructions", "use_responses_lite": True}]}

    def catalog_result(self):
        return SimpleNamespace(returncode=0, stdout=json.dumps(self.catalog).encode(), stderr=b"")

    def launch_patches(self):
        return patch("privacy_gateway.codex_client.shutil.which", return_value="/installed/codex"), \
            patch("privacy_gateway.codex_client.subprocess.run", return_value=self.catalog_result())

    def test_default_model_and_explicit_model_are_preserved(self):
        self.assertEqual(validate_codex_arguments([]), ([], "gpt-6-astra", None))
        args = ["--model", "other-model", "exec", "--json", "a prompt"]
        self.assertEqual(validate_codex_arguments(args), (args, "other-model", 2))

    def test_prompt_and_option_values_are_not_reinterpreted_as_commands(self):
        args = ["--output-schema", "exec", "exec", "--", "login"]
        self.assertEqual(validate_codex_arguments(args)[2], 2)
        self.assertEqual(validate_codex_arguments(["--", "--config=unsafe"])[0], ["--", "--config=unsafe"])

    def test_transport_and_service_bypasses_are_blocked(self):
        attempts = [
            ["-c", "model_provider=external"], ["--config=model_provider=external"],
            ["--remote", "unix:///tmp/server"], ["--oss"], ["--profile", "custom"],
            ["--enable", "hooks"], ["--search"], ["--image", "secret.png"],
            ["--dangerously-bypass-approvals-and-sandbox"], ["--dangerously-bypass-hook-trust"],
            ["-s", "danger-full-access"], ["-s", "workspace-write"], ["-s", "read-only"], ["-a", "never"], ["exec", "resume"], ["login"],
            ["app-server"], ["--model", "--config"], ["--output-schema", "-c", "provider=bad"],
        ]
        for args in attempts:
            with self.subTest(args=args), self.assertRaises(CodexConfigurationError):
                validate_codex_arguments(args)

    def test_incomplete_and_ambiguous_arguments_fail_closed(self):
        for args in (["--model"], ["--model=bad/model"], ["--help=yes"], ["one", "two"], ["nul\0prompt"]):
            with self.subTest(args=args), self.assertRaises(CodexConfigurationError):
                validate_codex_arguments(args)

    def test_existing_auth_survives_environment_transport_cleanup(self):
        original = {"PATH": "/usr/bin", "HOME": "/local/home", "CODEX_HOME": "/local/auth",
                    "OPENAI_API_KEY": "synthetic-api", "CODEX_API_KEY": "synthetic-exec",
                    "OPENAI_BASE_URL": "https://override.invalid", "CODEX_APP_SERVER_URL": "unix:///tmp/other",
                    "CHATGPT_BASE_URL": "https://override.invalid", "HTTPS_PROXY": "http://override.invalid",
                    "DYLD_INSERT_LIBRARIES": "/tmp/library", "OTEL_EXPORTER_OTLP_ENDPOINT": "https://override.invalid"}
        result = codex_environment(original)
        for key in ("OPENAI_API_KEY", "CODEX_API_KEY", "CODEX_HOME", "HOME"):
            self.assertEqual(result[key], original[key])
        for key in ("OPENAI_BASE_URL", "CODEX_APP_SERVER_URL", "CHATGPT_BASE_URL", "HTTPS_PROXY", "DYLD_INSERT_LIBRARIES", "OTEL_EXPORTER_OTLP_ENDPOINT"):
            self.assertNotIn(key, result)
        self.assertEqual(original["HTTPS_PROXY"], "http://override.invalid")
        self.assertEqual(result["OTEL_SDK_DISABLED"], "true")

    def test_temporary_catalog_keeps_real_model_and_instructions_with_standard_transport(self):
        which, run = self.launch_patches()
        with which, run as discover:
            with protected_codex_launch(self.server, ["--model", "gpt-6-astra"]) as (argv, env):
                self.assertEqual(argv[:2], ["/usr/bin/sandbox-exec", "-p"])
                settings = dict(arg.split("=", 1) for index, arg in enumerate(argv) if index and argv[index - 1] == "-c")
                path = Path(json.loads(settings["model_catalog_json"]))
                model = json.loads(path.read_text())["models"][0]
                self.assertEqual(model["slug"], "gpt-6-astra")
                self.assertEqual(model["base_instructions"], "Official synthetic instructions")
                self.assertEqual(self.server.state._codex_public_instructions,
                                 ("gpt-6-astra", "Official synthetic instructions"))
                self.assertEqual(model["model_messages"], self.catalog["models"][0]["model_messages"])
                self.assertEqual(model["context_window"], 272000)
                self.assertEqual(model["apply_patch_tool_type"], "freeform")
                self.assertFalse(model["use_responses_lite"])
                self.assertEqual(model["tool_mode"], "direct")
                self.assertTrue(model["node_repl_disabled"])
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                provider = json.loads(settings["model_provider"])
                self.assertTrue(provider.startswith("maskcode_"))
                self.assertEqual(json.loads(settings["model_providers." + provider + ".base_url"]), self.server.proxy_url)
                self.assertEqual(settings["model_providers." + provider + ".requires_openai_auth"], "true")
                self.assertEqual(settings["features.enable_request_compression"], "false")
                self.assertEqual(settings["mcp_servers"], "{}")
                self.assertEqual(settings["features.plugins"], "false")
                self.assertEqual(settings["features.hooks"], "false")
                self.assertEqual(settings["sandbox_mode"], '"danger-full-access"')
                self.assertEqual(settings["approval_policy"], '"on-request"')
                metadata_env = discover.call_args.kwargs["env"]
                self.assertNotIn("OPENAI_API_KEY", metadata_env)
                self.assertNotIn("CODEX_API_KEY", metadata_env)
                self.assertEqual(Path(metadata_env["CODEX_HOME"]), path.parent)
            self.assertFalse(path.exists())
        self.assertTrue(self.catalog["models"][0]["use_responses_lite"])

    def test_exec_flags_are_inserted_at_actual_command_before_literal_delimiter(self):
        which, run = self.launch_patches()
        args = ["--output-schema", "exec", "exec", "--", "login"]
        with which, run:
            with protected_codex_launch(self.server, args) as (argv, env):
                self.assertEqual(argv[-7:], ["--output-schema", "exec", "exec", "--ignore-user-config", "--ignore-rules", "--", "login"])

    def test_catalog_discovery_errors_never_echo_local_contents(self):
        with patch("privacy_gateway.codex_client.shutil.which", return_value="/installed/codex"):
            for result in (SimpleNamespace(returncode=1, stdout=b"secret", stderr=b"sensitive diagnostics"),
                           SimpleNamespace(returncode=0, stdout=b"not json secret", stderr=b"")):
                with self.subTest(result=result.returncode), patch("privacy_gateway.codex_client.subprocess.run", return_value=result):
                    with self.assertRaises(CodexConfigurationError) as caught:
                        with protected_codex_launch(self.server, []):
                            self.fail("Launch should fail")
                    self.assertNotIn("secret", str(caught.exception))
                    self.assertNotIn("sensitive", str(caught.exception))

    def test_unknown_selected_model_is_not_silently_substituted(self):
        which, run = self.launch_patches()
        with which, run, self.assertRaises(CodexConfigurationError):
            with protected_codex_launch(self.server, ["--model", "unknown-model"]):
                self.fail("Launch should fail")

    def test_missing_cli_and_timeout_fail_closed(self):
        with patch("privacy_gateway.codex_client.find_codex_binary", return_value=None), self.assertRaises(CodexConfigurationError):
            with protected_codex_launch(self.server, []):
                self.fail("Launch should fail")
        with patch("privacy_gateway.codex_client.shutil.which", return_value="/installed/codex"), \
                patch("privacy_gateway.codex_client.subprocess.run", side_effect=subprocess.TimeoutExpired("codex", 15)), \
                self.assertRaises(CodexConfigurationError):
            with protected_codex_launch(self.server, []):
                self.fail("Launch should fail")


@unittest.skipUnless(platform.system() == "Darwin", "macOS Seatbelt isolation")
class CodexIsolationTests(unittest.TestCase):
    def test_outer_profile_limits_writes_and_direct_sockets_in_actual_process(self):
        from privacy_gateway.codex_isolation import command
        with tempfile.TemporaryDirectory(prefix="maskcode-boundary-") as temporary, \
                socket.socket() as gateway, socket.socket() as other:
            root = Path(temporary).resolve()
            work, scratch, state, outside, additional = [root / name for name in ("work", "scratch", "state", "outside", "extra")]
            for path in (work, scratch, state, outside, additional):
                path.mkdir()
            original = outside / "preserve.txt"
            original.write_text("untouched")
            (work / "symlink").symlink_to(original)
            gateway.bind(("127.0.0.1", 0)); gateway.listen(1)
            other.bind(("127.0.0.1", 0)); other.listen(1)
            code = r'''import json,socket,sys
from pathlib import Path
work,scratch,state,outside,extra=map(Path,sys.argv[1:6])
r={}
for name,path in [('work',work/'new.txt'),('scratch',scratch/'new.txt'),('state',state/'new.txt'),('extra',extra/'new.txt'),('outside',outside/'new.txt'),('symlink',work/'symlink')]:
 try:path.write_text('changed');r[name]='allowed'
 except PermissionError:r[name]='blocked'
try:
 (work/'hardlink').hardlink_to(outside/'preserve.txt')
 (work/'hardlink').write_text('changed');r['hardlink']='allowed'
except PermissionError:r['hardlink']='blocked'
r['read_outside']=(outside/'preserve.txt').read_text()
for name,host,port in [('gateway','127.0.0.1',int(sys.argv[6])),('other','127.0.0.1',int(sys.argv[7])),('public','1.1.1.1',443)]:
 s=socket.socket();s.settimeout(1)
 try:s.connect((host,port));r[name]='allowed'
 except PermissionError:r[name]='blocked'
 except OSError:r[name]='inconclusive'
 finally:s.close()
print(json.dumps(r))
'''
            argv = [sys.executable, "-I", "-S", "-c", code, *map(str, (work, scratch, state, outside, additional)),
                    str(gateway.getsockname()[1]), str(other.getsockname()[1])]
            result = subprocess.run(command(gateway.getsockname()[1], argv, [work, additional], scratch, state),
                                    cwd=work, capture_output=True, text=True, timeout=8)
            self.assertEqual(result.returncode, 0, result.stderr)
            findings = json.loads(result.stdout)
            self.assertEqual(findings, {"work": "allowed", "scratch": "allowed", "state": "allowed", "extra": "allowed",
                "outside": "blocked", "symlink": "blocked", "hardlink": "blocked", "read_outside": "untouched",
                "gateway": "allowed", "other": "blocked", "public": "blocked"})
            self.assertEqual(original.read_text(), "untouched")


@unittest.skipUnless(os.environ.get("MASKCODE_TEST_INSTALLED_CODEX") == "1"
                     and platform.system() == "Darwin" and find_codex_binary(),
                     "Opt-in installed Codex integration; dummy auth and local fake transport only")
class InstalledCodexGatewayTests(unittest.TestCase):
    def test_standard_responses_round_trip_masks_outgoing_and_restores_reply(self):
        self._assert_standard_round_trip(chatgpt=False)

    def test_subscription_auth_preserves_native_bundled_instructions_and_context(self):
        self._assert_standard_round_trip(chatgpt=True)

    def _assert_standard_round_trip(self, *, chatgpt):
        from privacy_gateway.server import GatewayServer, GatewayState, Handler
        from privacy_gateway.redaction import Policy
        from privacy_gateway.semantic import SemanticScanner

        email = "synthetic.person@example.com"
        captured = []
        native_payloads = []
        local_inputs = []
        def detect(system, text, schema):
            local_inputs.append(text)
            return {"entities": []}
        scanner = SemanticScanner(SimpleNamespace(generate_json=detect))
        state = GatewayState(provider="codex", mode="auto", policy=Policy.from_dict({}),
                             semantic_scanner=scanner)
        read_json = Handler.read_json
        def capture_native(handler):
            payload = read_json(handler)
            if handler.state is state:
                native_payloads.append(copy.deepcopy(payload))
            return payload
        token = state.redactor.redact_text(email)
        def fake_transport(path, body, headers):
            captured.append((path, body, headers))
            item = {"id": "msg_synthetic", "type": "message", "role": "assistant", "status": "completed",
                    "phase": "final_answer", "content": [{"type": "output_text", "text": token, "annotations": []}]}
            response = {"id": "resp_synthetic", "object": "response", "created_at": 1,
                        "status": "completed", "model": "gpt-6-astra", "output": [item],
                        "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2}}
            packets = [
                {"type": "response.created", "response": {**response, "status": "in_progress", "output": []}},
                {"type": "response.output_item.added", "output_index": 0,
                 "item": {**item, "status": "in_progress", "content": []}},
                {"type": "response.content_part.added", "item_id": "msg_synthetic", "output_index": 0, "content_index": 0,
                 "part": {"type": "output_text", "text": "", "annotations": []}},
                {"type": "response.output_text.delta", "item_id": "msg_synthetic", "output_index": 0, "content_index": 0, "delta": token},
                {"type": "response.output_text.done", "item_id": "msg_synthetic", "output_index": 0, "content_index": 0, "text": token},
                {"type": "response.output_item.done", "output_index": 0, "item": item},
                {"type": "response.completed", "response": response},
            ]
            body = "".join("event: " + packet["type"] + "\ndata: " + json.dumps(packet) + "\n\n" for packet in packets).encode()
            return 200, "text/event-stream", body
        state.transport = fake_transport
        server = GatewayServer(state)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        capture_patch = patch.object(Handler, "read_json", capture_native)
        capture_patch.start()
        thread.start()
        try:
            with tempfile.TemporaryDirectory(prefix="maskcode-codex-synthetic-") as temp:
                local_env = {"PATH": os.environ["PATH"], "HOME": temp, "CODEX_HOME": temp,
                             "NO_COLOR": "1"}
                if chatgpt:
                    # Entirely fabricated credentials: the sandbox permits
                    # only our localhost gateway, whose transport is fake.
                    account = "00000000-0000-4000-8000-000000000000"
                    def encoded(value):
                        return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=").decode()
                    auth_token = ".".join((encoded({"alg": "RS256", "typ": "JWT"}), encoded({
                        "sub": "synthetic-local-user", "exp": int(time.time()) + 3600,
                        "email": "synthetic@example.com", "https://api.openai.com/auth": {
                            "chatgpt_account_id": account, "chatgpt_plan_type": "pro",
                            "user_id": "synthetic-local-user"}}), encoded("synthetic-signature")))
                    Path(temp, "auth.json").write_text(json.dumps({"auth_mode": "chatgpt", "tokens": {
                        "id_token": auth_token, "access_token": auth_token,
                        "refresh_token": "synthetic-refresh-token", "account_id": account},
                        "last_refresh": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}))
                else:
                    auth_token = "sk-synthetic-local-test-only"
                    local_env["OPENAI_API_KEY"] = auth_token
                    Path(temp, "auth.json").write_text(json.dumps({"OPENAI_API_KEY": auth_token}))
                with patch.dict(os.environ, local_env, clear=True):
                    with protected_codex_launch(server, ["exec", "--model", "gpt-6-astra", "--ephemeral",
                            "--skip-git-repo-check", "--json", "Reply only with this synthetic email: " + email], cwd=temp) as (argv, env):
                        settings = dict(arg.split("=", 1) for index, arg in enumerate(argv)
                                        if index and argv[index - 1] == "-c")
                        source_model = json.loads(Path(json.loads(settings["model_catalog_json"])).read_text())["models"][0]
                        result = subprocess.run(argv, cwd=temp, env=env, input="", text=True,
                                                capture_output=True, timeout=30)
                self.assertEqual(result.returncode, 0, "Installed Codex rejected the synthetic gateway response: "
                                 + json.dumps({"forwarded": state.forwarded, "blocked": state.blocked,
                                               "stdout": result.stdout[-1600:], "stderr": result.stderr[-600:]}))
                self.assertEqual(len(captured), 1)
                path, outgoing, headers = captured[0]
                self.assertEqual(path, "/responses")
                self.assertNotIn(email.encode(), outgoing)
                self.assertIn(token.encode(), outgoing)
                data = json.loads(outgoing)
                self.assertEqual(data["model"], "gpt-6-astra")
                self.assertEqual(len(native_payloads), 1)
                # Capture before any gateway processing: both authentication
                # paths send the native base instructions. Public prose such
                # as "basic instructions" must not rename this protocol key.
                self.assertEqual(native_payloads[0]["instructions"], source_model["base_instructions"])
                self.assertEqual(state.public_instruction_chars_skipped, len(source_model["base_instructions"]))
                self.assertTrue(local_inputs)  # Remaining request content still reaches the local detector.
                self.assertGreater(scanner.snapshot()["completed_chunks"], 0)
                self.assertTrue(data["instructions"])
                self.assertEqual(data["instructions"], state.redactor.redact_text(source_model["base_instructions"]))
                # Masking must not discard/reorder native permissions,
                # collaboration context, or the user's messages.
                self.assertEqual(data["input"], state.redactor.redact_json(native_payloads[0]["input"]))
                self.assertTrue(any(t.get("name") == "apply_patch" and t.get("type") == "custom" for t in data["tools"]))
                self.assertTrue(any(t.get("type") == "namespace" for t in data["tools"]))
                self.assertEqual(headers["authorization"], "Bearer " + auth_token)
                if chatgpt:
                    self.assertEqual(headers["chatgpt-account-id"], account)
                self.assertNotIn("Content-Encoding", headers)
                self.assertEqual(state.blocked, 0)
                events = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
                messages = [event["item"].get("text") for event in events
                            if event.get("type") == "item.completed" and event.get("item", {}).get("type") == "agent_message"]
                self.assertEqual(messages, [email])
        finally:
            state.close()
            server.shutdown()
            server.server_close()
            thread.join(2)
            capture_patch.stop()


    def test_real_agent_reads_patches_and_runs_tests_with_masked_context(self):
        from privacy_gateway.server import GatewayServer, GatewayState
        from privacy_gateway.redaction import Policy

        email = "synthetic.person@example.com"
        captured = []
        failures = []
        with tempfile.TemporaryDirectory(prefix="maskcode-codex-workflow-") as temporary:
            work = Path(temporary).resolve()
            (work / "contact.py").write_text('CONTACT_EMAIL = "' + email + '"\nRETRY_COUNT = 1\n')
            (work / "tests").mkdir()
            (work / "tests" / "test_contact.py").write_text(
                'import unittest\nfrom contact import CONTACT_EMAIL, RETRY_COUNT\n'
                'class TestContact(unittest.TestCase):\n'
                '    def test_contact_is_preserved(self):\n'
                '        self.assertEqual(CONTACT_EMAIL, "' + email + '")\n'
                '        self.assertEqual(RETRY_COUNT, 2)\n')
            config = work / "local-client-config"
            config.mkdir()
            (config / "auth.json").write_text('{"OPENAI_API_KEY":"sk-synthetic-local-test-only"}')
            state = GatewayState(provider="codex", mode="auto", policy=Policy.from_dict({"literals": [
                {"value": str(work), "label": "SYNTHETIC_PROJECT"}]}))
            token = state.redactor.redact_text(email)
            work_token = state.redactor.redact_text(str(work))

            def tool_output(data, call_id):
                return next((item.get("output") for item in data.get("input", [])
                             if item.get("call_id") == call_id and item.get("type") in
                             ("function_call_output", "custom_tool_call_output")), None)

            def stream(step, tool_type=None, name=None, value=None):
                ident = "item_synthetic_" + str(step)
                if tool_type:
                    field = "arguments" if tool_type == "function_call" else "input"
                    item = {"type": tool_type, "id": ident, "call_id": "call_synthetic_" + str(step),
                            "name": name, field: value, "status": "completed"}
                else:
                    item = {"type": "message", "id": ident, "role": "assistant", "status": "completed", "phase": "final_answer",
                            "content": [{"type": "output_text", "text": "Tests passed; contact preserved.", "annotations": []}]}
                response = {"id": "resp_synthetic_" + str(step), "object": "response", "created_at": 1,
                            "status": "completed", "model": "gpt-6-astra", "output": [item],
                            "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2}}
                packets = [{"type": "response.created", "response": {**response, "status": "in_progress", "output": []}}]
                if tool_type:
                    packets.append({"type": "response.output_item.added", "output_index": 0, "item": {**item, field: "", "status": "in_progress"}})
                    lane = "function_call_arguments" if tool_type == "function_call" else "custom_tool_call_input"
                    packets.append({"type": "response." + lane + ".delta", "item_id": ident, "output_index": 0, "delta": value})
                    packets.append({"type": "response." + lane + ".done", "item_id": ident, "output_index": 0, field: value})
                else:
                    packets.append({"type": "response.output_item.added", "output_index": 0,
                                    "item": {**item, "status": "in_progress", "content": []}})
                    packets.append({"type": "response.output_text.delta", "item_id": ident, "output_index": 0,
                                    "content_index": 0, "delta": item["content"][0]["text"]})
                packets += [{"type": "response.output_item.done", "output_index": 0, "item": item},
                            {"type": "response.completed", "response": response}]
                return 200, "text/event-stream", "".join("event: " + packet["type"] + "\ndata: " + json.dumps(packet) + "\n\n" for packet in packets).encode()

            def fake_transport(path, body, headers):
                try:
                    self.assertEqual(path, "/responses")
                    self.assertNotIn(email.encode(), body)
                    self.assertNotIn(str(work).encode(), body)
                    data = json.loads(body)
                    captured.append(data)
                    step = len(captured)
                    if step == 1:
                        return stream(step, "function_call", "exec_command", json.dumps({
                            "cmd": "cat contact.py", "workdir": work_token, "max_output_tokens": 2000}))
                    if step == 2:
                        read = tool_output(data, "call_synthetic_1")
                        self.assertIsNotNone(read)
                        self.assertIn(token, json.dumps(read))
                        self.assertIn("RETRY_COUNT = 1", json.dumps(read))
                        patch_text = ("*** Begin Patch\n*** Update File: " + work_token + "/contact.py\n@@\n"
                                      ' CONTACT_EMAIL = "' + token + '"\n-RETRY_COUNT = 1\n+RETRY_COUNT = 2\n*** End Patch\n')
                        return stream(step, "custom_tool_call", "apply_patch", patch_text)
                    if step == 3:
                        edited = tool_output(data, "call_synthetic_2")
                        self.assertIsNotNone(edited)
                        self.assertIn("Success", json.dumps(edited))
                        self.assertEqual((work / "contact.py").read_text(), 'CONTACT_EMAIL = "' + email + '"\nRETRY_COUNT = 2\n')
                        return stream(step, "function_call", "exec_command", json.dumps({
                            "cmd": "python3 -m unittest discover -s tests -q", "workdir": work_token,
                            "max_output_tokens": 2000, "yield_time_ms": 1000}))
                    if step == 4:
                        output = tool_output(data, "call_synthetic_3")
                        self.assertIsNotNone(output)
                        self.assertIn("OK", json.dumps(output))
                        return stream(step)
                    self.fail("Unexpected extra synthetic model request")
                except Exception as exc:
                    failures.append(type(exc).__name__ + ": " + str(exc))
                    raise

            state.transport = fake_transport
            server = GatewayServer(state)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                local_env = {"PATH": os.environ["PATH"], "HOME": str(config), "CODEX_HOME": str(config),
                             "OPENAI_API_KEY": "sk-synthetic-local-test-only", "NO_COLOR": "1"}
                with patch.dict(os.environ, local_env, clear=True):
                    with protected_codex_launch(server, ["exec", "--model", "gpt-6-astra", "--ephemeral",
                            "--skip-git-repo-check", "--json", "Read contact.py, change retries to2 while preserving the email, and run unittest."], cwd=work) as (argv, env):
                        result = subprocess.run(argv, cwd=work, env=env, input="", text=True,
                                                capture_output=True, timeout=40)
                self.assertEqual(failures, [])
                self.assertEqual(result.returncode, 0, json.dumps({"forwarded": state.forwarded, "blocked": state.blocked,
                                 "stdout": result.stdout[-1800:], "stderr": result.stderr[-600:]}))
                self.assertEqual(len(captured), 4)
                self.assertEqual(state.blocked, 0)
                self.assertEqual(state.forwarded, 4)
                self.assertIn("Tests passed; contact preserved.", result.stdout)
                self.assertEqual((work / "contact.py").read_text(), 'CONTACT_EMAIL = "' + email + '"\nRETRY_COUNT = 2\n')
            finally:
                state.close()
                server.shutdown()
                server.server_close()
                thread.join(2)


if __name__ == "__main__":
    unittest.main()
