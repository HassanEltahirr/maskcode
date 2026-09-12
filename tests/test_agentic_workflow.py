"""Installed Claude runs a coding task through the actual MaskCode terminal.

Opt in with MASKCODE_TEST_INSTALLED_ENGINE=1. A local fake upstream supplies
Read/Edit/Bash calls; the real CLI executes them in a temporary project. No
provider account, cloud request, or permanent project file is used. A fake local
extraction model discovers an unconfigured company through the real semantic
scanner before the first request reaches the fake provider.
"""
import asyncio
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from prompt_toolkit.input import create_pipe_input
from prompt_toolkit.output import DummyOutput

from privacy_gateway.client import claude_environment
from privacy_gateway.engine import ClaudeEngine
from privacy_gateway.redaction import Policy
from privacy_gateway.semantic import SemanticScanner
from privacy_gateway.server import GatewayServer, GatewayState
from privacy_gateway.terminal import TerminalApp


@unittest.skipUnless(os.environ.get("MASKCODE_TEST_INSTALLED_ENGINE") == "1"
                     and platform.system() == "Darwin" and shutil.which("claude"),
                     "Opt-in installed CLI coding workflow with local fake transport")
class AgenticWorkflowTests(unittest.IsolatedAsyncioTestCase):
    async def test_semantic_masked_read_edit_test_without_outgoing_approval_dialogs(self):
        from claude_tools_smoke import response, find_tool_result, FINISHED

        email = "sample.person@example.com"
        company = "Cedar Example LLC"
        dummy_key = "sk-ant-synthetic-agentic-test-only"
        final = "Fixed contact formatting; 1 test passed."
        broken = 'RECIPIENT = "' + company + ' <' + email + '>"\n\n' \
                 'def render_contact():\n    return RECIPIENT.lower()\n'
        fixed = broken.replace("return RECIPIENT.lower()", "return RECIPIENT")
        test_source = ('import unittest\nfrom contacts import render_contact\n\n'
                       'class ContactTests(unittest.TestCase):\n'
                       '    def test_preserves_contact_case(self):\n'
                       '        self.assertEqual(render_contact(), '
                       + repr(company + " <" + email + ">") + ')\n')
        captured, failures, events, approved_tools, local_inputs = [], [], [], [], []

        class FakeLocalExtractor:
            closed = False

            def generate_json(self, system, text, schema):
                local_inputs.append(text)
                # The real scanner validates these exact spans and the real
                # gateway learns them. No test helper registers the company.
                return {"entities": [{"value": company, "label": "ORG"}]
                        if company in text else []}

            def close(self):
                self.closed = True

        local_runtime = FakeLocalExtractor()
        scanner = SemanticScanner(local_runtime)
        with tempfile.TemporaryDirectory(prefix="maskcode-agentic-synthetic-") as work, \
                create_pipe_input() as pipe:
            config = Path(work) / "config"
            config.mkdir()
            source = Path(work) / "contacts.py"
            source.write_text(broken, encoding="utf-8")
            (Path(work) / "test_contacts.py").write_text(test_source, encoding="utf-8")
            # Establish a real failing test before the agent makes its edit.
            baseline = await asyncio.to_thread(subprocess.run,
                [sys.executable, "-m", "unittest", "-q"], cwd=work,
                capture_output=True, text=True, timeout=10)
            self.assertNotEqual(baseline.returncode, 0)
            self.assertIn("FAILED (failures=1)", baseline.stderr)

            state = GatewayState(mode="auto", semantic_scanner=scanner,
                policy=Policy.from_dict({"literals": [
                {"value": work, "label": "SYNTHETIC_PATH"},
                {"value": str(Path.home()), "label": "LOCAL_HOME"},
            ]}))
            self.assertNotIn(company, state.redactor._original_to_token)
            self.assertNotIn(company, [value for value, _ in state.policy.literals])
            email_token = company_token = path_token = broken_masked = fixed_masked = None

            def reply(step, model, tool=None, tool_id=None, inputs=None):
                status, content_type, body = response(model, tool, tool_id, inputs)
                body = body.replace(b"msg_synthetic_local_tools",
                                    ("msg_synthetic_agentic_" + str(step)).encode())
                return status, content_type, body.replace(FINISHED.encode(), final.encode())

            def tool_result(data, tool_id):
                result = find_tool_result(data, tool_id)
                self.assertIsNotNone(result)
                self.assertFalse(result.get("is_error"), "Real local tool failed")
                return json.dumps(result)

            def fake(path, body, headers):
                nonlocal email_token, company_token, path_token, broken_masked, fixed_masked
                try:
                    for original in (email, company, work):
                        self.assertNotIn(original.encode(), body)
                    self.assertEqual(headers.get("x-api-key"), dummy_key)
                    data = json.loads(body)
                    if path.startswith("/v1/messages/count_tokens"):
                        return 200, "application/json", b'{"input_tokens":100}'
                    captured.append(data)
                    step = len(captured)
                    model = data.get("model", "synthetic-model")
                    if step == 1:
                        self.assertTrue(any(company in text for text in local_inputs))
                        self.assertIn(company, state.redactor._original_to_token)
                        company_token = state.redactor._original_to_token[company]
                        self.assertIn(company_token.encode(), body)
                        email_token = state.redactor.redact_text(email)
                        path_token = state.redactor.redact_text(str(source))
                        broken_masked = state.redactor.redact_text(broken)
                        fixed_masked = state.redactor.redact_text(fixed)
                        offered = {item.get("name") for item in data.get("tools", [])}
                        self.assertTrue({"Read", "Edit", "Bash"} <= offered)
                        return reply(step, model, "Read", "toolu_agentic_read",
                                     {"file_path": path_token})
                    if step == 2:
                        result = tool_result(data, "toolu_agentic_read")
                        self.assertIn(email_token, result)
                        self.assertIn(company_token, result)
                        return reply(step, model, "Edit", "toolu_agentic_edit", {
                            "file_path": path_token, "old_string": broken_masked,
                            "new_string": fixed_masked, "replace_all": False})
                    if step == 3:
                        tool_result(data, "toolu_agentic_edit")
                        self.assertEqual(source.read_text(encoding="utf-8"), fixed)
                        return reply(step, model, "Bash", "toolu_agentic_test", {
                            "command": "python3 -m unittest -q",
                            "description": "Run the contact formatting regression test"})
                    if step == 4:
                        result = tool_result(data, "toolu_agentic_test")
                        self.assertIn("Ran 1 test", result)
                        self.assertIn("OK", result)
                        self.assertNotIn("FAILED", result)
                        return reply(step, model)
                    self.fail("Unexpected extra request in the synthetic coding task")
                except Exception as exc:
                    failures.append(str(exc))
                    raise

            state.transport = fake
            server = GatewayServer(state)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            env = claude_environment(server)
            self.assertEqual(env["CLAUDE_CODE_MAX_RETRIES"], "0")
            for key in list(env):
                if key.startswith(("ANTHROPIC_", "CLAUDE_CODE_OAUTH_")):
                    env.pop(key)
            env.update({"ANTHROPIC_BASE_URL": server.proxy_url,
                        "ANTHROPIC_API_KEY": dummy_key,
                        "CLAUDE_CONFIG_DIR": str(config), "HOME": work})
            ui = TerminalApp(work, mode="auto", input=pipe, output=DummyOutput())

            def on_event(event):
                events.append(event)
                ui.post_event(event)

            engine = ClaudeEngine(server, ["--tools", "Read,Edit,Bash",
                "--no-session-persistence", "--model", "sonnet", "--system-prompt",
                "Use the supplied tools for this synthetic local coding test."], work, on_event)
            ui.bind(engine, state)
            task = None

            async def eventually(predicate, timeout=20):
                deadline = asyncio.get_running_loop().time() + timeout
                while not predicate():
                    self.assertFalse(failures, "Local synthetic upstream: " + repr(failures))
                    self.assertFalse(task and task.done(), "Terminal unexpectedly closed")
                    self.assertNotEqual((ui._approval or {}).get("kind"), "gateway")
                    if asyncio.get_running_loop().time() >= deadline:
                        self.fail("Timed out in synthetic coding workflow: " + json.dumps({
                            "requests": len(captured), "status": ui.status,
                            "approval_kind": (ui._approval or {}).get("kind"),
                            "forwarded": state.forwarded, "blocked": state.blocked,
                            "approved_tools": approved_tools,
                        }))
                    await asyncio.sleep(.015)

            try:
                with patch("privacy_gateway.engine.claude_environment", return_value=env), \
                        patch("webbrowser.open") as open_browser, \
                        patch.object(state, "decision", wraps=state.decision) as outgoing_decision:
                    task = asyncio.create_task(ui.run_async())
                    await eventually(lambda: ui.ready)
                    pipe.send_text("Fix the contact formatting in contacts.py for " + company
                                   + " and " + email + ", then run the tests.\r")
                    # Use the actual terminal permission buttons when the CLI
                    # asks. Masked provider requests are never approved here.
                    while True:
                        await eventually(lambda: ui._approval is not None
                                         or (not ui.busy and final in ui.transcript_text()))
                        if ui._approval is None:
                            break
                        self.assertEqual(ui._approval["kind"], "tool")
                        self.assertTrue(ui.app.layout.has_focus(ui._deny_button))
                        permission = next(event for event in events
                            if event.get("type") == "permission_request"
                            and event.get("id") == ui._approval["id"])
                        name, inputs = permission["tool"], permission["input"]
                        self.assertIn(name, {"Read", "Edit", "Bash"})
                        if name == "Edit":
                            self.assertEqual(inputs["file_path"], str(source))
                            self.assertEqual(inputs["old_string"], broken)
                            self.assertEqual(inputs["new_string"], fixed)
                            self.assertEqual(source.read_text(encoding="utf-8"), broken)
                        elif name == "Bash":
                            self.assertEqual(inputs["command"], "python3 -m unittest -q")
                        approval_id = ui._approval["id"]
                        pipe.send_text("\t")
                        await eventually(lambda: ui.app.layout.has_focus(ui._approve_button), timeout=2)
                        pipe.send_text("\r")
                        await eventually(lambda: (ui._approval or {}).get("id") != approval_id)
                        approved_tools.append(name)
                    self.assertIn("Edit", approved_tools)
                    self.assertIn("Bash", approved_tools)
                    self.assertEqual(source.read_text(encoding="utf-8"), fixed)
                    self.assertEqual((Path(work) / "test_contacts.py").read_text(encoding="utf-8"), test_source)
                    self.assertIn(company, source.read_text(encoding="utf-8"))
                    self.assertIn(email, source.read_text(encoding="utf-8"))
                    after = await asyncio.to_thread(subprocess.run,
                        [sys.executable, "-m", "unittest", "-q"], cwd=work,
                        capture_output=True, text=True, timeout=10)
                    self.assertEqual(after.returncode, 0)
                    self.assertIn("OK", after.stderr)
                    self.assertEqual(ui.transcript_text().count(final), 1)
                    self.assertTrue(any(event.get("type") == "stream_event"
                        and event.get("event", {}).get("delta", {}).get("type") == "text_delta"
                        for event in events))
                    self.assertEqual(len(captured), 4)
                    self.assertEqual(state.forwarded, 4)
                    self.assertEqual(state.blocked, 0)
                    self.assertEqual(state.snapshot()["pending"], [])
                    self.assertTrue(state.snapshot()["semantic_scan"]["enabled"])
                    self.assertEqual(state.snapshot()["semantic_scan"]["blocked_requests"], 0)
                    self.assertGreater(state.snapshot()["semantic_scan"]["scanned_chunks"], 0)
                    self.assertTrue(local_inputs)
                    self.assertTrue(any(company in text for text in local_inputs))
                    self.assertTrue(all(dummy_key not in text for text in local_inputs))
                    self.assertTrue(all(email not in text for text in local_inputs))
                    self.assertEqual(ui.mode, "auto")
                    outgoing_decision.assert_not_called()
                    open_browser.assert_not_called()
                    self.assertFalse(failures)
                    self.assertIsNone(engine._process.poll())
                    pipe.send_text("/quit\r")
                    self.assertEqual(await asyncio.wait_for(task, 5), 0)
            finally:
                if task and not task.done():
                    ui._request_exit()
                    await asyncio.wait_for(task, 5)
                else:
                    await asyncio.to_thread(engine.close)
                state.close()
                await asyncio.to_thread(server.shutdown)
                server.server_close()
                thread.join(2)
            self.assertTrue(local_runtime.closed)
            self.assertFalse(scanner.snapshot()["enabled"])


if __name__ == "__main__":
    unittest.main()
