"""Optional real terminal → engine → review gateway → tool integration.

Run with MASKCODE_TEST_INSTALLED_ENGINE=1 python3 -m unittest discover -s tests
 -p test_terminal_integration.py -v

Only dummy authentication, temporary files/config, and a local fake upstream are
used. The installed Claude executable runs under the actual socket restriction.
"""
import asyncio
import json
import os
from pathlib import Path
import platform
import shutil
import tempfile
import threading
import unittest
from unittest.mock import patch

from prompt_toolkit.input import create_pipe_input
from prompt_toolkit.output import DummyOutput

from privacy_gateway.client import claude_environment
from privacy_gateway.engine import ClaudeEngine
from privacy_gateway.redaction import Policy
from privacy_gateway.server import GatewayServer, GatewayState
from privacy_gateway.terminal import TerminalApp


@unittest.skipUnless(os.environ.get("MASKCODE_TEST_INSTALLED_ENGINE") == "1"
                     and platform.system() == "Darwin" and shutil.which("claude"),
                     "Opt-in installed CLI terminal integration with local fake transport")
class InstalledTerminalIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_keyboard_review_tool_denial_approval_and_draft_preservation(self):
        from claude_tools_smoke import response, find_tool_result, FINISHED

        email = "sample.person@example.com"
        dummy_key = "sk-ant-synthetic-local-test-only"
        first_final = "Synthetic denied turn finished."
        second_final = "Synthetic approved turn finished."
        captured = []
        failures = []
        with tempfile.TemporaryDirectory(prefix="maskcode-terminal-synthetic-") as work, \
                create_pipe_input() as pipe:
            config = Path(work) / "config"
            config.mkdir()
            denied_path, approved_path = Path(work) / "denied.txt", Path(work) / "approved.txt"
            state = GatewayState(mode="review", review_timeout=30, policy=Policy.from_dict({"literals": [
                {"value": str(Path.home()), "label": "LOCAL_HOME"},
                {"value": work, "label": "SYNTHETIC_PATH"},
            ]}))
            email_token = state.redactor.redact_text(email)

            def reply(step, model, tool=None, tool_id=None, inputs=None, final=None):
                status, content_type, body = response(model, tool, tool_id, inputs)
                body = body.replace(b"msg_synthetic_local_tools", ("msg_synthetic_terminal_" + str(step)).encode())
                if final:
                    body = body.replace(FINISHED.encode(), final.encode())
                return status, content_type, body

            def fake(path, body, headers):
                # Assertions made by the HTTP worker are recorded explicitly;
                # the production gateway intentionally suppresses exceptions.
                try:
                    self.assertNotIn(email.encode(), body)
                    self.assertNotIn(work.encode(), body)
                    self.assertEqual(headers.get("x-api-key"), dummy_key)
                    data = json.loads(body)
                    if path.startswith("/v1/messages/count_tokens"):
                        return 200, "application/json", b'{"input_tokens":100}'
                    captured.append(data)
                    step = len(captured)
                    model = data.get("model", "synthetic-model")
                    if step == 1:
                        return reply(step, model, "Write", "toolu_terminal_deny", {
                            "file_path": state.redactor.redact_text(str(denied_path)), "content": email_token})
                    if step == 2:
                        result = find_tool_result(data, "toolu_terminal_deny")
                        self.assertIsNotNone(result)
                        self.assertTrue(result.get("is_error"))
                        return reply(step, model, final=first_final)
                    if step == 3:
                        self.assertIn("first synthetic turn", json.dumps(data))
                        self.assertIn("second synthetic turn", json.dumps(data))
                        return reply(step, model, "Write", "toolu_terminal_approve", {
                            "file_path": state.redactor.redact_text(str(approved_path)), "content": email_token})
                    if step == 4:
                        result = find_tool_result(data, "toolu_terminal_approve")
                        self.assertIsNotNone(result)
                        self.assertFalse(result.get("is_error"))
                        return reply(step, model, final=second_final)
                    self.fail("Unexpected extra synthetic model request")
                except Exception:
                    failures.append("Synthetic local transport assertion failed")
                    raise

            state.transport = fake
            server = GatewayServer(state)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            env = claude_environment(server)
            for key in list(env):
                if key.startswith(("ANTHROPIC_", "CLAUDE_CODE_OAUTH_")):
                    env.pop(key)
            env.update({"ANTHROPIC_BASE_URL": server.proxy_url, "ANTHROPIC_API_KEY": dummy_key,
                        "CLAUDE_CONFIG_DIR": str(config), "HOME": work})
            ui = TerminalApp(work, mode="review", input=pipe, output=DummyOutput())
            engine = ClaudeEngine(server, ["--tools", "Write", "--no-session-persistence",
                "--model", "sonnet", "--system-prompt", "Use Write for this synthetic local terminal test."],
                work, ui.post_event)
            ui.bind(engine, state)
            task = None

            async def eventually(predicate, timeout=15):
                deadline = asyncio.get_running_loop().time() + timeout
                while not predicate():
                    self.assertFalse(failures, "Synthetic local upstream validation failed")
                    self.assertFalse(task and task.done(), "Terminal unexpectedly closed")
                    if asyncio.get_running_loop().time() >= deadline:
                        self.fail("Timed out waiting for the synthetic terminal integration: " + json.dumps({
                            "model_requests": len(captured), "requests": state.requests,
                            "forwarded": state.forwarded, "blocked": state.blocked,
                            "approval_kind": (ui._approval or {}).get("kind"), "status": ui.status,
                            "pending_count": len(state.snapshot()["pending"]),
                            "deny_focused": bool(ui._deny_button and ui.app.layout.has_focus(ui._deny_button)),
                            "approve_focused": bool(ui._approve_button and ui.app.layout.has_focus(ui._approve_button)),
                            "deny_visible": bool(ui._deny_button and ui._deny_button.window in ui.app.layout.visible_windows),
                            "approve_visible": bool(ui._approve_button and ui._approve_button.window in ui.app.layout.visible_windows),
                            "approve_focusable": bool(ui._approve_button and ui._approve_button.window in list(ui.app.layout.get_focusable_windows())),
                            "completion_active": bool(ui.app.current_buffer.complete_state),
                        }))
                    await asyncio.sleep(.015)

            async def review(expected_count, draft):
                await eventually(lambda: ui._approval is not None and ui._approval["kind"] == "gateway")
                self.assertEqual(len(captured), expected_count)
                self.assertTrue(ui.app.layout.has_focus(ui._deny_button))
                self.assertEqual(ui.input.text, draft)
                self.assertNotIn(email, ui._approval_text.text)
                self.assertNotIn(work, ui._approval_text.text)
                self.assertNotIn(dummy_key, ui._approval_text.text)
                self.assertIn(email_token, ui._approval_text.text)
                pending = next(p for p in state.snapshot()["pending"] if p["id"] == ui._approval["id"])
                names = {name.lower() for name in pending["headers"]}
                self.assertFalse(names & {"authorization", "x-api-key", "proxy-authorization", "cookie"})
                self.assertIn("HEADERS (excluding authentication)", ui._approval_text.text)
                # An unrelated key does not grant approval; only the selected
                # Approve button followed by Enter sends the reviewed request.
                pipe.send_text("a")
                await asyncio.sleep(.12)
                self.assertEqual(len(captured), expected_count)
                pipe.send_text("\t")
                await eventually(lambda: ui.app.layout.has_focus(ui._approve_button), timeout=2)
                pipe.send_text("\r")
                await eventually(lambda: len(captured) == expected_count + 1)

            try:
                with patch("privacy_gateway.engine.claude_environment", return_value=env), \
                        patch("webbrowser.open") as open_browser:
                    task = asyncio.create_task(ui.run_async())
                    await eventually(lambda: ui.ready)
                    second_prompt = "second synthetic turn: write " + email
                    pipe.send_text("first synthetic turn: write " + email + "\r" + second_prompt)
                    await eventually(lambda: ui.input.text == second_prompt)
                    await review(0, second_prompt)
                    await eventually(lambda: ui._approval is not None and ui._approval["kind"] == "tool")
                    self.assertTrue(ui.app.layout.has_focus(ui._deny_button))
                    self.assertIn(email, ui._approval_text.text)
                    self.assertIn(str(denied_path), ui._approval_text.text)
                    self.assertFalse(denied_path.exists())
                    pipe.send_text("\r")  # Default Deny: no file write.
                    await review(1, second_prompt)
                    await eventually(lambda: not ui.busy and first_final in ui.transcript_text())
                    self.assertFalse(denied_path.exists())
                    self.assertEqual(ui.input.text, second_prompt)
                    self.assertEqual(ui.transcript_text().count(first_final), 1)
                    self.assertIn("Tool denied.", ui.transcript_text())

                    kept_draft = "keep this unsent draft"
                    pipe.send_text("\r" + kept_draft)
                    await eventually(lambda: ui.input.text == kept_draft)
                    await review(2, kept_draft)
                    await eventually(lambda: ui._approval is not None and ui._approval["kind"] == "tool")
                    self.assertTrue(ui.app.layout.has_focus(ui._deny_button))
                    self.assertIn(email, ui._approval_text.text)
                    self.assertFalse(approved_path.exists())
                    pipe.send_text("\t\r")  # Explicit local tool approval.
                    await review(3, kept_draft)
                    await eventually(lambda: not ui.busy and second_final in ui.transcript_text())
                    self.assertEqual(approved_path.read_text(), email)
                    self.assertFalse(denied_path.exists())
                    self.assertEqual(ui.transcript_text().count(first_final), 1)
                    self.assertEqual(ui.transcript_text().count(second_final), 1)
                    self.assertEqual(ui.input.text, kept_draft)
                    self.assertEqual(ui.history.get_strings(), [
                        "first synthetic turn: write " + email, second_prompt])
                    self.assertIn("Tool permitted.", ui.transcript_text())
                    self.assertEqual(len(captured), 4)
                    self.assertEqual(state.blocked, 0)
                    self.assertEqual(state.forwarded, 4)
                    self.assertFalse(failures)
                    self.assertIsNone(engine._process.poll())
                    open_browser.assert_not_called()
                    pipe.send_text("\x15/quit\r")
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


if __name__ == "__main__":
    unittest.main()
