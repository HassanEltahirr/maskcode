import asyncio
import copy
from pathlib import Path
import tempfile
import time
import unittest

from prompt_toolkit.document import Document
from prompt_toolkit.input import create_pipe_input, DummyInput
from prompt_toolkit.output import DummyOutput

from privacy_gateway.terminal import TerminalApp, SlashCompleter, safe_text, tool_description


class FakeGateway:
    def __init__(self):
        self.pending = []
        self.decisions = []
        self.closed = False

    def close(self):
        self.closed = True

    def snapshot(self):
        return {"mode": "review", "network_isolation": True, "forwarded": 0,
                "blocked": 0, "redactions": {"EMAIL": 2}, "pending": copy.deepcopy(self.pending)}

    def decision(self, ident, decision):
        if ident not in {item["id"] for item in self.pending}:
            return False
        self.decisions.append((ident, decision))
        self.pending = [item for item in self.pending if item["id"] != ident]
        return True


class FakeEngine:
    def __init__(self, ui):
        self.ui = ui
        self.sent = []
        self.permissions = []
        self.models = []
        self.closed = False
        self.interrupted = False
        self.initialization = {"model": "test-model"}
        self.start_delay = 0

    def start(self):
        if self.start_delay:
            time.sleep(self.start_delay)
        return self.initialization

    def send(self, prompt):
        self.sent.append(prompt)

    def interrupt(self):
        self.interrupted = True
        self.ui.post_event({"type": "result", "subtype": "success"})

    def decide_permission(self, ident, allowed):
        self.permissions.append((ident, allowed))
        return True

    def set_model(self, model):
        self.models.append(model)

    def close(self):
        self.closed = True


async def eventually(predicate, timeout=3):
    deadline = asyncio.get_running_loop().time() + timeout
    while not predicate():
        if asyncio.get_running_loop().time() > deadline:
            raise AssertionError("Timed out waiting for terminal state")
        await asyncio.sleep(.015)


class TerminalFlowTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.pipe_context = create_pipe_input()
        self.pipe = self.pipe_context.__enter__()
        self.ui = TerminalApp("/project", mode="review", input=self.pipe, output=DummyOutput())
        self.state = FakeGateway()
        self.engine = FakeEngine(self.ui)
        self.ui.bind(self.engine, self.state)
        self.task = None

    async def launch(self, initial_prompt=None, initial_draft=None):
        self.task = asyncio.create_task(self.ui.run_async(initial_prompt, initial_draft))
        await eventually(lambda: self.ui.ready)

    async def asyncTearDown(self):
        if self.task and not self.task.done():
            self.ui._request_exit()
        if self.task:
            await asyncio.wait_for(self.task, 3)
        self.pipe_context.__exit__(None, None, None)

    async def test_real_key_submission_streaming_and_final_are_one_response(self):
        await self.launch()
        self.pipe.send_text("fix this file\r")
        await eventually(lambda: bool(self.engine.sent))
        self.assertEqual(self.engine.sent, ["fix this file"])
        self.assertIn("YOU\n  fix this file", self.ui.transcript_text())
        self.ui.post_event({"type": "stream_event", "event": {"type": "message_start", "message": {"id": "m1"}}})
        self.ui.post_event({"type": "stream_event", "event": {"type": "content_block_start", "index": 0,
                           "content_block": {"type": "text", "text": ""}}})
        self.ui.post_event({"type": "stream_event", "event": {"type": "content_block_delta", "index": 0,
                           "delta": {"type": "text_delta", "text": "Fixed the file."}}})
        await eventually(lambda: "Fixed the file." in self.ui.transcript.text)
        self.ui.post_event({"type": "assistant", "message": {"id": "m1", "content": [{"type": "text", "text": "Fixed the file."}]}})
        self.ui.post_event({"type": "result", "subtype": "success", "result": "Fixed the file."})
        await eventually(lambda: not self.ui.busy)
        self.assertEqual(self.ui.transcript_text().count("Fixed the file."), 1)
        self.pipe.send_text("\x04")
        self.assertEqual(await asyncio.wait_for(self.task, 3), 0)
        self.assertTrue(self.engine.closed)

    async def test_multiline_composer_preserves_newlines_and_memory_history(self):
        await self.launch()
        self.pipe.send_text("first\nsecond\x1b\rthird\r")
        await eventually(lambda: bool(self.engine.sent))
        self.assertEqual(self.engine.sent, ["first\nsecond\nthird"])
        self.assertEqual(self.ui.history.get_strings(), ["first\nsecond\nthird"])

    async def test_code_prompt_whitespace_is_sent_exactly(self):
        await self.launch()
        original = "  indented code\n\tmore code  \n"
        self.ui.input.text = original
        self.pipe.send_text("\r")
        await eventually(lambda: bool(self.engine.sent))
        self.assertEqual(self.engine.sent, [original])

    async def test_absolute_path_prompt_is_sent_exactly_instead_of_discarded(self):
        await self.launch()
        prompt = "/Users/example/My Project/main.py\nFix the failing test for this file."
        self.ui.input.text = prompt
        self.pipe.send_text("\r")
        await eventually(lambda: self.engine.sent == [prompt])
        self.assertNotIn("Unknown command", self.ui.transcript_text())

    async def test_unknown_slash_text_reaches_the_agent(self):
        await self.launch()
        self.pipe.send_text("/custom-task inspect the workspace\r")
        await eventually(lambda: self.engine.sent == ["/custom-task inspect the workspace"])

    async def test_restart_key_keeps_draft_and_closes_without_sending_it(self):
        await self.launch()
        draft = "  next request\nwith a second line  "
        self.ui.input.text = draft
        self.pipe.send_text("\x1b[15~")
        self.assertEqual(await asyncio.wait_for(self.task, 3), 0)
        self.assertTrue(self.ui.restart_requested)
        self.assertFalse(self.ui.login_requested)
        self.assertEqual(self.ui.resume_draft, draft)
        self.assertEqual(self.engine.sent, [])
        self.assertTrue(self.engine.closed)
        self.assertTrue(self.state.closed)

    async def test_restart_before_ready_preserves_initial_task_and_newer_draft_unsent(self):
        self.engine.start_delay = .4
        self.task = asyncio.create_task(self.ui.run_async(initial_prompt="original task"))
        await asyncio.sleep(.05)
        self.pipe.send_text("newer draft")
        await eventually(lambda: self.ui.input.text == "newer draft")
        self.assertFalse(self.ui.ready)
        self.pipe.send_text("\x1b[15~")
        await asyncio.wait_for(self.task, 3)
        self.assertTrue(self.ui.restart_requested)
        self.assertEqual(self.ui.resume_draft, "original task\n\nnewer draft")
        self.assertEqual(self.engine.sent, [])

    async def test_restart_is_blocked_during_a_turn_and_preserves_the_next_draft(self):
        await self.launch()
        self.pipe.send_text("work\r")
        await eventually(lambda: self.engine.sent == ["work"])
        self.ui.input.text = "next draft"
        self.pipe.send_text("\x1b[15~")
        await eventually(lambda: "before starting a fresh conversation" in self.ui.transcript_text())
        self.assertFalse(self.ui.restart_requested)
        self.assertEqual(self.ui.input.text, "next draft")
        self.assertFalse(self.engine.closed)

    async def test_login_command_closes_for_official_login_without_sending_a_prompt(self):
        await self.launch()
        self.pipe.send_text("/login\r")
        self.assertEqual(await asyncio.wait_for(self.task, 3), 0)
        self.assertTrue(self.ui.login_requested)
        self.assertFalse(self.ui.restart_requested)
        self.assertEqual(self.ui.resume_draft, "")
        self.assertEqual(self.engine.sent, [])

    async def test_restored_draft_waits_for_explicit_send(self):
        draft = "next request\nnot previously sent"
        await self.launch(initial_draft=draft)
        await asyncio.sleep(.15)
        self.assertEqual(self.ui.input.text, draft)
        self.assertEqual(self.engine.sent, [])
        self.pipe.send_text("\r")
        await eventually(lambda: self.engine.sent == [draft])

    async def test_initial_draft_never_overwrites_an_existing_draft(self):
        self.ui.input.text = "newer draft"
        await self.launch(initial_draft="older draft")
        self.assertEqual(self.ui.input.text, "newer draft")
        self.assertEqual(self.engine.sent, [])

    async def test_slash_menu_completes_from_real_keyboard_input(self):
        await self.launch()
        self.pipe.send_text("/mo")
        await eventually(lambda: self.ui.input.buffer.complete_state is not None)
        self.pipe.send_text("\t")
        await eventually(lambda: self.ui.input.text == "/model")
        self.pipe.send_text("\r")
        await eventually(lambda: "Current model: test-model" in self.ui.transcript.text)
        self.assertEqual(self.engine.sent, [])

    async def test_bracketed_paste_keeps_multiline_text_until_explicit_send(self):
        await self.launch()
        self.pipe.send_text("\x1b[200~first\nsecond\x1b[201~")
        await eventually(lambda: self.ui.input.text == "first\nsecond")
        self.assertEqual(self.engine.sent, [])
        self.pipe.send_text("\r")
        await eventually(lambda: self.engine.sent == ["first\nsecond"])

    async def test_gateway_review_enter_denies_and_keeps_draft(self):
        await self.launch()
        self.pipe.send_text("keep my draft")
        await eventually(lambda: self.ui.input.text == "keep my draft")
        body = {"messages": [{"content": "PG_EMAIL_example"}], "long": ["line " + str(n) for n in range(200)]}
        self.state.pending.append({"id": "r1", "preview": body, "headers": {"content-type": "application/json"}})
        await eventually(lambda: self.ui._approval is not None)
        self.assertIn('"PG_EMAIL_example"', self.ui._approval_text.text)
        self.assertIn("line 199", self.ui._approval_text.text)
        self.assertIn("content-type", self.ui._approval_text.text)
        self.assertTrue(self.ui.app.layout.has_focus(self.ui._deny_button))
        self.pipe.send_text("\r")
        await eventually(lambda: bool(self.state.decisions))
        self.assertEqual(self.state.decisions, [("r1", "deny")])
        self.assertEqual(self.ui.input.text, "keep my draft")
        self.assertFalse(self.engine.sent)

    async def test_gateway_approval_requires_explicit_button_selection(self):
        await self.launch()
        self.state.pending.append({"id": "r2", "preview": {"prompt": "synthetic"}, "headers": {}})
        await eventually(lambda: self.ui._approval is not None)
        self.pipe.send_text("a")
        await asyncio.sleep(.15)
        self.assertEqual(self.state.decisions, [])
        self.pipe.send_text("\t\r")
        await eventually(lambda: bool(self.state.decisions))
        self.assertEqual(self.state.decisions, [("r2", "approve")])

    async def test_large_successive_reviews_allow_keyboard_approval_with_a_saved_draft(self):
        await self.launch()
        draft = "keep the next multiline\ndraft unsent"
        self.ui.input.text = draft
        payload = {"system": "Synthetic context " * 6000,
                   "messages": [{"content": "Synthetic line " + str(n)} for n in range(500)]}
        for ident in ("long-1", "long-2"):
            self.state.pending.append({"id": ident, "preview": payload, "headers": {"content-type": "application/json"}})
            await eventually(lambda: self.ui._approval is not None)
            self.assertTrue(self.ui.app.layout.has_focus(self.ui._deny_button))
            self.assertIn("Synthetic line 499", self.ui._approval_text.text)
            self.pipe.send_text("a")
            await asyncio.sleep(.12)
            self.assertNotIn((ident, "approve"), self.state.decisions)
            self.pipe.send_text("\t")
            await eventually(lambda: self.ui.app.layout.has_focus(self.ui._approve_button))
            self.pipe.send_text("\r")
            await eventually(lambda: (ident, "approve") in self.state.decisions)
            self.assertEqual(self.ui.input.text, draft)
        self.assertEqual(self.engine.sent, [])

    async def test_tool_approval_defaults_deny_and_does_not_approve_gateway(self):
        await self.launch()
        self.ui.post_event({"type": "permission_request", "id": "tool1", "tool": "Bash", "input": {"command": "echo synthetic"}})
        await eventually(lambda: self.ui._approval is not None)
        self.assertIn("$ echo synthetic", self.ui._approval_text.text)
        self.pipe.send_text("\r")
        await eventually(lambda: bool(self.engine.permissions))
        self.assertEqual(self.engine.permissions, [("tool1", False)])
        self.assertEqual(self.state.decisions, [])

    async def test_tool_details_toggle_preserves_complete_input_and_default_deny(self):
        await self.launch()
        content = "synthetic line\n" * 300 + "EXACT END"
        inputs = {"file_path": "/project/example.txt", "content": content, "future_option": True}
        self.ui.post_event({"type": "permission_request", "id": "write1", "tool": "Write", "input": inputs})
        await eventually(lambda: self.ui._approval is not None)
        self.assertIn("File: /project/example.txt", self.ui._approval_text.text)
        self.assertIn("preview shortened", self.ui._approval_text.text)
        self.assertIn("future option: true", self.ui._approval_text.text)
        self.assertNotIn("EXACT END", self.ui._approval_text.text)
        self.pipe.send_text("\x0f")
        await eventually(lambda: self.ui._approval_expanded)
        self.assertIn("EXACT END", self.ui._approval_text.text)
        self.assertIn('"future_option": true', self.ui._approval_text.text)
        self.assertTrue(self.ui.app.layout.has_focus(self.ui._deny_button))
        self.assertEqual(self.engine.permissions, [])
        self.pipe.send_text("\x0f")
        await eventually(lambda: not self.ui._approval_expanded)
        self.assertNotIn("EXACT END", self.ui._approval_text.text)
        self.pipe.send_text("\t\r")
        await eventually(lambda: bool(self.engine.permissions))
        self.assertEqual(self.engine.permissions, [("write1", True)])

    async def test_permission_cancellation_removes_stale_modal(self):
        await self.launch()
        self.ui.post_event({"type": "permission_request", "id": "tool1", "tool": "Edit", "input": {"path": "a.txt"}})
        await eventually(lambda: self.ui._approval is not None)
        self.ui.post_event({"type": "permission_cancelled", "id": "tool1"})
        await eventually(lambda: self.ui._approval is None)
        self.assertEqual(self.engine.permissions, [])
        self.assertIn("was not approved", self.ui.transcript.text)

    async def test_engine_exit_clears_permissions_and_late_ready_cannot_restart_it(self):
        await self.launch()
        self.ui.post_event({"type": "permission_request", "id": "tool1", "tool": "Write", "input": {"path": "a.txt"}})
        await eventually(lambda: self.ui._approval is not None)
        self.ui.post_event({"type": "permission_request", "id": "tool2", "tool": "Write", "input": {"path": "b.txt"}})
        self.state.pending.append({"id": "outgoing", "preview": {}, "headers": {}})
        self.ui.post_event({"type": "engine_exit", "code": 1})
        self.ui.post_event({"type": "ui_engine_ready"})
        self.ui.post_event({"type": "permission_request", "id": "tool3", "tool": "Write", "input": {"path": "c.txt"}})
        await eventually(lambda: self.ui._engine_exited and self.ui._approval is None)
        self.assertFalse(self.ui.ready)
        self.assertEqual(self.ui._tool_pending, [])
        self.assertEqual(self.engine.permissions, [])
        self.assertEqual(self.state.decisions, [("outgoing", "deny")])
        self.pipe.send_text("keep this retry draft\r")
        await eventually(lambda: self.ui.input.text == "keep this retry draft")
        self.assertIn("Engine stopped", self.ui.status)
        self.assertNotIn("starting", self.ui.status)
        self.assertEqual(self.engine.sent, [])

    async def test_startup_failure_preserves_unsent_initial_prompt_and_blocks_late_ready(self):
        def fail_start():
            raise RuntimeError("Synthetic startup failure")
        self.engine.start = fail_start
        self.task = asyncio.create_task(self.ui.run_async(initial_prompt="unsent initial request"))
        await eventually(lambda: self.ui._startup_failed)
        self.ui.post_event({"type": "ui_engine_ready"})
        await asyncio.sleep(.15)
        self.assertFalse(self.ui.ready)
        self.assertEqual(self.ui.input.text, "unsent initial request")
        self.assertEqual(self.engine.sent, [])
        self.pipe.send_text("\x1b[15~")
        await asyncio.wait_for(self.task, 3)
        self.assertTrue(self.ui.restart_requested)
        self.assertEqual(self.ui.resume_draft, "unsent initial request")

    async def test_late_gateway_review_cannot_reopen_a_dead_session_dialog(self):
        await self.launch()
        self.ui.post_event({"type": "engine_exit", "code": 1})
        await eventually(lambda: self.ui._engine_exited)
        self.assertTrue(self.state.closed)
        # Simulate a request arriving after the exit event's first snapshot.
        self.state.pending.append({"id": "late", "preview": {}, "headers": {}})
        await eventually(lambda: self.state.decisions == [("late", "deny")])
        self.assertIsNone(self.ui._approval)
        self.assertIn("Engine stopped", self.ui.status)

    async def test_startup_failure_preserves_both_initial_prompt_and_newer_draft(self):
        def fail_start():
            raise RuntimeError("Synthetic startup failure")
        self.engine.start = fail_start
        self.ui.input.text = "newer unsent draft"
        self.task = asyncio.create_task(self.ui.run_async(initial_prompt="older initial prompt"))
        await eventually(lambda: self.ui._startup_failed)
        self.assertEqual(self.ui.input.text, "older initial prompt\n\nnewer unsent draft")
        self.assertEqual(self.engine.sent, [])

    async def test_auth_failure_has_functional_login_recovery_and_keeps_draft(self):
        await self.launch()
        self.pipe.send_text("work\r")
        await eventually(lambda: self.engine.sent == ["work"])
        self.ui.input.text = "my next draft"
        self.ui.post_event({"type": "result", "is_error": True, "result": "Not logged in · Please run /login"})
        await eventually(lambda: self.ui._login_required)
        self.assertFalse(self.ui.ready)
        self.assertIn("Login required", self.ui.status)
        self.assertIn("official login", self.ui.transcript_text())
        self.assertEqual(self.ui.input.text, "my next draft")
        self.assertEqual(self.engine.sent, ["work"])
        self.ui._command("/login")
        await asyncio.wait_for(self.task, 3)
        self.assertTrue(self.ui.login_requested)
        self.assertEqual(self.ui.resume_draft, "my next draft")

    async def test_failed_turn_keeps_draft_and_does_not_retry(self):
        await self.launch()
        self.pipe.send_text("work\r")
        await eventually(lambda: self.engine.sent == ["work"])
        self.ui.input.text = "my next draft"
        self.ui.post_event({"type": "result", "is_error": True, "errors": ["Synthetic provider failure"]})
        await eventually(lambda: not self.ui.busy)
        self.assertTrue(self.ui.ready)
        self.assertIn("Turn failed", self.ui.status)
        self.assertEqual(self.ui.input.text, "my next draft")
        self.assertEqual(self.engine.sent, ["work"])

    async def test_expired_gateway_review_closes_and_never_approves(self):
        await self.launch()
        self.state.pending.append({"id": "r3", "preview": {"prompt": "synthetic"}, "headers": {}})
        await eventually(lambda: self.ui._approval is not None)
        self.state.pending.clear()
        await eventually(lambda: self.ui._approval is None)
        self.assertEqual(self.state.decisions, [])

    async def test_interrupt_and_model_commands_reach_engine(self):
        await self.launch()
        self.pipe.send_text("work\r")
        await eventually(lambda: self.ui.busy)
        self.pipe.send_text("\x03")
        await eventually(lambda: self.engine.interrupted and not self.ui.busy)
        self.pipe.send_text("/model sonnet\r")
        await eventually(lambda: self.engine.models == ["sonnet"] and self.ui.model == "sonnet")
        self.pipe.send_text("/clear\r")
        await eventually(lambda: not self.ui.entries)
        self.assertIn("conversation retained", self.ui.status)
        self.assertFalse(self.engine.closed)

    async def test_startup_does_not_block_drafting_and_initial_prompt_runs_once(self):
        self.engine.start_delay = .3
        self.task = asyncio.create_task(self.ui.run_async("initial request"))
        await asyncio.sleep(.06)
        self.pipe.send_text("my next draft")
        await eventually(lambda: self.ui.input.text == "my next draft")
        await eventually(lambda: self.engine.sent == ["initial request"])
        self.assertEqual(self.ui.input.text, "my next draft")
        await asyncio.sleep(.15)
        self.assertEqual(self.engine.sent, ["initial request"])

    async def test_exit_denies_all_pending_requests(self):
        await self.launch()
        self.state.pending.extend([
            {"id": "a", "preview": {}, "headers": {}},
            {"id": "b", "preview": {}, "headers": {}},
        ])
        self.ui._request_exit()
        await asyncio.wait_for(self.task, 3)
        self.assertEqual(self.state.decisions, [("a", "deny"), ("b", "deny")])
        self.assertTrue(self.engine.closed)
        self.assertTrue(self.state.closed)


class TerminalRenderingTests(unittest.TestCase):
    def make_ui(self):
        return TerminalApp("/project", input=DummyInput(), output=DummyOutput())

    def test_slash_completion_and_help_match_functional_commands(self):
        completions = list(SlashCompleter().get_completions(Document("/mo"), None))
        self.assertEqual([item.text for item in completions], ["/model"])
        self.assertEqual(list(SlashCompleter().get_completions(Document("explain /mo"), None)), [])
        self.assertEqual(list(SlashCompleter().get_completions(Document("/model name"), None)), [])

    def test_untrusted_terminal_escape_and_bidi_are_visible_not_executable(self):
        value = "hello\x1b]52;c;clipboard\x07\rspoof\u202e\x9b31m"
        result = safe_text(value)
        self.assertNotIn("\x1b", result)
        self.assertNotIn("\r", result)
        self.assertNotIn("\u202e", result)
        self.assertIn("\\u001b", result)
        self.assertIn("\\u202e", result)
        ui = self.make_ui()
        ui.handle_event({"type": "assistant", "message": {"id": "x", "content": [{"type": "text", "text": value}]}})
        self.assertNotIn("\x1b", ui.transcript_text())
        self.assertIn("clipboard", ui.transcript_text())

    def test_tool_stream_and_full_message_render_once_with_actual_results(self):
        ui = self.make_ui()
        ui.handle_event({"type": "stream_event", "event": {"type": "message_start", "message": {"id": "m"}}})
        ui.handle_event({"type": "stream_event", "event": {"type": "content_block_start", "index": 1,
                        "content_block": {"type": "tool_use", "id": "t", "name": "Read", "input": {}}}})
        ui.handle_event({"type": "stream_event", "event": {"type": "content_block_delta", "index": 1,
                        "delta": {"type": "input_json_delta", "partial_json": '{"file_path":"local.txt"}'}}})
        ui.handle_event({"type": "stream_event", "event": {"type": "content_block_stop", "index": 1}})
        ui.handle_event({"type": "assistant", "message": {"id": "m", "content": [
            {"type": "tool_use", "id": "t", "name": "Read", "input": {"file_path": "local.txt"}}]}})
        ui.handle_event({"type": "user", "message": {"content": [
            {"type": "tool_result", "tool_use_id": "t", "content": "file content", "is_error": False}]}})
        text = ui.transcript_text()
        self.assertEqual(text.count("local.txt"), 1)
        self.assertNotIn('"file_path"', text)
        self.assertIn("Read · result", text)
        self.assertIn("file content", text)

    def test_welcome_is_maskcode_not_native_provider_banner(self):
        ui = self.make_ui()
        header = "".join(text for _, text in ui._header())
        self.assertIn("M A S K C O D E", header)
        self.assertIn("Hermes-inspired", header)
        self.assertNotIn("Claude Code v", header)
        self.assertNotIn("Safe mode:", header)
        ui.handle_event({"type": "system", "subtype": "init", "model": "real-test-model"})
        self.assertIn("real-test-model", "".join(text for _, text in ui._status_line()))

    def test_engine_init_uses_actual_worktree_directory_and_rejects_invalid_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            ui = self.make_ui()
            self.assertFalse(ui.engine_cwd_known)
            ui.handle_event({"type": "system", "subtype": "init", "cwd": directory})
            self.assertTrue(ui.engine_cwd_known)
            self.assertEqual(ui.cwd, Path(directory).resolve())
            self.assertIn(str(ui.cwd), "".join(text for _, text in ui._header()))
        for invalid in ("relative-directory", "/nonexistent-maskcode-test-directory", str(Path(__file__).resolve()), None):
            with self.subTest(cwd=invalid):
                ui = self.make_ui()
                ui.handle_event({"type": "system", "subtype": "init", "cwd": invalid})
                self.assertEqual(ui.cwd, Path("/project"))
                self.assertFalse(ui.engine_cwd_known)

    def test_normal_startup_explains_automatic_masking_and_file_work(self):
        ui = self.make_ui()
        self.assertEqual(ui.mode, "auto")
        self.assertIn("MASKING", "".join(text for _, text in ui._status_line()))
        self.assertIn("read files", "".join(text for _, text in ui._welcome()))
        self.assertIn("Masking runs automatically", "".join(text for _, text in ui._welcome()))

    def test_permission_command_and_extra_execution_options_are_never_abbreviated(self):
        command = "printf synthetic\n" * 300 + "LAST COMMAND"
        summary = tool_description("Bash", {"command": command, "timeout": 123,
                                            "dangerouslyDisableSandbox": True}, review=True)
        self.assertIn(command, summary)
        self.assertIn("timeout: 123", summary)
        self.assertIn("dangerouslyDisableSandbox: true", summary)
        self.assertNotIn("shortened", summary)

    def test_edit_activity_shows_a_change_preview_and_preserves_both_paths_in_review(self):
        inputs = {"file_path": "/project/file.txt", "path": "/project/extra.txt",
                  "old_string": "before", "new_string": "after", "replace_all": True}
        summary = tool_description("Edit", inputs, review=True)
        self.assertIn("File: /project/file.txt", summary)
        self.assertIn("/project/extra.txt", summary)
        self.assertIn("-before", summary)
        self.assertIn("+after", summary)
        self.assertIn("replace all: true", summary)

    def test_large_tool_output_is_bounded_but_assistant_response_is_complete(self):
        ui = self.make_ui()
        output = "read line\n" * 1000 + "LAST OUTPUT"
        ui.handle_event({"type": "user", "message": {"content": [
            {"type": "tool_result", "tool_use_id": "t", "content": [{"type": "text", "text": output}]}]}})
        self.assertLess(len(ui.transcript_text()), 2400)
        self.assertIn("tool output shortened", ui.transcript_text())
        self.assertNotIn("LAST OUTPUT", ui.transcript_text())
        ui.handle_event({"type": "assistant", "message": {"id": "m", "content": output}})
        self.assertIn("LAST OUTPUT", ui.transcript_text())


if __name__ == "__main__":
    unittest.main()
