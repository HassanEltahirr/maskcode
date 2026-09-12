"""Default branded terminal routing without changing native machine output."""
import io
from pathlib import Path
import unittest
from unittest.mock import MagicMock, patch

from privacy_gateway import cli, terminal_entry


class TerminalArgumentsTests(unittest.TestCase):
    def test_prompt_and_options_are_separated_without_parsing_prompt_content(self):
        extra, words, machine = terminal_entry.split_arguments([
            "--model", "sonnet", "--append-system-prompt", "--print", "fix this file"])
        self.assertEqual(extra, ["--model", "sonnet", "--append-system-prompt", "--print"])
        self.assertEqual(words, ["fix this file"])
        self.assertFalse(machine)

    def test_delimiter_preserves_flag_looking_prompt(self):
        extra, words, machine = terminal_entry.split_arguments(["--model=sonnet", "--", "--print"])
        self.assertEqual(extra, ["--model=sonnet"])
        self.assertEqual(words, ["--print"])
        self.assertFalse(machine)

    def test_native_print_and_structured_modes_are_detected(self):
        for args in (["-p", "hello"], ["--print", "hello"], ["-pc", "hello"],
                     ["--output-format=json", "hello"], ["--input-format", "stream-json"]):
            with self.subTest(args=args):
                self.assertTrue(terminal_entry.split_arguments(args)[2])

    def test_resume_and_variadic_tools_preserve_native_values(self):
        args = ["--resume", "synthetic", "--tools", "Read", "Edit", "--", "hello"]
        self.assertEqual(terminal_entry.split_arguments(args),
                         (args[:5], ["hello"], False))

    def test_initial_model_label_only_uses_actual_model_option(self):
        self.assertEqual(terminal_entry.model_hint(["--model", "sonnet"]), "sonnet")
        self.assertEqual(terminal_entry.model_hint(["--model=sonnet", "--model", "opus"]), "opus")
        self.assertIsNone(terminal_entry.model_hint(["--system-prompt", "--model"]))

    def test_recovery_removes_session_replay_flags_but_preserves_option_values(self):
        extra, _, _ = terminal_entry.split_arguments([
            "--resume", "saved", "--session-id=fixed", "--continue", "--fork-session",
            "--append-system-prompt", "--resume", "--tools", "Read", "Edit", "--model", "sonnet"])
        self.assertEqual(terminal_entry.fresh_session_arguments(extra), [
            "--append-system-prompt", "--resume", "--tools", "Read", "Edit", "--model", "sonnet"])
        extra, _, _ = terminal_entry.split_arguments(["-rOLD", "-c", "--model=sonnet"])
        self.assertEqual(terminal_entry.fresh_session_arguments(extra), ["--model=sonnet"])

    def test_recovery_removes_worktree_creation_flags_but_not_values(self):
        for worktree in (["--worktree"], ["--worktree", "named"], ["-wNAMED"]):
            extra, _, _ = terminal_entry.split_arguments([
                *worktree, "--append-system-prompt", "--worktree", "--model=sonnet"])
            self.assertEqual(terminal_entry.fresh_session_arguments(extra), [
                "--append-system-prompt", "--worktree", "--model=sonnet"])


class TerminalEntryTests(unittest.TestCase):
    def test_real_entry_selects_background_masking_or_explicit_review(self):
        for arguments, mode in (([], "auto"), (["--mask-review"], "review")):
            with self.subTest(mode=mode), \
                    patch("sys.stdin.isatty", return_value=True), \
                    patch("sys.stdout.isatty", return_value=True), \
                    patch("privacy_gateway.cli.start_gateway") as gateway, \
                    patch("privacy_gateway.terminal_entry.self_test"), \
                    patch("privacy_gateway.terminal.TerminalApp") as terminal, \
                    patch("privacy_gateway.engine.ClaudeEngine") as engine, \
                    patch("privacy_gateway.terminal_entry.webbrowser.open") as browser:
                terminal.return_value.run.return_value = 0
                self.assertEqual(terminal_entry.run(arguments), 0)
                self.assertEqual(gateway.call_args.args[0].mode, mode)
                self.assertEqual(terminal.call_args.kwargs["mode"], mode)
                self.assertEqual(engine.call_args.args[1], [])
                terminal.return_value.bind.assert_called_once_with(
                    engine.return_value, gateway.return_value.state)
                browser.assert_not_called()

    def test_utility_launchers_are_automatic_but_standalone_inspector_requires_review(self):
        parser = cli.build_parser()
        self.assertEqual(parser.parse_args(["claude"]).mode, "auto")
        self.assertEqual(parser.parse_args(["codex"]).mode, "auto")
        self.assertEqual(parser.parse_args(["serve"]).mode, "review")
        self.assertEqual(parser.parse_args(["claude", "--mode", "review"]).mode, "review")

    def test_default_entry_uses_maskcode_interface(self):
        with patch("privacy_gateway.terminal_entry.run", return_value=7) as run:
            self.assertEqual(cli.main([]), 7)
            run.assert_called_once_with([])

    def test_help_and_version_identify_maskcode_without_starting_engine(self):
        for flag in ("--help", "--mask-help", "--version", "--mask-version"):
            output = io.StringIO()
            with self.subTest(flag=flag), patch("sys.stdout", output), \
                    patch("privacy_gateway.cli.start_gateway") as gateway:
                self.assertEqual(terminal_entry.run([flag]), 0)
                self.assertIn("MaskCode", output.getvalue())
                gateway.assert_not_called()

    def test_explicit_native_and_print_modes_keep_original_argv(self):
        for args in (["--mask-native"], ["--mask-native", "--help"], ["-p", "synthetic"],
                     ["--mask-auto", "-p", "synthetic", "--output-format", "json"]):
            with self.subTest(args=args), patch("privacy_gateway.native.run", return_value=9) as run:
                self.assertEqual(terminal_entry.run(args), 9)
                run.assert_called_once_with(args)

    def test_noninteractive_empty_invocation_does_not_start_hidden_child(self):
        with patch("sys.stdin.isatty", return_value=False), patch("sys.stderr", io.StringIO()), \
                patch("privacy_gateway.cli.start_gateway") as gateway:
            self.assertEqual(terminal_entry.run([]), 2)
            gateway.assert_not_called()

    def test_bad_mask_options_fail_before_gateway(self):
        with patch("sys.stderr", io.StringIO()), patch("privacy_gateway.cli.start_gateway") as gateway:
            self.assertEqual(terminal_entry.run(["--mask-reveiw"]), 1)
            gateway.assert_not_called()

    def test_explicit_login_uses_official_flow_without_a_coding_gateway(self):
        with patch("privacy_gateway.auth.official_login", return_value=0) as login, \
                patch("privacy_gateway.cli.start_gateway") as gateway:
            self.assertEqual(terminal_entry.run(["auth", "login"]), 0)
            login.assert_called_once_with(Path.cwd())
            gateway.assert_not_called()

    def test_login_does_not_accept_prompts_or_unreviewed_arguments(self):
        with patch("privacy_gateway.auth.official_login") as login, \
                patch("privacy_gateway.cli.start_gateway") as gateway, \
                patch("sys.stderr", io.StringIO()):
            self.assertEqual(terminal_entry.run(["auth", "login", "read my files"]), 2)
            login.assert_not_called()
            gateway.assert_not_called()

    def test_restart_recreates_protection_and_keeps_draft_without_replaying_initial_task(self):
        first = MagicMock(restart_requested=True, login_requested=False,
                          resume_draft="  /project/main.py fix this\n", model="selected-model")
        second = MagicMock(restart_requested=False, login_requested=False)
        first.run.return_value = 0
        second.run.return_value = 7
        with patch("sys.stdin.isatty", return_value=True), \
                patch("sys.stdout.isatty", return_value=True), \
                patch("privacy_gateway.cli.start_gateway") as gateway, \
                patch("privacy_gateway.terminal_entry.self_test") as isolation, \
                patch("privacy_gateway.terminal.TerminalApp", side_effect=[first, second]), \
                patch("privacy_gateway.engine.ClaudeEngine") as engine:
            self.assertEqual(terminal_entry.run(["--resume", "saved", "fix tests"]), 7)
            first.run.assert_called_once_with(initial_prompt="fix tests", initial_draft=None)
            second.run.assert_called_once_with(initial_prompt=None, initial_draft=first.resume_draft)
            self.assertEqual(engine.call_args_list[0].args[1], ["--resume", "saved"])
            self.assertEqual(engine.call_args_list[1].args[1], ["--model", "selected-model"])
            self.assertEqual(gateway.call_count, 2)
            self.assertEqual(isolation.call_count, 2)
            self.assertEqual(gateway.return_value.server_close.call_count, 2)
            second._append.assert_called_once()
            self.assertIn("fresh conversation", second._append.call_args.args[1])

    def test_login_closes_protected_session_first_and_cancel_returns_to_draft(self):
        first = MagicMock(restart_requested=False, login_requested=True,
                          resume_draft="unsent task", model="configured model")
        second = MagicMock(restart_requested=False, login_requested=False)
        first.run.return_value = second.run.return_value = 0
        order = []
        with patch("sys.stdin.isatty", return_value=True), \
                patch("sys.stdout.isatty", return_value=True), \
                patch("privacy_gateway.cli.start_gateway") as gateway, \
                patch("privacy_gateway.terminal_entry.self_test"), \
                patch("privacy_gateway.terminal.TerminalApp", side_effect=[first, second]), \
                patch("privacy_gateway.engine.ClaudeEngine") as engine, \
                patch("privacy_gateway.auth.official_login", side_effect=lambda cwd: order.append("login") or 130) as login:
            gateway.return_value.state.close.side_effect = lambda: order.append("deny pending")
            engine.return_value.close.side_effect = lambda: order.append("engine close")
            gateway.return_value.server_close.side_effect = lambda: order.append("gateway close")
            second.run.side_effect = lambda **kwargs: order.append("new terminal") or 0
            self.assertEqual(terminal_entry.run([]), 0)
            self.assertEqual(order[:5], ["deny pending", "engine close", "gateway close", "login", "new terminal"])
            login.assert_called_once_with(Path.cwd())
            second.run.assert_called_once_with(initial_prompt=None, initial_draft="unsent task")
            self.assertIn("Sign-in was not completed", second._append.call_args.args[1])

    def test_restart_reuses_reported_checkout_instead_of_creating_a_new_worktree(self):
        first = MagicMock(restart_requested=True, login_requested=False, resume_draft="",
                          model="configured model", cwd=Path("/synthetic/active-worktree"),
                          engine_cwd_known=True)
        second = MagicMock(restart_requested=False, login_requested=False)
        first.run.return_value = second.run.return_value = 0
        with patch("sys.stdin.isatty", return_value=True), \
                patch("sys.stdout.isatty", return_value=True), \
                patch("privacy_gateway.cli.start_gateway"), \
                patch("privacy_gateway.terminal_entry.self_test"), \
                patch("privacy_gateway.terminal.TerminalApp", side_effect=[first, second]) as terminal, \
                patch("privacy_gateway.engine.ClaudeEngine") as engine:
            self.assertEqual(terminal_entry.run(["--worktree"]), 0)
            self.assertEqual(engine.call_args_list[0].args[1], ["--worktree"])
            self.assertEqual(engine.call_args_list[1].args[1], [])
            self.assertEqual(engine.call_args_list[1].args[2], first.cwd)
            self.assertEqual(terminal.call_args_list[1].kwargs["cwd"], first.cwd)

    def test_restart_before_worktree_is_known_reports_original_directory_fallback(self):
        first = MagicMock(restart_requested=True, login_requested=False, resume_draft="unsent",
                          model="configured model", cwd=Path.cwd(), engine_cwd_known=False)
        second = MagicMock(restart_requested=False, login_requested=False)
        first.run.return_value = second.run.return_value = 0
        with patch("sys.stdin.isatty", return_value=True), \
                patch("sys.stdout.isatty", return_value=True), \
                patch("privacy_gateway.cli.start_gateway"), \
                patch("privacy_gateway.terminal_entry.self_test"), \
                patch("privacy_gateway.terminal.TerminalApp", side_effect=[first, second]), \
                patch("privacy_gateway.engine.ClaudeEngine") as engine:
            self.assertEqual(terminal_entry.run(["--worktree"]), 0)
            self.assertEqual(engine.call_args_list[1].args[1], [])
            self.assertEqual(engine.call_args_list[1].args[2], Path.cwd())
            self.assertIn("original project directory", second._append.call_args.args[1])

    def test_failed_network_self_test_cleans_up_without_starting_engine(self):
        with patch("sys.stdin.isatty", return_value=True), \
                patch("sys.stdout.isatty", return_value=True), \
                patch("sys.stderr", io.StringIO()), \
                patch("privacy_gateway.cli.start_gateway") as gateway, \
                patch("privacy_gateway.terminal_entry.self_test", side_effect=RuntimeError("failed")), \
                patch("privacy_gateway.engine.ClaudeEngine") as engine:
            self.assertEqual(terminal_entry.run([]), 1)
            engine.assert_not_called()
            gateway.return_value.state.close.assert_called_once()
            gateway.return_value.shutdown.assert_called_once()
            gateway.return_value.server_close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
