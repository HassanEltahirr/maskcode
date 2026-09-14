"""Native terminal launcher checks using synthetic servers and mocked children."""
import io
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from privacy_gateway import cli, native


class NativeRoutingTests(unittest.TestCase):
    def test_no_arguments_routes_to_maskcode_terminal(self):
        with patch("privacy_gateway.terminal_entry.run", return_value=23) as launch, \
                patch("privacy_gateway.cli.gateway_main") as gateway:
            self.assertEqual(cli.main([]), 23)
        launch.assert_called_once_with([])
        gateway.assert_not_called()

    def test_native_arguments_keep_order(self):
        arguments = ["--model", "sonnet", "--resume", "synthetic-session", "-p",
                     "Explain the example", "--output-format", "json"]
        with patch("privacy_gateway.terminal_entry.run", return_value=0) as launch:
            self.assertEqual(cli.main(arguments), 0)
            launch.assert_called_once_with(arguments)

    def test_native_subcommands_and_positional_words_are_not_wrapper_aliases(self):
        for arguments in (["doctor"], ["auth", "status"], ["plugin", "list"],
                          ["claude", "explain this name"], ["serve"], ["preview"]):
            with self.subTest(arguments=arguments), patch("privacy_gateway.terminal_entry.run", return_value=0) as launch, \
                    patch("privacy_gateway.cli.gateway_main") as gateway:
                self.assertEqual(cli.main(arguments), 0)
                launch.assert_called_once_with(arguments)
                gateway.assert_not_called()

    def test_explicit_gateway_namespace_routes_utilities(self):
        with patch("privacy_gateway.cli.gateway_main", return_value=17) as gateway, \
                patch("privacy_gateway.terminal_entry.run") as launch:
            self.assertEqual(cli.main(["gateway", "preview", "--json"]), 17)
        gateway.assert_called_once_with(["preview", "--json"])
        launch.assert_not_called()


class NativeArgumentTests(unittest.TestCase):
    def test_defaults_use_background_masking(self):
        args = native.parse_native([])
        self.assertEqual(args.mode, "auto")
        self.assertFalse(args.dashboard)
        self.assertEqual(args.args, [])
        self.assertIsNone(args.reasoning_effort)

    def test_explicit_codex_effort_is_scoped_and_not_forwarded_as_a_raw_flag(self):
        args = native.parse_native(["--mask-effort=medium", "--model", "gpt-6-astra",
                                    "--mask-backend", "codex", "hello"])
        self.assertEqual(args.reasoning_effort, "medium")
        self.assertEqual(args.args, ["--model", "gpt-6-astra", "hello"])
        for flags in (["--mask-effort", "medium"],
                      ["--mask-backend", "codex", "--mask-effort", "medium;extra=true"],
                      ["--mask-backend", "codex", "--mask-effort"]):
            with self.subTest(flags=flags), self.assertRaises(ValueError):
                native.parse_native(flags)

    def test_mask_options_are_removed_without_reordering_native_arguments(self):
        arguments = ["--model", "sonnet", "--mask-policy", "/synthetic/policy.json",
                     "-p", "Read the example", "--mask-cwd=/synthetic/project",
                     "--resume", "synthetic-session", "--mask-port", "43123",
                     "--output-format", "json"]
        args = native.parse_native(arguments)
        self.assertEqual(args.args, ["--model", "sonnet", "-p", "Read the example",
                                     "--resume", "synthetic-session", "--output-format", "json"])
        self.assertEqual(args.policy, Path("/synthetic/policy.json"))
        self.assertEqual(args.cwd, Path("/synthetic/project"))
        self.assertEqual(args.port, 43123)

    def test_delimiter_and_every_argument_after_it_are_preserved(self):
        tail = ["--", "--mask-policy", "literal-prompt", "--mask-review", "--mode", "review"]
        args = native.parse_native(["--model", "sonnet", *tail])
        self.assertEqual(args.args, ["--model", "sonnet", *tail])
        self.assertIsNone(args.policy)
        self.assertEqual(args.mode, "auto")

    def test_review_is_explicit_and_last_mode_option_wins(self):
        self.assertEqual(native.parse_native(["--mask-auto"]).mode, "auto")
        self.assertEqual(native.parse_native(["--mask-auto", "--mask-review"]).mode, "review")
        self.assertEqual(native.parse_native(["--mask-review", "--mask-auto"]).mode, "auto")

    def test_legacy_privacy_aliases_are_explicitly_extracted(self):
        args = native.parse_native(["--mode", "review", "--policy=/synthetic/policy.json",
                                    "--cwd", "/synthetic/project", "--port=43210", "--model", "sonnet"])
        self.assertEqual(args.mode, "review")
        self.assertEqual(args.policy, Path("/synthetic/policy.json"))
        self.assertEqual(args.cwd, Path("/synthetic/project"))
        self.assertEqual(args.port, 43210)
        self.assertEqual(args.args, ["--model", "sonnet"])

    def test_invalid_mask_options_fail_before_launch(self):
        for args in (["--mask-policy"], ["--mask-cwd="], ["--mask-port", "65536"],
                     ["--mask-port", "not-a-number"], ["--mode", "unexpected"],
                     ["--mask-reveiw"], ["--mask-auto=true"]):
            with self.subTest(args=args), self.assertRaises(ValueError):
                native.parse_native(args)


class NativeLaunchTests(unittest.TestCase):
    def setUp(self):
        self.server = Mock()
        self.server.server_port = 43123
        self.server.console_url = "http://127.0.0.1:43123/#synthetic-review-token"
        self.server.proxy_url = "http://127.0.0.1:43123/proxy/synthetic-proxy-token"
        self.server.state = SimpleNamespace(network_isolation=False, close=Mock())
        self.child_environment = {"ANTHROPIC_BASE_URL": self.server.proxy_url, "SYNTHETIC": "1"}
        self.output, self.errors = io.StringIO(), io.StringIO()
        patches = {
            "gateway": patch("privacy_gateway.cli.start_gateway", return_value=self.server),
            "self_test": patch("privacy_gateway.native.self_test", return_value=True),
            "which": patch("privacy_gateway.client.shutil.which", return_value="/synthetic/bin/claude"),
            "isolation": patch("privacy_gateway.client.command", side_effect=lambda port, argv: ["/synthetic/sandbox", *argv]),
            "environment": patch("privacy_gateway.native.claude_environment", return_value=self.child_environment),
            "info_environment": patch("privacy_gateway.native.isolated_environment", return_value={"PATH": "/synthetic/bin"}),
            "child": patch("privacy_gateway.native.subprocess.call", return_value=7),
            "browser": patch("privacy_gateway.native.webbrowser.open"),
            "directory": patch("privacy_gateway.native.Path.is_dir", return_value=True),
            "stdout": patch("privacy_gateway.native.sys.stdout", self.output),
            "stderr": patch("privacy_gateway.native.sys.stderr", self.errors),
        }
        for name, patcher in patches.items():
            setattr(self, name, patcher.start())
            self.addCleanup(patcher.stop)

    def assert_closed(self):
        self.server.state.close.assert_called_once_with()
        self.server.shutdown.assert_called_once_with()
        self.server.server_close.assert_called_once_with()

    def test_child_inherits_terminal_and_native_arguments_without_headless_flags(self):
        arguments = ["--model", "sonnet", "--resume", "synthetic-session", "-p",
                     "Explain the example", "--output-format", "json"]
        self.assertEqual(native.run(["--mask-auto", *arguments]), 7)
        self.child.assert_called_once()
        positional, keywords = self.child.call_args
        argv = positional[0]
        self.assertEqual(argv[-len(arguments):], arguments)
        self.assertEqual(set(keywords), {"cwd", "env"})
        self.assertIs(keywords["env"], self.child_environment)
        forced_prefix = argv[:-len(arguments)]
        for flag in ("--tools", "--allowedTools", "--input-format", "--output-format",
                     "--no-session-persistence", "-p", "--print"):
            self.assertNotIn(flag, forced_prefix)
        self.assertNotIn("stream-json", forced_prefix)
        self.assertIn("--safe-mode", forced_prefix)
        self.self_test.assert_called_once_with(43123)
        self.assertTrue(self.server.state.network_isolation)
        self.browser.assert_not_called()
        self.assertEqual(self.output.getvalue(), "")
        self.assertEqual(self.errors.getvalue(), "")
        self.assert_closed()

    def test_launch_preserves_delimiter_through_actual_command_builder(self):
        tail = ["--", "--mask-policy", "literal-prompt", "--mask-review"]
        self.assertEqual(native.run(tail), 7)
        argv = self.child.call_args.args[0]
        self.assertEqual(argv[-len(tail):], tail)
        self.assertEqual(self.gateway.call_args.args[0].mode, "auto")
        self.browser.assert_not_called()

    def test_native_no_arguments_launches_interactive_without_request_review(self):
        self.assertEqual(native.run([]), 7)
        argv = self.child.call_args.args[0]
        self.assertNotIn("-p", argv)
        self.assertNotIn("--print", argv)
        self.assertEqual(self.gateway.call_args.args[0].mode, "auto")
        self.browser.assert_not_called()
        self.assert_closed()

    def test_explicit_review_opens_dashboard_and_uses_review_mode(self):
        self.assertEqual(native.run(["--mask-review", "--model", "sonnet"]), 7)
        self.assertEqual(self.gateway.call_args.args[0].mode, "review")
        self.browser.assert_called_once_with(self.server.console_url)
        self.assertIn("approval", self.errors.getvalue())
        self.assertNotIn("--mask-review", self.child.call_args.args[0])

    def test_optional_dashboard_does_not_change_automatic_mode(self):
        self.assertEqual(native.run(["--mask-auto", "--mask-dashboard"]), 7)
        self.assertEqual(self.gateway.call_args.args[0].mode, "auto")
        self.browser.assert_called_once_with(self.server.console_url)

    def test_no_browser_still_requires_review(self):
        self.assertEqual(native.run(["--mask-review", "--no-browser"]), 7)
        self.assertEqual(self.gateway.call_args.args[0].mode, "review")
        self.browser.assert_not_called()
        self.assertIn(self.server.console_url, self.errors.getvalue())

    def test_explicit_automatic_mode_does_not_open_browser(self):
        self.assertEqual(native.run(["--mask-auto"]), 7)
        self.assertEqual(self.gateway.call_args.args[0].mode, "auto")
        self.browser.assert_not_called()

    def test_self_test_failure_prevents_all_child_launches_and_closes_gateway(self):
        self.self_test.side_effect = RuntimeError("synthetic isolation failure")
        self.assertEqual(native.run(["-p", "synthetic prompt"]), 1)
        self.child.assert_not_called()
        self.isolation.assert_not_called()
        self.browser.assert_not_called()
        self.assertFalse(self.server.state.network_isolation)
        self.assertIn("No direct fallback", self.errors.getvalue())
        self.assert_closed()

    def test_informational_native_commands_inherit_output_without_gateway(self):
        for option in ("--help", "-h", "--version", "-v"):
            with self.subTest(option=option):
                self.child.reset_mock()
                self.assertEqual(native.run([option]), 7)
                self.child.assert_called_once_with(["/synthetic/bin/claude", option], cwd=Path.cwd(), env={"PATH": "/synthetic/bin"})
        self.gateway.assert_not_called()
        self.self_test.assert_not_called()
        self.isolation.assert_not_called()
        self.environment.assert_not_called()
        self.browser.assert_not_called()

    def test_maskcode_help_version_are_local_and_do_not_launch_claude(self):
        for option in ("--mask-help", "--mask-version"):
            with self.subTest(option=option):
                self.assertEqual(native.run([option]), 0)
        self.gateway.assert_not_called()
        self.child.assert_not_called()
        self.browser.assert_not_called()


if __name__ == "__main__":
    unittest.main()
