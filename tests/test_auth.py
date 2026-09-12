"""Mock-only checks: these tests never start a real login or read credentials."""
import io
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from privacy_gateway.auth import official_login


class OfficialLoginTests(unittest.TestCase):
    def setUp(self):
        self.stdout, self.stderr = io.StringIO(), io.StringIO()
        self.addCleanup(patch.stopall)
        patch("sys.stdout", self.stdout).start()
        patch("sys.stderr", self.stderr).start()
        self.which = patch("privacy_gateway.auth.shutil.which", return_value="/synthetic/bin/claude").start()
        self.run = patch("privacy_gateway.auth.subprocess.run",
                         return_value=subprocess.CompletedProcess([], 0)).start()

    def test_exact_official_command_inherits_terminal_and_preserves_cwd(self):
        cwd = Path("/synthetic/project with spaces")
        with patch.dict("os.environ", {"HOME": "/synthetic/home", "PATH": "/synthetic/bin",
                                       "TERM": "xterm-256color", "CLAUDE_CONFIG_DIR": "/synthetic/config"}, clear=True):
            self.assertEqual(official_login(cwd), 0)
        self.which.assert_called_once_with("claude")
        self.run.assert_called_once_with(
            ["/synthetic/bin/claude", "auth", "login"], cwd=cwd,
            env={"HOME": "/synthetic/home", "PATH": "/synthetic/bin",
                 "TERM": "xterm-256color", "CLAUDE_CONFIG_DIR": "/synthetic/config"},
            check=False, close_fds=True)
        self.assertIn("Opening the official Claude sign-in flow...", self.stdout.getvalue())
        self.assertEqual(self.stderr.getvalue(), "")

    def test_login_scrubs_inference_auth_gateway_and_loader_overrides(self):
        env = {"HOME": "/synthetic/home", "PATH": "/synthetic/bin", "TERM": "dumb",
               "CLAUDE_CONFIG_DIR": "/synthetic/config",
               "CLAUDE_CODE_ACCESSIBILITY": "1", "CLAUDE_AX_SCREEN_READER": "1",
               "CLAUDE_CODE_DISABLE_ALTERNATE_SCREEN": "1", "CLAUDE_CODE_DISABLE_MOUSE": "1",
               "CLAUDE_CODE_DISABLE_MOUSE_CLICKS": "1", "CLAUDE_CODE_DISABLE_TERMINAL_TITLE": "1",
               "ANTHROPIC_API_KEY": "synthetic-secret", "ANTHROPIC_AUTH_TOKEN": "synthetic-secret",
               "ANTHROPIC_BASE_URL": "http://synthetic-gateway", "ANTHROPIC_MODEL": "synthetic-model",
               "CLAUDE_CODE_OAUTH_TOKEN": "synthetic-secret",
               "CLAUDE_CODE_OAUTH_REFRESH_TOKEN": "synthetic-secret",
               "CLAUDE_CODE_SAFE_MODE": "1", "CLAUDE_NEW_UNKNOWN_OVERRIDE": "blocked",
               "OTEL_EXPORTER_OTLP_ENDPOINT": "http://synthetic-telemetry",
               "NODE_OPTIONS": "synthetic-loader", "DYLD_INSERT_LIBRARIES": "synthetic-loader",
               "HTTPS_PROXY": "http://synthetic-proxy", "BASH_ENV": "/synthetic/startup"}
        preserved = {name: value for name, value in env.items()
                     if name in {"HOME", "PATH", "TERM", "CLAUDE_CONFIG_DIR", "CLAUDE_CODE_ACCESSIBILITY",
                                 "CLAUDE_AX_SCREEN_READER", "CLAUDE_CODE_DISABLE_ALTERNATE_SCREEN",
                                 "CLAUDE_CODE_DISABLE_MOUSE", "CLAUDE_CODE_DISABLE_MOUSE_CLICKS",
                                 "CLAUDE_CODE_DISABLE_TERMINAL_TITLE"}}
        with patch.dict("os.environ", env, clear=True):
            self.assertEqual(official_login("/synthetic/project"), 0)
        self.assertEqual(self.run.call_args.kwargs["env"], preserved)
        self.assertNotIn("synthetic-secret", self.stdout.getvalue() + self.stderr.getvalue())

    def test_missing_cli_does_not_start_a_fallback(self):
        self.which.return_value = None
        self.assertEqual(official_login("/synthetic/project"), 127)
        self.run.assert_not_called()
        self.assertIn("Install the official Claude CLI", self.stderr.getvalue())

    def test_child_failure_returns_status_without_retry(self):
        self.run.return_value = subprocess.CompletedProcess([], 7)
        self.assertEqual(official_login("/synthetic/project"), 7)
        self.run.assert_called_once()
        self.assertIn("maskcode auth login", self.stderr.getvalue())

    def test_os_error_has_fixed_diagnostic_without_exception_content(self):
        self.run.side_effect = OSError("synthetic-private-exception-content")
        self.assertEqual(official_login("/synthetic/project"), 1)
        self.run.assert_called_once()
        self.assertIn("Check the Claude installation and project directory", self.stderr.getvalue())
        self.assertNotIn("synthetic-private-exception-content", self.stderr.getvalue())

    def test_keyboard_interrupt_returns_conventional_status(self):
        self.run.side_effect = KeyboardInterrupt
        self.assertEqual(official_login("/synthetic/project"), 130)
        self.run.assert_called_once()

    def test_child_signal_returns_conventional_status(self):
        self.run.return_value = subprocess.CompletedProcess([], -2)
        self.assertEqual(official_login("/synthetic/project"), 130)
        self.run.assert_called_once()


if __name__ == "__main__":
    unittest.main()
