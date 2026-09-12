"""Boundary checks with synthetic data; no provider requests or credentials."""
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import subprocess
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from privacy_gateway.client import (
    ClientConfigurationError, build_claude_command, claude_environment, validate_claude_arguments,
)
from privacy_gateway.isolation import command, isolated_environment, profile, self_test


class NativeBoundaryTests(unittest.TestCase):
    def test_native_context_model_and_terminal_options_keep_working(self):
        for arguments in (
            [], ["--model", "sonnet", "-p", "Explain this function"],
            ["--resume", "synthetic-id", "--effort=high"],
            ["--tools", "Read,Edit", "--allowedTools", "Read", "Edit", "-p", "synthetic prompt"],
            ["--permission-mode", "acceptEdits", "--worktree", "synthetic-name"],
            ["--permission-mode", "default"],
            ["--system-prompt", "--settings", "-p", "Echo the option name"],
            ["--", "--settings", "--chrome", "--remote-control"],
            ["-pc"], ["-rsynthetic-session"], ["-prsynthetic-session"],
        ):
            with self.subTest(arguments=arguments):
                validate_claude_arguments(arguments)

    def test_settings_and_integrations_cannot_override_forced_prefix(self):
        options = ("--settings", "--setting-sources", "--managed-settings", "--mcp-config",
                   "--chrome", "--ide", "--plugin-dir", "--plugin-url", "--plugin-dir-no-mcp",
                   "--remote-control", "--sdk-url", "--remote", "--bg", "--background",
                   "--bg-pty-host", "--chrome-native-host", "--computer-use-mcp", "--tmux",
                   "--agent", "--agents", "--init", "--init-only", "--permission-prompt-tool",
                   "--dangerously-load-development-channels", "--betas", "--future-network-switch")
        for option in options:
            for argument in (option, option + "=synthetic"):
                with self.subTest(argument=argument), self.assertRaises(ClientConfigurationError):
                    validate_claude_arguments(["--model", "sonnet", argument])

    def test_tool_permission_bypass_is_not_available(self):
        for arguments in (["--dangerously-skip-permissions"], ["--allow-dangerously-skip-permissions"],
                          ["--permission-mode", "bypassPermissions"], ["--permission-mode=bypassPermissions"]):
            with self.subTest(arguments=arguments), self.assertRaises(ClientConfigurationError):
                validate_claude_arguments(arguments)

    def test_native_service_and_setup_subcommands_are_rejected(self):
        for arguments in (["auth", "login"], ["plugin", "install", "synthetic-plugin"],
                          ["agents"], ["mcp", "serve"], ["ultrareview"], ["gateway"],
                          ["setup-token"], ["--model", "sonnet", "update"],
                          ["--", "remote-control"]):
            with self.subTest(arguments=arguments), self.assertRaises(ClientConfigurationError):
                validate_claude_arguments(arguments)

    def test_native_read_only_diagnostics_remain_available(self):
        for arguments in (["doctor"], ["auth", "status", "--json"], ["plugin", "list"],
                          ["mcp", "list"], ["auto-mode", "defaults"]):
            with self.subTest(arguments=arguments):
                validate_claude_arguments(arguments)

    def test_unsafe_arguments_fail_before_resolving_or_starting_child(self):
        with patch("privacy_gateway.client.shutil.which") as lookup, \
                patch("privacy_gateway.client.command") as sandbox, self.assertRaises(ClientConfigurationError):
            build_claude_command(SimpleNamespace(server_port=41234), ["--settings", "synthetic.json"])
        lookup.assert_not_called()
        sandbox.assert_not_called()

    def test_forced_configuration_and_original_native_argv_are_preserved(self):
        extra = ["--model", "sonnet", "--", "--settings", "literal prompt"]
        with patch("privacy_gateway.client.shutil.which", return_value="/synthetic/claude"), \
                patch("privacy_gateway.client.command", side_effect=lambda port, argv: argv):
            argv = build_claude_command(SimpleNamespace(server_port=41234), extra)
        self.assertEqual(argv[-len(extra):], extra)
        self.assertEqual(argv[argv.index("--setting-sources") + 1], "")
        self.assertEqual(json.loads(argv[argv.index("--mcp-config") + 1]), {"mcpServers": {}})
        settings = json.loads(argv[argv.index("--settings") + 1])
        self.assertTrue(settings["disableAllHooks"])
        self.assertTrue(settings["skipWebFetchPreflight"])


class EnvironmentBoundaryTests(unittest.TestCase):
    def test_child_keeps_login_and_project_environment_but_drops_injections(self):
        original = {
            "HOME": "/synthetic/home", "PATH": "/synthetic/bin", "TERM": "xterm-256color",
            "PROJECT_TEST_MODE": "1", "NODE_ENV": "test", "CLAUDE_CONFIG_DIR": "/synthetic/config",
            "ANTHROPIC_API_KEY": "synthetic-key", "ANTHROPIC_AUTH_TOKEN": "synthetic-token",
            "CLAUDE_CODE_OAUTH_TOKEN": "synthetic-oauth", "ANTHROPIC_MODEL": "sonnet",
            "CLAUDE_CODE_ACCESSIBILITY": "1", "CLAUDE_CODE_SAFE_MODE": "0",
            "ANTHROPIC_BASE_URL": "https://synthetic-invalid.example",
            "ANTHROPIC_UNIX_SOCKET": "/synthetic/socket", "ANTHROPIC_CUSTOM_HEADERS": "X-Test: synthetic",
            "CLAUDE_CODE_USE_VERTEX": "1", "CLAUDE_CODE_USE_GATEWAY": "1",
            "CLAUDE_CODE_PROCESS_WRAPPER": "synthetic-wrapper", "CLAUDE_CODE_SHELL_PREFIX": "synthetic",
            "CLAUDE_CODE_MANAGED_SETTINGS_PATH": "/synthetic/settings.json",
            "CLAUDE_BRIDGE_BASE_URL": "https://synthetic-invalid.example",
            "CLAUDE_CODE_FUTURE_TRANSPORT": "synthetic", "CLAUDE_ENV_FILE": "/synthetic/env",
            "OTEL_EXPORTER_OTLP_ENDPOINT": "https://synthetic-invalid.example",
            "OTEL_LOG_USER_PROMPTS": "true", "OTEL_SDK_DISABLED": "false",
            "NODE_OPTIONS": "--require synthetic", "NODE_PATH": "/synthetic/modules",
            "BUN_OPTIONS": "--preload synthetic", "DYLD_INSERT_LIBRARIES": "/synthetic/inject.dylib",
            "LD_PRELOAD": "/synthetic/inject.so", "BASH_ENV": "/synthetic/rc",
            "ENV": "/synthetic/rc", "ZDOTDIR": "/synthetic/zsh", "RUBYOPT": "-rsynthetic",
            "HTTP_PROXY": "http://127.0.0.1:9999", "https_proxy": "http://127.0.0.1:9999",
        }
        server = SimpleNamespace(proxy_url="http://127.0.0.1:41234/proxy/synthetic-token")
        with patch.dict(os.environ, original, clear=True):
            result = claude_environment(server)
            self.assertEqual(dict(os.environ), original)
        retained = ("HOME", "PATH", "TERM", "PROJECT_TEST_MODE", "NODE_ENV", "CLAUDE_CONFIG_DIR",
                    "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN",
                    "ANTHROPIC_MODEL", "CLAUDE_CODE_ACCESSIBILITY")
        for name in retained:
            self.assertEqual(result[name], original[name], name)
        for name in set(original) - set(retained) - {"ANTHROPIC_BASE_URL", "CLAUDE_CODE_SAFE_MODE", "OTEL_SDK_DISABLED"}:
            self.assertNotIn(name, result)
        self.assertEqual(result["ANTHROPIC_BASE_URL"], server.proxy_url)
        self.assertEqual(result["CLAUDE_CODE_SAFE_MODE"], "1")
        self.assertEqual(result["CLAUDE_CODE_ATTRIBUTION_HEADER"], "0")
        self.assertEqual(result["OTEL_SDK_DISABLED"], "true")

    def test_generic_child_environment_removes_loader_hooks_case_variants(self):
        original = {"PATH": "/synthetic/bin", "Http_Proxy": "synthetic", "ALL_PROXY": "synthetic",
                    "NODE_CHANNEL_FD": "8", "BASH_FUNC_synthetic%%": "synthetic",
                    "PYTHONSTARTUP": "/synthetic/startup.py", "BUN_INSPECT": "1"}
        self.assertEqual(isolated_environment(original), {"PATH": "/synthetic/bin"})
        self.assertEqual(original["NODE_CHANNEL_FD"], "8")


@unittest.skipUnless(platform.system() == "Darwin" and Path("/usr/bin/sandbox-exec").exists(),
                     "Requires the actual macOS sandbox-exec boundary")
class InstalledBoundaryTests(unittest.TestCase):
    def test_direct_socket_restriction_self_test(self):
        with socket.socket() as gateway:
            gateway.bind(("127.0.0.1", 0))
            gateway.listen(1)
            self.assertTrue(self_test(gateway.getsockname()[1]))

    @unittest.skipUnless(shutil.which("claude"), "Requires installed Claude Code")
    def test_installed_native_parser_accepts_enforced_flags_without_model_request(self):
        # --version exits before auth or model work. This also catches native
        # parser regressions in enforced flags while keeping all egress denied.
        with socket.socket() as gateway:
            gateway.bind(("127.0.0.1", 0))
            gateway.listen(1)
            server = SimpleNamespace(server_port=gateway.getsockname()[1],
                                     proxy_url="http://127.0.0.1:%d/proxy/synthetic" % gateway.getsockname()[1])
            with patch.dict(os.environ, {"PATH": os.environ.get("PATH", ""), "HOME": str(Path.home())}, clear=True):
                result = subprocess.run(build_claude_command(server, ["--version"]),
                                        env=claude_environment(server), capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, "Native protected launch failed; process output omitted")
        self.assertIn("Claude Code", result.stdout)


class ProfileValidationTests(unittest.TestCase):
    def test_invalid_ports_and_commands_are_rejected(self):
        for port in (True, 0, 65536, "41234"):
            with self.subTest(port=port), self.assertRaises(ValueError):
                profile(port)
        for argv in ([], [None], ["synthetic\0binary"]):
            with self.subTest(argv=argv), self.assertRaises(ValueError):
                command(41234, argv)


if __name__ == "__main__":
    unittest.main()
