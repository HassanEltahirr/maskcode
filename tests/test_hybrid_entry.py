"""Local scanner lifecycle and explicit backend selection without model calls."""
import io
from pathlib import Path
import unittest
from unittest.mock import MagicMock, patch

from privacy_gateway import cli, native, terminal_entry
from privacy_gateway.ollama_runtime import OllamaRuntimeError


class HybridEntryTests(unittest.TestCase):
    def test_normal_maskcode_defaults_to_local_detector_with_explicit_opt_out(self):
        self.assertEqual(native.parse_native([]).local_model, "qwen2.5:1.5b")
        self.assertIsNone(native.parse_native(["--mask-rules-only"]).local_model)
        self.assertEqual(native.parse_native(["--mask-local-model", "llama3.2:latest"]).local_model, "llama3.2:latest")
        parser = cli.build_parser()
        self.assertEqual(parser.parse_args(["codex"]).local_model, "qwen2.5:1.5b")
        self.assertIsNone(parser.parse_args(["codex", "--rules-only"]).local_model)

    def test_ollama_start_failure_never_starts_cloud_engine(self):
        with patch("privacy_gateway.ollama_runtime.ManagedOllama") as runtime, \
                patch("privacy_gateway.engine.ClaudeEngine") as engine, \
                patch("sys.stdin.isatty", return_value=True), \
                patch("sys.stdout.isatty", return_value=True), patch("sys.stderr", io.StringIO()):
            runtime.return_value.start.side_effect = OllamaRuntimeError("Synthetic local failure")
            self.assertEqual(terminal_entry.run([]), 1)
            engine.assert_not_called()

    def test_interrupt_after_ollama_start_closes_owned_runtime(self):
        with patch("privacy_gateway.ollama_runtime.ManagedOllama") as factory, \
                patch("privacy_gateway.semantic.SemanticScanner") as scanner, \
                patch("privacy_gateway.cli.GatewayServer", side_effect=KeyboardInterrupt):
            runtime = factory.return_value
            runtime.start.return_value = runtime
            with self.assertRaises(KeyboardInterrupt):
                cli.start_gateway(native.parse_native([]))
            scanner.return_value.close.assert_called_once()
            runtime.close.assert_called_once()

    def test_thread_start_failure_closes_server_and_detector(self):
        with patch("privacy_gateway.ollama_runtime.ManagedOllama") as factory, \
                patch("privacy_gateway.semantic.SemanticScanner") as scanner, \
                patch("privacy_gateway.cli.GatewayServer") as server, \
                patch("privacy_gateway.cli.threading.Thread") as thread:
            runtime = factory.return_value
            runtime.start.return_value = runtime
            thread.return_value.start.side_effect = RuntimeError("synthetic")
            with self.assertRaises(RuntimeError):
                cli.start_gateway(native.parse_native([]))
            scanner.return_value.close.assert_called_once()
            runtime.close.assert_called_once()
            server.return_value.server_close.assert_called_once()

    def test_rules_only_does_not_start_ollama(self):
        with patch("privacy_gateway.ollama_runtime.ManagedOllama") as runtime, \
                patch("privacy_gateway.cli.GatewayServer"), patch("privacy_gateway.cli.threading.Thread"):
            cli.start_gateway(native.parse_native(["--mask-rules-only"]))
            runtime.assert_not_called()

    def test_codex_backend_routes_before_claude_argument_validation(self):
        with patch("privacy_gateway.native.run_codex", return_value=7) as run, \
                patch("privacy_gateway.terminal_entry.split_arguments") as claude:
            self.assertEqual(terminal_entry.run(["--mask-backend", "codex", "--model", "gpt-6-astra"]), 7)
            args = run.call_args.args[0]
            self.assertEqual(args.provider, "codex")
            self.assertEqual(args.args, ["--model", "gpt-6-astra"])
            self.assertEqual(args.local_model, "qwen2.5:1.5b")
            claude.assert_not_called()

    def test_unknown_backend_fails_without_starting_any_engine(self):
        with patch("privacy_gateway.cli.start_gateway") as gateway, patch("sys.stderr", io.StringIO()):
            self.assertEqual(terminal_entry.run(["--mask-backend", "fake-local-astra"]), 1)
            gateway.assert_not_called()


if __name__ == "__main__":
    unittest.main()
