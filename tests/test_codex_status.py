"""Local-only status formatting and native terminal output ordering."""
import io
import unittest
from unittest.mock import Mock, patch

from privacy_gateway import native


class CodexStatusTests(unittest.TestCase):
    def test_summary_includes_only_valid_numeric_scan_statistics(self):
        scan = {"requests": 2, "total_scan_seconds": 3.125, "scanned_chunks": 7,
                "cache_hits": 11, "prompt": "synthetic private text",
                "diagnostic": "synthetic credential", "model": "untrusted model label"}
        self.assertEqual(native.format_scan_summary(scan),
                         "MaskCode local scan: 3.1s total · 7 chunks scanned · 11 cache hits.")
        for field, invalid in (("requests", 0), ("requests", True),
                               ("total_scan_seconds", "synthetic private text"),
                               ("total_scan_seconds", float("nan")),
                               ("total_scan_seconds", float("inf")),
                               ("total_scan_seconds", -1), ("scanned_chunks", -1),
                               ("scanned_chunks", True), ("cache_hits", "private")):
            with self.subTest(field=field, value_type=type(invalid).__name__):
                self.assertIsNone(native.format_scan_summary({**scan, field: invalid}))
        for invalid in (None, [], "private", {}):
            self.assertIsNone(native.format_scan_summary(invalid))

    def make_server(self, scanner):
        server = Mock(server_port=40123)
        server.state.semantic_scanner = scanner
        return server

    def test_notice_precedes_native_terminal_and_summary_follows_exit_before_cleanup(self):
        stderr = io.StringIO()
        scanner = Mock()
        server = self.make_server(scanner)
        args = native.parse_native(["--mask-backend", "codex", "--model", "gpt-6-astra"])
        stages = []
        def launch(actual_server, actual_args):
            self.assertIs(actual_server, server)
            self.assertIs(actual_args, args)
            self.assertIn("First local scan loads the detector", stderr.getvalue())
            self.assertIn("Working timer includes masking", stderr.getvalue())
            self.assertNotIn("MaskCode local scan:", stderr.getvalue())
            scanner.snapshot.assert_not_called()
            stages.append("native-exit")
            return 7
        def snapshot():
            self.assertEqual(stages, ["native-exit"])
            server.state.close.assert_not_called()
            stages.append("summary")
            return {"requests": 1, "total_scan_seconds": 12.26, "scanned_chunks": 4, "cache_hits": 2}
        scanner.snapshot.side_effect = snapshot
        def close():
            self.assertEqual(stages, ["native-exit", "summary"])
            self.assertIn("12.3s total · 4 chunks scanned · 2 cache hits", stderr.getvalue())
            stages.append("cleanup")
        server.state.close.side_effect = close
        with patch("privacy_gateway.cli.start_gateway", return_value=server), \
                patch("privacy_gateway.cli.launch_codex", side_effect=launch), \
                patch("privacy_gateway.native.self_test"), patch("sys.stderr", stderr):
            self.assertEqual(native.run_codex(args), 7)
        self.assertEqual(stages, ["native-exit", "summary", "cleanup"])
        server.shutdown.assert_called_once()
        server.server_close.assert_called_once()

    def test_no_summary_without_scans_and_no_local_notice_when_rules_only(self):
        for enabled in (False, True):
            with self.subTest(local_detector=enabled):
                scanner = Mock() if enabled else None
                if scanner is not None:
                    scanner.snapshot.return_value = {"requests": 0, "total_scan_seconds": 0,
                                                     "scanned_chunks": 0, "cache_hits": 0}
                server = self.make_server(scanner)
                stderr = io.StringIO()
                with patch("privacy_gateway.cli.start_gateway", return_value=server), \
                        patch("privacy_gateway.cli.launch_codex", return_value=0), \
                        patch("privacy_gateway.native.self_test"), patch("sys.stderr", stderr):
                    self.assertEqual(native.run_codex(native.parse_native(["--mask-backend", "codex"])), 0)
                self.assertNotIn("MaskCode local scan:", stderr.getvalue())
                self.assertEqual("First local scan loads the detector" in stderr.getvalue(), enabled)

    def test_summary_failure_preserves_exit_code_and_launch_error_skips_summary(self):
        for launch_error in (False, True):
            with self.subTest(launch_error=launch_error):
                scanner = Mock()
                scanner.snapshot.side_effect = RuntimeError("synthetic private diagnostic")
                server = self.make_server(scanner)
                stderr = io.StringIO()
                error = RuntimeError("synthetic launch failure")
                with patch("privacy_gateway.cli.start_gateway", return_value=server), \
                        patch("privacy_gateway.cli.launch_codex", return_value=23,
                              side_effect=error if launch_error else None), \
                        patch("privacy_gateway.native.self_test"), patch("sys.stderr", stderr):
                    args = native.parse_native(["--mask-backend", "codex"])
                    if launch_error:
                        with self.assertRaises(RuntimeError) as caught:
                            native.run_codex(args)
                        self.assertIs(caught.exception, error)
                        scanner.snapshot.assert_not_called()
                    else:
                        self.assertEqual(native.run_codex(args), 23)
                self.assertNotIn("private diagnostic", stderr.getvalue())
                self.assertNotIn("MaskCode local scan:", stderr.getvalue())
                server.state.close.assert_called_once()

    def test_maskcode_terminal_displays_current_scan_progress(self):
        from prompt_toolkit.formatted_text import fragment_list_to_text
        from prompt_toolkit.input import create_pipe_input
        from prompt_toolkit.output import DummyOutput
        from privacy_gateway.terminal import TerminalApp
        with create_pipe_input() as pipe:
            app = TerminalApp("/synthetic-project", input=pipe, output=DummyOutput())
            app._snapshot = {"semantic_scan": {"enabled": True, "status": "scanning",
                                               "scanned_chunks": 40, "completed_chunks": 1,
                                               "current_chunks": 3}}
            line = fragment_list_to_text(app._status_line())
        self.assertIn("1/3 chunks checked", line)
        self.assertNotIn("40 chunks", line)


if __name__ == "__main__":
    unittest.main()
