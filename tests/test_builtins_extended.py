"""Extended built-in detectors and the offline scan command. Synthetic data only."""
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from privacy_gateway import cli
from privacy_gateway.redaction import Redactor
from privacy_gateway.scan import scan_paths

# Fabricated, structurally valid examples; none are real credentials.
_SECRETS = [
    "glpat-" + "A1b2C3d4E5f6G7h8I9j0",
    "hf_" + "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
    "npm_" + "A" * 18 + "b" * 18,
    "ya29." + "a0AfH6SMBx" * 3,
    "GOCSPX-" + "SyntheticClientSecret00",
    "SG." + "a" * 22 + "." + "b" * 43,
    "shpat_" + "0123456789abcdef" * 2,
    "https://hooks.slack.com/services/T00000000/B00000000/" + "X" * 24,
    "https://discord.com/api/webhooks/123456789/" + "Synthetic_Token-abc12345",
]


class ExtendedBuiltinTests(unittest.TestCase):
    def test_additional_secret_formats_are_masked_and_restored(self):
        for value in _SECRETS:
            with self.subTest(value=value[:12]):
                redactor = Redactor()
                text = "config uses " + value + " here"
                masked = redactor.redact_text(text)
                self.assertNotIn(value, masked)
                self.assertIn("PG_SECRET_", masked)
                self.assertEqual(redactor.restore_text(masked), text)

    def test_valid_iban_is_masked_and_invalid_checksum_is_not(self):
        for value in ("AE070331234567890123456", "GB82 WEST 1234 5698 7654 32", "DE89370400440532013000"):
            with self.subTest(value=value):
                redactor = Redactor()
                masked = redactor.redact_text("pay " + value)
                self.assertNotIn(value, masked)
                self.assertIn("PG_IBAN_", masked)
                self.assertEqual(redactor.restore_text(masked), "pay " + value)
        for value in ("AE070331234567890123457", "AB12 CDEF GHIJ KLMN", "HTTP2 TLS13"):
            with self.subTest(value=value):
                self.assertEqual(Redactor().redact_text(value), value)

    def test_account_key_fields_are_credentials(self):
        text = 'AccountKey="synthetic+account/key=="'
        masked = Redactor().redact_text(text)
        self.assertNotIn("synthetic+account/key==", masked)
        self.assertEqual(Redactor().redact_json({"account_key": "x"})["account_key"][:10], "PG_SECRET_")


class ScanCommandTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "clean.py").write_text("print('hello')\n", encoding="utf-8")
        (self.root / "settings.env").write_text(
            "# synthetic\nCONTACT=sample.person@example.com\nAPI_KEY=abcdef123456\n", encoding="utf-8")
        (self.root / "blob.bin").write_bytes(b"\0\1\2sample.person@example.com")
        (self.root / ".git").mkdir()
        (self.root / ".git" / "config").write_text("x@example.com", encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def test_report_lists_labels_and_lines_but_never_values(self):
        report = scan_paths([self.root])
        self.assertEqual(report["scanned_files"], 2)
        self.assertEqual(len(report["findings"]), 1)
        finding = report["findings"][0]
        self.assertTrue(finding["path"].endswith("settings.env"))
        self.assertEqual(finding["lines"], [2, 3])
        self.assertEqual(finding["labels"], {"EMAIL": 1, "SECRET": 1})
        self.assertEqual(report["skipped"][0]["reason"], "binary")
        dumped = json.dumps(report)
        self.assertNotIn("sample.person", dumped)
        self.assertNotIn("abcdef123456", dumped)
        self.assertNotIn("PG_", dumped)

    def test_cli_exit_codes(self):
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(cli.main(["gateway", "scan", str(self.root / "clean.py")]), 0)
            self.assertEqual(cli.main(["gateway", "scan", "--json", str(self.root)]), 1)
        self.assertNotIn("sample.person", out.getvalue())

    def test_multiline_private_key_is_reported(self):
        key = self.root / "id.txt"
        key.write_text("-----BEGIN PRIVATE KEY-----\nSYNTHETIC\n-----END PRIVATE KEY-----\n", encoding="utf-8")
        report = scan_paths([key])
        self.assertIn("PRIVATE_KEY", report["totals"])


if __name__ == "__main__":
    unittest.main()
