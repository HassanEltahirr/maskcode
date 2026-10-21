"""Everyday app: loopback-only UI, token gate, mask/restore round trip, words file."""
import http.client
import json
import os
import tempfile
import threading
import unittest
from pathlib import Path

from privacy_gateway.app import AppServer, AppState, load_policy_data, save_terms, suggest_names


class AppTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.policy = Path(self.tmp.name) / "policy.json"
        self.server = AppServer(AppState(self.policy))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_port
        self.token = self.server.state.token

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.tmp.cleanup()

    def call(self, method, path, body=None, token=True, host=None, origin=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        headers = {"Host": host or "127.0.0.1:%d" % self.port}
        if token:
            headers["X-MaskCode-Token"] = self.token if token is True else token
        if origin:
            headers["Origin"] = origin
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        conn.request(method, path, body=data, headers=headers)
        resp = conn.getresponse()
        raw = resp.read()
        conn.close()
        try:
            return resp.status, json.loads(raw), resp
        except ValueError:
            return resp.status, raw, resp

    def test_binds_loopback_only(self):
        self.assertEqual(self.server.server_address[0], "127.0.0.1")
        self.assertIn("#" + self.token, self.server.url)

    def test_page_served_with_strict_headers_and_no_token_in_html(self):
        status, body, resp = self.call("GET", "/", token=False)
        self.assertEqual(status, 200)
        self.assertIn(b"MaskCode", body)
        self.assertNotIn(self.token.encode(), body)
        self.assertIn("frame-ancestors 'none'", resp.getheader("Content-Security-Policy"))
        self.assertEqual(resp.getheader("Cache-Control"), "no-store")

    def test_api_requires_token(self):
        self.assertEqual(self.call("GET", "/api/status", token=False)[0], 401)
        self.assertEqual(self.call("GET", "/api/status", token="wrong")[0], 401)
        self.assertEqual(self.call("POST", "/api/mask", {"text": "x"}, token=False)[0], 401)

    def test_rejects_foreign_host_and_origin(self):
        self.assertEqual(self.call("GET", "/", token=False, host="evil.example")[0], 403)
        status, _, _ = self.call("POST", "/api/mask", {"text": "a"}, origin="https://evil.example")
        self.assertEqual(status, 401)

    def test_mask_restore_round_trip(self):
        email = "jane.doe" + "@" + "example.com"
        key = "sk-" + "abcdefghijklmnopqrstuv"
        text = "Write to %s, phone +971 50 123 4567, key %s." % (email, key)
        status, masked, _ = self.call("POST", "/api/mask", {"text": text})
        self.assertEqual(status, 200)
        self.assertNotIn(email, masked["masked"])
        self.assertNotIn(key, masked["masked"])
        kinds = {item["kind"] for item in masked["items"]}
        self.assertTrue({"Email", "Phone", "Secret key"} <= kinds)
        reply = "Sure. I emailed " + masked["items"][0]["token"] + " today."
        status, restored, _ = self.call("POST", "/api/restore", {"text": reply})
        self.assertEqual(status, 200)
        self.assertIn(email, restored["restored"])
        self.assertEqual(restored["replaced"], 1)
        self.assertEqual(restored["unknown"], 0)

    def test_reset_forgets_previous_placeholders(self):
        _, masked, _ = self.call("POST", "/api/mask", {"text": "mail a.b" + "@" + "example.org"})
        token = masked["items"][0]["token"]
        self.assertEqual(self.call("POST", "/api/reset", {})[0], 200)
        _, restored, _ = self.call("POST", "/api/restore", {"text": token})
        self.assertEqual(restored["restored"], token)
        self.assertEqual(restored["unknown"], 1)

    def test_private_words_saved_and_applied_case_insensitively(self):
        status, body, _ = self.call("POST", "/api/terms", {"terms": [
            {"value": "Cedar Holdings", "label": "CLIENT"}, {"value": "cedar holdings", "label": "ORG"},
            {"value": "Project Falcon", "label": "PROJECT"}]})
        self.assertEqual(status, 200)
        self.assertEqual(body["terms"], 2)  # duplicate ignored
        data = load_policy_data(self.policy)
        self.assertEqual([t["value"] for t in data["literals"]], ["Cedar Holdings", "Project Falcon"])
        _, masked, _ = self.call("POST", "/api/mask", {"text": "Ask CEDAR HOLDINGS about project falcon"})
        self.assertNotIn("CEDAR", masked["masked"])
        self.assertNotIn("falcon", masked["masked"])
        _, listed, _ = self.call("GET", "/api/terms")
        self.assertEqual(len(listed["terms"]), 2)

    def test_save_terms_keeps_existing_patterns(self):
        self.policy.write_text(json.dumps({"literals": [], "patterns": [{"regex": "CASE-[0-9]{4}", "label": "CASE"}]}),
                               encoding="utf-8")
        save_terms([{"value": "Acme", "label": "ORG"}], self.policy)
        data = json.loads(self.policy.read_text(encoding="utf-8"))
        self.assertEqual(data["patterns"][0]["label"], "CASE")
        self.assertEqual(data["literals"][0]["value"], "Acme")

    def test_invalid_words_rejected_without_writing(self):
        status, body, _ = self.call("POST", "/api/terms", {"terms": [{"value": "  ", "label": "ORG"}]})
        self.assertEqual(status, 400)
        self.assertFalse(self.policy.exists())
        status, _, _ = self.call("POST", "/api/terms", {"terms": [{"value": "x", "label": "bad label"}]})
        self.assertEqual(status, 400)

    def test_broken_policy_file_falls_back_to_builtins(self):
        self.policy.write_text("{not json", encoding="utf-8")
        state = AppState(self.policy)
        self.assertIsNotNone(state.policy_error)
        self.assertIn("PG_EMAIL", state.mask("x" + "@" + "example.com")["masked"])

    def test_scan_reports_labels_without_values(self):
        folder = Path(self.tmp.name) / "proj"
        folder.mkdir()
        secret = "ghp_" + "A" * 30
        (folder / "config.txt").write_text("token=" + secret + "\n", encoding="utf-8")
        (folder / "clean.txt").write_text("hello world\n", encoding="utf-8")
        status, report, _ = self.call("POST", "/api/scan", {"path": str(folder)})
        self.assertEqual(status, 200)
        self.assertEqual(report["scanned_files"], 2)
        self.assertEqual(len(report["findings"]), 1)
        self.assertNotIn(secret, json.dumps(report))

    def test_scan_missing_path_is_friendly(self):
        status, body, _ = self.call("POST", "/api/scan", {"path": str(Path(self.tmp.name) / "nope")})
        self.assertEqual(status, 400)
        self.assertIn("does not exist", body["error"])

    def test_oversized_body_rejected(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.putrequest("POST", "/api/mask", skip_host=True)
        conn.putheader("Host", "127.0.0.1:%d" % self.port)
        conn.putheader("X-MaskCode-Token", self.token)
        conn.putheader("Content-Type", "application/json")
        conn.putheader("Content-Length", str(5 * 1024 * 1024))
        conn.endheaders()
        resp = conn.getresponse()
        self.assertEqual(resp.status, 400)
        conn.close()

    def test_status_reports_tools_and_version(self):
        status, body, _ = self.call("GET", "/api/status")
        self.assertEqual(status, 200)
        self.assertIn("version", body)
        self.assertEqual(set(body["tools"]), {"claude", "codex", "ollama"})


class SuggestionTests(unittest.TestCase):
    def test_suggests_multiword_names_and_skips_greetings(self):
        text = "Hi team,\nPlease reply to Nadia Rahman at Cedar Holdings about Project Falcon on Monday.\nBest Regards"
        self.assertEqual(suggest_names(text), ["Nadia Rahman", "Cedar Holdings", "Project Falcon"])

    def test_ignores_placeholders_and_single_words(self):
        self.assertEqual(suggest_names("Email PG_EMAIL_0123abcd_0001 to Alice today."), [])

    def test_mask_response_includes_suggestions(self):
        state = AppState(Path(tempfile.mkdtemp()) / "p.json")
        self.assertIn("Cedar Holdings", state.mask("Invoice Cedar Holdings now")["suggestions"])


class CliEntryTests(unittest.TestCase):
    def test_app_subcommand_help(self):
        from privacy_gateway.cli import main
        with self.assertRaises(SystemExit) as raised:
            main(["app", "--help"])
        self.assertEqual(raised.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
