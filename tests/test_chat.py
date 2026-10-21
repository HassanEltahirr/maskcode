"""Chat: the provider only ever receives masked text; replies are restored locally."""
import http.client
import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from privacy_gateway.app import AppServer, AppState, save_terms
from privacy_gateway.chat import load_settings, public_settings, safe_prefix, save_settings

EMAIL = "nadia.rahman" + "@" + "cedar.example"


class FakeProvider(BaseHTTPRequestHandler):
    seen = []

    def log_message(self, *a):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        FakeProvider.seen.append({"path": self.path, "auth": self.headers.get("Authorization"), "body": body})
        last = body["messages"][-1]["content"]
        token = next(w.strip(".,()") for w in last.split() if w.startswith("PG_"))
        reply = "Sure, I will email " + token + " today."
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        # split the placeholder across chunks to exercise safe streaming
        for piece in (reply[:22], reply[22:30], reply[30:]):
            chunk = {"choices": [{"delta": {"content": piece}}]}
            self.wfile.write(("data: " + json.dumps(chunk) + "\n\n").encode())
            self.wfile.flush()
        self.wfile.write(b"data: [DONE]\n\n")


class ChatTests(unittest.TestCase):
    def setUp(self):
        FakeProvider.seen = []
        self.tmp = Path(tempfile.mkdtemp())
        self.provider = ThreadingHTTPServer(("127.0.0.1", 0), FakeProvider)
        threading.Thread(target=self.provider.serve_forever, daemon=True).start()
        save_settings(self.tmp, {"provider": "custom", "base_url": "http://127.0.0.1:%d/v1" % self.provider.server_port,
                                 "model": "fake-model", "api_key": "test-key-123"})
        save_terms([{"value": "Cedar Holdings", "label": "TERM"}], self.tmp / "policy.json")
        self.app = AppServer(AppState(self.tmp / "policy.json", self.tmp))
        threading.Thread(target=self.app.serve_forever, daemon=True).start()

    def tearDown(self):
        for s in (self.app, self.provider):
            s.shutdown()
            s.server_close()

    def chat(self, text, chat="c1"):
        conn = http.client.HTTPConnection("127.0.0.1", self.app.server_port, timeout=10)
        conn.request("POST", "/api/chat", body=json.dumps({"chat": chat, "text": text}), headers={
            "Host": "127.0.0.1:%d" % self.app.server_port, "Content-Type": "application/json",
            "X-MaskCode-Token": self.app.state.token})
        resp = conn.getresponse()
        events = [json.loads(line) for line in resp.read().decode().splitlines() if line]
        return resp.status, events

    def test_provider_sees_only_masked_text_and_reply_is_restored(self):
        status, events = self.chat("Write to " + EMAIL + " at Cedar Holdings")
        self.assertEqual(status, 200)
        sent = json.dumps(FakeProvider.seen[0]["body"])
        self.assertNotIn(EMAIL, sent)
        self.assertNotIn("Cedar Holdings", sent)
        self.assertEqual(FakeProvider.seen[0]["auth"], "Bearer test-key-123")
        masked = events[0]
        self.assertEqual(masked["type"], "masked")
        self.assertIn("PG_EMAIL_", masked["masked"])
        reply = "".join(e["text"] for e in events if e["type"] == "delta")
        self.assertEqual(reply, "Sure, I will email " + EMAIL + " today.")
        done = events[-1]
        self.assertEqual(done["type"], "done")
        self.assertIn("PG_EMAIL_", done["masked_reply"])

    def test_history_stays_masked_on_follow_up(self):
        self.chat("Email " + EMAIL)
        self.chat("Remind " + EMAIL + " again")
        second = FakeProvider.seen[1]["body"]["messages"]
        self.assertEqual([m["role"] for m in second], ["system", "user", "assistant", "user"])
        self.assertNotIn(EMAIL, json.dumps(second))

    def test_chat_requires_key(self):
        save_settings(self.tmp, {"provider": "openai", "api_key": "", "model": "gpt-4o-mini"})
        import os
        os.environ.pop("OPENAI_API_KEY", None)
        status, _ = self._raw_chat()
        self.assertEqual(status, 400)

    def _raw_chat(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.app.server_port, timeout=10)
        conn.request("POST", "/api/chat", body=json.dumps({"chat": "x", "text": "hi"}), headers={
            "Host": "127.0.0.1:%d" % self.app.server_port, "Content-Type": "application/json",
            "X-MaskCode-Token": self.app.state.token})
        r = conn.getresponse()
        r.read()
        return r.status, None

    def test_settings_never_expose_key(self):
        pub = public_settings(load_settings(self.tmp))
        self.assertNotIn("api_key", pub)
        self.assertTrue(pub["has_key"])
        self.assertNotIn("test-key-123", json.dumps(pub))

    def test_settings_reject_plain_http_for_remote_hosts(self):
        with self.assertRaises(ValueError):
            save_settings(self.tmp, {"provider": "custom", "base_url": "http://example.com/v1", "model": "m", "api_key": "k"})

    def test_safe_prefix_holds_partial_placeholders(self):
        self.assertEqual(safe_prefix("hello PG_EMA"), "hello ")
        self.assertEqual(safe_prefix("hello P"), "hello ")
        self.assertEqual(safe_prefix("a PG_EMAIL_1a2b3c4d_0001 b"), "a PG_EMAIL_1a2b3c4d_0001 b")


if __name__ == "__main__":
    unittest.main()
