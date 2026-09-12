import http.client
import json
import threading
import time
import unittest

from privacy_gateway.redaction import Policy
from privacy_gateway.server import GatewayServer, GatewayState


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.state = GatewayState(policy=Policy.from_dict({"literals": [{"value": "Private Example Ltd", "label": "ORG"}]}), mode="auto")
        self.captured = []
        def fake(path, body, headers):
            self.captured.append((path, body, headers))
            parsed = json.loads(body)
            return 200, "application/json", json.dumps({"type": "message", "content": [
                {"type": "text", "text": parsed["messages"][0]["content"]}]}).encode()
        self.state.transport = fake
        self.server = GatewayServer(self.state)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.path = "/proxy/" + self.state.proxy_token + "/v1/messages"
        self.payload = {"model": "test-model", "max_tokens": 80, "messages": [
            {"role": "user", "content": "Private Example Ltd uses demo@example.com"}]}

    def tearDown(self):
        self.state.close()
        self.server.shutdown()
        self.server.server_close()

    def request(self, path, payload=None, headers=None, method="POST"):
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        actual_headers = {"Content-Type": "application/json", "Authorization": "Bearer synthetic-test-auth"}
        actual_headers.update(headers or {})
        body = json.dumps(payload).encode() if payload is not None else None
        conn.request(method, path, body, actual_headers)
        response = conn.getresponse()
        data = response.read()
        status = response.status
        conn.close()
        try:
            return status, json.loads(data)
        except ValueError:
            return status, data

    def test_masks_wire_and_restores_client_output(self):
        status, data = self.request(self.path + "?beta=true", self.payload, {
            "anthropic-beta": "oauth-2025-04-20,interleaved-thinking-2025-05-14",
            "anthropic-version": "2023-06-01", "Cookie": "private-cookie",
            "X-Custom-Confidential": "Private Example Ltd"})
        self.assertEqual(status, 200)
        path, wire, headers = self.captured[0]
        self.assertNotIn(b"Private Example Ltd", wire)
        self.assertNotIn(b"demo@example.com", wire)
        self.assertEqual(path, "/v1/messages?beta=true")
        self.assertEqual(headers["anthropic-beta"], "oauth-2025-04-20,interleaved-thinking-2025-05-14")
        self.assertEqual(headers["authorization"], "Bearer synthetic-test-auth")
        self.assertNotIn("cookie", headers)
        self.assertNotIn("x-custom-confidential", headers)
        self.assertEqual(data["content"][0]["text"], self.payload["messages"][0]["content"])

    def test_review_required_and_proxy_cannot_approve(self):
        self.state.mode = "review"
        result = []
        worker = threading.Thread(target=lambda: result.append(self.request(self.path, self.payload)))
        worker.start()
        deadline = time.monotonic() + 3
        while not self.state.snapshot()["pending"] and time.monotonic() < deadline:
            time.sleep(.01)
        pending = self.state.snapshot()["pending"]
        self.assertEqual(len(pending), 1)
        self.assertEqual(self.captured, [])
        rid = pending[0]["id"]
        self.assertNotIn("Private Example Ltd", json.dumps(pending))
        denied, _ = self.request("/api/decision", {"id": rid, "decision": "approve"},
                                 {"X-Veil-Token": self.state.proxy_token})
        self.assertEqual(denied, 403)
        self.assertEqual(self.captured, [])
        approved, _ = self.request("/api/decision", {"id": rid, "decision": "approve"},
                                   {"X-Veil-Token": self.state.review_token})
        self.assertEqual(approved, 200)
        worker.join(3)
        self.assertEqual(result[0][0], 200)
        self.assertEqual(len(self.captured), 1)

    def test_accept_is_derived_from_streaming_not_arbitrary_client_headers(self):
        for stream, expected in ((True, "text/event-stream"), (False, "application/json")):
            with self.subTest(stream=stream):
                status, _ = self.request(self.path, {**self.payload, "stream": stream},
                                         {"Accept": "private/should-not-forward"})
                self.assertEqual(status, 200)
                self.assertEqual(self.captured[-1][2]["Accept"], expected)
                self.assertEqual(self.captured[-1][2]["Accept-Encoding"], "identity")

    def test_mime_matching_is_case_insensitive_but_rejects_html_and_lookalikes(self):
        self.state.transport = lambda *_: (200, "Application/JSON; charset=UTF-8", b'{"content":[]}')
        self.assertEqual(self.request(self.path, self.payload)[0], 200)
        for content_type in ("text/html", "application/jsonp", "text/event-stream-fake"):
            with self.subTest(content_type=content_type):
                self.state.transport = lambda *_, kind=content_type: (200, kind, b'{"private":"response-body"}')
                status, output = self.request(self.path, self.payload)
                self.assertEqual(status, 400)
                self.assertNotIn("response-body", json.dumps(output))

    def test_missing_mime_accepts_only_a_complete_expected_codex_stream(self):
        self.state.provider = "codex"
        path = "/proxy/" + self.state.proxy_token + "/responses"
        token = self.state.redactor.redact_text("demo@example.com")
        item = {"type": "message", "id": "msg_test", "role": "assistant", "content": [
            {"type": "output_text", "text": token}]}
        packets = [{"type": "response.created", "response": {"id": "resp_test", "status": "in_progress"}},
                   {"type": "response.completed", "response": {"id": "resp_test", "status": "completed", "output": [item]}}]
        stream = "".join("event: " + packet["type"] + "\ndata: " + json.dumps(packet) + "\n\n"
                         for packet in packets).encode()
        self.state.transport = lambda *_: (200, "", stream)
        payload = {"model": "gpt-6-astra", "input": "Echo demo@example.com", "stream": True}
        status, restored = self.request(path, payload)
        self.assertEqual(status, 200)
        self.assertIn(b"demo@example.com", restored)
        for content_type, body, request in (("text/html", stream, payload), ("", b"<html>secret</html>", payload),
                ("", stream, {**payload, "stream": False}), ("", stream[:stream.rfind(b"event:")], payload)):
            with self.subTest(content_type=content_type, stream=request["stream"]):
                self.state.transport = lambda *_, mime=content_type, data=body: (200, mime, data)
                status, result = self.request(path, request)
                self.assertEqual(status, 400)
                self.assertNotIn("demo@example.com", json.dumps(result))

    def test_review_expiry_sends_nothing(self):
        self.state.mode = "review"
        self.state.review_timeout = .03
        status, _ = self.request(self.path, self.payload)
        self.assertEqual(status, 400)
        self.assertEqual(self.captured, [])
        self.assertFalse(self.state.snapshot()["pending"])

    def test_local_preview_does_not_use_transport(self):
        status, body = self.request("/api/preview", {"text": "preview@example.com"},
                                    {"X-Veil-Token": self.state.review_token})
        self.assertEqual(status, 200)
        self.assertNotIn("preview@example.com", body["text"])
        self.assertEqual(self.captured, [])

    def test_origin_host_route_query_and_credentials_fail_closed(self):
        cases = [
            (self.path, {"Origin": "https://evil.example"}, 403),
            (self.path, {"Host": "evil.example"}, 403),
            (self.path.replace("messages", "files"), {}, 400),
            (self.path + "?private=secret", {}, 400),
            ("/proxy/not-the-capability/v1/messages", {}, 403),
            (self.path, {"Content-Encoding": "gzip"}, 400),
            (self.path, {"Authorization": ""}, 400),
        ]
        for path, headers, expected in cases:
            with self.subTest(path=path, headers=headers):
                self.assertEqual(self.request(path, self.payload, headers)[0], expected)
        self.assertEqual(self.captured, [])

    def test_media_blocks_before_transport(self):
        self.payload["messages"][0]["content"] = [{"type": "image", "source": {
            "type": "base64", "media_type": "image/png", "data": "private"}}]
        status, _ = self.request(self.path, self.payload)
        self.assertEqual(status, 400)
        self.assertEqual(self.captured, [])

    def test_header_is_rechecked_after_body_discovers_short_secret(self):
        self.payload["messages"][0]["content"] = [{"type": "tool_use", "id": "tool_test",
            "name": "Read", "input": {"password": "later_discovered_secret"}}]
        status, _ = self.request(self.path, self.payload, {"anthropic-beta": "later_discovered_secret"})
        self.assertEqual(status, 400)
        self.assertEqual(self.captured, [])

    def test_errors_do_not_echo_upstream(self):
        self.state.transport = lambda *_: (401, "application/json", b'{"secret":"private-response"}')
        status, body = self.request(self.path, self.payload)
        self.assertEqual(status, 401)
        self.assertNotIn("private-response", json.dumps(body))

    def test_transport_exception_not_exposed(self):
        def bad(*_):
            raise RuntimeError("private-exception-content")
        self.state.transport = bad
        status, body = self.request(self.path, self.payload)
        self.assertEqual(status, 502)
        self.assertNotIn("private-exception-content", json.dumps(body))

    def test_console_and_status_require_separate_capability(self):
        status, _ = self.request("/", method="GET")
        self.assertEqual(status, 200)
        self.assertEqual(self.request("/api/status", method="GET")[0], 403)
        status, body = self.request("/api/status", method="GET", headers={"X-Veil-Token": self.state.review_token})
        self.assertEqual(status, 200)
        self.assertNotIn(self.state.proxy_token, json.dumps(body))
        self.assertNotIn(self.state.review_token, json.dumps(body))

    def test_openai_disables_remote_storage(self):
        self.state.provider = "openai"
        self.state.transport = lambda path, body, headers: (self.captured.append(json.loads(body)) or
            (200, "application/json", b'{"output":[]}'))
        status, _ = self.request(self.path.replace("messages", "responses"), {
            "model": "gpt-6-astra", "input": "hello demo@example.com", "store": True})
        self.assertEqual(status, 200)
        self.assertFalse(self.captured[0]["store"])
        self.assertNotIn("demo@example.com", self.captured[0]["input"])


if __name__ == "__main__":
    unittest.main()
