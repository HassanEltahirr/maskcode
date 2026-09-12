"""Synthetic adversarial checks. Transport is mocked; no provider calls occur."""
import copy
import http.client
import json
import threading
import time
import unittest

from privacy_gateway.protocol import PrivacyBlocked, restore_response, restore_sse, sanitize_payload
from privacy_gateway.redaction import Policy, Redactor
from privacy_gateway.server import GatewayServer, GatewayState


def synthetic_sse(*events):
    return b"".join(b"data: " + json.dumps(event).encode() + b"\n\n" for event in events)


class CredentialDiscoveryOrderTests(unittest.TestCase):
    def test_numeric_credentials_and_payment_identifiers_never_forward(self):
        for data in ({"password": 91827}, {"card": 4111111111111111},
                     {"nested": [784199012345671]}, {"secret": 31.25}):
            with self.subTest(data=data), self.assertRaises(PrivacyBlocked):
                sanitize_payload({"model": "synthetic", "max_tokens": 64, "messages": [
                    {"role": "assistant", "content": [{"type": "tool_use", "id": "test",
                      "name": "Edit", "input": data}]}]}, Redactor(), "anthropic")

    def test_regular_protocol_numeric_settings_remain_numeric(self):
        payload = {"model": "synthetic", "max_tokens": 128, "temperature": .5,
                   "stream": True, "messages": [{"role": "user", "content": "hello"}]}
        self.assertEqual(sanitize_payload(payload, Redactor(), "anthropic"), payload)

    def test_residual_known_secret_fails_closed_if_a_masking_pass_misses_it(self):
        class BrokenRedactor(Redactor):
            def redact_json(self, value):
                return value
        r = BrokenRedactor(Policy.from_dict({"literals": [{"value": "Synthetic Confidential", "label": "ORG"}]}))
        with self.assertRaises(PrivacyBlocked):
            sanitize_payload({"model": "synthetic", "messages": [
                {"role": "user", "content": "Synthetic Confidential"}]}, r, "anthropic")

    def test_text_hides_mentions_before_credential_assignment(self):
        redactor = Redactor()
        original = "Mention short_secret first, then password=short_secret"
        cleaned = redactor.redact_text(original)
        self.assertNotIn("short_secret", cleaned)
        self.assertEqual(redactor.restore_text(cleaned), original)

    def test_json_hides_mentions_before_credential_definition(self):
        redactor = Redactor()
        original = {"summary": "short_secret", "password": "short_secret"}
        cleaned = redactor.redact_json(original)
        self.assertNotIn("short_secret", json.dumps(cleaned))
        self.assertEqual(cleaned["summary"], cleaned["password"])
        self.assertEqual(redactor.restore_json(cleaned), original)

    def test_protocol_hides_earlier_mentions_in_other_message(self):
        redactor = Redactor()
        original = {"model": "synthetic-model", "messages": [
            {"role": "user", "content": "short_secret"},
            {"role": "assistant", "content": [{"type": "tool_use", "name": "Edit",
                "id": "tool_test", "input": {"password": "short_secret"}}]},
        ]}
        cleaned = sanitize_payload(original, redactor, "anthropic")
        self.assertNotIn("short_secret", json.dumps(cleaned))

    def test_protocol_identifiers_checked_after_secret_discovery(self):
        original = {"model": "short_secret", "messages": [
            {"role": "assistant", "content": [{"type": "tool_use", "name": "Edit",
                "id": "tool_test", "input": {"password": "short_secret"}}]},
        ]}
        with self.assertRaises(PrivacyBlocked):
            sanitize_payload(original, Redactor(), "anthropic")


class ExecutableRestorationTests(unittest.TestCase):
    def setUp(self):
        # The value is only inert test data. No shell or interpreter executes it.
        self.original = "Company' ; echo SYNTHETIC_MARKER ; echo '"
        self.r = Redactor(Policy.from_dict({"literals": [{"value": self.original, "label": "ORG"}]}))
        self.token = self.r.redact_text(self.original)

    def test_executable_fields_reject_substitutions(self):
        for field in ("command", "cmd", "code", "script"):
            with self.subTest(field=field), self.assertRaises(PrivacyBlocked):
                restore_response({"content": [{"type": "tool_use", "name": "local_tool",
                    "input": {field: "printf '%s' '" + self.token + "'"}}]}, self.r)

    def test_executable_tool_names_reject_substitutions(self):
        for name in ("Bash", "shell", "exec_command", "python"):
            with self.subTest(name=name), self.assertRaises(PrivacyBlocked):
                restore_response({"content": [{"type": "tool_use", "name": name,
                    "input": {"text": self.token}}]}, self.r)

    def test_openai_executable_arguments_are_blocked(self):
        with self.assertRaises(PrivacyBlocked):
            restore_response({"output": [{"type": "function_call", "name": "exec_command",
                "arguments": json.dumps({"command": "echo '" + self.token + "'"})}]}, self.r, "openai")

    def test_anthropic_executable_sse_is_blocked_across_chunks(self):
        arguments = json.dumps({"command": "echo '" + self.token + "'"})
        raw = synthetic_sse(
            {"type": "content_block_start", "index": 0, "content_block": {
                "type": "tool_use", "name": "Bash", "id": "tool_test", "input": {}}},
            {"type": "content_block_delta", "index": 0, "delta": {
                "type": "input_json_delta", "partial_json": arguments[:25]}},
            {"type": "content_block_delta", "index": 0, "delta": {
                "type": "input_json_delta", "partial_json": arguments[25:]}},
            {"type": "content_block_stop", "index": 0},
        )
        with self.assertRaises(PrivacyBlocked):
            restore_sse(raw, self.r, "anthropic")

    def test_structured_file_arguments_and_display_text_restore(self):
        raw = {"content": [
            {"type": "text", "text": self.token},
            {"type": "tool_use", "name": "Write", "id": "tool_test", "input": {
                "path": "/synthetic/" + self.token + ".txt", "content": self.token}},
        ]}
        restored = restore_response(raw, self.r)
        self.assertEqual(restored["content"][0]["text"], self.original)
        self.assertEqual(restored["content"][1]["input"]["content"], self.original)
        self.assertEqual(restored["content"][1]["input"]["path"], "/synthetic/" + self.original + ".txt")
        self.assertEqual(raw["content"][0]["text"], self.token)

    def test_executable_arguments_without_substitution_stay_unchanged(self):
        raw = {"content": [{"type": "tool_use", "name": "Bash", "input": {"command": "pwd"}}]}
        self.assertEqual(restore_response(raw, self.r), raw)


class WireReviewSecurityTests(unittest.TestCase):
    def setUp(self):
        self.confidential = 'Synthetic "Confidential" Company'
        self.state = GatewayState("anthropic", Policy.from_dict({"literals": [
            {"value": self.confidential, "label": "ORG"}]}), mode="review", review_timeout=3)
        self.captured = []

        def transport(path, body, headers):
            self.captured.append((path, body, headers))
            return 200, "application/json", b'{"content":[]}'

        self.state.transport = transport
        self.server = GatewayServer(self.state)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.state.close()
        self.server.shutdown()
        self.server.server_close()

    def request(self, path, payload, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        actual = {"Content-Type": "application/json", "Authorization": "Bearer synthetic_auth"}
        actual.update(headers or {})
        connection.request("POST", path, json.dumps(payload).encode(), actual)
        response = connection.getresponse()
        status, data = response.status, response.read()
        connection.close()
        return status, json.loads(data)

    def test_approval_forwards_exact_reviewed_json_object(self):
        original = {"model": "synthetic-test", "max_tokens": 1,
                    "messages": [{"role": "user", "content": self.confidential + " person@example.com"}]}
        result = []
        worker = threading.Thread(target=lambda: result.append(self.request(
            "/proxy/" + self.state.proxy_token + "/v1/messages", original)))
        worker.start()
        deadline = time.monotonic() + 2
        pending = []
        while time.monotonic() < deadline:
            pending = self.state.snapshot()["pending"]
            if pending:
                break
            time.sleep(.005)
        self.assertEqual(len(pending), 1)
        preview = copy.deepcopy(pending[0]["preview"])
        self.assertEqual(self.captured, [])
        self.assertNotIn(self.confidential, json.dumps(preview))
        status, _ = self.request("/api/decision", {"id": pending[0]["id"], "decision": "approve"},
                                 {"X-Veil-Token": self.state.review_token})
        self.assertEqual(status, 200)
        worker.join(4)
        self.assertEqual(result[0][0], 200)
        self.assertEqual(json.loads(self.captured[0][1]), preview)
        self.assertNotIn(self.state.proxy_token, str(self.captured[0][2]))
        self.assertNotIn(self.state.review_token, str(self.captured[0][2]))

    def test_correct_review_token_with_foreign_origin_is_rejected(self):
        status, _ = self.request("/api/preview", {"text": "synthetic"}, {
            "X-Veil-Token": self.state.review_token, "Origin": "https://foreign.example"})
        self.assertEqual(status, 403)
        self.assertEqual(self.captured, [])

    def test_preview_includes_active_gateway_policy(self):
        status, data = self.request("/api/preview", {"text": self.confidential, "literals": []},
                                    {"X-Veil-Token": self.state.review_token})
        self.assertEqual(status, 200)
        self.assertNotIn(self.confidential, data["text"])
        self.assertEqual(self.captured, [])


if __name__ == "__main__":
    unittest.main()
