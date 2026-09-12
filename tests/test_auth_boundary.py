"""Synthetic HTTP authentication-channel and approval-boundary regressions."""
import http.client
import json
import threading
import time
import unittest

from privacy_gateway.server import GatewayServer, GatewayState


class AuthenticationBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.state = GatewayState(mode="auto", review_timeout=3)
        self.captured = []

        def fake(path, body, headers):
            self.captured.append((path, json.loads(body), dict(headers)))
            return 200, "application/json", b'{"content":[]}'

        self.state.transport = fake
        self.server = GatewayServer(self.state)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.auth = {"Authorization": "Bearer synthetic-session-auth"}

    def tearDown(self):
        self.state.close()
        self.server.shutdown()
        self.server.server_close()

    def request(self, credentials=None, extra=None, route="/v1/messages"):
        headers = {"Content-Type": "application/json", **(self.auth if credentials is None else credentials)}
        headers.update(extra or {})
        payload = {"model": "synthetic-model", "max_tokens": 1,
                   "messages": [{"role": "user", "content": "Synthetic local test."}]}
        if self.state.provider == "codex":
            payload = {"model": "synthetic-model", "input": "Synthetic local test."}
            route = "/responses"
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        try:
            connection.request("POST", "/proxy/" + self.state.proxy_token + route,
                               json.dumps(payload).encode(), headers)
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()

    def wait_pending(self):
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            pending = self.state.snapshot()["pending"]
            if pending:
                return pending[0]
            time.sleep(.005)
        self.fail("Synthetic request did not reach local review")

    def assert_auth_blocked(self, result, expected_forwarded):
        status, body = result
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["type"], "privacy_gateway_error")
        self.assertEqual(body["error"]["message"], "Provider credentials changed; restart the gateway session")
        self.assertEqual(len(self.captured), expected_forwarded)
        for confidential in ("synthetic-session-auth", "synthetic-changed-secret", "synthetic-extra-key"):
            self.assertNotIn(confidential, json.dumps(body))
        return body["error"]["message"]

    def test_first_and_same_authentication_are_forwarded_unchanged(self):
        self.assertEqual(self.request(route="/v1/messages/count_tokens")[0], 200)
        self.assertEqual(self.request()[0], 200)
        self.assertEqual(len(self.captured), 2)
        for _, _, headers in self.captured:
            self.assertEqual(headers["authorization"], self.auth["Authorization"])

    def test_changed_or_additional_credentials_are_rejected_before_transport(self):
        self.assertEqual(self.request()[0], 200)
        errors = set()
        for auth in ({"Authorization": "Bearer synthetic-changed-secret"},
                     {**self.auth, "X-API-Key": "synthetic-extra-key"},
                     {"X-API-Key": "synthetic-extra-key"}):
            with self.subTest(header_names=sorted(auth)):
                errors.add(self.assert_auth_blocked(self.request(auth), 1))
        self.assertEqual(len(errors), 1, "Credential mismatch errors must use a fixed safe message")
        self.assertEqual(self.request()[0], 200)

    def test_removing_one_initial_credential_is_rejected(self):
        initial = {**self.auth, "X-API-Key": "synthetic-extra-key"}
        self.assertEqual(self.request(initial)[0], 200)
        self.assert_auth_blocked(self.request(self.auth), 1)

    def test_auth_header_name_case_does_not_change_identity(self):
        self.assertEqual(self.request()[0], 200)
        self.assertEqual(self.request({"authorization": self.auth["Authorization"]})[0], 200)
        self.assertEqual(len(self.captured), 2)

    def test_concurrent_first_reviews_cannot_establish_different_credentials(self):
        self.state.mode = "review"
        results = []
        workers = [threading.Thread(target=lambda auth=auth: results.append(self.request(auth)))
                   for auth in (self.auth, {"Authorization": "Bearer synthetic-changed-secret"})]
        for worker in workers:
            worker.start()
        deadline = time.monotonic() + 2
        pending = []
        while time.monotonic() < deadline:
            pending = self.state.snapshot()["pending"]
            if len(pending) == 2:
                break
            time.sleep(.005)
        try:
            self.assertEqual(len(pending), 2)
            for item in pending:
                self.assertTrue(self.state.decision(item["id"], "approve"))
        finally:
            for item in self.state.snapshot()["pending"]:
                self.state.decision(item["id"], "deny")
            for worker in workers:
                worker.join(4)
        self.assertEqual(sorted(status for status, _ in results), [200, 400])
        self.assertEqual(len(self.captured), 1)
        self.assert_auth_blocked(next(result for result in results if result[0] == 400), 1)

    def test_codex_account_identifier_is_bound_with_authentication(self):
        self.state.provider = "codex"
        initial = {**self.auth, "ChatGPT-Account-ID": "synthetic-account-one"}
        self.assertEqual(self.request(initial)[0], 200)
        self.assertEqual(self.request(initial)[0], 200)
        changed = {**self.auth, "ChatGPT-Account-ID": "synthetic-changed-secret"}
        self.assert_auth_blocked(self.request(changed), 2)
        self.assert_auth_blocked(self.request(self.auth), 2)

    def test_review_exposes_nonauth_headers_without_credentials(self):
        self.state.mode = "review"
        result = []
        beta = "synthetic-preview-2026-01-01"
        worker = threading.Thread(target=lambda: result.append(self.request(
            extra={"anthropic-beta": beta, "anthropic-version": "2023-06-01"})))
        worker.start()
        try:
            pending = self.wait_pending()
            snapshot = json.dumps(self.state.snapshot())
            self.assertNotIn(self.auth["Authorization"], snapshot)
            self.assertNotIn("synthetic-session-auth", snapshot)
            self.assertNotIn("authorization", pending["headers"])
            self.assertEqual(pending["headers"]["anthropic-beta"], beta)
            self.assertEqual(pending["headers"]["anthropic-version"], "2023-06-01")
            self.assertEqual(self.captured, [])
            self.assertTrue(self.state.decision(pending["id"], "approve"))
        finally:
            if not result:
                # A failed assertion must not leave a blocked review thread.
                for item in self.state.snapshot()["pending"]:
                    self.state.decision(item["id"], "deny")
            worker.join(4)
        self.assertEqual(result[0][0], 200)
        self.assertEqual(self.captured[0][2]["anthropic-beta"], beta)

    def test_closed_automatic_gateway_cannot_forward(self):
        self.state.close()
        status, body = self.request()
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["message"], "Gateway session is closed")
        self.assertEqual(self.captured, [])
        self.assertEqual(self.state.forwarded, 0)

    def test_closing_pending_review_rejects_without_forwarding(self):
        self.state.mode = "review"
        result = []
        worker = threading.Thread(target=lambda: result.append(self.request()))
        worker.start()
        self.wait_pending()
        self.state.close()
        worker.join(4)
        self.assertFalse(worker.is_alive())
        self.assertEqual(result[0][0], 400)
        self.assertEqual(result[0][1]["error"]["message"], "Gateway session is closed")
        self.assertEqual(self.captured, [])


if __name__ == "__main__":
    unittest.main()
