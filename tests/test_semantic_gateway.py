"""Actual gateway boundary with fake local detection and fake cloud inference."""
import http.client
import base64
import json
import threading
import time
import unittest
from unittest.mock import patch

from privacy_gateway.protocol import readable_fragments, sanitize_payload, PrivacyBlocked
from privacy_gateway.redaction import Redactor, SensitiveValueError
from privacy_gateway.semantic import SemanticScanner
from privacy_gateway.server import GatewayServer, GatewayState


class FakeLocalModel:
    model = "synthetic-local-model"
    isolation_scope = "synthetic test"

    def __init__(self):
        self.calls = []
        self.closed = False
        self.invalid = False

    def generate_json(self, system, text, schema):
        self.calls.append(text)
        if self.invalid:
            return {"entities": [{"value": "invented private value", "label": "PERSON"}]}
        return {"entities": [{"value": value, "label": label} for value, label in [
            ("Mira Zorvan", "PERSON"), ("Taldor Systems", "ORG"), ("مريم حسن", "PERSON")]
            if value in text]}

    def close(self):
        self.closed = True


class SemanticGatewayTests(unittest.TestCase):
    def setUp(self):
        self.runtime = FakeLocalModel()
        self.scanner = SemanticScanner(self.runtime)
        self.state = GatewayState(mode="auto", semantic_scanner=self.scanner, local_runtime=self.runtime)
        self.captured = []
        def cloud(path, body, headers):
            self.captured.append((path, body, headers))
            data = json.loads(body)
            return 200, "application/json", json.dumps({"type": "message", "content": [
                {"type": "text", "text": data["messages"][0]["content"]}]}).encode()
        self.state.transport = cloud
        self.server = GatewayServer(self.state)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.state.close()
        self.server.shutdown()
        self.server.server_close()

    def request(self, text, extra_headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        headers = {"Content-Type": "application/json", "Authorization": "Bearer synthetic-private-auth"}
        headers.update(extra_headers or {})
        connection.request("POST", "/proxy/" + self.state.proxy_token + "/v1/messages",
            body=json.dumps({"model": "test-model", "max_tokens": 100,
                "messages": [{"role": "user", "content": text}]}),
            headers=headers)
        response = connection.getresponse()
        result = response.status, json.loads(response.read())
        connection.close()
        return result

    def test_local_discovery_masks_unconfigured_names_and_restores_exact_reply(self):
        original = 'Mira Zorvan at Taldor Systems writes to مريم حسن: test@example.com'
        status, result = self.request(original)
        self.assertEqual(status, 200)
        self.assertEqual(result["content"][0]["text"], original)
        outgoing = self.captured[0][1]
        for value in ("Mira Zorvan", "Taldor Systems", "مريم حسن", "test@example.com"):
            self.assertNotIn(value, json.dumps(json.loads(outgoing), ensure_ascii=False))
        self.assertIn("PG_PERSON_", outgoing.decode())
        self.assertIn("PG_ORG_", outgoing.decode())
        local_text = "".join(self.runtime.calls)
        self.assertNotIn("test@example.com", local_text)  # Rules run first.
        self.assertNotIn("synthetic-private-auth", local_text)
        self.assertEqual(self.captured[0][2]["authorization"], "Bearer synthetic-private-auth")

    def test_invalid_local_output_blocks_cloud_and_does_not_fall_back(self):
        self.runtime.invalid = True
        status, result = self.request("Mira Zorvan")
        self.assertEqual(status, 400)
        self.assertEqual(self.captured, [])
        self.assertIn("Local privacy scan", json.dumps(result))
        self.assertNotIn("invented private value", json.dumps(result))

    def test_scanner_process_failure_blocks_forwarding(self):
        with patch.object(self.runtime, "generate_json", side_effect=RuntimeError("private exception value")):
            status, result = self.request("Mira Zorvan")
        self.assertEqual(status, 400)
        self.assertEqual(self.captured, [])
        self.assertNotIn("private exception value", json.dumps(result))

    def test_status_contains_counts_without_discovered_values(self):
        self.request("Mira Zorvan")
        status = self.state.snapshot()
        self.assertTrue(status["semantic_scan"]["enabled"])
        self.assertEqual(status["local_model"], self.runtime.model)
        self.assertNotIn("Mira Zorvan", json.dumps(status))
        self.state.close()
        self.assertTrue(self.runtime.closed)

    def test_newly_discovered_value_invalidates_a_waiting_approved_preview(self):
        self.state.mode = "review"
        outcome = []
        with patch.object(self.scanner, "scan", return_value=[]):
            worker = threading.Thread(target=lambda: outcome.append(self.request("Mira Zorvan")))
            worker.start()
            deadline = time.monotonic() + 3
            while not self.state.snapshot()["pending"] and time.monotonic() < deadline:
                time.sleep(.01)
            pending = self.state.snapshot()["pending"]
            self.assertTrue(pending)
            self.state.redactor.protect_literals([("Mira Zorvan", "PERSON")])
            self.state.decision(pending[0]["id"], "approve")
            worker.join(3)
        self.assertEqual(outcome[0][0], 400)
        self.assertEqual(self.captured, [])

    def test_header_discovery_waits_for_the_final_body_check_and_send_lock(self):
        entered, release, contended = threading.Event(), threading.Event(), threading.Event()
        class ObservedLock:
            def __init__(self):
                self.lock = threading.Lock()

            def __enter__(self):
                if not self.lock.acquire(blocking=False):
                    contended.set()
                    self.lock.acquire()
                return self

            def __exit__(self, *_):
                self.lock.release()

        self.state._scan_lock = ObservedLock()
        original_check = self.state.check_credentials
        def check(headers, establish=False):
            original_check(headers, establish)
            if establish:
                entered.set()
                if not release.wait(3):
                    raise RuntimeError("Synthetic test gate timed out")
        self.state.check_credentials = check
        results, errors = {}, []
        def request(label, text, headers=None):
            try:
                results[label] = self.request(text, headers)
            except Exception as exc:
                errors.append(type(exc).__name__)
        first = threading.Thread(target=request, args=("first", "OrionRift"))
        second = threading.Thread(target=request, args=("second", "safe", {"anthropic-beta": "api_key=OrionRift"}))
        first.start()
        try:
            self.assertTrue(entered.wait(3))
            # A is paused after its final revalidation, holding the scan lock.
            # B must wait for that lock before its header can mutate the vault.
            second.start()
            self.assertTrue(contended.wait(1), "Header discovery bypassed the final send lock")
            self.assertEqual(self.state.redactor.redact_text("OrionRift"), "OrionRift")
        finally:
            release.set()
            first.join(3)
            if second.ident is not None:
                second.join(3)
        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(results["first"][0], 200)
        self.assertEqual(results["second"][0], 400)
        self.assertEqual(len(self.captured), 1)
        # The later header learns its value only after A sends. No retroactive
        # sensitivity claim is made about A's already-authorized request.
        self.assertNotEqual(self.state.redactor.redact_text("OrionRift"), "OrionRift")

    def test_semantic_rules_are_reapplied_to_protocol_identifiers(self):
        body = {"model": "Mira Zorvan", "messages": [{"role": "user", "content": "Hello"}]}
        with self.assertRaises(PrivacyBlocked):
            self.state.sanitize(body, set())

    def test_numeric_sensitive_spans_block_instead_of_corrupting_json_types(self):
        body = {"model": "test-model", "messages": [{"role": "user", "content": [
            {"type": "tool_use", "id": "call1", "name": "local", "input": {"budget": 98765}}]}]}
        with patch.object(self.scanner, "scan", return_value=[("98765", "FINANCIAL")]):
            with self.assertRaises(PrivacyBlocked):
                self.state.sanitize(body, set())

    def test_public_protocol_false_positives_do_not_replace_framing_or_disable_rules(self):
        body = {"model": "test-model", "messages": [{"role": "user", "content":
            "Give basic instructions about function descriptions for Mira Zorvan."}]}
        found = [("function", "SENSITIVE"), ("instructions", "SENSITIVE"), ("Mira Zorvan", "PERSON")]
        with patch.object(self.scanner, "scan", return_value=found) as scan:
            clean = self.state.sanitize(body, set(), headers={"Content-Type": "application/json",
                "Accept-Encoding": "identity", "User-Agent": "maskcode/0.7.0",
                "Authorization": "Bearer synthetic-private-auth"})
        self.assertIn("function", clean["messages"][0]["content"])
        self.assertIn("instructions", clean["messages"][0]["content"])
        self.assertNotIn("Mira Zorvan", clean["messages"][0]["content"])
        for value in ("application/json", "identity", "maskcode/0.7.0", "Bearer synthetic-private-auth"):
            self.assertNotIn(value, scan.call_args.args[0])
        # The semantic exception never overrides an explicitly protected term.
        self.state.redactor.protect_literals([("instructions", "SECRET")])
        with self.assertRaises(PrivacyBlocked):
            self.state.sanitize({"model": "test-model", "instructions": "Hello", "input": "Hi"}, set())


class SemanticBoundaryTests(unittest.TestCase):
    def test_projection_omits_fixed_vocabulary_but_keeps_unknown_names_and_values(self):
        payload = {"tools": [{"type": "function", "name": "private_customer_tool", "description": "Mira Zorvan"}],
                   "reasoning": {"effort": "high"}, "parallel_tool_calls": True,
                   "input": "Help with a function for Mira Zorvan"}
        fragments = readable_fragments(payload)
        for value in ("function", "description", "reasoning", "effort", "high", "parallel_tool_calls"):
            self.assertNotIn(value, fragments)
        self.assertIn("private_customer_tool", fragments)
        self.assertIn("Mira Zorvan", fragments)
        self.assertIn("Help with a function for Mira Zorvan", fragments)

    def test_fragments_decode_embedded_json_and_exclude_provider_opaque_blocks(self):
        payload = {"arguments": json.dumps({"client": 'Mira "Z" Zorvan', "budget": 98765}),
                   "content": [{"type": "thinking", "thinking": "opaque-private-value", "signature": "signed"}]}
        fragments = readable_fragments(payload)
        self.assertIn('Mira "Z" Zorvan', fragments)
        self.assertIn("98765", fragments)
        self.assertNotIn("opaque-private-value", fragments)

    def test_discovered_entities_restore_exact_code_without_model_rewriting(self):
        redactor = Redactor()
        redactor.protect_literals([("Mira Zorvan", "PERSON"), ("Taldor Systems", "ORG")])
        original = 'CLIENT = "Mira Zorvan"\nORG = "Taldor Systems"\ndef total(n):\n    return sum(range(n))\n'
        clean = redactor.redact_text(original)
        self.assertNotIn("Mira Zorvan", clean)
        changed = clean.replace("range(n)", "range(n + 1)")
        self.assertEqual(redactor.restore_text(changed), original.replace("range(n)", "range(n + 1)"))
        self.assertEqual(redactor.redact_text(original), clean)

    def test_entity_batch_is_validated_before_mutating_the_vault(self):
        redactor = Redactor()
        with self.assertRaises(SensitiveValueError):
            redactor.protect_literals([("Mira Zorvan", "PERSON"), ("", "ORG")])
        self.assertEqual(redactor.counts(), {})
        with self.assertRaises(SensitiveValueError):
            redactor.protect_literals([("PG_PERSON_deadbeef_0001", "PERSON")])

    def test_learned_entities_also_mask_bounded_url_and_base64_variants(self):
        redactor = Redactor()
        redactor.protect_literals([("Mira Zorvan", "PERSON")])
        encoded = base64.b64encode(b"Mira Zorvan").decode()
        original = "Mira Zorvan ?person=Mira%20Zorvan " + encoded
        clean = redactor.redact_text(original)
        for value in ("Mira Zorvan", "Mira%20Zorvan", encoded):
            self.assertNotIn(value, clean)
        self.assertEqual(redactor.restore_text(clean), original)

    def test_legitimate_project_name_with_pg_prefix_can_be_learned(self):
        redactor = Redactor()
        redactor.protect_literals([("PG_Analytics", "PROJECT")])
        clean = redactor.redact_text("Work on PG_Analytics")
        self.assertNotIn("PG_Analytics", clean)
        self.assertEqual(redactor.restore_text(clean), "Work on PG_Analytics")

    def test_explicit_rules_only_keeps_existing_protocol_behavior(self):
        redactor = Redactor()
        body = {"model": "test-model", "messages": [{"role": "user", "content": "Mira Zorvan test@example.com"}]}
        clean = sanitize_payload(body, redactor, "anthropic")
        self.assertIn("Mira Zorvan", clean["messages"][0]["content"])
        self.assertNotIn("test@example.com", clean["messages"][0]["content"])


if __name__ == "__main__":
    unittest.main()
