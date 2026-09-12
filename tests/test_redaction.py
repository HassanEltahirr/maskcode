import base64
import concurrent.futures
import json
import re
import tempfile
import unittest
from urllib.parse import quote
from pathlib import Path

from privacy_gateway.redaction import Policy, Redactor, SensitiveValueError


class RedactionTests(unittest.TestCase):
    def test_phone_and_card_heuristics_do_not_corrupt_alphanumeric_protocol_ids(self):
        # Deliberately fabricated UUID with phone-like digit groups.
        ident = "01a01234-5678-4000-a111-000000000000"
        self.assertEqual(Redactor().redact_text(ident), ident)
        self.assertEqual(Redactor().redact_text("x4111111111111111f"), "x4111111111111111f")
        redactor = Redactor(Policy.from_dict({"literals": [{"value": ident, "label": "ID"}]}))
        self.assertNotEqual(redactor.redact_text(ident), ident)
        self.assertNotEqual(Redactor().redact_text('phone="04 123 4567"'), 'phone="04 123 4567"')

    def test_builtin_identities_and_cards(self):
        values = [
            "alice@example.com", "+971 50 123 4567", "050-123-4567",
            "04 123 4567", "+1 (415) 555-2671", "0044 20 7946 0958",
            "784-1990-1234567-1", "192.168.1.32", "4111 1111 1111 1111",
        ]
        for value in values:
            with self.subTest(value=value):
                redactor = Redactor()
                output = redactor.redact_text(value)
                self.assertNotIn(value, output)
                self.assertRegex(output, r"^PG_[A-Z0-9_]+_[0-9a-f]{8}_0001$")
                self.assertEqual(redactor.restore_text(output), value)

    def test_avoid_invalid_ip_card_and_localhost(self):
        value = "127.0.0.1 999.123.45.67 4111 1111 1111 1112 1111111111111111"
        self.assertEqual(Redactor().redact_text(value), value)
        redactor = Redactor(Policy.from_dict({"redact_loopback": True}))
        self.assertNotIn("127.0.0.1", redactor.redact_text("127.0.0.1"))

    def test_secret_formats_and_private_key(self):
        values = [
            "AKIA1234567890ABCDEF", "sk-proj-1234567890abcdefghijklmnop",
            "sk-ant-api03-1234567890abcdefghijklmnop",
            "ghp_1234567890abcdefghijklmnop", "github_pat_1234567890abcdefghijklmnop",
            "xoxb-1234567890-abcdef", "sk_live_1234567890abcdefghij",
            "-----BEGIN RSA PRIVATE KEY-----\nABCDEF\n-----END RSA PRIVATE KEY-----",
            "-----BEGIN PRIVATE KEY-----\nABCDEF\n-----END PRIVATE KEY-----",
        ]
        for value in values:
            with self.subTest(value=value):
                redactor = Redactor()
                output = redactor.redact_text(value)
                self.assertNotIn(value, output)
                self.assertEqual(redactor.restore_text(output), value)

    def test_assignments_preserve_key_and_punctuation(self):
        for value in ['password="hello world"', "api_key='short'", "token=abcdef", '"password": "a\\\"b"']:
            with self.subTest(value=value):
                redactor = Redactor()
                output = redactor.redact_text(value)
                self.assertNotEqual(output, value)
                self.assertTrue(output.startswith(value.split("=")[0]) if "=" in value else output.startswith('"password":'))
                self.assertEqual(redactor.restore_text(output), value)
        redactor = Redactor()
        self.assertTrue(redactor.redact_text("Authorization: Bearer abcdefghijkl").startswith("Authorization: Bearer PG_SECRET_"))
        self.assertTrue(redactor.redact_text("Authorization: Bearer tiny").startswith("Authorization: Bearer PG_SECRET_"))
        url = "https://user:password@example.com"
        hidden_url = redactor.redact_text(url)
        self.assertNotIn("password", hidden_url)
        self.assertEqual(redactor.restore_text(hidden_url), url)

    def test_basic_prose_is_not_mistaken_for_authentication(self):
        redactor = Redactor()
        prose = "simple edits, basic instructions, or information already clear"
        self.assertEqual(redactor.redact_text(prose), prose)
        self.assertEqual(redactor.counts(), {})

    def test_basic_credentials_and_explicit_auth_headers_still_mask(self):
        for value in ("Basic dXNlcjpwYXNz", "basic dTpw", "Authorization: Basic instructions"):
            with self.subTest(value=value):
                redactor = Redactor()
                masked = redactor.redact_text(value)
                self.assertNotEqual(masked, value)
                self.assertIn("PG_SECRET_", masked)
                self.assertEqual(redactor.restore_text(masked), value)

    def test_exact_literals_unicode_and_overlap(self):
        policy = Policy.from_dict({"literals": [
            {"value": "Acme", "label": "ORG"},
            {"value": "Acme Corp", "label": "ORG"},
            {"value": "مريم حسن", "label": "PERSON"},
            {"value": "Acme Corp", "label": "DUPLICATE"},
        ]})
        redactor = Redactor(policy)
        original = "Acme Corp met مريم حسن at Acme."
        output = redactor.redact_text(original)
        self.assertNotIn("Corp", output)
        self.assertNotIn("مريم", output)
        self.assertEqual(redactor.restore_text(output), original)
        self.assertEqual(redactor.counts(), {"ORG": 2, "PERSON": 1})
        self.assertEqual(redactor.redact_text("حسن"), "حسن")

    def test_casefold_literals_preserve_each_exact_spelling(self):
        redactor = Redactor(Policy.from_dict({"literals": [
            {"value": "Straße Holdings", "label": "ORG", "ignore_case": True},
        ]}))
        original = "Straße Holdings / STRASSE HOLDINGS / strasse holdings"
        masked = redactor.redact_text(original)
        self.assertNotIn("Holdings", masked)
        self.assertNotIn("STRASSE", masked)
        self.assertNotIn("strasse", masked)
        self.assertEqual(redactor.restore_text(masked), original)
        self.assertEqual(redactor.counts(), {"ORG": 3})
        self.assertEqual(redactor.redact_text(original), masked)

    def test_existing_policy_stays_case_sensitive(self):
        redactor = Redactor(Policy.from_dict({"literals": [{"value": "Acme", "label": "ORG"}]}))
        self.assertEqual(redactor.redact_text("ACME acme"), "ACME acme")

    def test_normalized_literals_restore_original_unicode(self):
        redactor = Redactor(Policy.from_dict({"literals": [
            {"value": "Café", "label": "PERSON", "normalize": True, "ignore_case": True},
            {"value": "Acme", "label": "ORG", "normalize": True},
        ]}))
        original = "CAFE\u0301 Café Ａｃｍｅ"
        masked = redactor.redact_text(original)
        self.assertNotIn("CAFE", masked)
        self.assertNotIn("Café", masked)
        self.assertNotIn("Ａｃｍｅ", masked)
        self.assertEqual(redactor.restore_text(masked), original)

    def test_encoded_variants_and_embedded_literals_restore_exactly(self):
        redactor = Redactor(Policy.from_dict({"literals": [
            {"value": "Acme / Café", "label": "ORG", "ignore_case": True,
             "normalize": True, "encodings": ["url", "base64"]},
        ]}))
        text = "prefix aCmE / Cafe\u0301 suffix"
        variants = [
            quote(text, safe=""), quote(text, safe="").replace("%20", "+"),
            base64.b64encode(text.encode()).decode(),
            base64.urlsafe_b64encode(text.encode()).decode().rstrip("="),
            "".join("%%%02x" % byte for byte in "Acme / Café".encode()),
            "payload=" + base64.b64encode(text.encode()).decode(),
            base64.b64encode(b"\xff" + text.encode() + b"\x00").decode(),
        ]
        for original in variants:
            with self.subTest(original=original):
                masked = redactor.redact_text(original)
                self.assertNotEqual(masked, original)
                self.assertEqual(redactor.restore_text(masked), original)
                redactor.assert_sanitized(masked)

    def test_encoded_literals_require_explicit_opt_in(self):
        encoded = base64.b64encode(b"Acme Company").decode()
        redactor = Redactor(Policy.from_dict({"literals": [
            {"value": "Acme Company", "label": "ORG"},
        ]}))
        self.assertEqual(redactor.redact_text(encoded), encoded)

    def test_base64_case_is_not_treated_as_case_insensitive(self):
        redactor = Redactor(Policy.from_dict({"literals": [
            {"value": "Acme Company", "label": "ORG", "ignore_case": True, "encodings": ["base64"]},
        ]}))
        encoded = base64.b64encode(b"Acme Company").decode()
        unrelated = encoded.swapcase()
        self.assertEqual(redactor.redact_text(unrelated), unrelated)
        self.assertNotEqual(redactor.redact_text(encoded), encoded)

    def test_oversized_encoded_inspection_fails_closed(self):
        redactor = Redactor(Policy.from_dict({"literals": [
            {"value": "Acme", "label": "ORG", "encodings": ["base64"]},
        ]}))
        with self.assertRaisesRegex(SensitiveValueError, "inspection limit"):
            redactor.redact_text("A" * 65537)

    def test_sensitive_numeric_json_fails_without_changing_types(self):
        for original in ({"password": 1234}, {"card": 4111111111111111},
                         {"data": [784199012345671]}, '{"api_key": 1234}'):
            with self.subTest(original=original), self.assertRaises(SensitiveValueError):
                Redactor().redact_json(original)
        configured = Redactor(Policy.from_dict({"literals": [{"value": "1234", "label": "PIN"}]}))
        with self.assertRaises(SensitiveValueError):
            configured.redact_json({"reference": 1234})
        ordinary = {"max_tokens": 4096, "temperature": 0.7, "stream": True, "unused": None}
        self.assertEqual(Redactor().redact_json(ordinary), ordinary)
        Redactor().assert_sanitized(json.dumps(ordinary))

    def test_foreign_pseudonym_syntax_cannot_hide_configured_secret(self):
        redactor = Redactor(Policy.from_dict({"literals": [{"value": "deadbeef", "label": "ORG"}]}))
        original = "PG_EMAIL_deadbeef_0001"
        masked = redactor.redact_text(original)
        self.assertNotIn("deadbeef", masked)
        self.assertEqual(redactor.restore_text(masked), original)
        token = redactor.redact_json({"password": original})["password"]
        self.assertNotEqual(token, original)

    def test_tokens_restore_when_embedded_in_identifiers_and_filenames(self):
        redactor = Redactor(Policy.from_dict({"literals": [{"value": "Acme", "label": "ORG"}]}))
        for original in ("prefixAcmeSuffix", "Acme_config", "Acme12345", "AcmeAcme"):
            masked = redactor.redact_text(original)
            self.assertNotIn("Acme", masked)
            self.assertEqual(redactor.restore_text(masked), original)
            self.assertEqual(redactor.redact_text(masked), masked)

    def test_residual_check_recognizes_known_secret_and_safe_tokens(self):
        redactor = Redactor(Policy.from_dict({"literals": [
            {"value": "Acme", "label": "ORG", "ignore_case": True, "encodings": ["base64"]},
        ]}))
        masked = redactor.redact_json({"org": "ACME", "password": "tiny"})
        redactor.assert_sanitized(masked)
        redactor.assert_sanitized(json.dumps(masked, indent=2))
        for leaked in ({"org": "aCmE"}, {"message": "tiny"}, {"password": 1234},
                       base64.b64encode(b"prefix Acme suffix").decode()):
            with self.subTest(leaked=leaked), self.assertRaises(SensitiveValueError):
                redactor.assert_sanitized(leaked)

    def test_custom_pattern(self):
        policy = Policy.from_dict({"patterns": [{"regex": r"CLIENT-\d{4}", "label": "CLIENT"}]})
        redactor = Redactor(policy)
        output = redactor.redact_text("CLIENT-1234")
        self.assertTrue(output.startswith("PG_CLIENT_"))
        self.assertEqual(redactor.restore_text(output), "CLIENT-1234")

    def test_mapping_is_stable_protected_and_session_specific(self):
        redactor = Redactor()
        first = redactor.redact_text("alice@example.com")
        self.assertEqual(redactor.redact_text("alice@example.com"), first)
        self.assertEqual(redactor.redact_text(first), first)
        self.assertEqual(redactor.counts(), {"EMAIL": 1})
        self.assertNotEqual(Redactor().redact_text("alice@example.com"), first)
        foreign = "PG_EMAIL_deadbeef_0001"
        self.assertEqual(redactor.redact_text(foreign), foreign)
        self.assertEqual(redactor.restore_text(foreign), foreign)

    def test_nested_json_string_restores_quotes_backslashes_unicode(self):
        secret = 'Secret "quoted" \\ folder/مريم\nnext line'
        org = 'Acme "International" \\ Ltd'
        redactor = Redactor(Policy.from_dict({"literals": [{"value": org, "label": "ORG"}]}))
        arguments = {"password": secret, "company": org, "email": "alice@example.com"}
        original = {"tool_calls": [{"function": {"arguments": json.dumps(arguments, ensure_ascii=True)}}]}
        output = redactor.redact_json(original)
        args = json.loads(output["tool_calls"][0]["function"]["arguments"])
        self.assertNotIn("Secret", str(args))
        self.assertNotIn("Acme", str(args))
        restored = redactor.restore_json(output)
        restored_args = json.loads(restored["tool_calls"][0]["function"]["arguments"])
        self.assertEqual(restored_args, arguments)
        self.assertEqual(original["tool_calls"][0]["function"]["arguments"], json.dumps(arguments, ensure_ascii=True))

    def test_embedded_ambiguous_json_fails_closed(self):
        for original in ('{"password":"first", "password":"second"}', '{"value": NaN}'):
            with self.subTest(original=original):
                with self.assertRaises(SensitiveValueError):
                    Redactor().redact_json(original)
                with self.assertRaises(SensitiveValueError):
                    Redactor().restore_json(original)

    def test_pseudonym_key_collisions_fail_closed(self):
        redactor = Redactor(Policy.from_dict({"literals": [{"value": "Acme", "label": "ORG"}]}))
        token = redactor.redact_text("Acme")
        original = {"Acme": 1, token: 2}
        with self.assertRaises(SensitiveValueError):
            redactor.redact_json(original)
        with self.assertRaises(SensitiveValueError):
            redactor.restore_json(original)

    def test_json_keys_are_redacted_and_restored(self):
        redactor = Redactor()
        original = {"alice@example.com": ["Contact alice@example.com", 42, True, None]}
        output = redactor.redact_json(original)
        self.assertNotIn("alice@example.com", json.dumps(output))
        self.assertEqual(redactor.restore_json(output), original)

    def test_short_credential_and_known_original(self):
        redactor = Redactor()
        result = redactor.redact_json({"api_key": "tiny"})
        token = result["api_key"]
        self.assertTrue(token.startswith("PG_SECRET_"))
        self.assertEqual(redactor.redact_text("key tiny"), "key " + token)
        self.assertEqual(redactor.redact_json(result), result)
        self.assertEqual(redactor.restore_json(result), {"api_key": "tiny"})

    def test_environment_prefixed_credentials(self):
        keys = ["AWS_SECRET_ACCESS_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "DB_PASSWORD", "GITHUB_TOKEN"]
        for key in keys:
            with self.subTest(key=key):
                redactor = Redactor()
                raw = f'{key}="short_secret"'
                output = redactor.redact_text(raw)
                self.assertNotIn("short_secret", output)
                self.assertTrue(output.startswith(key + '="'))
                self.assertEqual(redactor.restore_text(output), raw)
                self.assertNotIn("short_secret", json.dumps(redactor.redact_json({key: "short_secret"})))

    def test_deeply_encoded_json_and_invalid_json_fallback(self):
        redactor = Redactor()
        original = json.dumps({"inner": json.dumps({"email": "a@example.com"})})
        output = redactor.redact_json(original)
        self.assertNotIn("a@example.com", output)
        restored = json.loads(redactor.restore_json(output))
        self.assertEqual(json.loads(restored["inner"]), {"email": "a@example.com"})
        malformed = '{ invalid a@example.com'
        self.assertEqual(redactor.restore_json(redactor.redact_json(malformed)), malformed)

    def test_restoration_token_snapshot_contains_no_originals(self):
        redactor = Redactor()
        self.assertEqual(redactor.restoration_tokens(), ())
        token = redactor.redact_text("alice@example.com")
        snapshot = redactor.restoration_tokens()
        self.assertEqual(snapshot, (token,))
        redactor.redact_text("bob@example.com")
        self.assertEqual(snapshot, (token,))
        self.assertNotIn("example.com", str(redactor.restoration_tokens()))

    def test_parallel_calls_share_one_mapping(self):
        redactor = Redactor()
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(redactor.redact_text, ["a@example.com"] * 100))
        self.assertEqual(len(set(results)), 1)
        self.assertEqual(redactor.counts(), {"EMAIL": 1})

    def test_invalid_policy(self):
        for policy in [
            [], {"unknown": []}, {"literals": "secret"},
            {"literals": [{"value": "", "label": "ORG"}]},
            {"literals": [{"value": "test", "label": "not-valid"}]},
            {"literals": [{"value": "test", "label": "A" * 25}]},
            {"patterns": [{"regex": "[", "label": "ORG"}]},
            {"patterns": [{"regex": ".*", "label": "ORG"}]},
            {"redact_loopback": "false"},
            {"literals": [{"value": "test", "label": "ORG", "ignore_case": "true"}]},
            {"literals": [{"value": "test", "label": "ORG", "normalize": 1}]},
            {"literals": [{"value": "test", "label": "ORG", "encodings": "url"}]},
            {"literals": [{"value": "test", "label": "ORG", "encodings": ["url", "url"]}]},
            {"literals": [{"value": "test", "label": "ORG", "encodings": ["hex"]}]},
            {"literals": [{"value": "test", "label": "ORG", "encodings": [{}]}]},
            {"literals": [{"value": "x" * 16385, "label": "ORG", "encodings": ["base64"]}]},
        ]:
            with self.subTest(policy=policy), self.assertRaises(ValueError):
                Policy.from_dict(policy)

    def test_load_policy_file(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "policy.json"
            path.write_text(json.dumps({"literals": [{"value": "Acme", "label": "ORG"}]}))
            self.assertNotEqual(Redactor(Policy.from_file(path)).redact_text("Acme"), "Acme")
        self.assertEqual(Policy.from_file(None), Policy())


if __name__ == "__main__":
    unittest.main()
