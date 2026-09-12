import copy
import json
import unittest

from privacy_gateway.protocol import (PrivacyBlocked, collect_sse_trusted_opaque,
                      collect_trusted_opaque, restore_response, restore_sse,
                      sanitize_payload)
from privacy_gateway.redaction import Policy, Redactor


class FakeRedactor:
    def __init__(self):
        self.secret = 'Amina "Private"\\Name'
        self.token = "__PRIVATE_PERSON_1__"

    def redact_text(self, text):
        return text.replace(self.secret, self.token)

    def restore_text(self, text):
        return text.replace(self.token, self.secret)

    def _walk(self, value, operation):
        if isinstance(value, str):
            return operation(value)
        if isinstance(value, list):
            return [self._walk(item, operation) for item in value]
        if isinstance(value, dict):
            return {operation(key): self._walk(item, operation)
                    for key, item in value.items()}
        return value

    def redact_json(self, value):
        return self._walk(value, self.redact_text)

    def restore_json(self, value):
        return self._walk(value, self.restore_text)

    def assert_sanitized(self, value):
        if self.redact_json(value) != value:
            raise PrivacyBlocked("Residual protected data is blocked.")


def sse(*events):
    return b"".join(b"event: " + event.get("type", "message").encode()
                    + b"\ndata: " + json.dumps(event).encode() + b"\n\n"
                    for event in events)


def sse_json(data):
    return [json.loads(line[6:]) for line in data.decode().splitlines()
            if line.startswith("data: ") and line != "data: [DONE]"]


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.r = FakeRedactor()

    def request(self, content=None):
        return {"model": "claude-test", "messages": [{"role": "user",
                "content": self.r.secret if content is None else content}]}

    def test_redacts_nested_text_and_schema_keys_and_drops_identifiers(self):
        payload = self.request()
        payload["metadata"] = {"user_id": self.r.secret}
        payload["user"] = self.r.secret
        payload["tools"] = [{"name": "local_edit", "description": self.r.secret,
            "input_schema": {"type": "object", "properties": {
                self.r.secret: {"type": "string", "description": self.r.secret}}}}]
        original = copy.deepcopy(payload)
        cleaned = sanitize_payload(payload, self.r, "anthropic")
        self.assertNotIn(self.r.secret, json.dumps(cleaned, ensure_ascii=False))
        self.assertNotIn("metadata", cleaned)
        self.assertNotIn("user", cleaned)
        self.assertIn(self.r.token, cleaned["tools"][0]["input_schema"]["properties"])
        self.assertEqual(payload, original)

    def test_redacts_serialized_arguments_with_quoted_original(self):
        payload = {"model": "openai-test", "input": [{"type": "function_call",
            "call_id": "call_1", "name": "local_edit",
            "arguments": json.dumps({"name": self.r.secret})}]}
        clean = sanitize_payload(payload, self.r, "openai")
        self.assertEqual(json.loads(clean["input"][0]["arguments"]), {"name": self.r.token})

    def test_client_tracking_metadata_is_removed_before_secret_discovery(self):
        from privacy_gateway.redaction import Redactor
        redactor = Redactor()
        payload = {"model": "openai-test", "input": "Hello",
                   "client_metadata": {"x-codex-turn-metadata": json.dumps({
                       "started_at": 4222222222222, "password": "synthetic-tracking-only"})}}
        # A 13-digit timestamp can coincidentally satisfy a card heuristic.
        # Tracking metadata has no task role and never reaches either detector
        # or provider; confidential numeric task data remains blocked.
        clean = sanitize_payload(payload, redactor, "openai")
        self.assertEqual(clean, {"model": "openai-test", "input": "Hello"})
        self.assertEqual(redactor.counts(), {})

    def test_instructions_field_survives_basic_prose_and_blocks_key_substitution(self):
        payload = {"model": "openai-test", "instructions": "Give basic instructions.", "input": "Hi"}
        self.assertEqual(sanitize_payload(payload, Redactor(), "openai"), payload)
        protected = Redactor(Policy.from_dict({"literals": [{"value": "instructions", "label": "SECRET"}]}))
        with self.assertRaises(PrivacyBlocked):
            sanitize_payload(payload, protected, "openai")

    def test_protected_protocol_values_block_without_echoing_secret(self):
        for key in ("model",):
            payload = self.request()
            payload[key] = self.r.secret
            with self.assertRaises(PrivacyBlocked) as caught:
                sanitize_payload(payload, self.r, "anthropic")
            self.assertNotIn(self.r.secret, str(caught.exception))
        payload = self.request()
        payload["tools"] = [{"name": self.r.secret, "input_schema": {"type": "object"}}]
        with self.assertRaises(PrivacyBlocked):
            sanitize_payload(payload, self.r, "anthropic")

    def test_media_hosted_tools_unknown_blocks_and_remote_state_are_blocked(self):
        variants = [
            self.request([{"type": "image", "source": {"type": "base64", "data": "AAAA"}}]),
            self.request([{"type": "document", "source": {"type": "url", "url": "https://example.com"}}]),
            self.request([{"type": "new_unreviewed_content", "data": "opaque"}]),
            {"model": "test", "input": [{"type": "item_reference", "id": "item_1"}]},
            {"model": "test", "input": "hi", "tools": [{"type": "web_search"}]},
            {"model": "test", "input": "hi", "previous_response_id": "resp_1"},
            {"model": "test", "input": "hi", "encrypted_content": "opaque"},
        ]
        for payload in variants:
            with self.subTest(payload=payload), self.assertRaises(PrivacyBlocked):
                sanitize_payload(payload, self.r, "openai")

    def test_plain_text_urls_and_custom_functions_allowed(self):
        payload = {"model": "test", "input": "Read https://example.com/docs",
                   "tools": [{"type": "function", "name": "local_edit",
                              "parameters": {"type": "object"}}]}
        self.assertEqual(sanitize_payload(payload, self.r, "openai"), payload)

    def test_only_exact_trusted_reasoning_can_replay(self):
        block = {"type": "thinking", "thinking": self.r.token, "signature": "provider-signature"}
        payload = self.request([block])
        with self.assertRaises(PrivacyBlocked):
            sanitize_payload(payload, self.r, "anthropic")
        trusted = collect_trusted_opaque({"content": [block]})
        clean = sanitize_payload(payload, self.r, "anthropic", trusted)
        self.assertEqual(clean["messages"][0]["content"][0], block)
        altered = copy.deepcopy(payload)
        altered["messages"][0]["content"][0]["thinking"] = self.r.secret
        with self.assertRaises(PrivacyBlocked):
            sanitize_payload(altered, self.r, "anthropic", trusted)

    def test_openai_encrypted_reasoning_provenance(self):
        block = {"type": "reasoning", "id": "reason_1", "summary": [],
                 "encrypted_content": "opaque"}
        payload = {"model": "test", "input": [block]}
        with self.assertRaises(PrivacyBlocked):
            sanitize_payload(payload, self.r, "openai")
        self.assertEqual(sanitize_payload(payload, self.r, "openai",
                         collect_trusted_opaque(block)), payload)

    def test_restore_json_preserves_thinking_and_ids(self):
        payload = {"id": self.r.token, "content": [
            {"type": "thinking", "thinking": self.r.token, "signature": self.r.token},
            {"type": "text", "text": self.r.token},
            {"type": "tool_use", "id": "tool_1", "name": "edit",
             "input": {self.r.token: self.r.token}}]}
        restored = restore_response(payload, self.r)
        self.assertEqual(restored["id"], self.r.token)
        self.assertEqual(restored["content"][0], payload["content"][0])
        self.assertEqual(restored["content"][1]["text"], self.r.secret)
        self.assertEqual(restored["content"][2]["input"], {self.r.secret: self.r.secret})

    def test_anthropic_text_and_json_cross_chunk_restoration(self):
        args = json.dumps({"name": self.r.token})
        raw = sse(
            {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}},
            {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": self.r.token[:8]}},
            {"type": "ping"},
            {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": self.r.token[8:]}},
            {"type": "content_block_stop", "index": 0},
            {"type": "content_block_start", "index": 1, "content_block": {"type": "tool_use", "id": "tool_1", "name": "edit", "input": {}}},
            {"type": "content_block_delta", "index": 1, "delta": {"type": "input_json_delta", "partial_json": args[:18]}},
            {"type": "content_block_delta", "index": 1, "delta": {"type": "input_json_delta", "partial_json": args[18:]}},
            {"type": "content_block_stop", "index": 1})
        output = sse_json(restore_sse(raw, self.r, "anthropic"))
        text = "".join(event.get("delta", {}).get("text", "") for event in output)
        arguments = "".join(event.get("delta", {}).get("partial_json", "") for event in output)
        self.assertEqual(text, self.r.secret)
        self.assertEqual(json.loads(arguments), {"name": self.r.secret})
        self.assertEqual([e["type"] for e in output], [e["type"] for e in sse_json(raw)])

    def test_sse_thinking_unchanged_and_complete_provenance(self):
        raw = sse(
            {"type": "content_block_start", "index": 0, "content_block": {"type": "thinking", "thinking": "", "signature": ""}},
            {"type": "content_block_delta", "index": 0, "delta": {"type": "thinking_delta", "thinking": self.r.token}},
            {"type": "content_block_delta", "index": 0, "delta": {"type": "signature_delta", "signature": "sig"}},
            {"type": "content_block_stop", "index": 0})
        self.assertEqual(sse_json(restore_sse(raw, self.r, "anthropic")), sse_json(raw))
        block = {"type": "thinking", "thinking": self.r.token, "signature": "sig"}
        trusted = collect_sse_trusted_opaque(raw, "anthropic")
        self.assertEqual(trusted, collect_trusted_opaque(block))
        self.assertEqual(sanitize_payload(self.request([block]), self.r, "anthropic", trusted), self.request([block]))
        partial = raw[:raw.rfind(b"event: content_block_stop")]
        self.assertFalse(collect_sse_trusted_opaque(partial, "anthropic"))

    def test_openai_responses_deltas_and_completed_copies(self):
        arguments = json.dumps({"name": self.r.token})
        raw = sse(
            {"type": "response.output_text.delta", "item_id": "msg_1", "content_index": 0, "delta": self.r.token[:5]},
            {"type": "response.output_text.delta", "item_id": "msg_1", "content_index": 0, "delta": self.r.token[5:]},
            {"type": "response.function_call_arguments.delta", "item_id": "fc_1", "delta": arguments[:15]},
            {"type": "response.function_call_arguments.delta", "item_id": "fc_1", "delta": arguments[15:]},
            {"type": "response.function_call_arguments.done", "item_id": "fc_1", "arguments": arguments},
            {"type": "response.completed", "response": {"output": [
                {"type": "message", "content": [{"type": "output_text", "text": self.r.token}]},
                {"type": "function_call", "name": "edit", "arguments": arguments}]}})
        output = sse_json(restore_sse(raw, self.r, "openai"))
        self.assertEqual(output[0]["delta"] + output[1]["delta"], self.r.secret)
        self.assertEqual(json.loads(output[2]["delta"] + output[3]["delta"]), {"name": self.r.secret})
        self.assertEqual(json.loads(output[4]["arguments"]), {"name": self.r.secret})
        self.assertEqual(output[5]["response"]["output"][0]["content"][0]["text"], self.r.secret)

    def test_chat_completions_partial_arguments_and_done_marker(self):
        arguments = json.dumps({"name": self.r.token})
        chunks = [{"object": "chat.completion.chunk", "choices": [{"index": 0,
            "delta": {"tool_calls": [{"index": 0, "function": {"arguments": part}}]}}]}
            for part in (arguments[:10], arguments[10:])]
        raw = sse(*chunks) + b": keepalive\n\ndata: [DONE]\n\n"
        restored = restore_sse(raw, self.r, "openai")
        output = sse_json(restored)
        joined = "".join(event["choices"][0]["delta"]["tool_calls"][0]["function"]["arguments"] for event in output)
        self.assertEqual(json.loads(joined), {"name": self.r.secret})
        self.assertIn(b": keepalive", restored)
        self.assertIn(b"data: [DONE]", restored)

    def test_bad_stream_and_incomplete_arguments_fail_closed(self):
        for raw in (b"data: {oops}\n\n", b"data: \xff\n\n",
                    sse({"type": "response.function_call_arguments.delta", "delta": '{"name":'})):
            with self.subTest(raw=raw), self.assertRaises(PrivacyBlocked):
                restore_sse(raw, self.r, "openai")

    def test_real_redactor_masks_short_credentials_and_embedded_json(self):
        secret = 'Noura "Private"\\مريم'
        r = Redactor(Policy.from_dict({"literals": [{"value": secret, "label": "PERSON"}]}))
        data = {"password": "p@ss", "name": secret}
        payload = self.request([{"type": "tool_use", "id": "tool_1", "name": "edit",
            "input": {"password": "p@ss", "nested_json": json.dumps(data)}}])
        clean = sanitize_payload(payload, r, "anthropic")
        item = clean["messages"][0]["content"][0]["input"]
        self.assertNotEqual(item["password"], "p@ss")
        self.assertNotEqual(json.loads(item["nested_json"])["name"], secret)
        self.assertNotEqual(json.loads(item["nested_json"])["password"], "p@ss")
        self.assertEqual(r.restore_json(item), {"password": "p@ss", "nested_json": json.dumps(data, ensure_ascii=False)})
        self.assertEqual(sanitize_payload(clean, r, "anthropic"), clean)

    def test_real_redactor_blocks_known_original_in_protocol_identity(self):
        r = Redactor()
        r.redact_json({"password": "dangerous-short"})
        with self.assertRaises(PrivacyBlocked):
            sanitize_payload({"model": "dangerous-short", "input": "hello"}, r, "openai")

    def test_executable_restoration_blocked_but_file_data_is_safe(self):
        for name, argument in (("Bash", {"command": self.r.token}),
                               ("edit", {"nested": {"script": self.r.token}}),
                               ("python", {"source": self.r.token})):
            with self.subTest(name=name), self.assertRaises(PrivacyBlocked):
                restore_response({"type": "tool_use", "name": name, "input": argument}, self.r)
        good = {"type": "tool_use", "name": "Edit", "input": {
            "file_path": "/tmp/" + self.r.token + ".txt", "content": self.r.token}}
        self.assertEqual(restore_response(good, self.r)["input"]["content"], self.r.secret)

    def test_sse_named_executable_arguments_blocked_even_unusual_field(self):
        args = json.dumps({"source": self.r.token})
        raw = sse(
            {"type": "response.output_item.added", "output_index": 0,
             "item": {"id": "fc_1", "type": "function_call", "name": "python", "arguments": ""}},
            {"type": "response.function_call_arguments.delta", "item_id": "fc_1", "delta": args[:12]},
            {"type": "response.function_call_arguments.delta", "item_id": "fc_1", "delta": args[12:]})
        with self.assertRaises(PrivacyBlocked):
            restore_sse(raw, self.r, "openai")


if __name__ == "__main__":
    unittest.main()
