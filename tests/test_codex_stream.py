import json
import unittest
from unittest.mock import patch

from privacy_gateway import codex_stream
from privacy_gateway.codex_stream import validate_codex_sse
from privacy_gateway.protocol import PrivacyBlocked


def frame(payload, *, event=True):
    prefix = ("event: " + payload["type"] + "\n") if event else ""
    return (prefix + "data: " + json.dumps(payload, ensure_ascii=False) + "\n\n").encode("utf-8")


def complete(**changes):
    return {"type": "response.completed", "response": {"id": "resp_1", "status": "completed",
            "error": None, "output": [], **changes}}


class CodexStreamTests(unittest.TestCase):
    def test_normal_responses_text_reasoning_and_custom_tool_lifecycle(self):
        item = {"id": "ct_1", "type": "custom_tool_call", "name": "apply_patch", "input": ""}
        payloads = [
            {"type": "response.created", "response": {"id": "resp_1", "status": "in_progress", "error": None}},
            {"type": "codex.rate_limits", "rate_limits": {"primary": {"used_percent": 1.25, "resets_at": 1234}, "plan_type": "pro"}},
            {"type": "response.in_progress", "response": {"id": "resp_1", "status": "in_progress"}},
            {"type": "response.reasoning_summary_part.added", "item_id": "rs_1", "part": {"type": "summary_text", "text": ""}},
            {"type": "response.reasoning_summary_text.delta", "item_id": "rs_1", "delta": "A brief plan"},
            {"type": "response.reasoning_summary_text.done", "item_id": "rs_1", "text": "A brief plan"},
            {"type": "response.reasoning_summary_part.done", "item_id": "rs_1", "part": {"type": "summary_text", "text": "A brief plan"}},
            {"type": "response.output_item.added", "item": item},
            {"type": "response.custom_tool_call_input.delta", "item_id": "ct_1", "delta": "*** Begin Patch\n"},
            {"type": "response.custom_tool_call_input.done", "item_id": "ct_1", "input": "*** Begin Patch\n*** Delete File: x\n*** End Patch"},
            {"type": "response.output_item.done", "item": {**item, "input": "*** Begin Patch\n*** Delete File: x\n*** End Patch"}},
            {"type": "response.content_part.added", "part": {"type": "output_text", "text": ""}},
            {"type": "response.output_text.delta", "delta": "مرحبا"},
            {"type": "response.output_text.annotation.added", "annotation": {"type": "url_citation", "url": "https://example.com", "title": "Synthetic source"}},
            {"type": "response.output_text.done", "text": "مرحبا"},
            {"type": "response.content_part.done", "part": {"type": "output_text", "text": "مرحبا"}},
            complete(),
        ]
        self.assertIsNone(validate_codex_sse(b"".join(frame(item) for item in payloads)))

    def test_bom_crlf_comments_safe_id_retry_and_final_done_are_supported(self):
        data = (b": keepalive\n\nid: resp_1\nretry: 1000\n" + frame(complete())
                + b": final heartbeat\n\ndata: [DONE]\n\n: harmless final comment")
        self.assertIsNone(validate_codex_sse(b"\xef\xbb\xbf" + data.replace(b"\n", b"\r\n")))

    def test_event_field_is_optional_and_pretty_multiline_json_is_valid(self):
        body = json.dumps(complete(), indent=2)
        data = "\n".join("data: " + line for line in body.splitlines()) + "\n\n"
        self.assertIsNone(validate_codex_sse(data.encode()))
        self.assertIsNone(validate_codex_sse(frame({"type": "response.completed", "response": {}}, event=False)))

    def test_harmless_rate_limits_may_follow_completion_but_not_done(self):
        metadata = frame({"type": "codex.rate_limits", "primary": {"used_percent": 12}, "credits": {"has_credits": True}})
        self.assertIsNone(validate_codex_sse(frame(complete()) + metadata + b"data: [DONE]\n\n"))
        with self.assertRaises(PrivacyBlocked):
            validate_codex_sse(frame(complete()) + b"data: [DONE]\n\n" + metadata)

    def test_html_arbitrary_bodies_and_non_sse_lines_never_count_as_streams(self):
        invalid = [b"<html><body>upstream failed</body></html>", b"{}", b"plain text",
                   b"Content-Type: text/event-stream\n\n" + frame(complete()),
                   b"garbage\n" + frame(complete()), b"<html>\n\n" + frame(complete()),
                   b"data: <html>bad</html>\n\n" + frame(complete()),
                   b": only comments\n\n", b"", b" \n\n" + frame(complete())]
        for data in invalid:
            with self.subTest(data=data[:50]), self.assertRaises(PrivacyBlocked):
                validate_codex_sse(data)

    def test_truncation_or_missing_completion_fails_closed(self):
        ended = frame(complete())
        invalid = [ended[:-1], ended[:-2], ended[:-8],
                   frame({"type": "response.created", "response": {"status": "in_progress"}}),
                   b"data: [DONE]\n\n", ended + b"event: response.output_text.delta\n",
                   ended + b"data: {\"type\":\"response.output_text.delta\"}",
                   ended + b"event: response.completed\n\n"]
        for data in invalid:
            with self.subTest(data=data[-60:]), self.assertRaises(PrivacyBlocked):
                validate_codex_sse(data)

    def test_event_type_mismatch_missing_type_and_duplicate_fields_fail(self):
        invalid = [
            b"event: response.output_text.delta\ndata: " + json.dumps(complete()).encode() + b"\n\n",
            b"data: {\"response\":{\"status\":\"completed\"}}\n\n",
            b"event: response.completed\nevent: response.completed\ndata: " + json.dumps(complete()).encode() + b"\n\n",
            b"id: a\nid: b\n" + frame(complete()),
            b"retry: 1\nretry: 2\n" + frame(complete()),
            b"event: response.future_unknown\ndata: {\"type\":\"response.future_unknown\"}\n\n" + frame(complete()),
        ]
        for data in invalid:
            with self.subTest(data=data[:70]), self.assertRaises(PrivacyBlocked):
                validate_codex_sse(data)

    def test_duplicate_keys_non_objects_nonfinite_numbers_and_invalid_utf8_fail(self):
        bad_json = [
            '{"type":"response.completed","type":"response.completed","response":{}}',
            '{"type":"response.completed","response":{"status":"completed","status":"completed"}}',
            '{"type":"response.completed","response":{},"value":NaN}',
            '{"type":"response.completed","response":{},"value":Infinity}',
            '{"type":"response.completed","response":{},"value":1e999}',
            '{"type":"response.completed","response":{},"value":"\\ud800"}',
            '[]', '"response.completed"', 'null', '{}', '{broken',
        ]
        for body in bad_json:
            with self.subTest(body=body), self.assertRaises(PrivacyBlocked):
                validate_codex_sse(("data: " + body + "\n\n").encode())
        for data in (b"data: \xff\n\n", frame(complete()).replace(b"\n", b"\r"), "not bytes"):
            with self.subTest(data_type=type(data).__name__), self.assertRaises(PrivacyBlocked):
                validate_codex_sse(data)

    def test_error_failed_incomplete_cancelled_or_conflicting_response_ids_fail(self):
        invalid = [
            frame({"type": "error", "message": "Synthetic private provider error"}) + frame(complete()),
            frame({"type": "response.failed", "response": {"status": "failed"}}),
            frame({"type": "response.incomplete", "response": {"status": "incomplete"}}),
            frame(complete(status="incomplete")), frame(complete(status="failed")),
            frame(complete(error={"message": "Synthetic private provider error"})),
            frame(complete(incomplete_details={"reason": "max_output_tokens"})),
            frame({"type": "response.completed", "response": {"status": "completed"}, "error": {}}),
            frame({"type": "response.created", "response": {"status": "cancelled"}}) + frame(complete()),
            frame({"type": "response.output_item.done", "item": {"status": "incomplete"}}) + frame(complete()),
            frame({"type": "response.created", "response": {"id": "resp_other", "status": "in_progress"}}) + frame(complete()),
            frame({"type": "response.completed"}),
        ]
        for data in invalid:
            with self.subTest(data=data[:80]), self.assertRaises(PrivacyBlocked) as caught:
                validate_codex_sse(data)
            self.assertNotIn("Synthetic private provider error", str(caught.exception))

    def test_duplicate_completion_and_executable_data_after_completion_fail(self):
        invalid = [frame(complete()) + frame(complete()),
                   frame(complete()) + frame({"type": "response.output_text.delta", "delta": "late"}),
                   frame(complete()) + frame({"type": "response.custom_tool_call_input.delta", "delta": "late patch"}),
                   frame(complete()) + frame({"type": "response.function_call_arguments.done", "arguments": "{}"}),
                   frame(complete()) + b"data: [DONE]\n\ndata: [DONE]\n\n"]
        for key in ("input", "arguments", "item", "delta", "response", "output"):
            invalid.append(frame(complete()) + frame({"type": "codex.rate_limits", "nested": {key: "hidden execution data"}}))
        for data in invalid:
            with self.subTest(data=data[-80:]), self.assertRaises(PrivacyBlocked):
                validate_codex_sse(data)

    def test_unsafe_id_retry_and_unknown_fields_fail(self):
        for field in (b"id: <script>\n", b"id: a\x00b\n", b"id: " + b"a" * 257 + b"\n",
                      b"retry: -1\n", b"retry: 99999999999\n", b"retry: 3600001\n",
                      b"unknown: ignored by permissive parsers\n", b"event : response.completed\n"):
            with self.subTest(field=field[:50]), self.assertRaises(PrivacyBlocked):
                validate_codex_sse(field + frame(complete()))

    def test_size_event_depth_and_node_bounds_fail_without_raw_diagnostics(self):
        with patch.object(codex_stream, "MAX_STREAM_BYTES", 16), self.assertRaises(PrivacyBlocked):
            validate_codex_sse(frame(complete()))
        with patch.object(codex_stream, "MAX_EVENTS", 1), self.assertRaises(PrivacyBlocked):
            validate_codex_sse(frame({"type": "response.created", "response": {}}) + frame(complete()))
        for constant, limit in (("MAX_JSON_DEPTH", 1), ("MAX_JSON_NODES", 2)):
            with self.subTest(constant=constant), patch.object(codex_stream, constant, limit), self.assertRaises(PrivacyBlocked):
                validate_codex_sse(frame(complete()))


if __name__ == "__main__":
    unittest.main()
