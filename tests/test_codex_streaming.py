"""Incremental Codex checks using synthetic local streams only."""
import http.client
import json
import os
from pathlib import Path
import queue
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

from privacy_gateway.codex_client import find_codex_binary, protected_codex_launch
from privacy_gateway.codex_streaming import CodexStream
from privacy_gateway.protocol import PrivacyBlocked
from privacy_gateway.redaction import Policy, Redactor
from privacy_gateway.server import GatewayServer, GatewayState, Handler, UpstreamChunks


def wire(*packets):
    return b"".join(("event: " + packet["type"] + "\ndata: " + json.dumps(packet, ensure_ascii=False)
                     + "\n\n").encode() for packet in packets)


def parsed(data):
    return [json.loads(line[6:]) for line in data.decode().splitlines()
            if line.startswith("data: ") and line != "data: [DONE]"]


def delta(text, **fields):
    return {"type": "response.output_text.delta", "item_id": "msg_1", "output_index": 1,
            "content_index": 0, "delta": text, **fields}


def message(text):
    return {"id": "msg_1", "type": "message", "role": "assistant", "status": "completed",
            "phase": "final_answer", "content": [{"type": "output_text", "text": text, "annotations": []}]}


def start():
    reasoning = {"id": "rs_1", "type": "reasoning", "summary": [], "encrypted_content": "opaque_synthetic"}
    return [
        {"type": "response.created", "response": {"id": "resp_1", "status": "in_progress", "output": []}},
        {"type": "response.output_item.added", "output_index": 0, "item": {**reasoning, "encrypted_content": None}},
        {"type": "response.output_item.done", "output_index": 0, "item": reasoning},
        {"type": "response.output_item.added", "output_index": 1,
         "item": {**message(""), "status": "in_progress", "content": []}},
        {"type": "response.content_part.added", "item_id": "msg_1", "output_index": 1,
         "content_index": 0, "part": {"type": "output_text", "text": "", "annotations": []}},
    ]


def end(text):
    return [
        {"type": "response.output_text.done", "item_id": "msg_1", "output_index": 1, "content_index": 0, "text": text},
        {"type": "response.output_item.done", "output_index": 1, "item": message(text)},
        {"type": "response.completed", "response": {"id": "resp_1", "status": "completed", "model": "gpt-6-astra",
            "output": [message(text)], "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2}}},
    ]


def patch_events(text):
    item = {"id": "ct_1", "type": "custom_tool_call", "call_id": "call_1", "name": "apply_patch", "input": text}
    return [
        {"type": "response.output_item.added", "output_index": 2, "item": {**item, "input": ""}},
        {"type": "response.custom_tool_call_input.delta", "output_index": 2, "item_id": "ct_1", "delta": text},
        {"type": "response.custom_tool_call_input.done", "output_index": 2, "item_id": "ct_1", "input": text},
        {"type": "response.output_item.done", "output_index": 2, "item": item},
    ]


def text_part_events(part_type, initial, continuation, *, include_delta=True):
    prefix, field = {
        "output_text": ("response.output_text", "text"),
        "refusal": ("response.refusal", "refusal"),
        "summary_text": ("response.reasoning_summary_text", "text"),
        "reasoning_text": ("response.reasoning_text", "text"),
    }[part_type]
    part_prefix = "response.reasoning_summary_part" if part_type == "summary_text" else "response.content_part"
    index = {"summary_index": 0} if part_type == "summary_text" else {"content_index": 0}
    identity = {"item_id": "text_1", "output_index": 0, **index}
    part = {"type": part_type, field: initial + continuation}
    item = ({"id": "text_1", "type": "reasoning", "summary": [part]} if part_type == "summary_text" else
            {"id": "text_1", "type": "reasoning", "content": [part]} if part_type == "reasoning_text" else
            {"id": "text_1", "type": "message", "role": "assistant", "content": [part]})
    packets = [
        {"type": "response.created", "response": {"id": "resp_1", "status": "in_progress", "output": []}},
        {"type": "response.output_item.added", "output_index": 0,
         "item": {**item, "content": [], "summary": []}},
        {"type": part_prefix + ".added", **identity, "part": {"type": part_type, field: initial}},
    ]
    if include_delta:
        packets.append({"type": prefix + ".delta", **identity, "delta": continuation})
    packets.extend([
        {"type": part_prefix + ".done", **identity, "part": part},
        {"type": "response.output_item.done", "output_index": 0, "item": item},
        {"type": "response.completed", "response": {"id": "resp_1", "status": "completed", "output": [item]}},
    ])
    return packets, prefix, part_prefix, field


class IncrementalCodexTests(unittest.TestCase):
    def setUp(self):
        self.original = "سارة synthetic@example.com"
        self.redactor = Redactor(Policy.from_dict({"literals": [{"value": self.original, "label": "PERSON"}]}))
        self.token = self.redactor.redact_text(self.original)

    def test_text_and_message_done_arrive_after_reasoning_before_upstream_eof(self):
        waiting = False
        def chunks():
            nonlocal waiting
            yield wire(*start(), delta("Visible " + self.token), *end("Visible " + self.token)[:-1])
            waiting = True
            yield wire(end("Visible " + self.token)[-1])
        restorer = CodexStream(self.redactor)
        iterator = restorer.restore(chunks())
        seen = b""
        while b'"id":"msg_1","type":"message","role":"assistant","status":"completed"' not in seen:
            seen += next(iterator)
        self.assertFalse(waiting)
        self.assertIn(self.original.encode(), seen)
        self.assertNotIn(self.token.encode(), seen)
        self.assertIn(b"opaque_synthetic", seen)
        self.assertNotIn(b"response.completed", seen)
        self.assertEqual(restorer.trusted_opaque, set())
        seen += b"".join(iterator)
        self.assertIn(b"response.completed", seen)
        self.assertTrue(restorer.trusted_opaque)

    def test_every_token_and_utf8_byte_boundary_restores_without_duplicate_text(self):
        for cut in range(len(self.token) + 1):
            raw = wire(*start(), delta("مرحبا " + self.token[:cut]), delta(self.token[cut:] + "!"),
                       *end("مرحبا " + self.token + "!"))
            chunks = [raw[index:index + 1] for index in range(len(raw))]
            with self.subTest(cut=cut):
                restored = b"".join(CodexStream(self.redactor).restore(chunks))
                text = "".join(event["delta"] for event in parsed(restored)
                               if event["type"] == "response.output_text.delta")
                self.assertEqual(text, "مرحبا " + self.original + "!")
                self.assertNotIn(self.token, restored.decode())

    def test_unmatched_token_prefix_flushes_before_message_done(self):
        text = "Partial literal " + self.token[:-2]
        restored = parsed(b"".join(CodexStream(self.redactor).restore([
            wire(*start(), delta(text, sequence_number=4), *end(text))])))
        deltas = [event for event in restored if event["type"] == "response.output_text.delta"]
        self.assertEqual("".join(event["delta"] for event in deltas), text)
        self.assertEqual(len(deltas), 2)
        self.assertNotIn("sequence_number", deltas[-1])
        self.assertLess(restored.index(deltas[-1]), next(index for index, event in enumerate(restored)
                                                     if event["type"] == "response.output_text.done"))

    def test_nonempty_text_parts_restore_tokens_across_initial_text_and_deltas(self):
        safe_patch = "*** Begin Patch\n*** Add File: safe.txt\n+okay\n*** End Patch\n"
        for part_type in ("output_text", "refusal", "summary_text", "reasoning_text"):
            for held in (False, True):
                for cut in (0, len(self.token) // 2, len(self.token)):
                    with self.subTest(part_type=part_type, held=held, cut=cut):
                        initial = "Initial " + self.token[:cut]
                        continuation = self.token[cut:] + " final"
                        packets, prefix, part_prefix, field = text_part_events(part_type, initial, continuation)
                        if held:
                            packets[1:1] = patch_events(safe_patch)
                        result = parsed(b"".join(CodexStream(self.redactor).restore([wire(*packets)])))
                        text = "".join(event["part"][field] if event["type"] == part_prefix + ".added" else event["delta"]
                                       for event in result if event["type"] in {part_prefix + ".added", prefix + ".delta"})
                        self.assertEqual(text, "Initial " + self.original + " final")
                        completed_part = next(event["part"][field] for event in result if event["type"] == part_prefix + ".done")
                        self.assertEqual(completed_part, text)

    def test_part_done_flushes_suffix_before_closing_without_separate_text_done(self):
        for part_type in ("output_text", "refusal", "summary_text", "reasoning_text"):
            for initial_only in (False, True):
                with self.subTest(part_type=part_type, initial_only=initial_only):
                    text = "Literal " + self.token[:-2]
                    packets, prefix, part_prefix, field = text_part_events(part_type,
                        text if initial_only else "", "" if initial_only else text,
                        include_delta=not initial_only)
                    result = parsed(b"".join(CodexStream(self.redactor).restore([wire(*packets)])))
                    delta_indices = [index for index, event in enumerate(result) if event["type"] == prefix + ".delta"]
                    done_index = next(index for index, event in enumerate(result) if event["type"] == part_prefix + ".done")
                    self.assertTrue(delta_indices)
                    self.assertLess(delta_indices[-1], done_index)
                    combined = "".join(event["part"][field] if event["type"] == part_prefix + ".added" else event["delta"]
                                       for event in result if event["type"] in {part_prefix + ".added", prefix + ".delta"})
                    self.assertEqual(combined, text)

    def test_text_part_completion_must_match_and_closed_parts_reject_more_deltas(self):
        for part_type in ("output_text", "refusal", "summary_text", "reasoning_text"):
            for invalid in ("different_done", "reopened", "mixed_tool_metadata"):
                packets, prefix, part_prefix, field = text_part_events(part_type, "Initial ", "text")
                if invalid == "different_done":
                    packets[-3]["part"][field] = "Different text"
                elif invalid == "reopened":
                    packets.insert(-2, {**packets[3], "delta": "late"})
                else:
                    packets[2]["part"]["arguments"] = "unexpected tool metadata"
                seen = b""
                with self.subTest(part_type=part_type, invalid=invalid), self.assertRaises(PrivacyBlocked):
                    for chunk in CodexStream(self.redactor).restore([wire(*packets)]):
                        seen += chunk
                self.assertNotIn(b"response.completed", seen)

    def test_tool_start_arguments_and_completion_are_withheld_until_clean_eof(self):
        reached_eof = False
        patch_text = "*** Begin Patch\n*** Add File: contact.txt\n+" + self.token + "\n*** End Patch\n"
        def chunks():
            nonlocal reached_eof
            yield wire(*start(), delta("Visible first"), *patch_events(patch_text), *end("Visible first"))
            reached_eof = True
        restorer = CodexStream(self.redactor)
        before, after = b"", b""
        for chunk in restorer.restore(chunks()):
            if reached_eof:
                after += chunk
            else:
                before += chunk
        self.assertIn(b"Visible first", before)
        self.assertNotIn(b"custom_tool_call", before)
        self.assertNotIn(b"response.completed", before)
        self.assertIn(b"custom_tool_call", after)
        self.assertIn(self.original.encode(), after)
        self.assertNotIn(self.token.encode(), after)

    def test_malformed_completion_tail_and_injected_patch_never_release_tools(self):
        safe_patch = "*** Begin Patch\n*** Add File: a.txt\n+okay\n*** End Patch\n"
        base = wire(*start(), delta("Readable prefix"))
        failures = [
            wire(*patch_events(safe_patch)),
            wire(*patch_events(safe_patch), *end("Readable prefix")) + b"data: {unfinished",
            wire(*patch_events(safe_patch), {"type": "response.completed", "response": {"status": "incomplete"}}),
            wire(*patch_events(safe_patch), *end("Readable prefix")) + wire({"type": "response.output_text.delta", "delta": "late"}),
            wire(*patch_events("*** Begin Patch\n*** Add File: a.txt\n+text\n*** End Patch\nINJECTED"), *end("Readable prefix")),
            b"event: response.output_text.delta\nevent: response.output_text.delta\ndata: {}\n\n",
            b"data: {\"type\":\"response.output_text.delta\",\"delta\":\"x\",\"value\":1e999}\n\n",
            b"data: \xff\n\n",
        ]
        for tail in failures:
            with self.subTest(tail=tail[-60:]):
                restorer, seen = CodexStream(self.redactor), b""
                with self.assertRaises(PrivacyBlocked):
                    for chunk in restorer.restore([base, tail]):
                        seen += chunk
                self.assertIn(b"Readable prefix", seen)
                self.assertNotIn(b"custom_tool_call", seen)
                self.assertNotIn(b"response.completed", seen)
                self.assertEqual(restorer.trusted_opaque, set())

    def test_restored_value_cannot_inject_patch_framing(self):
        original = "line\n*** End Patch\n*** Delete File: victim.txt\n*** Begin Patch"
        redactor = Redactor(Policy.from_dict({"literals": [{"value": original, "label": "SECRET"}]}))
        token = redactor.redact_text(original)
        payload = wire(*start(), delta("Safe prefix"), *patch_events(
            "*** Begin Patch\n*** Add File: safe.txt\n+" + token + "\n*** End Patch\n"), *end("Safe prefix"))
        seen = b""
        with self.assertRaises(PrivacyBlocked):
            for chunk in CodexStream(redactor).restore([payload]):
                seen += chunk
        self.assertNotIn(b"custom_tool_call", seen)
        self.assertNotIn(b"victim.txt", seen)

    def test_text_done_must_match_the_lane_and_reopening_is_rejected(self):
        for packets in ((*start(), delta("one"), *end("different")),
                        (*start(), delta("one"), end("one")[0], delta("two"), end("one")[-1])):
            with self.assertRaises(PrivacyBlocked):
                b"".join(CodexStream(self.redactor).restore([wire(*packets)]))

    def test_tool_completion_flushes_pending_display_and_mixed_text_tool_fields_block(self):
        text = "Literal prefix " + self.token[:-2]
        safe_patch = "*** Begin Patch\n*** Add File: safe.txt\n+okay\n*** End Patch\n"
        tools = patch_events(safe_patch)
        completion = end(text)[-1]
        completion["response"]["output"].append(tools[-1]["item"])
        result = parsed(b"".join(CodexStream(self.redactor).restore([
            wire(*start(), delta(text), *tools, completion)])))
        self.assertEqual("".join(event["delta"] for event in result
                                 if event["type"] == "response.output_text.delta"), text)
        for field in ({"input": "unexpected tool data"}, {"nested": {"type": "custom_tool_call", "input": "bad"}}):
            seen = b""
            with self.subTest(field=field), self.assertRaises(PrivacyBlocked):
                for chunk in CodexStream(self.redactor).restore([wire(*start(), delta(self.token, **field), *end(self.token))]):
                    seen += chunk
            self.assertNotIn(self.token.encode(), seen)
            self.assertNotIn(b"response.completed", seen)


class LocalCodexStreamingTests(unittest.TestCase):
    def test_disconnect_during_headers_closes_upstream_before_reading_body(self):
        handler = object.__new__(Handler)
        handler.send_response = Mock()
        handler.send_header = Mock()
        handler.end_headers = Mock(side_effect=BrokenPipeError())
        upstream, restorer = Mock(), Mock()
        handler.respond_provider_stream(upstream, restorer)
        upstream.close.assert_called_once_with()
        restorer.restore.assert_not_called()
        self.assertTrue(handler.close_connection)

    def setUp(self):
        self.state = GatewayState(provider="codex", mode="auto")
        self.server = GatewayServer(self.state)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.state.close()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)

    def request(self):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        connection.request("POST", "/proxy/" + self.state.proxy_token + "/responses",
            json.dumps({"model": "gpt-6-astra", "input": "Synthetic hello", "stream": True}),
            {"Content-Type": "application/json", "Authorization": "Bearer synthetic_auth"})
        return connection, connection.getresponse()

    def test_http_text_is_visible_before_eof_with_explicit_and_absent_mime(self):
        for mime in ("text/event-stream", ""):
            release = threading.Event()
            closed = threading.Event()
            def chunks():
                try:
                    yield wire(*start(), delta("Visible immediately"))
                    if not release.wait(3):
                        raise RuntimeError("synthetic wait timed out")
                    yield wire(*end("Visible immediately"))
                finally:
                    closed.set()
            self.state.transport = lambda *_: (200, mime, chunks())
            connection, response = self.request()
            try:
                seen = b""
                while b"Visible immediately" not in seen:
                    line = response.readline()
                    self.assertTrue(line, seen)
                    seen += line
                self.assertFalse(release.is_set())
                self.assertNotIn(b"response.completed", seen)
                release.set()
                seen += response.read()
                self.assertIn(b"response.completed", seen)
                self.assertTrue(closed.wait(1))
            finally:
                release.set()
                connection.close()
        self.assertEqual(self.state.blocked, 0)

    def test_truncated_http_stream_returns_safe_error_without_tools_or_success(self):
        def chunks():
            yield wire(*start(), delta("Readable prefix"))
            raise OSError("private synthetic diagnostic")
        self.state.transport = lambda *_: (200, "", chunks())
        connection, response = self.request()
        try:
            seen = response.read()
        finally:
            connection.close()
        self.assertIn(b"Readable prefix", seen)
        self.assertIn(b"event: error", seen)
        self.assertNotIn(b"private synthetic diagnostic", seen)
        self.assertNotIn(b"response.completed", seen)
        self.assertEqual(self.state.blocked, 1)

    def test_actual_transport_does_not_buffer_expected_codex_sse(self):
        class Response:
            status = 200
            def getheader(self, name, default=""):
                return mime if name == "Content-Type" else default
            def read(self, *_):
                raise AssertionError("Codex SSE used full buffered read")
            def close(self):
                pass
        class Connection:
            def request(self, *args, **kwargs):
                pass
            def getresponse(self):
                return Response()
            def close(self):
                pass
        for mime in ("text/event-stream; charset=utf-8", ""):
            with patch("privacy_gateway.server.http.client.HTTPSConnection", return_value=Connection()):
                status, _, upstream = self.state.send_upstream("/responses", b'{"stream":true}', {"Accept": "text/event-stream"})
            self.assertEqual(status, 200)
            self.assertIsInstance(upstream, UpstreamChunks)
            upstream.close()

    @unittest.skipUnless(os.environ.get("MASKCODE_TEST_INSTALLED_CODEX") == "1" and find_codex_binary(),
                         "Set MASKCODE_TEST_INSTALLED_CODEX=1 for the installed CLI with a local fake provider")
    def test_installed_codex_displays_message_after_reasoning_before_provider_eof(self):
        release = threading.Event()
        email = "synthetic.stream@example.com"
        token = self.state.redactor.redact_text(email)
        def chunks():
            yield wire(*start(), delta(token), *end(token)[:-1])
            if not release.wait(10):
                raise RuntimeError("native CLI did not display the early message")
            yield wire(end(token)[-1])
        self.state.transport = lambda *_: (200, "", chunks())
        with tempfile.TemporaryDirectory(prefix="maskcode-codex-stream-") as temporary:
            Path(temporary, "auth.json").write_text('{"OPENAI_API_KEY":"sk-synthetic-local-only"}')
            environment = {"PATH": os.environ["PATH"], "HOME": temporary, "CODEX_HOME": temporary,
                           "OPENAI_API_KEY": "sk-synthetic-local-only", "NO_COLOR": "1"}
            with patch.dict(os.environ, environment, clear=True):
                with protected_codex_launch(self.server, ["exec", "--model", "gpt-6-astra", "--ephemeral",
                        "--skip-git-repo-check", "--json", "Echo " + email], cwd=temporary) as (argv, env):
                    process = subprocess.Popen(argv, cwd=temporary, env=env, stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    lines = queue.Queue()
                    reader = threading.Thread(target=lambda: [lines.put(line) for line in process.stdout], daemon=True)
                    reader.start()
                    seen = []
                    try:
                        while True:
                            line = lines.get(timeout=10)
                            seen.append(line)
                            if email in line:
                                event = json.loads(line)
                                self.assertEqual(event["type"], "item.completed")
                                self.assertEqual(event["item"]["type"], "agent_message")
                                break
                        self.assertFalse(release.is_set())
                        self.assertIsNone(process.poll())
                        release.set()
                        self.assertEqual(process.wait(timeout=15), 0)
                        reader.join(2)
                        self.assertEqual(self.state.forwarded, 1)
                        self.assertEqual(self.state.blocked, 0)
                    finally:
                        release.set()
                        if process.poll() is None:
                            process.terminate()
                            process.wait(timeout=5)
                        process.stdout.close()
                        process.stderr.close()
