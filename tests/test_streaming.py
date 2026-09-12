"""Synthetic streaming checks: no provider traffic or credentials."""
import http.client
import json
import threading
import unittest
from unittest.mock import patch

from privacy_gateway.protocol import PrivacyBlocked, collect_trusted_opaque
from privacy_gateway.redaction import Policy, Redactor
from privacy_gateway.server import GatewayServer, GatewayState, UpstreamChunks
from privacy_gateway.streaming import AnthropicStream, TextRestorer, parse_events


def wire(*events):
    return b"".join(("event: " + e["type"] + "\ndata: " +
                     json.dumps(e, ensure_ascii=False) + "\n\n").encode() for e in events)


def start():
    return {"type": "message_start", "message": {"type": "message", "id": "msg_test",
        "role": "assistant", "content": [], "model": "synthetic-model"}}


def block(kind="text", **fields):
    if kind == "text":
        fields.setdefault("text", "")
    return {"type": "content_block_start", "index": 0,
            "content_block": {"type": kind, **fields}}


def delta(text):
    return {"type": "content_block_delta", "index": 0,
            "delta": {"type": "text_delta", "text": text}}


def end(reason="end_turn"):
    return [{"type": "content_block_stop", "index": 0},
            {"type": "message_delta", "delta": {"stop_reason": reason}},
            {"type": "message_stop"}]


def values(data):
    return [e.payload for e in parse_events([data]) if e.has_json]


def text_output(data):
    result = ""
    for value in values(data):
        if value["type"] == "content_block_start" and value["content_block"]["type"] == "text":
            result += value["content_block"]["text"]
        elif value["type"] == "content_block_delta":
            result += value.get("delta", {}).get("text", "")
    return result


class TextRestorationTests(unittest.TestCase):
    def setUp(self):
        self.secret = 'مريم "Private"\\🙂'
        self.redactor = Redactor(Policy.from_dict({"literals": [{"value": self.secret, "label": "PERSON"}]}))
        self.token = self.redactor.redact_text(self.secret)

    def test_every_token_boundary_and_character_at_a_time(self):
        source = "Hello " + self.token + " — " + self.token + "!"
        for split in range(len(source) + 1):
            lane = TextRestorer(self.redactor)
            with self.subTest(split=split):
                output = lane.feed(source[:split]) + lane.feed(source[split:]) + lane.feed("", final=True)
                self.assertEqual(output, self.redactor.restore_text(source))
        lane = TextRestorer(self.redactor)
        self.assertEqual("".join(lane.feed(c) for c in source) + lane.feed("", final=True),
                         self.redactor.restore_text(source))

    def test_word_boundaries_match_nonstreaming_restoration(self):
        for before in ("", "x", "م", "_", " ", "🙂"):
            for after in ("", "x", "م", "_", " ", "🙂"):
                source = before + self.token + after
                for split in range(len(source) + 1):
                    lane = TextRestorer(self.redactor)
                    output = lane.feed(source[:split]) + lane.feed(source[split:]) + lane.feed("", final=True)
                    self.assertEqual(output, self.redactor.restore_text(source))

    def test_ordinary_text_immediate_and_possible_token_withheld(self):
        lane = TextRestorer(self.redactor)
        self.assertEqual(lane.feed("Hello"), "Hello")
        self.assertEqual(lane.feed(" " + self.token[:4]), " ")
        self.assertEqual(lane.feed(self.token[4:]), self.secret)
        self.assertEqual(lane.feed("!"), "!")

    def test_utf8_and_sse_framing_at_every_byte_boundary(self):
        source = wire(start(), block(), delta("مرحبا " + self.token + " 🙂"), *end())
        for split in range(len(source) + 1):
            output = b"".join(AnthropicStream(self.redactor).restore([source[:split], source[split:]]))
            self.assertEqual(text_output(output), "مرحبا " + self.secret + " 🙂")
        one_byte = [bytes([value]) for value in source]
        self.assertEqual(text_output(b"".join(AnthropicStream(self.redactor).restore(one_byte))),
                         "مرحبا " + self.secret + " 🙂")

    def test_ambiguous_token_counter_waits_for_longest_known_match(self):
        class SyntheticRedactor:
            def restoration_tokens(self):
                return ("PG_TEST_abcdef01_1000", "PG_TEST_abcdef01_10000")
            def restore_text(self, value):
                return value.replace("PG_TEST_abcdef01_10000", "long").replace("PG_TEST_abcdef01_1000", "short")
        short, long = SyntheticRedactor().restoration_tokens()
        lane = TextRestorer(SyntheticRedactor())
        self.assertEqual(lane.feed(short), "")
        self.assertEqual(lane.feed("0"), "long")
        lane = TextRestorer(SyntheticRedactor())
        self.assertEqual(lane.feed(short), "")
        self.assertEqual(lane.feed("!"), "short!")
        lane = TextRestorer(SyntheticRedactor())
        self.assertEqual(lane.feed(short), "")
        self.assertEqual(lane.feed("", final=True), "short")
        lane = TextRestorer(SyntheticRedactor())
        value = "PG_" + "x" * 5000
        self.assertEqual(lane.feed(value), value)
        self.assertEqual(lane.pending, "")

    def test_start_text_and_deltas_share_one_restoration_lane(self):
        source = wire(start(), block(text=self.token[:8]), delta(self.token[8:]), *end())
        self.assertEqual(text_output(b"".join(AnthropicStream(self.redactor).restore([source]))), self.secret)

    def test_crlf_cr_bom_multiline_and_comments(self):
        source = b'\xef\xbb\xbf: comment\r\n\r\n' + wire(start(), block(), delta("hello"), *end()).replace(b"\n", b"\r\n")
        chunks = [source[i:i + 1] for i in range(len(source))]
        output = b"".join(AnthropicStream(self.redactor).restore(chunks))
        self.assertEqual(text_output(output), "hello")
        self.assertIn(b": comment", output)
        cr = wire(start(), block(), delta("hello"), *end()).replace(b"\n", b"\r")
        self.assertEqual(text_output(b"".join(AnthropicStream(self.redactor).restore([cr]))), "hello")


class ToolBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.secret = "Company' ; echo SYNTHETIC_MARKER ; echo '"
        self.redactor = Redactor(Policy.from_dict({"literals": [{"value": self.secret, "label": "ORG"}]}))
        self.token = self.redactor.redact_text(self.secret)

    def tool(self, name, arguments):
        split = len(arguments) // 2
        return [start(), block("tool_use", name=name, id="tool_test", input={}),
                {"type": "content_block_delta", "index": 0,
                 "delta": {"type": "input_json_delta", "partial_json": arguments[:split]}},
                {"type": "content_block_delta", "index": 0,
                 "delta": {"type": "input_json_delta", "partial_json": arguments[split:]}}, *end("tool_use")]

    def reject_without_tools(self, data):
        emitted = []
        with self.assertRaises(PrivacyBlocked):
            for piece in AnthropicStream(self.redactor).restore([data]):
                emitted.append(piece)
        seen = b"".join(emitted)
        self.assertNotIn(b"tool_use", seen)
        self.assertNotIn(b"input_json_delta", seen)
        self.assertNotIn(b"message_stop", seen)

    def test_executable_restoration_has_no_partial_tool_emission(self):
        arguments = json.dumps({"command": "echo '" + self.token + "'"})
        self.reject_without_tools(wire(*self.tool("Bash", arguments)))

    def test_invalid_duplicate_nonobject_arguments_have_no_tool_emission(self):
        for arguments in ('{"file_path":', '{"command":"pwd","command":"other"}', '[]',
                          '{"value":NaN}', 'null'):
            with self.subTest(arguments=arguments):
                self.reject_without_tools(wire(*self.tool("Edit", arguments)))

    def test_tools_wait_for_clean_eof_not_just_block_or_message_stop(self):
        events = self.tool("Edit", json.dumps({"file_path": "/tmp/" + self.token, "content": self.token}))
        for count in range(2, len(events)):
            with self.subTest(count=count):
                self.reject_without_tools(wire(*events[:count]))
        self.reject_without_tools(wire(*events) + b"data: {broken}\n\n")
        self.reject_without_tools(wire(*events, {"type": "ping"}))

    def test_valid_structured_edit_restores_after_all_checks(self):
        arguments = {"file_path": "/tmp/" + self.token, "content": self.token}
        events = self.tool("Edit", json.dumps(arguments))
        checked = False
        def chunks():
            nonlocal checked
            yield wire(*events)
            checked = True
        emitted = []
        for piece in AnthropicStream(self.redactor).restore(chunks()):
            if b"tool_use" in piece:
                self.assertTrue(checked)
            emitted.append(piece)
        output = values(b"".join(emitted))
        encoded = "".join(v.get("delta", {}).get("partial_json", "") for v in output)
        self.assertEqual(json.loads(encoded), {"file_path": "/tmp/" + self.secret, "content": self.secret})

    def test_response_input_and_restored_output_caps(self):
        self.reject_without_tools(wire(*self.tool("Edit", '{"content":"' + self.token + '"}')) + b"x" * 100)
        source = wire(start(), block(), delta("hello"), *end())
        with self.assertRaises(PrivacyBlocked):
            b"".join(AnthropicStream(self.redactor, maximum=len(source) - 1).restore([source]))
        big = "a" * 4000
        redactor = Redactor(Policy.from_dict({"literals": [{"value": big, "label": "LONG"}]}))
        token = redactor.redact_text(big)
        source = wire(start(), block(), delta(token), *end())
        with self.assertRaises(PrivacyBlocked):
            b"".join(AnthropicStream(redactor, maximum=1000).restore([source]))

    def test_thinking_is_unchanged_and_trusted_only_at_valid_completion(self):
        events = [start(), block("thinking", thinking="", signature=""),
                  {"type": "content_block_delta", "index": 0,
                   "delta": {"type": "thinking_delta", "thinking": self.token}},
                  {"type": "content_block_delta", "index": 0,
                   "delta": {"type": "signature_delta", "signature": "sig-test"}}, *end()]
        restorer = AnthropicStream(self.redactor)
        output = b"".join(restorer.restore([wire(*events)]))
        self.assertEqual(values(output), events)
        expected = {"type": "thinking", "thinking": self.token, "signature": "sig-test"}
        self.assertEqual(restorer.trusted_opaque, collect_trusted_opaque(expected))
        restorer = AnthropicStream(self.redactor)
        with self.assertRaises(PrivacyBlocked):
            b"".join(restorer.restore([wire(*events[:-1])]))
        self.assertEqual(restorer.trusted_opaque, set())

    def test_wrong_event_type_order_and_invalid_encoding_fail(self):
        cases = [wire(start(), start()), wire(block()),
                 wire(start(), block(), {"type": "content_block_delta", "index": 2,
                     "delta": {"type": "text_delta", "text": "x"}}),
                 wire(start()) + b'event: ping\ndata: {"type":"message_stop"}\n\n',
                 wire(start()) + b'data: {"type":"ping","type":"message_stop"}\n\n',
                 wire(start()) + b'data: \xff\n\n', wire(start()) + b'data: {"type":"ping"}',
                 wire(start(), block("tool_use", id="tool_test", name="Edit", input={}), delta("wrong"))]
        for data in cases:
            with self.subTest(data=data), self.assertRaises(PrivacyBlocked):
                b"".join(AnthropicStream(self.redactor).restore([data]))


class LiveLocalStreamingTests(unittest.TestCase):
    def setUp(self):
        self.state = GatewayState(mode="auto")
        self.server = GatewayServer(self.state)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.state.close()
        self.server.shutdown()
        self.server.server_close()

    def request(self):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        path = "/proxy/" + self.state.proxy_token + "/v1/messages"
        connection.request("POST", path, json.dumps({"model": "test", "messages": [{"role": "user", "content": "hello"}], "stream": True}),
            {"Content-Type": "application/json", "Authorization": "Bearer synthetic_auth"})
        return connection, connection.getresponse()

    def test_first_text_arrives_while_upstream_is_still_waiting(self):
        release = threading.Event()
        def chunks():
            yield wire(start(), block(), delta("First text now. "))
            if not release.wait(3):
                raise RuntimeError("synthetic upstream timed out")
            yield wire(delta("Later text."), *end())
        self.state.transport = lambda *_: (200, "text/event-stream", chunks())
        connection, response = self.request()
        try:
            first = b""
            while b"First text now." not in first:
                first += response.readline()
            self.assertFalse(release.is_set())
            self.assertNotIn(b"message_stop", first)
            release.set()
            all_data = first + response.read()
            self.assertEqual(text_output(all_data), "First text now. Later text.")
            self.assertEqual(self.state.blocked, 0)
        finally:
            release.set()
            connection.close()

    def test_interrupted_stream_errors_without_success_or_tools(self):
        def chunks():
            yield wire(start(), block(), delta("Readable prefix"))
            raise OSError("must_not_appear_in_client_output")
        self.state.transport = lambda *_: (200, "text/event-stream", chunks())
        connection, response = self.request()
        data = response.read()
        connection.close()
        self.assertIn(b"Readable prefix", data)
        self.assertIn(b"event: error", data)
        self.assertNotIn(b"message_stop", data)
        self.assertNotIn(b"must_not_appear", data)
        self.assertEqual(self.state.blocked, 1)

    def test_production_transport_leaves_stream_open_until_consumed(self):
        class Response:
            status = 200
            closed = False
            calls = 0
            def getheader(self, name, default=None):
                return "text/event-stream" if name == "Content-Type" else default
            def read1(self, size):
                self.calls += 1
                return b"chunk" if self.calls == 1 else b""
            def read(self, *args):
                raise AssertionError("SSE must not use buffered read")
            def close(self):
                self.closed = True
        class Connection:
            closed = False
            def request(self, *args, **kwargs):
                pass
            def getresponse(self):
                return response
            def close(self):
                self.closed = True
        response, connection = Response(), Connection()
        with patch("privacy_gateway.server.http.client.HTTPSConnection", return_value=connection):
            status, content_type, body = self.state.send_upstream("/v1/messages", b"{}", {})
        self.assertIsInstance(body, UpstreamChunks)
        self.assertFalse(connection.closed)
        self.assertEqual(response.calls, 0)
        self.assertEqual(list(body), [b"chunk"])
        self.assertTrue(connection.closed)
        self.assertTrue(response.closed)

    def test_closed_session_blocks_auto_and_review_requests(self):
        for mode in ("auto", "review"):
            state = GatewayState(mode=mode)
            state.close()
            with self.subTest(mode=mode), self.assertRaises(PrivacyBlocked):
                state.approve({})
        self.state.close()
        self.state.transport = lambda *_: self.fail("closed session forwarded a request")
        connection, response = self.request()
        self.assertEqual(response.status, 400)
        response.read()
        connection.close()
        self.assertEqual(self.state.forwarded, 0)

    def test_review_timeout_must_be_finite_positive_and_bounded(self):
        for value in (float("inf"), float("nan"), -1, 0, 3601, True, "5"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                GatewayState(review_timeout=value)


if __name__ == "__main__":
    unittest.main()
