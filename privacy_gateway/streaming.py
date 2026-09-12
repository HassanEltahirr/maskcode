"""Incremental Anthropic SSE restoration with a fail-closed tool boundary.

Readable text streams as it arrives, except a possible pseudonym suffix. Tool
blocks and all following events are withheld until a complete, valid message
and clean upstream EOF. A broken stream can expose partial display text, but
never a partial tool call or a successful message completion.
"""
from __future__ import annotations

import codecs
import copy
import json
import re
from typing import Any, Iterable, Iterator

from .protocol import (MAX_SSE_BYTES, PrivacyBlocked, _Event,
                       _restore_tool_data, collect_trusted_opaque)


_ERROR = "Malformed or incomplete provider event stream."


def _strict_json(data: str) -> Any:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError()
            result[key] = value
        return result

    def constant(_):
        raise ValueError()

    try:
        return json.loads(data, object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, TypeError, RecursionError, OverflowError):
        raise PrivacyBlocked(_ERROR) from None


class TextRestorer:
    """Incremental, longest-match replacement using a snapshot of issued tokens.

    The retained suffix is at most the longest known token. Exact tokens may be
    embedded in filenames/identifiers. The trie also handles issued counters
    where one token is a prefix of another, without waiting for whitespace.
    """
    def __init__(self, redactor: Any, trie: dict | None = None):
        self.redactor = redactor
        self.pending = ""
        if trie is None:
            trie = {}
            for token in redactor.restoration_tokens():
                node = trie
                for character in token:
                    node = node.setdefault(character, {})
                node[None] = token
        self.trie = trie

    def feed(self, value: str, final: bool = False) -> str:
        if not isinstance(value, str):
            raise PrivacyBlocked(_ERROR)
        joined = self.pending + value
        self.pending = ""
        output = []
        position = 0
        while position < len(joined):
            node = self.trie
            end = position
            matched = None
            matched_end = position
            while end < len(joined) and joined[end] in node:
                node = node[joined[end]]
                end += 1
                if None in node:
                    matched, matched_end = node[None], end
            if end == len(joined) and not final and any(key is not None for key in node):
                self.pending = joined[position:]
                break
            if matched is not None:
                output.append(self.redactor.restore_text(matched))
                position = matched_end
            else:
                output.append(joined[position])
                position += 1
        return "".join(output)



def _event(lines: list[str]) -> _Event:
    data = []
    name = None
    for line in lines:
        if line.startswith(":"):
            continue
        field, separator, value = line.partition(":")
        value = value.removeprefix(" ")
        if field == "data":
            data.append(value if separator else "")
        elif field == "event":
            if name is not None:
                raise PrivacyBlocked(_ERROR)
            name = value
        elif field not in {"id", "retry"}:
            raise PrivacyBlocked(_ERROR)
    if not data:
        if name is not None:
            raise PrivacyBlocked(_ERROR)
        return _Event(lines)
    payload = _strict_json("\n".join(data))
    if not isinstance(payload, dict) or not isinstance(payload.get("type"), str):
        raise PrivacyBlocked(_ERROR)
    if name is not None and name != payload["type"]:
        raise PrivacyBlocked(_ERROR)
    return _Event(lines, payload, True)


def parse_events(chunks: Iterable[bytes], maximum: int = MAX_SSE_BYTES) -> Iterator[_Event]:
    """Decode strict UTF-8 and SSE lines across arbitrary transport boundaries."""
    decoder = codecs.getincrementaldecoder("utf-8-sig")("strict")
    total = 0
    pending = ""
    lines = []
    try:
        for chunk in chunks:
            if not isinstance(chunk, bytes):
                raise PrivacyBlocked(_ERROR)
            total += len(chunk)
            if total > maximum:
                raise PrivacyBlocked("Provider stream exceeds the supported size.")
            pending += decoder.decode(chunk)
            while True:
                match = re.search(r"[\r\n]", pending)
                if match is None:
                    break
                index = match.start()
                if pending[index] == "\r" and index + 1 == len(pending):
                    break
                width = 2 if pending[index:index + 2] == "\r\n" else 1
                line, pending = pending[:index], pending[index + width:]
                if line:
                    lines.append(line)
                elif lines:
                    yield _event(lines)
                    lines = []
        pending += decoder.decode(b"", final=True)
        # A final CR is itself a legal line ending.
        if pending.endswith("\r"):
            line, pending = pending[:-1], ""
            if line:
                lines.append(line)
            elif lines:
                yield _event(lines)
                lines = []
        if pending or lines:
            raise PrivacyBlocked(_ERROR)
    except UnicodeError:
        raise PrivacyBlocked(_ERROR) from None


class AnthropicStream:
    """Single-use iterator; trusted_opaque is populated only at clean EOF."""
    def __init__(self, redactor: Any, maximum: int = MAX_SSE_BYTES):
        self.redactor = redactor
        self._text_trie = TextRestorer(redactor).trie
        self.maximum = maximum
        self.trusted_opaque: set[str] = set()
        self._candidate_trust: set[str] = set()
        self._started = self._stopped = self._message_delta = False
        self._active = None
        self._index = -1
        self._held_mode = False
        self._held: list[bytes] = []
        self._written = 0

    def _emit(self, event: _Event) -> list[bytes]:
        try:
            data = event.encode()
        except (ValueError, TypeError, RecursionError, UnicodeError):
            raise PrivacyBlocked(_ERROR) from None
        self._written += len(data)
        if self._written > self.maximum:
            raise PrivacyBlocked("Restored stream exceeds the supported size.")
        if self._held_mode:
            self._held.append(data)
            return []
        return [data]

    def _delta(self, index: int, text: str) -> _Event:
        return _Event(["event: content_block_delta", "data:"], {
            "type": "content_block_delta", "index": index,
            "delta": {"type": "text_delta", "text": text}}, True)

    def _tool_complete(self) -> list[bytes]:
        active = self._active
        block = active["block"]
        pieces = active["arguments"]
        if pieces:
            if block["input"]:
                raise PrivacyBlocked(_ERROR)
            arguments = _strict_json("".join(pieces))
            if not isinstance(arguments, dict):
                raise PrivacyBlocked(_ERROR)
        else:
            arguments = block["input"]
        restored = _restore_tool_data(arguments, self.redactor, block["name"])
        if not isinstance(restored, dict):
            raise PrivacyBlocked(_ERROR)
        encoded = json.dumps(restored, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
        emitted = False
        for event in active["events"]:
            value = event.payload
            if value and value.get("type") == "content_block_start":
                value["content_block"]["input"] = {} if pieces else restored
            elif value and value.get("type") == "content_block_delta":
                value["delta"]["partial_json"] = encoded if not emitted else ""
                emitted = True
            self._emit(event)
        return []

    def _accept(self, event: _Event) -> list[bytes]:
        value = event.payload
        if self._stopped:
            # Even extra valid content after message_stop invalidates completion.
            raise PrivacyBlocked(_ERROR)
        if not event.has_json or value["type"] == "ping":
            if self._active and self._active["kind"] == "tool_use":
                self._active["events"].append(event)
                return []
            return self._emit(event)
        kind = value["type"]
        if kind == "error":
            raise PrivacyBlocked("Provider interrupted the stream; response details suppressed.")
        if kind == "message_start":
            message = value.get("message")
            if (self._started or not isinstance(message, dict)
                    or message.get("type") != "message" or message.get("role") != "assistant"
                    or message.get("content") != []):
                raise PrivacyBlocked(_ERROR)
            self._started = True
            return self._emit(event)
        if not self._started:
            raise PrivacyBlocked(_ERROR)
        if kind == "content_block_start":
            index, block = value.get("index"), value.get("content_block")
            if (self._active is not None or self._message_delta
                    or type(index) is not int or index != self._index + 1
                    or not isinstance(block, dict)):
                raise PrivacyBlocked(_ERROR)
            block_kind = block.get("type")
            if block_kind not in {"text", "tool_use", "thinking", "redacted_thinking"}:
                raise PrivacyBlocked("Unsupported provider content block.")
            self._index = index
            self._active = {"kind": block_kind, "block": copy.deepcopy(block), "events": [event],
                            "arguments": []}
            if block_kind == "tool_use":
                if (not isinstance(block.get("input"), dict)
                        or not isinstance(block.get("name"), str) or not block["name"]
                        or not isinstance(block.get("id"), str) or not block["id"]):
                    raise PrivacyBlocked(_ERROR)
                self._held_mode = True
                return []
            if block_kind == "text":
                restorer = self._active["restorer"] = TextRestorer(self.redactor, self._text_trie)
                block["text"] = restorer.feed(block.get("text"))
            elif block_kind == "thinking":
                if (not isinstance(block.get("thinking"), str)
                        or not isinstance(block.get("signature", ""), str)):
                    raise PrivacyBlocked(_ERROR)
            elif not isinstance(block.get("data"), str):
                raise PrivacyBlocked(_ERROR)
            return self._emit(event)
        if kind in {"content_block_delta", "content_block_stop"}:
            if self._active is None or type(value.get("index")) is not int or value["index"] != self._index:
                raise PrivacyBlocked(_ERROR)
            active = self._active
            if active["kind"] == "tool_use":
                active["events"].append(event)
            if kind == "content_block_stop":
                result = []
                if active["kind"] == "tool_use":
                    self._tool_complete()
                else:
                    if active["kind"] == "text":
                        tail = active["restorer"].feed("", final=True)
                        if tail:
                            result += self._emit(self._delta(self._index, tail))
                    else:
                        self._candidate_trust.update(collect_trusted_opaque(active["block"]))
                    result += self._emit(event)
                self._active = None
                return result
            delta = value.get("delta")
            if not isinstance(delta, dict):
                raise PrivacyBlocked(_ERROR)
            delta_kind = delta.get("type")
            if active["kind"] == "text" and delta_kind == "text_delta":
                delta["text"] = active["restorer"].feed(delta.get("text"))
            elif active["kind"] == "tool_use" and delta_kind == "input_json_delta":
                if not isinstance(delta.get("partial_json"), str):
                    raise PrivacyBlocked(_ERROR)
                active["arguments"].append(delta["partial_json"])
                return []
            elif active["kind"] == "thinking" and delta_kind in {"thinking_delta", "signature_delta"}:
                field = "thinking" if delta_kind == "thinking_delta" else "signature"
                if not isinstance(delta.get(field), str):
                    raise PrivacyBlocked(_ERROR)
                block = active["block"]
                block[field] = block.get(field, "") + delta[field]
            else:
                raise PrivacyBlocked(_ERROR)
            return self._emit(event)
        if kind == "message_delta":
            if (self._active is not None or self._message_delta
                    or not isinstance(value.get("delta"), dict)):
                raise PrivacyBlocked(_ERROR)
            if not isinstance(value["delta"].get("stop_reason"), str):
                raise PrivacyBlocked(_ERROR)
            self._message_delta = True
            self._held_mode = True
            return self._emit(event)
        if kind == "message_stop":
            if self._active is not None or not self._message_delta:
                raise PrivacyBlocked(_ERROR)
            self._stopped = True
            self._held_mode = True
            return self._emit(event)
        raise PrivacyBlocked("Unsupported provider stream event.")

    def restore(self, chunks: Iterable[bytes]) -> Iterator[bytes]:
        for event in parse_events(chunks, self.maximum):
            yield from self._accept(event)
        if not self._started or not self._stopped or self._active is not None:
            raise PrivacyBlocked(_ERROR)
        self.trusted_opaque = self._candidate_trust
        yield from self._held
        self._held.clear()
