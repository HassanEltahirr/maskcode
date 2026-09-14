"""Incremental Codex display text; executable events remain gated on clean EOF.

Opaque reasoning stays byte-for-byte intact and in its native event order, but
does not become trusted replay context until the whole response validates.
"""
from __future__ import annotations

import codecs
import copy
import re

from .codex_stream import (MAX_EVENTS, MAX_STREAM_BYTES, _EVENT_NAME, _EVENTS,
                           _FAILED, _FAILURE, _SAFE_ID, _rate_metadata_only,
                           _strict_object, validate_codex_sse)
from .protocol import (PrivacyBlocked, _Event, _parse_sse,
                       collect_sse_trusted_opaque, restore_response, restore_sse)
from .streaming import TextRestorer
from .provider_ids import ProviderIdRegistry, collect_event_ids


def _packet(lines):
    fields, data = {}, []
    for line in lines:
        if line.startswith(":"):
            continue
        name, separator, value = line.partition(":")
        value = value.removeprefix(" ")
        if not separator and name != "data":
            raise ValueError()
        if name == "data":
            data.append(value)
            continue
        if name in fields:
            raise ValueError()
        if name == "event" and _EVENT_NAME.fullmatch(value):
            pass
        elif name == "id" and _SAFE_ID.fullmatch(value):
            pass
        elif name == "retry" and re.fullmatch(r"[0-9]{1,7}", value) and int(value) <= 3600000:
            pass
        else:
            raise ValueError()
        fields[name] = value
    if not data:
        if "event" in fields:
            raise ValueError()
        return _Event(lines)
    body = "\n".join(data)
    if body == "[DONE]":
        if "event" in fields:
            raise ValueError()
        return _Event(lines)
    payload = _strict_object(body)
    kind = payload.get("type")
    if kind not in _EVENTS or ("event" in fields and fields["event"] != kind):
        raise ValueError()
    if payload.get("error") is not None:
        raise ValueError()
    response = payload.get("response")
    if response is not None:
        if (not isinstance(response, dict) or response.get("error") is not None
                or response.get("incomplete_details") is not None or response.get("status") in _FAILED):
            raise ValueError()
    item = payload.get("item")
    if isinstance(item, dict) and item.get("status") in _FAILED:
        raise ValueError()
    if kind == "response.completed" and (not isinstance(response, dict)
            or response.get("status", "completed") != "completed"):
        raise ValueError()
    if kind == "codex.rate_limits":
        _rate_metadata_only(payload)
    return _Event(lines, payload, True)


def _events(chunks, maximum):
    """Strict SSE framing across UTF-8 and CRLF transport boundaries."""
    decoder = codecs.getincrementaldecoder("utf-8-sig")("strict")
    pending, lines, size, count = "", [], 0, 0
    try:
        for chunk in chunks:
            if not isinstance(chunk, bytes):
                raise ValueError()
            size += len(chunk)
            if size > maximum:
                raise ValueError()
            pending += decoder.decode(chunk)
            while "\n" in pending:
                line, pending = pending.split("\n", 1)
                line = line.removesuffix("\r")
                if "\r" in line:
                    raise ValueError()
                if line:
                    lines.append(line)
                elif lines:
                    count += 1
                    if count > MAX_EVENTS:
                        raise ValueError()
                    yield _packet(lines)
                    lines = []
        pending += decoder.decode(b"", final=True)
        if "\r" in pending:
            raise ValueError()
        if pending:
            lines.append(pending)
        if lines:
            # Only harmless comment/id/retry trailers may lack a blank line.
            if any(line == "data" or line.startswith(("data:", "event:")) for line in lines):
                raise ValueError()
            yield _packet(lines)
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError):
        raise PrivacyBlocked(_FAILURE) from None


_TEXT = {"response.output_text": "text", "response.refusal": "refusal",
         "response.reasoning_summary_text": "text", "response.reasoning_text": "text"}
_PART_TEXT = {"output_text": "response.output_text", "refusal": "response.refusal",
              "summary_text": "response.reasoning_summary_text", "reasoning_text": "response.reasoning_text"}
_TOOL_KEYS = frozenset({"arguments", "input", "call_id", "tool_calls", "tool_use_id"})


def _part_lane(payload):
    kind = payload.get("type", "")
    if kind not in {"response.content_part.added", "response.content_part.done",
                    "response.reasoning_summary_part.added", "response.reasoning_summary_part.done"}:
        return None
    part = payload.get("part")
    if not isinstance(part, dict):
        return None
    return _PART_TEXT.get(part.get("type"))


def _executable(value):
    if isinstance(value, dict):
        kind = value.get("type", "")
        if set(value) & _TOOL_KEYS or (isinstance(kind, str)
                and (kind.endswith("_call") or kind in {"tool_use", "function"})):
            return True
        return any(_executable(child) for child in value.values())
    return isinstance(value, list) and any(_executable(child) for child in value)


class CodexStream:
    """Single-use restorer: display can precede EOF, tools and success cannot."""
    def __init__(self, redactor, maximum=MAX_STREAM_BYTES):
        self.redactor, self.maximum = redactor, maximum
        self.trusted_opaque = set()
        self.trusted_provider_ids = frozenset()
        self._trie = TextRestorer(redactor).trie
        self._lanes, self._identities = {}, {}
        self._written = 0

    def _identity(self, payload):
        return payload.get("item_id", self._identities.get(payload.get("output_index", 0),
                                                           payload.get("output_index", 0)))

    def _key(self, payload, prefix):
        return (self._identity(payload), payload.get("summary_index", payload.get("content_index", 0)), prefix)

    def _new_lane(self, template):
        return {"restorer": TextRestorer(self.redactor, self._trie),
                "raw": [], "template": template, "closed": False}

    def _finish_lane(self, lane, text):
        if not isinstance(text, str) or text != "".join(lane["raw"]):
            raise PrivacyBlocked(_FAILURE)
        return self._flush(lane)

    def _flush(self, lane):
        if lane["closed"]:
            return []
        lane["closed"] = True
        text = lane["restorer"].feed("", final=True)
        if not text:
            return []
        payload = copy.deepcopy(lane["template"])
        # This local suffix event has no provider sequence number.
        payload.pop("sequence_number", None)
        payload["delta"] = text
        return [_Event(["event: " + payload["type"], "data:"], payload, True)]

    def _transform(self, event):
        before = []
        if not event.has_json:
            return before, event
        raw = event.payload
        kind = raw["type"]
        item = raw.get("item")
        prefix, _, suffix = kind.rpartition(".")
        part_prefix = _part_lane(raw)
        if (prefix in _TEXT or part_prefix is not None) and _executable(raw):
            raise PrivacyBlocked(_FAILURE)
        if kind == "response.completed":
            # A response can finish with tools in its final output and omit a
            # text.done copy. Flush display suffixes before the tool shortcut.
            for lane in self._lanes.values():
                before.extend(self._flush(lane))
        if kind == "response.output_item.added" and isinstance(item, dict) and "id" in item:
            index = raw.get("output_index", 0)
            if index in self._identities and self._identities[index] != item["id"]:
                raise PrivacyBlocked(_FAILURE)
            self._identities[index] = item["id"]
        # Tool restoration requires complete argument/patch lanes and is done
        # once by restore_sse after EOF, never on an incomplete delta here.
        if _executable(raw) or kind.startswith(("response.function_call_arguments.", "response.custom_tool_call_input.")):
            return before, event
        transformed = _Event(event.lines, restore_response(raw, self.redactor, "openai"), True)
        if part_prefix is not None:
            key = self._key(raw, part_prefix)
            field = _TEXT[part_prefix]
            text = raw["part"].get(field)
            if suffix == "added":
                if key in self._lanes or not isinstance(text, str):
                    raise PrivacyBlocked(_FAILURE)
                template = {name: value for name, value in raw.items() if name != "part"}
                template["type"] = part_prefix + ".delta"
                lane = self._new_lane(template)
                self._lanes[key] = lane
                lane["raw"].append(text)
                transformed.payload["part"][field] = lane["restorer"].feed(text)
            elif key in self._lanes:
                # Flush before the part closes even when the provider omits
                # the separate output_text/refusal/reasoning_text.done event.
                before.extend(self._finish_lane(self._lanes[key], text))
        if prefix in _TEXT:
            key = self._key(raw, prefix)
            if suffix == "delta":
                if not isinstance(raw.get("delta"), str):
                    raise PrivacyBlocked(_FAILURE)
                lane = self._lanes.setdefault(key, self._new_lane(raw))
                if lane["closed"]:
                    raise PrivacyBlocked(_FAILURE)
                lane["raw"].append(raw["delta"])
                lane["template"] = raw
                transformed.payload["delta"] = lane["restorer"].feed(raw["delta"])
            elif suffix == "done" and key in self._lanes:
                lane = self._lanes[key]
                before.extend(self._finish_lane(lane, raw.get(_TEXT[prefix])))
        if kind == "response.output_item.done" and isinstance(item, dict):
            identity = item.get("id", self._identity(raw))
            for key, lane in self._lanes.items():
                if key[0] == identity:
                    before.extend(self._flush(lane))
        return before, transformed

    def _encode(self, event):
        data = event.encode()
        self._written += len(data)
        if self._written > self.maximum:
            raise PrivacyBlocked("Restored provider stream exceeds the supported size.")
        return data

    def restore(self, chunks):
        original, transformed, prefixes = [], [], []
        held = None
        try:
            for event in _events(chunks, self.maximum):
                index = len(original)
                raw = event.payload if event.has_json else {}
                kind = raw.get("type", "")
                item = raw.get("item", {})
                if (held is None and (not event.has_json
                        or kind == "response.completed" or _executable(raw)
                        or kind.startswith(("response.function_call_arguments.", "response.custom_tool_call_input."))
                        or (kind.startswith("response.output_item.") and
                            (not isinstance(item, dict) or item.get("type") not in {"message", "reasoning"}))
                        or (isinstance(raw.get("response"), dict) and raw["response"].get("output")))):
                    # Comment heartbeats do not hold back later display events.
                    if event.has_json or any(line.startswith("data") for line in event.lines):
                        held = index
                before, restored = self._transform(event)
                original.append(event)
                transformed.append(restored)
                prefixes.append(before)
                if held is None:
                    for output in [*before, restored]:
                        yield self._encode(output)
            data = b"".join(event.encode() for event in original)
            validate_codex_sse(data)
            # Validate every complete tool lane, every completed copy, and all
            # patch framing/restoration before releasing even a tool's start.
            validated = _parse_sse(restore_sse(data, self.redactor, "openai"))
            if len(validated) != len(original):
                raise PrivacyBlocked(_FAILURE)
            ready = []
            for index in range(held if held is not None else len(original), len(original)):
                raw = original[index].payload if original[index].has_json else {}
                prefix, _, suffix = raw.get("type", "").rpartition(".")
                incremental_text = ((prefix in _TEXT and suffix == "delta") or
                                    (_part_lane(raw) is not None and suffix == "added"))
                event = transformed[index] if incremental_text else validated[index]
                for output in [*prefixes[index], event]:
                    ready.append(self._encode(output))
            self.trusted_opaque = collect_sse_trusted_opaque(data, "openai")
            identities = ProviderIdRegistry()
            for event in original:
                if event.has_json:
                    identities.remember(collect_event_ids(event.payload, "openai"))
            self.trusted_provider_ids = identities.snapshot()
            yield from ready
        except PrivacyBlocked:
            raise
        except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError, KeyError):
            raise PrivacyBlocked(_FAILURE) from None
