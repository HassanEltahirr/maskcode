"""Strict validation for the Codex Responses stream with an absent MIME header.

This is a narrow content-type fallback, not a general SSE content sniffer. It
does not restore values, execute tools, log content, or contact a provider.
"""
from __future__ import annotations

import json
import math
import re

from .protocol import PrivacyBlocked


MAX_STREAM_BYTES = 32 * 1024 * 1024
MAX_JSON_DEPTH = 64
MAX_JSON_NODES = 250000
MAX_EVENTS = 100000
_FAILURE = "Codex returned an invalid or incomplete event stream. Nothing was executed."
_EVENT_NAME = re.compile(r"[A-Za-z0-9_.-]{1,128}\Z")
_SAFE_ID = re.compile(r"[A-Za-z0-9_.:/-]{0,256}\Z")
_SURROGATE = re.compile(r"[\ud800-\udfff]")
_EVENTS = frozenset({
    "response.created", "response.queued", "response.in_progress", "response.completed",
    "response.output_item.added", "response.output_item.done",
    "response.content_part.added", "response.content_part.done",
    "response.output_text.delta", "response.output_text.done",
    "response.output_text.annotation.added",
    "response.refusal.delta", "response.refusal.done",
    "response.function_call_arguments.delta", "response.function_call_arguments.done",
    "response.custom_tool_call_input.delta", "response.custom_tool_call_input.done",
    "response.reasoning_summary_part.added", "response.reasoning_summary_part.done",
    "response.reasoning_summary_text.delta", "response.reasoning_summary_text.done",
    "response.reasoning_text.delta", "response.reasoning_text.done",
    "codex.rate_limits",
})
_FAILED = frozenset({"failed", "incomplete", "cancelled", "canceled"})
_EXECUTABLE_METADATA_KEYS = frozenset({
    "arguments", "input", "output", "item", "content", "messages", "response", "delta",
    "tool_calls", "function_call", "custom_tool_call", "call_id", "tool_use_id",
})


def _strict_object(text):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError()
            result[key] = value
        return result

    def number(value):
        result = float(value)
        if not math.isfinite(result):
            raise ValueError()
        return result

    def constant(_):
        raise ValueError()

    result = json.loads(text, object_pairs_hook=pairs, parse_float=number, parse_constant=constant)
    if not isinstance(result, dict):
        raise ValueError()
    pending, nodes = [(result, 0)], 0
    while pending:
        value, depth = pending.pop()
        nodes += 1
        if depth > MAX_JSON_DEPTH or nodes > MAX_JSON_NODES:
            raise ValueError()
        if isinstance(value, dict):
            if any(_SURROGATE.search(key) for key in value):
                raise ValueError()
            pending.extend((child, depth + 1) for child in value.values())
        elif isinstance(value, list):
            pending.extend((child, depth + 1) for child in value)
        elif isinstance(value, str) and _SURROGATE.search(value):
            raise ValueError()
    return result


def _rate_metadata_only(payload):
    pending = [payload]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            if set(value) & _EXECUTABLE_METADATA_KEYS:
                raise ValueError()
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)


def validate_codex_sse(data):
    """Accept one complete, framed Codex response or raise a fixed safe error.

    The caller must restrict this fallback to an expected streamed Codex
    ``/responses`` request whose Content-Type header is absent. Explicit HTML or
    other unsupported MIME types must not use this fallback.
    """
    try:
        if not isinstance(data, bytes) or not data or len(data) > MAX_STREAM_BYTES:
            raise ValueError()
        text = data.decode("utf-8-sig").replace("\r\n", "\n")
        if "\r" in text:
            raise ValueError()
        lines = text.split("\n")
        if text.endswith("\n"):
            lines.pop()  # This final sentinel is not a terminating blank line.
        fields, data_lines = {}, []
        completed = done = False
        count = 0
        response_id = None

        def finish():
            nonlocal completed, done, count, response_id
            if not data_lines:
                if "event" in fields:
                    raise ValueError()
                return
            count += 1
            if count > MAX_EVENTS or done:
                raise ValueError()
            body = "\n".join(data_lines)
            if body == "[DONE]":
                if not completed or "event" in fields:
                    raise ValueError()
                done = True
                return
            payload = _strict_object(body)
            kind = payload.get("type")
            if not isinstance(kind, str) or kind not in _EVENTS:
                raise ValueError()
            if "event" in fields and fields["event"] != kind:
                raise ValueError()
            if payload.get("error") is not None:
                raise ValueError()
            if completed and kind != "codex.rate_limits":
                raise ValueError()
            if kind == "codex.rate_limits":
                _rate_metadata_only(payload)
                return
            response = payload.get("response")
            if response is not None:
                if (not isinstance(response, dict) or response.get("error") is not None
                        or response.get("incomplete_details") is not None):
                    raise ValueError()
                if response.get("status") in _FAILED:
                    raise ValueError()
                if "id" in response:
                    ident = response["id"]
                    if not isinstance(ident, str) or not ident or (response_id is not None and ident != response_id):
                        raise ValueError()
                    response_id = ident
            item = payload.get("item")
            if isinstance(item, dict) and item.get("status") in _FAILED:
                raise ValueError()
            if kind == "response.completed":
                if not isinstance(response, dict) or response.get("status", "completed") != "completed":
                    raise ValueError()
                completed = True

        for line in lines:
            if not line:
                finish()
                fields, data_lines = {}, []
                continue
            if line.startswith(":"):
                continue
            field, separator, value = line.partition(":")
            if not separator and field != "data":
                raise ValueError()
            value = value.removeprefix(" ")
            if field == "data":
                data_lines.append(value)
            elif field == "event":
                if field in fields or _EVENT_NAME.fullmatch(value) is None:
                    raise ValueError()
                fields[field] = value
            elif field == "id":
                if field in fields or _SAFE_ID.fullmatch(value) is None:
                    raise ValueError()
                fields[field] = value
            elif field == "retry":
                if field in fields or not re.fullmatch(r"[0-9]{1,7}", value) or int(value) > 3600000:
                    raise ValueError()
                fields[field] = value
            else:
                raise ValueError()
        if data_lines or "event" in fields or not completed:
            raise ValueError()
    except Exception:
        raise PrivacyBlocked(_FAILURE) from None
