"""Session-local discovery hints for validated provider protocol values.

These hashes are not replay capabilities and never exempt data from redaction.
Only the response boundary may admit them after complete validation. Unknown
IDs and copies in content or arbitrary dictionaries stay in detector input.
Exact provider tool-call cores can also be omitted from their direct replay
slots: the provider already knows them. Tool results are always inspected.
This module never inspects authentication or opens a socket.
"""
from __future__ import annotations

from collections import OrderedDict
import hashlib
import json
import re
import threading


MAX_PROVIDER_IDS = 2048
MAX_PROVIDER_ID_CHARS = 256
MAX_PROVIDER_CORE_CHARS = 256 * 1024
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]*\Z")
_KINDS = frozenset({"anthropic.tool", "openai.message", "openai.function.item",
                    "openai.function.call", "openai.custom.item", "openai.custom.call",
                    "openai.function.core", "openai.custom.core"})


def _identity(kind, value):
    if (kind not in _KINDS or not isinstance(value, str)
            or not 1 <= len(value) <= MAX_PROVIDER_ID_CHARS or not _ID.fullmatch(value)):
        return None
    return kind, hashlib.sha256(value.encode("ascii")).digest()


class ProviderIdRegistry:
    """Bounded hash-only registry; callers must validate provenance first."""

    def __init__(self):
        self._entries = OrderedDict()
        self._lock = threading.Lock()

    def remember(self, identities):
        with self._lock:
            for identity in identities:
                if (not isinstance(identity, tuple) or len(identity) != 2
                        or not isinstance(identity[0], str) or identity[0] not in _KINDS
                        or type(identity[1]) is not bytes
                        or len(identity[1]) != 32):
                    continue
                self._entries[identity] = None
                self._entries.move_to_end(identity)
                while len(self._entries) > MAX_PROVIDER_IDS:
                    self._entries.popitem(last=False)

    def snapshot(self):
        with self._lock:
            return frozenset(self._entries)

    def clear(self):
        with self._lock:
            self._entries.clear()


def _call_core(item):
    """Strict known record shape; optional metadata is never part of an exemption."""
    if not isinstance(item, dict):
        return None
    kind = item.get("type")
    if kind == "function_call":
        field, family = "arguments", "openai.function"
    elif kind == "custom_tool_call" and item.get("name") == "apply_patch":
        field, family = "input", "openai.custom"
    else:
        return None
    required = {"type", "call_id", "name", field}
    if (not required <= item.keys() or item.keys() - required - {"namespace", "id", "status"}
            or _identity(family + ".call", item.get("call_id")) is None
            or not isinstance(item.get("name"), str) or not 1 <= len(item["name"]) <= 256
            or not isinstance(item.get(field), str) or len(item[field]) > MAX_PROVIDER_CORE_CHARS
            or ("namespace" in item and (not isinstance(item["namespace"], str)
                                         or not 1 <= len(item["namespace"]) <= 256))):
        return None
    # Metadata remains in discovery even when this exact core matches.
    core = {key: item[key] for key in ("type", "call_id", "name", "namespace", field) if key in item}
    return family + ".core", field, core


def _core_identity(kind, core):
    try:
        encoded = json.dumps(core, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError):
        return None
    return kind, hashlib.sha256(encoded).digest()


def _call_identities(item):
    result = _call_core(item)
    if result is None:
        return set()
    kind, field, core = result
    identity = _core_identity(kind, core)
    if identity is None:
        return set()
    identities = {identity}
    if field == "arguments":
        def pairs(values):
            value = {}
            for key, child in values:
                if key in value:
                    raise ValueError("Duplicate JSON key")
                value[key] = child
            return value
        def constant(_):
            raise ValueError("Nonfinite JSON value")
        try:
            # The rules-first sanitizer compacts embedded argument JSON. Store
            # precisely that serialization too: no sorted keys, value coercion,
            # or fuzzy comparison. Malformed/ambiguous JSON gets no exemption.
            parsed = json.loads(core[field], object_pairs_hook=pairs, parse_constant=constant)
            compact = json.dumps(parsed, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
            if len(compact) > MAX_PROVIDER_CORE_CHARS:
                return set()
            identities.add(_core_identity(kind, {**core, field: compact}))
        except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError):
            return set()
    return identities


def _item_ids(item):
    if not isinstance(item, dict):
        return set()
    kind = item.get("type")
    values = []
    if kind == "message" and item.get("role") == "assistant":
        values.append(("openai.message", item.get("id")))
    elif (kind == "function_call" and isinstance(item.get("name"), str)
          and isinstance(item.get("arguments"), str)):
        values.extend((("openai.function.item", item.get("id")),
                       ("openai.function.call", item.get("call_id"))))
    elif (kind == "custom_tool_call" and item.get("name") == "apply_patch"
          and isinstance(item.get("input"), str)):
        values.extend((("openai.custom.item", item.get("id")),
                       ("openai.custom.call", item.get("call_id"))))
    identities = {identity for kind, value in values if (identity := _identity(kind, value)) is not None}
    identities.update(_call_identities(item))
    return identities


def _anthropic_tool_ids(block):
    if (not isinstance(block, dict) or block.get("type") != "tool_use"
            or not isinstance(block.get("name"), str) or not isinstance(block.get("input"), dict)):
        return set()
    identity = _identity("anthropic.tool", block.get("id"))
    return {identity} if identity is not None else set()


def collect_response_ids(payload, provider):
    """Collect only direct response protocol slots, after response validation."""
    collected = ProviderIdRegistry()
    if not isinstance(payload, dict):
        return collected.snapshot()
    if provider in {"anthropic", "claude"}:
        if payload.get("type") == "message" and payload.get("role") == "assistant":
            content = payload.get("content")
            if isinstance(content, list):
                for block in content:
                    collected.remember(_anthropic_tool_ids(block))
    elif provider in {"openai", "codex"}:
        if (payload.get("object") == "response" and payload.get("status") == "completed"
                and payload.get("error") is None and payload.get("incomplete_details") is None):
            output = payload.get("output")
            if isinstance(output, list):
                for item in output:
                    collected.remember(_item_ids(item))
    return collected.snapshot()


def collect_event_ids(payload, provider):
    """Collect candidates from a raw event; admit only after validated EOF."""
    if not isinstance(payload, dict):
        return set()
    if provider in {"anthropic", "claude"} and payload.get("type") == "content_block_start":
        return _anthropic_tool_ids(payload.get("content_block"))
    if provider in {"openai", "codex"}:
        if payload.get("type") == "response.output_item.done":
            return _item_ids(payload.get("item"))
        if payload.get("type") == "response.completed":
            return collect_response_ids(payload.get("response"), provider)
    return set()


def discovery_view(payload, provider, trusted):
    """Omit proven IDs and exact tool cores from their direct replay slots only.

    Copy only affected protocol containers. The caller must run deterministic
    validation on the original payload before and after entity discovery.
    """
    if not trusted or not isinstance(payload, dict):
        return payload
    omitted = {}

    def omit(path):
        branch = omitted
        for component in path[:-1]:
            branch = branch.setdefault(component, {})
        branch[path[-1]] = None

    def mark(path, kind, value):
        if _identity(kind, value) in trusted:
            omit(path)

    if provider in {"openai", "codex"} and isinstance(payload.get("input"), list):
        for index, item in enumerate(payload["input"]):
            if not isinstance(item, dict):
                continue
            kind = item.get("type", "message")
            path = ("input", index)
            if kind == "message" and item.get("role") == "assistant":
                mark((*path, "id"), "openai.message", item.get("id"))
            elif kind in {"function_call", "custom_tool_call"}:
                family = "openai.function" if kind == "function_call" else "openai.custom"
                mark((*path, "id"), family + ".item", item.get("id"))
                mark((*path, "call_id"), family + ".call", item.get("call_id"))
                core = _call_core(item)
                if core is not None and _core_identity(core[0], core[2]) in trusted:
                    for field in core[2]:
                        omit((*path, field))
            elif kind in {"function_call_output", "custom_tool_call_output"}:
                family = "openai.function" if kind == "function_call_output" else "openai.custom"
                mark((*path, "call_id"), family + ".call", item.get("call_id"))
    elif provider in {"anthropic", "claude"} and isinstance(payload.get("messages"), list):
        for index, message in enumerate(payload["messages"]):
            if not isinstance(message, dict) or not isinstance(message.get("content"), list):
                continue
            for block_index, block in enumerate(message["content"]):
                if not isinstance(block, dict):
                    continue
                path = ("messages", index, "content", block_index)
                if message.get("role") == "assistant" and block.get("type") == "tool_use":
                    mark((*path, "id"), "anthropic.tool", block.get("id"))
                elif message.get("role") == "user" and block.get("type") == "tool_result":
                    mark((*path, "tool_use_id"), "anthropic.tool", block.get("tool_use_id"))

    def project(value, changes):
        result = value.copy()
        for field, descendants in changes.items():
            if descendants is None:
                del result[field]
            else:
                result[field] = project(result[field], descendants)
        return result

    return project(payload, omitted) if omitted else payload
