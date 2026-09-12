"""Conservative JSON/SSE boundary for a local privacy gateway.

Only provider-origin, byte-equivalent opaque reasoning blocks may be replayed.
The shared JSON boundary and buffered SSE fallback live here. Production
Anthropic responses use the incremental text / validated-tool implementation
in streaming.py; other provider streams remain buffered at most 32 MiB.
"""

from __future__ import annotations

import copy
import json
import math
from dataclasses import dataclass
from typing import Any

from .shell_restore import ShellRestoreBlocked, restore_simple_command
from .redaction import SensitiveValueError


MAX_SSE_BYTES = 32 * 1024 * 1024


class PrivacyBlocked(ValueError):
    """A safe-to-display error: never includes request values or credentials."""

    def __init__(self, reason: str = "Request blocked by privacy policy.") -> None:
        self.reason = reason
        super().__init__(reason)


_OPAQUE_TYPES = {"thinking", "redacted_thinking", "reasoning"}
_OPAQUE_KEYS = {"signature", "encrypted_content", "encrypted_reasoning"}
_MEDIA_KEYS = {
    "image_url", "audio_url", "video_url", "file_url", "file_id", "file_data",
    "input_audio", "media_type", "attachments", "attachment", "images",
    "audio", "video", "files", "mcp_servers",
}
_BLOCKED_TYPES = {
    "image", "image_url", "input_image", "output_image", "document", "file",
    "input_file", "audio", "input_audio", "output_audio", "video", "base64",
    "url", "item_reference", "server_tool_use", "web_search_tool_result",
    "web_fetch_tool_result", "code_execution_tool_result", "container_upload",
    "compaction", "tool_search_tool_result", "mcp_tool_use", "mcp_tool_result",
}
_CONTENT_TYPES = {"text", "input_text", "output_text", "tool_use", "tool_result",
                  "refusal"} | _OPAQUE_TYPES
_INPUT_TYPES = {"message", "function_call", "function_call_output", "custom_tool_call", "custom_tool_call_output"} | _OPAQUE_TYPES
_IDENTITIES = {"model", "type", "role", "id", "tool_use_id", "call_id", "name", "namespace"}
_STRUCTURAL_KEYS = {
    "model", "messages", "input", "output", "content", "system", "instructions", "tools",
    "type", "role", "id", "tool_use_id", "call_id", "name", "text", "source",
    "input_schema", "parameters", "arguments", "function", "tool_choice",
    "max_tokens", "max_output_tokens", "stream", "thinking", "cache_control",
}
_DROP_TOP_LEVEL = {"metadata", "client_metadata", "user", "safety_identifier", "prompt_cache_key"}
_STATE_REFERENCES = {"previous_response_id", "conversation", "container"}
_EXECUTABLE_FIELDS = {"command", "cmd", "code", "script"}
_EXECUTABLE_TOOLS = {"bash", "shell", "exec_command", "python", "python3",
                     "run_code", "execute_code", "run_python", "terminal"}

# Fixed public protocol/schema vocabulary is not a confidential entity merely
# because a small local model labels it one. Explicit policies and deterministic
# secret detection still apply to it and can block an incompatible request.
# Unknown names, schema keys, and content remain eligible for local discovery.
PUBLIC_PROTOCOL_TERMS = frozenset(_STRUCTURAL_KEYS | _IDENTITIES | _CONTENT_TYPES | _INPUT_TYPES | {
    "function", "namespace", "custom", "grammar", "lark", "json_schema",
    "object", "string", "number", "integer", "boolean", "array", "null",
    "true", "false", "low", "medium", "high", "xhigh", "max", "minimal", "none", "auto", "any",
    "properties", "additionalProperties", "description", "title", "items", "required",
    "format", "syntax", "definition", "strict", "enum", "default", "minimum", "maximum",
    "parallel_tool_calls", "reasoning", "effort", "store", "include", "verbosity",
    "application/json", "text/event-stream", "identity", "codex_cli_rs",
})


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False)


def _opaque(value: Any) -> bool:
    return (isinstance(value, dict) and isinstance(value.get("type"), str)
            and value["type"] in _OPAQUE_TYPES)


def collect_trusted_opaque(payload: Any) -> set[str]:
    """Call only with responses received from the configured provider.

    Never call this on a client request. The returned set is a capability cache,
    not a redaction detector: possession allows an exact opaque block to replay.
    """
    result: set[str] = set()

    def visit(value: Any) -> None:
        if _opaque(value):
            result.add(_canonical(value))
            return
        if isinstance(value, dict):
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(payload)
    return result


def readable_fragments(payload: Any) -> list[str]:
    """Raw readable strings for local entity detection after protocol validation.

    Provider-signed opaque blocks are excluded. Embedded JSON is decoded so a
    discovered name containing quotes or Unicode can match its actual original.
    Data keys are included too; the detector cannot create a hidden key channel.
    """
    fragments = []

    def visit(value, depth=0):
        if depth > 64:
            raise PrivacyBlocked("Local inspection structure exceeds the supported depth.")
        if _opaque(value):
            return
        if isinstance(value, str):
            if value.lstrip().startswith(("{", "[")):
                try:
                    decoded = json.loads(value)
                except (ValueError, RecursionError):
                    pass
                else:
                    visit(decoded, depth + 1)
                    return
            if value and value not in PUBLIC_PROTOCOL_TERMS:
                fragments.append(value)
        elif isinstance(value, dict):
            for key, child in value.items():
                if key not in PUBLIC_PROTOCOL_TERMS:
                    visit(key, depth + 1)
                visit(child, depth + 1)
        elif isinstance(value, list):
            for child in value:
                visit(child, depth + 1)
        elif isinstance(value, (int, float)) and not isinstance(value, bool):
            fragments.append(str(value))

    visit(payload)
    return fragments


def sanitize_payload(payload: dict, redactor: Any, provider: str,
                     trusted_opaque: set[str] | None = None) -> dict:
    """Redact all readable request data, rejecting unsupported transport features.

    Custom local function tools are accepted. Attachments, hosted tools, remote
    conversation references, and unproven opaque reasoning are rejected. Textual
    URLs are ordinary text and are passed through the configured redactor.
    """
    if not isinstance(payload, dict):
        raise PrivacyBlocked("Expected a JSON request object.")
    trusted = trusted_opaque or set()
    normalized = str(provider).lower()
    if normalized not in {"anthropic", "claude", "openai"}:
        raise PrivacyBlocked("Unsupported provider protocol.")

    tools = payload.get("tools", [])
    if not isinstance(tools, list):
        raise PrivacyBlocked("Unsupported tool configuration.")
    def validate_tool(tool, depth=0):
        if not isinstance(tool, dict):
            raise PrivacyBlocked("Unsupported tool configuration.")
        if depth > 4:
            raise PrivacyBlocked("Tool namespaces exceed the supported depth.")
        kind = tool.get("type")
        if normalized in {"anthropic", "claude"}:
            allowed = (kind is None or kind == "custom") and isinstance(tool.get("input_schema"), dict)
        elif kind == "namespace":
            nested = tool.get("tools")
            if not isinstance(tool.get("name"), str) or not isinstance(nested, list) or not nested:
                raise PrivacyBlocked("Unsupported tool namespace.")
            for child in nested:
                validate_tool(child, depth + 1)
            return
        elif kind == "custom":
            form = tool.get("format", {})
            allowed = (tool.get("name") == "apply_patch" and isinstance(form, dict)
                       and form.get("type") == "grammar" and form.get("syntax") == "lark"
                       and isinstance(form.get("definition"), str))
        else:
            allowed = kind == "function"
        if not allowed:
            raise PrivacyBlocked("Hosted or unsupported tools are blocked.")
    for tool in tools:
        validate_tool(tool)

    def walk(value: Any, path: tuple = (), data_context: bool = False) -> Any:
        if isinstance(value, str):
            # The Redactor also understands JSON encoded inside string fields.
            return redactor.redact_json(value)
        if isinstance(value, list):
            return [walk(child, path + (index,), data_context)
                    for index, child in enumerate(value)]
        if not isinstance(value, dict):
            if isinstance(value, float) and not math.isfinite(value):
                raise PrivacyBlocked("Unsupported JSON value.")
            if value is None or isinstance(value, (bool, int, float)):
                return redactor.redact_json(value)
            raise PrivacyBlocked("Unsupported JSON value.")
        if _opaque(value):
            if _canonical(value) not in trusted:
                raise PrivacyBlocked("Unverified opaque reasoning is blocked.")
            return copy.deepcopy(value)
        kind = value.get("type")
        if kind == "custom_tool_call" and (value.get("name") != "apply_patch" or not isinstance(value.get("input"), str)):
            raise PrivacyBlocked("Unsupported custom tool call.")
        if isinstance(kind, str) and (kind in _BLOCKED_TYPES or
                kind.startswith(("web_search", "web_fetch", "computer_", "mcp_",
                                 "code_execution", "file_search", "image_generation"))):
            raise PrivacyBlocked("Media, references, or hosted content are blocked.")
        if not data_context and isinstance(value.get("content"), list):
            for block in value["content"]:
                if isinstance(block, dict) and (not isinstance(block.get("type"), str)
                        or block["type"] not in _CONTENT_TYPES):
                    raise PrivacyBlocked("Unsupported content block is blocked.")
        if not path and isinstance(value.get("input"), list):
            for block in value["input"]:
                if isinstance(block, dict) and (not isinstance(block.get("type", "message"), str)
                        or block.get("type", "message") not in _INPUT_TYPES):
                    raise PrivacyBlocked("Unsupported input item is blocked.")
        result = {}
        for key, child in value.items():
            if not isinstance(key, str):
                raise PrivacyBlocked("Expected string JSON keys.")
            if not path and key in _DROP_TOP_LEVEL:
                continue
            if key in _OPAQUE_KEYS and child not in (None, ""):
                raise PrivacyBlocked("Unverified opaque data is blocked.")
            if key in _MEDIA_KEYS and child not in (None, "", [], {}):
                raise PrivacyBlocked("Media, references, or hosted content are blocked.")
            if not path and key in _STATE_REFERENCES and child not in (None, "", {}, []):
                raise PrivacyBlocked("Remote conversation state is blocked.")
            clean_key = redactor.redact_text(key)
            if not data_context and key in _STRUCTURAL_KEYS and clean_key != key:
                raise PrivacyBlocked("A protocol identifier contains protected data.")
            if clean_key in result:
                raise PrivacyBlocked("Redaction would create ambiguous JSON keys.")
            child_data = data_context or key in {"input_schema", "parameters", "arguments"}
            child_data = child_data or (key == "input" and isinstance(child, dict))
            if key == "arguments" and isinstance(child, str) and child:
                try:
                    parsed = json.loads(child)
                except (ValueError, RecursionError):
                    raise PrivacyBlocked("Malformed request tool arguments.") from None
                result[clean_key] = json.dumps(walk(parsed, path + (key,), True),
                    ensure_ascii=False, separators=(",", ":"), allow_nan=False)
            elif not data_context and key in _IDENTITIES and isinstance(child, str):
                cleaned = redactor.redact_text(child)
                if cleaned != child:
                    raise PrivacyBlocked("A protocol identifier contains protected data.")
                result[clean_key] = child
            elif isinstance(child, (str, int, float)) and not isinstance(child, bool):
                # Preserve dictionary context: {"password": "short-secret"}
                # cannot be recognized by scanning the isolated value alone.
                contextual = redactor.redact_json({key: child})
                result[clean_key] = next(iter(contextual.values()))
            else:
                result[clean_key] = walk(child, path + (key,), child_data)
        return result

    try:
        # Discover contextual secrets throughout readable request data first.
        # Revisit the original payload so earlier mentions are concealed and
        # protocol identifiers are revalidated against newly learned secrets.
        # Dropped metadata and trusted opaque blocks remain outside discovery.
        walk(payload)
        clean = walk(payload)
        # Auth is outside this body, and signed provider-origin reasoning is
        # admitted only by exact provenance. Everything readable gets a second
        # residual-data check after discovery and structural validation.
        def readable(value):
            if _opaque(value):
                return None
            if isinstance(value, dict):
                return {key: readable(child) for key, child in value.items()}
            if isinstance(value, list):
                return [readable(child) for child in value]
            return value
        redactor.assert_sanitized(readable(clean))
        return clean
    except SensitiveValueError as exc:
        raise PrivacyBlocked(str(exc)) from None
    except (RecursionError, OverflowError, TypeError):
        raise PrivacyBlocked("Unsupported JSON structure.") from None


def _restore_tool_data(value: Any, redactor: Any, tool_name: Any = None) -> Any:
    """Do not turn a harmless placeholder into executable shell/code syntax.

    Structured file paths and file content can be restored. Native Bash permits
    a narrow set of simple reading/navigation commands with quoted operands;
    general shell programs and interpreter source still fail closed.
    """
    try:
        restored = redactor.restore_json(copy.deepcopy(value))
    except SensitiveValueError as exc:
        raise PrivacyBlocked(str(exc)) from None
    safe_bash = False
    safe_command_field = "command"
    if (isinstance(tool_name, str) and tool_name.lower() in _EXECUTABLE_TOOLS
            and restored != value):
        if (tool_name == "Bash" and isinstance(value, dict)
                and isinstance(value.get("command"), str)
                and set(value) <= {"command", "description", "timeout", "run_in_background"}):
            try:
                if restored["command"] != value["command"]:
                    restored["command"] = restore_simple_command(value["command"], redactor)
                safe_bash = True
            except ShellRestoreBlocked:
                raise PrivacyBlocked("Restoration in this shell command is blocked; use structured file tools or a simple file-reading command.") from None
        elif (tool_name == "exec_command" and isinstance(value, dict)
              and isinstance(value.get("cmd"), str)
              and set(value) <= {"cmd", "workdir", "yield_time_ms", "max_output_tokens", "tty", "login",
                                 "shell", "sandbox_permissions", "justification", "prefix_rule"}
              and value.get("shell") == restored.get("shell")
              and value.get("prefix_rule") == restored.get("prefix_rule")):
            try:
                if restored["cmd"] != value["cmd"]:
                    restored["cmd"] = restore_simple_command(value["cmd"], redactor)
                safe_bash = True
                safe_command_field = "cmd"
            except ShellRestoreBlocked:
                raise PrivacyBlocked("Restoration in this shell command is blocked; use apply_patch or a simple file-reading command.") from None
        else:
            raise PrivacyBlocked("Restoration inside executable tool arguments is blocked.")

    def check(original: Any, changed: Any) -> None:
        if isinstance(original, dict) and isinstance(changed, dict):
            for key, child in original.items():
                changed_key = redactor.restore_text(key)
                other = changed.get(changed_key)
                if ({key.lower(), changed_key.lower()} & _EXECUTABLE_FIELDS
                        and child != other and not (safe_bash and original is value and key == safe_command_field)):
                    raise PrivacyBlocked("Restoration inside executable tool arguments is blocked.")
                check(child, other)
        elif isinstance(original, list) and isinstance(changed, list):
            for child, other in zip(original, changed):
                check(child, other)
        elif isinstance(original, str) and isinstance(changed, str) and original != changed:
            # The redactor restores JSON-in-string values too; carry the same
            # command restriction through those nested serialization layers.
            if original.lstrip().startswith(("{", "[")):
                try:
                    before, after = json.loads(original), json.loads(changed)
                except (ValueError, RecursionError):
                    return
                check(before, after)

    check(value, restored)
    return restored


def _restore_arguments(arguments: str, redactor: Any, tool_name: Any = None) -> str:
    if not arguments:
        return arguments
    try:
        parsed = json.loads(arguments)
        return json.dumps(_restore_tool_data(parsed, redactor, tool_name), ensure_ascii=False,
                          separators=(",", ":"), allow_nan=False)
    except PrivacyBlocked:
        raise
    except (ValueError, TypeError, RecursionError):
        raise PrivacyBlocked("Malformed provider tool arguments.") from None


def _restore_patch_input(text, redactor, tool_name):
    if tool_name != "apply_patch" or not isinstance(text, str):
        raise PrivacyBlocked("Unsupported custom tool response.")
    if text == "":
        return ""
    from .patch_restore import restore_patch, PatchRestoreBlocked
    try:
        return restore_patch(text, redactor)
    except PatchRestoreBlocked:
        raise PrivacyBlocked("Unsafe or incomplete patch restoration was blocked.") from None


def restore_response(payload: Any, redactor: Any, provider: str = "anthropic") -> Any:
    """Restore display text and local tool arguments; preserve protocol/opaque data."""
    chat_delta = isinstance(payload, dict) and payload.get("object") == "chat.completion.chunk"
    def visit(value: Any) -> Any:
        if isinstance(value, list):
            return [visit(child) for child in value]
        if not isinstance(value, dict):
            return copy.deepcopy(value)
        if _opaque(value):
            return copy.deepcopy(value)
        result = {}
        for key, child in value.items():
            if key in _OPAQUE_KEYS:
                result[key] = copy.deepcopy(child)
            elif key == "arguments" and isinstance(child, str) and not chat_delta:
                result[key] = _restore_arguments(child, redactor, value.get("name"))
            elif key == "input" and value.get("type") == "tool_use":
                result[key] = _restore_tool_data(child, redactor, value.get("name"))
            elif key == "input" and value.get("type") == "custom_tool_call":
                result[key] = _restore_patch_input(child, redactor, value.get("name"))
            elif key in {"text", "output_text", "refusal"} and isinstance(child, str):
                result[key] = redactor.restore_text(child)
            elif key == "content" and isinstance(child, str):
                result[key] = redactor.restore_text(child)
            else:
                result[key] = visit(child)
        return result

    try:
        return visit(payload)
    except SensitiveValueError as exc:
        raise PrivacyBlocked(str(exc)) from None
    except (RecursionError, TypeError):
        raise PrivacyBlocked("Unsupported provider response.") from None


@dataclass
class _Event:
    lines: list[str]
    payload: Any = None
    has_json: bool = False

    def encode(self) -> bytes:
        if not self.has_json:
            return ("\n".join(self.lines) + "\n\n").encode("utf-8")
        data = "data: " + json.dumps(self.payload, ensure_ascii=False,
                                      separators=(",", ":"), allow_nan=False)
        lines = []
        emitted = False
        for line in self.lines:
            if line == "data" or line.startswith("data:"):
                if not emitted:
                    lines.append(data)
                    emitted = True
            else:
                lines.append(line)
        return ("\n".join(lines) + "\n\n").encode("utf-8")


def _parse_sse(data: bytes) -> list[_Event]:
    if not isinstance(data, bytes) or len(data) > MAX_SSE_BYTES:
        raise PrivacyBlocked("Provider stream exceeds the supported size.")
    try:
        text = data.decode("utf-8-sig").replace("\r\n", "\n").replace("\r", "\n")
        events = []
        for packet in text.split("\n\n"):
            if not packet.strip():
                continue
            lines = packet.split("\n")
            event = _Event(lines)
            parts = []
            for line in lines:
                if line == "data":
                    parts.append("")
                elif line.startswith("data:"):
                    parts.append(line[5:].removeprefix(" "))
            if parts:
                joined = "\n".join(parts)
                if joined.strip() not in {"", "[DONE]"}:
                    event.payload = json.loads(joined)
                    event.has_json = True
            events.append(event)
        return events
    except (UnicodeError, ValueError, RecursionError):
        raise PrivacyBlocked("Malformed provider event stream.") from None


def collect_sse_trusted_opaque(data: bytes, provider: str) -> set[str]:
    """Collect opaque provider output, reconstructing signed Anthropic blocks."""
    result: set[str] = set()
    active: dict[int, dict] = {}
    for event in _parse_sse(data):
        value = event.payload
        if not event.has_json or not isinstance(value, dict):
            continue
        # Complete OpenAI reasoning items and full final response objects.
        if value.get("type") != "content_block_start":
            result.update(collect_trusted_opaque(value))
        kind = value.get("type")
        index = value.get("index")
        if kind == "content_block_start" and _opaque(value.get("content_block")):
            active[index] = copy.deepcopy(value["content_block"])
        elif kind == "content_block_delta" and index in active:
            delta = value.get("delta", {})
            block = active[index]
            if delta.get("type") == "thinking_delta":
                block["thinking"] = block.get("thinking", "") + delta.get("thinking", "")
            elif delta.get("type") == "signature_delta":
                block["signature"] = block.get("signature", "") + delta.get("signature", "")
        elif kind == "content_block_stop" and index in active:
            result.add(_canonical(active.pop(index)))
    # Partial blocks are deliberately not trusted after an interrupted stream.
    return result


def restore_sse(data: bytes, redactor: Any, provider: str) -> bytes:
    """Restore complete text/argument lanes before replaying a buffered SSE stream.

    Event order, IDs, tool names, thinking, signatures, comments, pings, and errors
    are retained. A restored lane is emitted in its first delta; later deltas in
    that lane become empty. Consumers still see normal block/message boundaries.
    """
    events = _parse_sse(data)
    lanes: dict[tuple, list[tuple[dict, str, str]]] = {}
    generations: dict[Any, int] = {}
    tool_names: dict[tuple, str] = {}

    def lane(key: tuple, obj: dict, field: str, raw: Any) -> None:
        if not isinstance(raw, str):
            raise PrivacyBlocked("Malformed provider event stream.")
        lanes.setdefault(key, []).append((obj, field, raw))

    for event in events:
        if not event.has_json:
            continue
        raw = event.payload
        contextual = raw
        if isinstance(raw, dict) and raw.get("type") == "response.function_call_arguments.done":
            contextual = dict(raw)
            identity = raw.get("item_id", raw.get("output_index", 0))
            contextual["name"] = tool_names.get(("openai", identity, "arguments"))
        event.payload = restore_response(contextual, redactor, provider)
        if contextual is not raw and "name" not in raw:
            event.payload.pop("name", None)
        value = event.payload
        if not isinstance(raw, dict):
            continue
        kind = raw.get("type", "")
        if kind == "content_block_start":
            index = raw.get("index")
            generations[index] = generations.get(index, 0) + 1
            block = raw.get("content_block", {})
            if block.get("type") == "tool_use":
                tool_names[("anthropic", index, generations[index], "arguments")] = block.get("name")
        elif kind == "content_block_delta":
            delta = raw.get("delta", {})
            index = raw.get("index")
            delta_kind = delta.get("type")
            prefix = ("anthropic", index, generations.get(index, 0))
            if delta_kind == "text_delta":
                lane(prefix + ("text",), value["delta"], "text", delta.get("text"))
            elif delta_kind == "input_json_delta":
                lane(prefix + ("arguments",), value["delta"], "partial_json", delta.get("partial_json"))
        elif kind == "response.output_item.added":
            item = raw.get("item", {})
            if item.get("type") == "function_call":
                tool_names[("openai", item.get("id", raw.get("output_index", 0)), "arguments")] = item.get("name")
                tool_names[("openai", raw.get("output_index", 0), "arguments")] = item.get("name")
            elif item.get("type") == "custom_tool_call":
                tool_names[("openai", item.get("id", raw.get("output_index", 0)), "patch")] = item.get("name")
                tool_names[("openai", raw.get("output_index", 0), "patch")] = item.get("name")
        elif kind == "response.output_text.delta":
            identity = raw.get("item_id", raw.get("output_index", 0))
            lane(("openai", identity, raw.get("content_index", 0), "text"), value,
                 "delta", raw.get("delta"))
        elif kind == "response.function_call_arguments.delta":
            identity = raw.get("item_id", raw.get("output_index", 0))
            lane(("openai", identity, "arguments"), value, "delta", raw.get("delta"))
        elif kind == "response.custom_tool_call_input.delta":
            identity = raw.get("item_id", raw.get("output_index", 0))
            lane(("openai", identity, "patch"), value, "delta", raw.get("delta"))
        elif kind == "response.custom_tool_call_input.done":
            identity = raw.get("item_id", raw.get("output_index", 0))
            value["input"] = _restore_patch_input(raw.get("input"), redactor,
                tool_names.get(("openai", identity, "patch")))
        elif raw.get("object") == "chat.completion.chunk":
            for offset, choice in enumerate(raw.get("choices", [])):
                destination = value["choices"][offset].get("delta", {})
                delta = choice.get("delta", {})
                choice_id = choice.get("index", offset)
                if isinstance(delta.get("content"), str):
                    lane(("chat", choice_id, "text"), destination, "content", delta["content"])
                for tool_offset, tool in enumerate(delta.get("tool_calls", [])):
                    function = tool.get("function", {})
                    tool_key = ("chat", choice_id, tool.get("index", tool_offset), "arguments")
                    if isinstance(function.get("name"), str):
                        tool_names[tool_key] = function["name"]
                    if "arguments" in function:
                        target = destination["tool_calls"][tool_offset]["function"]
                        lane(tool_key,
                             target, "arguments", function["arguments"])

    for key, pieces in lanes.items():
        original = "".join(piece[2] for piece in pieces)
        if key[-1] == "arguments":
            restored = _restore_arguments(original, redactor, tool_names.get(key))
        elif key[-1] == "patch":
            restored = _restore_patch_input(original, redactor, tool_names.get(key))
        else:
            restored = redactor.restore_text(original)
        for offset, (target, field, _) in enumerate(pieces):
            target[field] = restored if offset == 0 else ""
    try:
        result = b"".join(event.encode() for event in events)
    except (ValueError, TypeError, RecursionError):
        raise PrivacyBlocked("Unsupported provider event stream.") from None
    if len(result) > MAX_SSE_BYTES:
        raise PrivacyBlocked("Restored stream exceeds the supported size.")
    return result
