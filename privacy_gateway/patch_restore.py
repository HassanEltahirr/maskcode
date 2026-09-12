"""Restore masked text inside a validated apply_patch document, without I/O.

Framing, operation types, hunk markers, and body prefixes remain immutable.
Only individual path/content fragments are restored; no restored fragment may
introduce a new line or control character. The native client remains responsible
for permissions and for executing the patch against its actual working tree.
"""
from __future__ import annotations

import posixpath
import re


MAX_PATCH_BYTES = 8 * 1024 * 1024
MAX_LINES = 100000
MAX_OPERATIONS = 4096
MAX_HUNKS = 16384
MAX_PATH_BYTES = 4096
_FAILURE = "Masked patch could not be restored safely. No patch was executed."
_CONTROLS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f\u2028-\u202e\u2066-\u2069]")
_OPERATIONS = (("add", "*** Add File: "), ("update", "*** Update File: "),
               ("delete", "*** Delete File: "))
_MOVE = "*** Move to: "


class PatchRestoreBlocked(ValueError):
    """A fixed diagnostic containing no file name, source, or restored value."""

    def __init__(self):
        super().__init__(_FAILURE)


def _check_size(text):
    if (not isinstance(text, str) or len(text) > MAX_PATCH_BYTES
            or len(text.encode("utf-8")) > MAX_PATCH_BYTES):
        raise PatchRestoreBlocked()


def _lines(text):
    """Accept uniform LF or CRLF and preserve the exact optional final EOL."""
    newline = "\r\n" if "\r\n" in text else "\n"
    if newline == "\r\n":
        if "\r" in text.replace("\r\n", "") or "\n" in text.replace("\r\n", ""):
            raise PatchRestoreBlocked()
    elif "\r" in text:
        raise PatchRestoreBlocked()
    trailing = text.endswith(newline)
    if text.count(newline) + (0 if trailing else 1) > MAX_LINES:
        raise PatchRestoreBlocked()
    lines = text.split(newline)
    if trailing:
        lines.pop()
    if len(lines) > MAX_LINES or any(_CONTROLS.search(line) for line in lines):
        raise PatchRestoreBlocked()
    return lines, newline, trailing


def _path(value):
    if (not value or value != value.strip() or "\t" in value or _CONTROLS.search(value)
            or "\n" in value or "\r" in value or len(value.encode("utf-8")) > MAX_PATH_BYTES
            or value.startswith("*** ") or value.endswith("/")):
        raise PatchRestoreBlocked()
    normalized = posixpath.normpath(value)
    if normalized in (".", "..", "/", "//"):
        raise PatchRestoreBlocked()
    return normalized


def _operation(line):
    for kind, prefix in _OPERATIONS:
        if line.startswith(prefix):
            return kind, prefix, line[len(prefix):]
    return None


def _parse(lines):
    if len(lines) < 3 or lines[0] != "*** Begin Patch" or lines[-1] != "*** End Patch":
        raise PatchRestoreBlocked()
    records = [("fixed", "", lines[0])]
    touched = set()
    operations = hunks = 0
    index = 1

    def path_record(prefix, value):
        normalized = _path(value)
        if normalized in touched:
            raise PatchRestoreBlocked()
        touched.add(normalized)
        records.append(("path", prefix, value))

    while index < len(lines) - 1:
        parsed = _operation(lines[index])
        if parsed is None:
            raise PatchRestoreBlocked()
        kind, prefix, path = parsed
        operations += 1
        if operations > MAX_OPERATIONS:
            raise PatchRestoreBlocked()
        path_record(prefix, path)
        index += 1
        moved = False
        if kind == "update" and index < len(lines) - 1 and lines[index].startswith(_MOVE):
            path_record(_MOVE, lines[index][len(_MOVE):])
            moved = True
            index += 1
        body_count = hunk_body = 0
        has_hunk = ended = False
        while index < len(lines) - 1 and _operation(lines[index]) is None:
            line = lines[index]
            if kind == "delete" or ended:
                raise PatchRestoreBlocked()
            if kind == "add":
                if not line.startswith("+"):
                    raise PatchRestoreBlocked()
                records.append(("body", "+", line[1:]))
                body_count += 1
            elif line == "*** End of File":
                if not hunk_body:
                    raise PatchRestoreBlocked()
                records.append(("fixed", "", line))
                ended = True
            elif line == "@@" or line.startswith("@@ "):
                if has_hunk and not hunk_body:
                    raise PatchRestoreBlocked()
                if line.startswith("@@ ") and not line[3:]:
                    raise PatchRestoreBlocked()
                hunks += 1
                if hunks > MAX_HUNKS:
                    raise PatchRestoreBlocked()
                has_hunk, hunk_body = True, 0
                records.append(("context", "@@ ", line[3:]) if line.startswith("@@ ")
                               else ("fixed", "", line))
            elif line and line[0] in " +-":
                if not has_hunk:
                    hunks += 1
                    if hunks > MAX_HUNKS:
                        raise PatchRestoreBlocked()
                    has_hunk = True
                body_count += 1
                hunk_body += 1
                records.append(("body", line[0], line[1:]))
            else:
                raise PatchRestoreBlocked()
            index += 1
        if kind == "update" and ((has_hunk and not hunk_body) or (not body_count and not moved)):
            raise PatchRestoreBlocked()
    if not operations:
        raise PatchRestoreBlocked()
    records.append(("fixed", "", lines[-1]))
    return records


def restore_patch(text, redactor):
    """Return a validated patch with exact issued placeholders restored.

    Empty text is allowed only as an initial streaming placeholder. The caller
    must withhold execution until a complete nonempty patch has been received.
    No file is read, resolved, written, or executed here.
    """
    try:
        _check_size(text)
        if text == "":
            return ""
        lines, newline, trailing = _lines(text)
        records = _parse(lines)
        restored_lines = []
        result_bytes = len(newline) * (len(records) - 1 + int(trailing))
        for kind, prefix, value in records:
            if kind == "fixed":
                restored_lines.append(value)
                result_bytes += len(value.encode("utf-8"))
                if result_bytes > MAX_PATCH_BYTES:
                    raise PatchRestoreBlocked()
                continue
            restored = redactor.restore_text(value)
            if (not isinstance(restored, str) or "\n" in restored or "\r" in restored
                    or _CONTROLS.search(restored) or restored.count("\t") > value.count("\t")):
                raise PatchRestoreBlocked()
            _check_size(restored)
            result_bytes += len(prefix.encode("utf-8")) + len(restored.encode("utf-8"))
            if result_bytes > MAX_PATCH_BYTES:
                raise PatchRestoreBlocked()
            restored_lines.append(prefix + restored)
        result = newline.join(restored_lines) + (newline if trailing else "")
        _check_size(result)
        checked = _parse(restored_lines)
        if [(kind, prefix) for kind, prefix, _ in checked] != [(kind, prefix) for kind, prefix, _ in records]:
            raise PatchRestoreBlocked()
        return result
    except Exception:
        raise PatchRestoreBlocked() from None
