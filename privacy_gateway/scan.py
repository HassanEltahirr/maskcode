"""Offline, rules-only audit of local files before an agent session.

Reports which files and lines contain values the gateway would mask, grouped
by label. Matched values and placeholders are never printed, so the report is
safe to paste into an issue or CI log. No network call or model is used.
"""
from __future__ import annotations

from collections import Counter
import os
from pathlib import Path

from .redaction import Policy, Redactor, SensitiveValueError, _CANONICAL_TOKEN

_SKIP_DIRS = frozenset({".git", ".hg", ".svn", "node_modules", ".venv", "venv", "__pycache__",
                        ".mypy_cache", ".pytest_cache", ".tox", "dist", "build", ".idea"})


def _files(paths):
    for root in paths:
        root = Path(root)
        if root.is_file():
            yield root
        elif root.is_dir():
            for directory, dirs, names in os.walk(root):
                dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIRS and not d.endswith(".egg-info"))
                for name in sorted(names):
                    yield Path(directory) / name
        else:
            raise ValueError("A scan path does not exist.")


def _labels(masked: str) -> list[str]:
    # Placeholders look like PG_<LABEL>_<nonce>_<counter>; recover only the label.
    return [match.group()[3:].rsplit("_", 2)[0] for match in _CANONICAL_TOKEN.finditer(masked)]


def scan_paths(paths, policy: Policy | None = None, max_bytes: int = 2 * 1024 * 1024) -> dict:
    findings, skipped, scanned = [], [], 0
    totals: Counter[str] = Counter()
    for path in _files(paths):
        try:
            if path.stat().st_size > max_bytes:
                skipped.append({"path": str(path), "reason": "too large"})
                continue
            raw = path.read_bytes()
        except OSError:
            skipped.append({"path": str(path), "reason": "unreadable"})
            continue
        if b"\0" in raw[:8192]:
            skipped.append({"path": str(path), "reason": "binary"})
            continue
        text = raw.decode("utf-8", errors="replace")
        scanned += 1
        # A fresh redactor per file: mappings never leak between reports.
        redactor = Redactor(policy)
        lines: dict[int, list[str]] = {}
        for number, line in enumerate(text.splitlines(), 1):
            try:
                masked = redactor.redact_text(line)
            except SensitiveValueError:
                lines[number] = ["BLOCKED"]
                continue
            if masked != line:
                lines[number] = _labels(masked) or ["MASKED"]
        # Multi-line spans such as private keys only match on the whole text.
        try:
            whole = _labels(Redactor(policy).redact_text(text))
        except SensitiveValueError:
            whole = ["BLOCKED"]
        if "PRIVATE_KEY" in whole and not any("PRIVATE_KEY" in v for v in lines.values()):
            lines.setdefault(0, []).append("PRIVATE_KEY")
        if lines:
            labels = Counter(label for values in lines.values() for label in values)
            totals.update(labels)
            findings.append({"path": str(path), "labels": dict(sorted(labels.items())),
                             "lines": sorted(n for n in lines if n)})
    return {"scanned_files": scanned, "findings": findings, "skipped": skipped,
            "totals": dict(sorted(totals.items()))}


def format_report(report: dict) -> str:
    out = []
    for item in report["findings"]:
        labels = ", ".join("%s x%d" % pair for pair in item["labels"].items())
        lines = item["lines"]
        where = (" lines " + ",".join(map(str, lines[:12])) + (" ..." if len(lines) > 12 else "")) if lines else ""
        out.append("%s: %s%s" % (item["path"], labels, where))
    if report["skipped"]:
        out.append("Skipped %d file(s) (binary, unreadable or too large)." % len(report["skipped"]))
    total = sum(report["totals"].values())
    out.append("Scanned %d file(s): %s" % (report["scanned_files"],
        "no maskable values found." if not total else "%d maskable value(s) in %d file(s) — %s." % (
            total, len(report["findings"]), ", ".join("%s %d" % pair for pair in report["totals"].items()))))
    out.append("Rules only (no local AI detector); values are not printed.")
    return "\n".join(out)
