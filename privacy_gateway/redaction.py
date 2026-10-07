"""Local, reversible pseudonymization with no network calls or plaintext storage.

This is a heuristic redactor, not a proof of anonymization: context, uncommon
identifiers, indirect clues, and partial names can escape detection. Names and
business-specific terms must be supplied as literals or locally authored regular
expressions. Literals are exact by default; case, Unicode normalization, and
encoded variants are opt-in. Recognized sensitive numeric JSON values are blocked
instead of silently changing their type. A literal ``Alice Smith`` does not independently conceal ``Alice`` or ``Smith``. Reversible
pseudonyms and their originals live only in this Redactor instance's memory.

JSON-looking strings are parsed and reserialized when valid, so tool arguments
containing quotes, backslashes, and Unicode remain valid during restoration.
Whitespace inside these embedded JSON strings may consequently change.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import base64
import ipaddress
import json
import re
import secrets
import threading
import unicodedata
from urllib.parse import quote, quote_plus, unquote_to_bytes
from pathlib import Path
from typing import Any, Pattern


_LABEL = re.compile(r"[A-Z][A-Z0-9_]{0,23}\Z")
_CANONICAL_TOKEN = re.compile(r"PG_[A-Z][A-Z0-9_]{0,23}_[0-9a-f]{8}_[0-9]{4,}")
_CREDENTIAL_NAME = (
    r"(?:[A-Za-z][A-Za-z0-9]*[_-])*"
    r"(?:password|passwd|pwd|secret|client[_-]?secret|api[_-]?key|"
    r"secret[_-]?(?:access[_-]?)?key|access[_-]?key|"
    r"access[_-]?token|refresh[_-]?token|session[_-]?token|auth[_-]?token|token|"
    r"private[_-]?key|account[_-]?key|shared[_-]?access[_-]?key|"
    r"authorization|credential)s?"
)
_CREDENTIAL_KEY = re.compile(_CREDENTIAL_NAME + r"\Z", re.IGNORECASE)
# Conventional count/limit keys are not credential values. Their numeric values
# still pass the known-literal and built-in identity checks below.
_TOKEN_COUNT_KEYS = frozenset({"max_tokens", "max_completion_tokens", "max_output_tokens",
    "max_input_tokens", "input_tokens", "output_tokens", "total_tokens", "budget_tokens",
    "cache_read_input_tokens", "cache_creation_input_tokens", "cached_tokens"})


def _credential_key(key: Any) -> bool:
    return isinstance(key, str) and key.lower() not in _TOKEN_COUNT_KEYS and bool(_CREDENTIAL_KEY.fullmatch(key))


_ASSIGNMENT = re.compile(
    r"\b(?P<key>" + _CREDENTIAL_NAME + r")" +
    r"\b[\"']?\s*[:=]\s*"
    r"(?:\"(?P<double>(?:\\.|[^\"\\])*)\"|"
    r"'(?P<single>(?:\\.|[^'\\])*)'|"
    r"`(?P<backtick>[^`]*)`|(?P<bare>[^\s,;}\]]+))", re.IGNORECASE
)
_BUILTINS: tuple[tuple[str, Pattern[str]], ...] = (
    ("PRIVATE_KEY", re.compile(
        r"-----BEGIN (?:[A-Z0-9 ]* )?PRIVATE KEY-----[\s\S]*?"
        r"-----END (?:[A-Z0-9 ]* )?PRIVATE KEY-----"
    )),
    ("EMAIL", re.compile(
        r"(?<![\w.!#$%&'*+/=?^`{|}~-])"
        r"[\w.!#$%&'*+/=?^`{|}~-]+@"
        r"(?:[\w](?:[\w-]*[\w])?\.)+[A-Za-z\u0080-\uffff]{2,}"
        r"(?![\w-])", re.UNICODE
    )),
    ("UAE_ID", re.compile(r"(?<!\d)784[- ]?\d{4}[- ]?\d{7}[- ]?\d(?!\d)")),
    ("PHONE", re.compile(
        r"(?<![\w+])(?:\+|00)[1-9]\d{0,2}(?:[ .()\-]*\d){6,13}(?!\d)"
    )),
    ("PHONE", re.compile(
        r"(?<!\w)0(?:5[024568](?:[- .]?\d){7}|[234679](?:[- .]?\d){7})(?!\w)"
    )),
    ("IPV4", re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")),
    ("SECRET", re.compile(
        r"(?<![\w-])(?:"
        r"(?:AKIA|ASIA)[A-Z0-9]{16}|"
        r"sk-(?:(?:proj|ant-api\d+)-)?[A-Za-z0-9_-]{16,}|"
        r"(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}|"
        r"gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
        r"xox[baprs]-[A-Za-z0-9-]{12,}|"
        r"AIza[A-Za-z0-9_-]{30,}|"
        r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}|"
        r"glpat-[A-Za-z0-9_-]{20,}|gl(?:dt|rt|ptt|soat|cbt)-[A-Za-z0-9_-]{20,}|"
        r"hf_[A-Za-z0-9]{30,}|npm_[A-Za-z0-9]{36}|pypi-AgE[A-Za-z0-9_-]{50,}|"
        r"ya29\.[A-Za-z0-9_-]{20,}|GOCSPX-[A-Za-z0-9_-]{20,}|"
        r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}|"
        r"shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}|dop_v1_[a-f0-9]{64}|"
        r"xapp-[0-9]-[A-Za-z0-9-]{20,}"
        r")(?![\w-])"
    )),
    ("SECRET", re.compile(
        r"https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]{16,}"
        r"|https://[a-z0-9.-]+\.webhook\.office\.com/[^\s\"'<>]{20,}"
        r"|https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]{20,}"
    )),
    ("IBAN", re.compile(r"(?<![A-Za-z0-9])[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?(?![A-Za-z0-9])")),
    ("CREDIT_CARD", re.compile(r"(?<!\w)\d(?:[ -]?\d){12,18}(?!\w)")),
)
_AUTH = re.compile(r"\bBearer\s+([A-Za-z0-9._~+/=-]{8,})", re.IGNORECASE)
_BASIC_AUTH = re.compile(r"\bBasic\s+([A-Za-z0-9+/]{4,}={0,2})(?![A-Za-z0-9+/=])", re.IGNORECASE)
_AUTH_HEADER = re.compile(
    r"\bauthorization\s*[:=]\s*(?:Bearer|Basic)\s+([A-Za-z0-9._~+/=-]+)", re.IGNORECASE
)
_BASE64_TEXT = re.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{8,}={0,2}(?![A-Za-z0-9+/_=-])")
_URL_TEXT = re.compile(r"[^\s<>\"`\[\]{}]+")
_ENCODED_LIMIT = 65536
_URL_CREDENTIAL = re.compile(r"\b[a-z][a-z0-9+.-]*://([^\s/@]+:[^\s/@]+)@", re.IGNORECASE)


class SensitiveValueError(ValueError):
    """A sensitive or ambiguous value cannot safely be represented on the wire."""


def _strict_json(value: str) -> Any:
    def pairs(items):
        result = {}
        for key, child in items:
            if key in result:
                raise SensitiveValueError("Ambiguous embedded JSON is blocked.")
            result[key] = child
        return result

    def constant(_):
        raise SensitiveValueError("Unsupported embedded JSON value.")

    return json.loads(value, object_pairs_hook=pairs, parse_constant=constant)


@dataclass(frozen=True, repr=False)
class LiteralRule:
    value: str
    label: str
    ignore_case: bool = False
    normalize: bool = False
    encodings: tuple[str, ...] = ()


@dataclass(frozen=True, repr=False)
class Policy:
    """Validated local policy; built-in detection is always enabled.

    Literals accept optional ``ignore_case`` and ``normalize`` booleans and
    ``encodings`` containing ``url`` and/or ``base64``. These recognize bounded,
    single-layer representations, not arbitrary encodings or partial names.
    Existing value/label policies remain exact and case-sensitive. Regexes are
    trusted local configuration and should avoid expensive patterns.
    """

    literals: tuple[tuple[str, str], ...] = ()
    patterns: tuple[tuple[Pattern[str], str], ...] = ()
    redact_loopback: bool = False
    literal_rules: tuple[LiteralRule, ...] = ()

    @classmethod
    def from_file(cls, path: str | Path | None = None) -> "Policy":
        if path is None:
            return cls()
        with Path(path).open("r", encoding="utf-8") as stream:
            return cls.from_dict(json.load(stream))

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Policy":
        if not isinstance(data, dict):
            raise ValueError("Policy must be a JSON object")
        unknown = set(data) - {"literals", "patterns", "redact_loopback"}
        if unknown:
            raise ValueError("Policy contains unsupported fields")
        literals: list[tuple[str, str]] = []
        patterns: list[tuple[Pattern[str], str]] = []
        rules: list[LiteralRule] = []
        for kind, field in (("literals", "value"), ("patterns", "regex")):
            entries = data.get(kind, [])
            if not isinstance(entries, list):
                raise ValueError(f"Policy {kind} must be a list")
            for index, entry in enumerate(entries):
                required = {field, "label"}
                allowed = required | ({"ignore_case", "normalize", "encodings"} if kind == "literals" else set())
                if not isinstance(entry, dict) or not required <= set(entry) or set(entry) - allowed:
                    raise ValueError(f"Invalid fields in policy {kind}[{index}]")
                value, label = entry[field], entry["label"]
                if not isinstance(value, str) or not value:
                    raise ValueError(f"Policy {kind}[{index}] requires a nonempty {field}")
                if not isinstance(label, str) or _LABEL.fullmatch(label) is None:
                    raise ValueError("Policy labels must be 1–24 uppercase identifier characters")
                if kind == "literals":
                    ignore_case, normalize = entry.get("ignore_case", False), entry.get("normalize", False)
                    if not isinstance(ignore_case, bool) or not isinstance(normalize, bool):
                        raise ValueError("Literal ignore_case and normalize must be true or false")
                    encodings = entry.get("encodings", [])
                    if (not isinstance(encodings, list) or any(not isinstance(item, str)
                            or item not in {"url", "base64"} for item in encodings)
                            or len(encodings) != len(set(encodings))):
                        raise ValueError("Literal encodings must contain unique url/base64 values")
                    if encodings and len(value.encode("utf-8")) > 16384:
                        raise ValueError("Encoded literal exceeds 16 KiB")
                    literals.append((value, label))
                    if ignore_case or normalize or encodings:
                        rules.append(LiteralRule(value, label, ignore_case, normalize, tuple(encodings)))
                else:
                    try:
                        pattern = re.compile(value)
                    except re.error:
                        raise ValueError(f"Invalid regex in patterns[{index}]") from None
                    if pattern.search("") is not None:
                        raise ValueError(f"Regex in patterns[{index}] must not match empty text")
                    patterns.append((pattern, label))
        loopback = data.get("redact_loopback", False)
        if not isinstance(loopback, bool):
            raise ValueError("redact_loopback must be true or false")
        return cls(tuple(literals), tuple(patterns), loopback, tuple(rules))


def _fold_with_spans(value: str, normalize: bool, ignore_case: bool) -> tuple[str, list[tuple[int, int]]]:
    """Keep original spans while matching case folds and Unicode equivalents.

    Normalize base-plus-combining clusters together so reordered accents are
    matched without losing the exact input needed for reversible restoration.
    NFKD also catches compatibility forms such as full-width Latin letters.
    """
    chunks: list[str] = []
    spans: list[tuple[int, int]] = []
    start = 0
    while start < len(value):
        end = start + 1
        if normalize:
            while end < len(value) and unicodedata.combining(value[end]):
                end += 1
        chunk = value[start:end]
        if normalize:
            chunk = unicodedata.normalize("NFKD", chunk)
        if ignore_case:
            chunk = chunk.casefold()
            if normalize:
                chunk = unicodedata.normalize("NFKD", chunk)
        chunks.append(chunk)
        spans.extend([(start, end)] * len(chunk))
        start = end
    return "".join(chunks), spans


def _encoding_variants(rule: LiteralRule) -> set[str]:
    """Only configured literals, one encoding layer, bounded policy input."""
    originals = {rule.value}
    if rule.normalize:
        originals.update(unicodedata.normalize(form, rule.value)
                         for form in ("NFC", "NFD", "NFKC", "NFKD"))
    # Case-independent matching is applied to decoded text, not base64 bytes.
    # Common exact encodings are useful without pretending base64 is caseless.
    if rule.ignore_case:
        originals.update(variant for item in tuple(originals)
                         for variant in (item.lower(), item.upper(), item.casefold()))
    variants: set[str] = set()
    for original in originals:
        if "url" in rule.encodings:
            variants.update((quote(original, safe=""), quote_plus(original, safe="")))
            raw = "".join("%%%02X" % byte for byte in original.encode("utf-8"))
            variants.add(raw)
        if "base64" in rule.encodings:
            raw = original.encode("utf-8")
            variants.update((base64.b64encode(raw).decode("ascii"),
                             base64.urlsafe_b64encode(raw).decode("ascii")))
    variants.update(item.rstrip("=") for item in tuple(variants) if item.endswith("="))
    # Percent hex digits are case-insensitive; literal letters are not.
    variants.update(re.sub(r"%[0-9A-F]{2}", lambda m: m.group().lower(), item)
                    for item in tuple(variants) if "%" in item)
    return variants


def _iban(value: str) -> bool:
    """ISO 13616 length and mod-97 check; rejects ordinary uppercase words."""
    compact = value.replace(" ", "")
    if not 15 <= len(compact) <= 34 or not any(char.isdigit() for char in compact[4:]):
        return False
    rearranged = compact[4:] + compact[:4]
    try:
        return int("".join(str(int(char, 36)) for char in rearranged)) % 97 == 1
    except ValueError:
        return False


def _luhn(value: str) -> bool:
    digits = [int(char) for char in value if char.isdigit()]
    if not 13 <= len(digits) <= 19 or len(set(digits)) == 1:
        return False
    total = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


class Redactor:
    """Thread-safe redaction session. Do not log or persist this instance.

    ``counts()`` reports distinct mapped originals by category. Mappings remain
    stable for this instance, and known originals are concealed in later text
    wherever their exact substring appears. Mapping lifetime ends with process
    memory; restart creates fresh tokens and cannot restore an earlier session.
    """

    def __init__(self, policy: Policy | None = None):
        if policy is not None and not isinstance(policy, Policy):
            raise TypeError("policy must be a Policy")
        self.policy = policy if policy is not None else Policy()
        self._lock = threading.RLock()
        self._nonce = secrets.token_hex(4)
        self._original_to_token: dict[str, str] = {}
        self._token_to_original: dict[str, str] = {}
        self._labels: Counter[str] = Counter()
        self._token_regex: Pattern[str] | None = None
        self._encoded_literals = tuple((variant, rule.label)
            for rule in self.policy.literal_rules for variant in _encoding_variants(rule))
        self._dynamic_rules = ()

    def _pseudonym(self, value: str, label: str) -> str:
        existing = self._original_to_token.get(value)
        if existing is not None:
            return existing
        token = f"PG_{label}_{self._nonce}_{len(self._original_to_token) + 1:04d}"
        self._original_to_token[value] = token
        self._token_to_original[token] = value
        self._labels[label] += 1
        self._token_regex = None
        return token

    def protect_literals(self, entities: list[tuple[str, str]]) -> None:
        """Learn validated exact spans without letting a detector rewrite text.

        Validate the entire batch before changing the in-memory vault. A learned
        span is protected in subsequent requests and restored using the same
        deterministic token mechanism as explicitly configured literals.
        """
        if not isinstance(entities, list) or len(entities) > 4096:
            raise SensitiveValueError("Invalid local detector output.")
        for item in entities:
            if not isinstance(item, (tuple, list)) or len(item) != 2:
                raise SensitiveValueError("Invalid local detector output.")
            value, label = item
            if (not isinstance(value, str) or not value or len(value) > 16384
                    or not isinstance(label, str) or _LABEL.fullmatch(label) is None
                    or _CANONICAL_TOKEN.search(value)):
                raise SensitiveValueError("Invalid local detector output.")
        with self._lock:
            rules = [LiteralRule(value, label, encodings=("url", "base64"))
                     for value, label in entities if value not in self._original_to_token]
            try:
                encoded = tuple((variant, rule.label) for rule in rules for variant in _encoding_variants(rule))
            except (UnicodeError, ValueError):
                raise SensitiveValueError("Invalid local detector output.") from None
            self._dynamic_rules += tuple(rules)
            self._encoded_literals += encoded
            for value, label in entities:
                self._pseudonym(value, label)

    def _known_tokens(self) -> Pattern[str]:
        if self._token_regex is None:
            # Match exact issued tokens even when embedded in filenames or
            # identifiers. Word boundaries lose substitutions beside "_" or
            # digits; longest alternatives avoid a shorter counter prefix.
            self._token_regex = re.compile("|".join(re.escape(token) for token in
                sorted(self._token_to_original, key=len, reverse=True)) or r"(?!x)x")
        return self._token_regex

    def redact_text(self, value: str) -> str:
        with self._lock:
            known_before = len(self._original_to_token)
            result = self._redact_text_pass(value)
            if len(self._original_to_token) != known_before:
                # An assignment can identify a short secret that also occurs
                # outside the assignment earlier in this same string.
                result = self._redact_text_pass(value)
            return result

    def _redact_text_pass(self, value: str) -> str:
        if not isinstance(value, str):
            raise TypeError("redact_text requires a string")
        with self._lock:
            protected = [match.span() for match in self._known_tokens().finditer(value)]
            candidates: list[tuple[int, int, str]] = []

            def add(start: int, end: int, label: str) -> None:
                if start >= end:
                    return
                if any(start < stop and end > begin for begin, stop in protected):
                    return
                candidates.append((start, end, label))

            # Explicit configuration wins ties over heuristic detection.
            literals = list(self.policy.literals) + list(self._encoded_literals)
            literals.extend((original, "KNOWN") for original in self._original_to_token)
            for literal, label in literals:
                start = value.find(literal)
                while start != -1:
                    add(start, start + len(literal), label)
                    start = value.find(literal, start + 1)
            folded_views: dict[tuple[bool, bool], tuple[str, list[tuple[int, int]]]] = {}
            for rule in self.policy.literal_rules:
                if not (rule.normalize or rule.ignore_case):
                    continue
                mode = (rule.normalize, rule.ignore_case)
                if mode not in folded_views:
                    folded_views[mode] = _fold_with_spans(value, *mode)
                folded, spans = folded_views[mode]
                needle, _ = _fold_with_spans(rule.value, *mode)
                start = folded.find(needle)
                while start != -1:
                    add(spans[start][0], spans[start + len(needle) - 1][1], rule.label)
                    start = folded.find(needle, start + 1)
            for pattern, label in self.policy.patterns:
                for match in pattern.finditer(value):
                    add(*match.span(), label)
            for label, pattern in _BUILTINS:
                for match in pattern.finditer(value):
                    raw = match.group()
                    if label == "CREDIT_CARD" and not _luhn(raw):
                        continue
                    if label == "IBAN" and not _iban(raw):
                        continue
                    if label == "PHONE":
                        digits = re.sub(r"\D", "", raw)
                        if raw.startswith("00"):
                            digits = digits[2:]
                        if not 8 <= len(digits) <= 15:
                            continue
                    if label == "IPV4":
                        try:
                            address = ipaddress.IPv4Address(raw)
                        except ipaddress.AddressValueError:
                            continue
                        if address.is_loopback and not self.policy.redact_loopback:
                            continue
                    add(*match.span(), label)
            for match in _ASSIGNMENT.finditer(value):
                if not _credential_key(match.group("key")):
                    continue
                for group in ("double", "single", "backtick", "bare"):
                    if match.group(group) is not None:
                        if (group == "bare" and match.group("key").lower() == "authorization"
                                and match.group(group).lower() in {"bearer", "basic"}):
                            break
                        add(*match.span(group), "SECRET")
                        break
            for pattern in (_AUTH, _AUTH_HEADER, _URL_CREDENTIAL):
                for match in pattern.finditer(value):
                    add(*match.span(1), "SECRET")
            for match in _BASIC_AUTH.finditer(value):
                raw = match.group(1)
                if len(raw) > _ENCODED_LIMIT:
                    raise SensitiveValueError("Encoded text exceeds the local inspection limit.")
                try:
                    decoded = base64.b64decode(raw + "=" * (-len(raw) % 4), validate=True)
                except (ValueError, UnicodeError):
                    continue
                # Standalone prose such as "basic instructions" is not HTTP
                # authentication. A Basic credential encodes user:password.
                # Explicit Authorization fields remain conservatively masked.
                if b":" in decoded and not any(byte < 32 or byte == 127 for byte in decoded):
                    add(*match.span(1), "SECRET")

            for start, end, label in self._encoded_candidates(value):
                add(start, end, label)

            # Choose longest full matches first, so a full name or secret is
            # never split into an overlapping smaller match.
            selected: list[tuple[int, int, str]] = []
            for candidate in sorted(candidates, key=lambda item: (-(item[1] - item[0]), item[0])):
                start, end, _ = candidate
                if not any(start < stop and end > begin for begin, stop, _ in selected):
                    selected.append(candidate)
            chunks: list[str] = []
            cursor = 0
            for start, end, label in sorted(selected):
                chunks.append(value[cursor:start])
                chunks.append(self._pseudonym(value[start:end], label))
                cursor = end
            chunks.append(value[cursor:])
            return "".join(chunks)

    def _encoded_candidates(self, value: str) -> list[tuple[int, int, str]]:
        candidates: list[tuple[int, int, str]] = []

        def matches(decoded: str, rule: LiteralRule) -> bool:
            if rule.normalize or rule.ignore_case:
                text, _ = _fold_with_spans(decoded, rule.normalize, rule.ignore_case)
                literal, _ = _fold_with_spans(rule.value, rule.normalize, rule.ignore_case)
                return literal in text
            return rule.value in decoded

        for encoding, pattern in (("url", _URL_TEXT), ("base64", _BASE64_TEXT)):
            rules = [rule for rule in (*self.policy.literal_rules, *self._dynamic_rules) if encoding in rule.encodings]
            if not rules:
                continue
            for match in pattern.finditer(value):
                raw = match.group()
                if encoding == "url" and "%" not in raw and "+" not in raw:
                    continue
                if len(raw) > _ENCODED_LIMIT:
                    raise SensitiveValueError("Encoded text exceeds the local inspection limit.")
                try:
                    if encoding == "url":
                        decoded_values = {unquote_to_bytes(raw).decode("utf-8", errors="replace"),
                            unquote_to_bytes(raw.replace("+", " ")).decode("utf-8", errors="replace")}
                    else:
                        padded = raw + "=" * (-len(raw) % 4)
                        decoded_values = {base64.b64decode(padded, altchars=b"-_", validate=True).decode("utf-8", errors="replace")}
                except (ValueError, UnicodeError):
                    continue
                for rule in rules:
                    if any(matches(decoded, rule) for decoded in decoded_values):
                        candidates.append((*match.span(), rule.label))
                        break
        return candidates

    def restoration_tokens(self) -> tuple[str, ...]:
        """Snapshot only issued placeholders; never exposes their originals."""
        with self._lock:
            return tuple(self._token_to_original)

    def restore_text(self, value: str) -> str:
        if not isinstance(value, str):
            raise TypeError("restore_text requires a string")
        with self._lock:
            return self._known_tokens().sub(lambda match: self._token_to_original[match.group()], value)

    def _json_string(self, value: str, restore: bool, depth: int) -> str:
        stripped = value.strip()
        if depth < 64 and stripped.startswith(("{", "[")):
            try:
                parsed = _strict_json(value)
            except SensitiveValueError:
                raise
            except (ValueError, RecursionError):
                pass
            else:
                return json.dumps(self._walk(parsed, restore, depth + 1), ensure_ascii=False)
        return self.restore_text(value) if restore else self.redact_text(value)

    def _walk(self, value: Any, restore: bool, depth: int = 0) -> Any:
        if isinstance(value, str):
            return self._json_string(value, restore, depth)
        if isinstance(value, dict):
            result = {}
            for key, item in value.items():
                new_key = self._walk(key, restore, depth + 1) if isinstance(key, str) else key
                credential = not restore and _credential_key(key)
                if credential and isinstance(item, (int, float)) and not isinstance(item, bool):
                    raise SensitiveValueError("Sensitive numeric JSON values are blocked.")
                if (credential and isinstance(item, str) and item
                        and item not in self._token_to_original):
                    new_item = self._pseudonym(item, "SECRET")
                else:
                    new_item = self._walk(item, restore, depth + 1)
                if new_key in result:
                    raise SensitiveValueError("Ambiguous JSON keys are blocked.")
                result[new_key] = new_item
            return result
        if isinstance(value, list):
            return [self._walk(item, restore, depth + 1) for item in value]
        if isinstance(value, tuple):
            return tuple(self._walk(item, restore, depth + 1) for item in value)
        if not restore and isinstance(value, (int, float)) and not isinstance(value, bool):
            raw = str(value)
            if self.redact_text(raw) != raw:
                raise SensitiveValueError("Sensitive numeric JSON values are blocked.")
        return value

    def redact_json(self, value: Any) -> Any:
        with self._lock:
            # Discover contextual secrets before producing the result. A
            # password declared late in an object must also conceal earlier
            # mentions elsewhere in that same document.
            self._walk(value, False)
            return self._walk(value, False)

    def assert_sanitized(self, value: Any) -> None:
        """Fail closed when known/configured sensitive data remains readable.

        This is a second local check, not a promise to recognize unknown secrets.
        The caller must exclude provider-authentication and trusted opaque blocks.
        Exceptions contain no input, original values, or pseudonym mappings.
        """
        def check(item: Any) -> None:
            if isinstance(item, str):
                if self.redact_text(item) != item:
                    raise SensitiveValueError("Residual protected data is blocked.")
                if item.lstrip().startswith(("{", "[")):
                    try:
                        parsed = _strict_json(item)
                    except SensitiveValueError:
                        raise
                    except (ValueError, RecursionError):
                        return
                    check(parsed)
            elif isinstance(item, dict):
                for key, child in item.items():
                    check(key)
                    if (_credential_key(key)
                            and isinstance(child, str) and child
                            and child not in self._token_to_original):
                        raise SensitiveValueError("Residual protected data is blocked.")
                    if (_credential_key(key)
                            and isinstance(child, (int, float)) and not isinstance(child, bool)):
                        raise SensitiveValueError("Sensitive numeric JSON values are blocked.")
                    check(child)
            elif isinstance(item, (list, tuple)):
                for child in item:
                    check(child)
            elif isinstance(item, (int, float)) and not isinstance(item, bool):
                if self.redact_text(str(item)) != str(item):
                    raise SensitiveValueError("Sensitive numeric JSON values are blocked.")
        with self._lock:
            check(value)

    def restore_json(self, value: Any) -> Any:
        with self._lock:
            return self._walk(value, True)

    def counts(self) -> dict[str, int]:
        with self._lock:
            return dict(self._labels)
