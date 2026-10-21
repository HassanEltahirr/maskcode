"""MaskCode desktop app: a private, loopback-only web UI for everyday users.

``maskcode app`` opens a window in the default browser where people can:

* paste text, get a safe-to-share version with placeholders, and copy it into
  any AI chat (ChatGPT, Claude, Gemini, Copilot ...);
* paste the AI's reply back and restore the original names and values locally;
* keep a list of their own protected words (client names, projects, people);
* check a folder for values that would be masked, without printing them.

Everything stays on this computer. The server binds 127.0.0.1 only, requires a
per-launch secret on every API call, checks Host/Origin, writes no logs, and
keeps the placeholder vault in memory only. It uses the Python standard library
and works on Windows, macOS and Linux.
"""
from __future__ import annotations

import hmac
import json
import re
import os
import platform
import secrets
import shutil
import sys
import tempfile
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from pathlib import Path

from . import __version__
from .redaction import Policy, Redactor, SensitiveValueError, _CANONICAL_TOKEN, _LABEL

MAX_BODY = 4 * 1024 * 1024
MAX_TERMS = 2000
FRIENDLY = {
    "EMAIL": "Email", "PHONE": "Phone", "SECRET": "Secret key", "PRIVATE_KEY": "Private key",
    "IBAN": "Bank account", "CREDIT_CARD": "Card number", "IPV4": "IP address", "UAE_ID": "Emirates ID",
    "ORG": "Company", "PERSON": "Person", "PROJECT": "Project", "LOCATION": "Place", "CLIENT": "Client",
    "CREDENTIAL": "Password", "LOCAL_HOME": "Folder path", "PATH": "Folder path", "TERM": "Private word",
}
TERM_LABELS = ("TERM", "PERSON", "ORG", "CLIENT", "PROJECT", "LOCATION")
# Suggest likely names (2-4 capitalised words) the rules cannot know about. The
# user decides; nothing is hidden or saved until they accept a suggestion.
_NAME = re.compile(r"\b(?:[A-Z][a-z]+|[A-Z]{2,})(?:[ \-&](?:[A-Z][a-z]+|[A-Z]{2,}|of|and|de|al|bin)){1,3}\b")
_COMMON = frozenset("""hi hello dear thanks thank regards best kind please the this that these those
monday tuesday wednesday thursday friday saturday sunday january february march april may june july
august september october november december i we you he she it they our your my team all yes no ok
dear sir madam good morning afternoon evening note subject re fw fwd attached see also new next
""".split())


def suggest_names(text: str, limit: int = 12) -> list:
    found, seen = [], set()
    for match in _NAME.finditer(text):
        words = match.group().replace("-", " ").split()
        while words and words[0].lower() in _COMMON:
            words = words[1:]
        # A capitalised first word at the start of a sentence is usually just
        # grammar ("Invoice Cedar Holdings"); drop it if a name still remains.
        before = text[:match.start()].rstrip(" \t")
        if len(words) > 2 and (not before or before[-1] in ".!?:\n"):
            words = words[1:]
        while words and words[-1].lower() in {"of", "and", "de", "al", "bin"} | _COMMON:
            words = words[:-1]
        if len(words) < 2:
            continue
        phrase = " ".join(words)
        if phrase.lower() in seen or _CANONICAL_TOKEN.search(phrase):
            continue
        seen.add(phrase.lower())
        found.append(phrase)
        if len(found) >= limit:
            break
    return found


def data_dir() -> Path:
    """Per-user settings folder; MASKCODE_HOME overrides it (tests, portable use)."""
    override = os.environ.get("MASKCODE_HOME")
    return Path(override).expanduser() if override else Path.home() / ".maskcode"


def default_policy_path() -> Path:
    return data_dir() / "policy.json"


def load_policy_data(path: Path | None = None) -> dict:
    path = path or default_policy_path()
    if not path.is_file():
        return {"literals": [], "patterns": []}
    with path.open("r", encoding="utf-8") as stream:
        data = json.load(stream)
    Policy.from_dict(data)  # validate before use
    data.setdefault("literals", [])
    data.setdefault("patterns", [])
    return data


def save_terms(terms: list, path: Path | None = None) -> dict:
    """Replace the literal list, keep any hand-written patterns, write atomically."""
    path = path or default_policy_path()
    if not isinstance(terms, list) or len(terms) > MAX_TERMS:
        raise ValueError("Too many protected words")
    literals, seen = [], set()
    for item in terms:
        if not isinstance(item, dict):
            raise ValueError("Invalid protected word")
        value = item.get("value")
        label = item.get("label", "TERM")
        if not isinstance(value, str) or not value.strip() or len(value) > 500:
            raise ValueError("Each protected word needs 1-500 characters")
        if not isinstance(label, str) or _LABEL.fullmatch(label) is None:
            raise ValueError("Invalid category")
        value = value.strip()
        if value.lower() in seen:
            continue
        seen.add(value.lower())
        literals.append({"value": value, "label": label, "ignore_case": True, "normalize": True,
                         "encodings": ["url", "base64"]})
    try:
        current = load_policy_data(path)
    except (OSError, ValueError):
        current = {"literals": [], "patterns": []}
    data = {"literals": literals, "patterns": current.get("patterns", [])}
    if current.get("redact_loopback"):
        data["redact_loopback"] = True
    Policy.from_dict(data)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".policy-", suffix=".json", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(data, stream, ensure_ascii=False, indent=2)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return data


class AppState:
    def __init__(self, policy_path: Path | None = None, settings_dir: Path | None = None):
        self.policy_path = policy_path or default_policy_path()
        self.settings_dir = settings_dir or data_dir()
        self.chats = {}
        self.token = secrets.token_urlsafe(32)
        self._lock = threading.Lock()
        self.policy_error = None
        self.redactor = self._new_redactor()
        self.stats = {"masked": 0, "restored": 0}

    def _policy(self) -> Policy:
        try:
            self.policy_error = None
            return Policy.from_dict(load_policy_data(self.policy_path))
        except (OSError, ValueError):
            self.policy_error = "Your protected-words file could not be read, so only built-in detection is active."
            return Policy()

    def _new_redactor(self) -> Redactor:
        return Redactor(self._policy())

    def reset(self):
        with self._lock:
            self.redactor = self._new_redactor()
            self.stats = {"masked": 0, "restored": 0}
            self.chats = {}

    def mask(self, text: str) -> dict:
        with self._lock:
            redactor = self.redactor
        try:
            masked = redactor.redact_text(text)
        except SensitiveValueError:
            raise ValueError("Part of this text could not be masked safely. Remove unusual encoded content and try again.")
        items, seen = [], set()
        for match in _CANONICAL_TOKEN.finditer(masked):
            token = match.group()
            if token in seen:
                continue
            seen.add(token)
            label = token[3:].rsplit("_", 2)[0]
            items.append({"token": token, "label": label, "kind": FRIENDLY.get(label, label.title().replace("_", " ")),
                          "original": redactor.restore_text(token)})
        with self._lock:
            self.stats["masked"] += 1
        return {"masked": masked, "items": items, "suggestions": suggest_names(masked)}

    def restore(self, text: str) -> dict:
        with self._lock:
            redactor = self.redactor
        restored = redactor.restore_text(text)
        known = set(redactor.restoration_tokens())
        found = {m.group() for m in _CANONICAL_TOKEN.finditer(text)}
        with self._lock:
            self.stats["restored"] += 1
        return {"restored": restored, "replaced": len(found & known), "unknown": len(found - known)}


def _tools() -> dict:
    found = {}
    for name in ("claude", "codex", "ollama"):
        found[name] = bool(shutil.which(name))
    return found


def _page() -> bytes:
    return resources.files("privacy_gateway").joinpath("app.html").read_bytes()


class AppHandler(BaseHTTPRequestHandler):
    server_version = "MaskCode"
    sys_version = ""

    def log_message(self, *unused):  # never log request lines or bodies
        return

    @property
    def state(self) -> AppState:
        return self.server.state

    def _boundary_ok(self) -> bool:
        port = self.server.server_port
        hosts = {"127.0.0.1:%d" % port, "localhost:%d" % port}
        if self.headers.get("Host") not in hosts:
            return False
        origin = self.headers.get("Origin")
        return not origin or origin in {"http://" + h for h in hosts}

    def _authorized(self) -> bool:
        return self._boundary_ok() and hmac.compare_digest(
            self.headers.get("X-MaskCode-Token", ""), self.state.token)

    def _send(self, status: int, body: bytes, content_type: str):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
                         "img-src data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, payload: dict):
        self._send(status, json.dumps(payload, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")

    def _body(self) -> dict:
        if self.headers.get_content_type() != "application/json":
            raise ValueError("Expected JSON")
        length = int(self.headers.get("Content-Length") or 0)
        if length < 0 or length > MAX_BODY:
            raise ValueError("This text is too large (limit 4 MB).")
        data = json.loads(self.rfile.read(length) or b"{}")
        if not isinstance(data, dict):
            raise ValueError("Expected a JSON object")
        return data

    def do_GET(self):
        if not self._boundary_ok():
            return self._send(403, b"Forbidden", "text/plain")
        if self.path in ("/", "/index.html"):
            return self._send(200, _page(), "text/html; charset=utf-8")
        if not self._authorized():
            return self._json(401, {"error": "This window has expired. Close it and run maskcode app again."})
        if self.path == "/api/status":
            s = self.state
            literals = []
            try:
                literals = load_policy_data(s.policy_path).get("literals", [])
            except (OSError, ValueError):
                pass
            return self._json(200, {
                "version": __version__, "platform": platform.system() or "Unknown",
                "policy_path": str(s.policy_path), "terms": len(literals), "policy_error": s.policy_error,
                "tools": _tools(), "stats": s.stats, "vault": len(s.redactor.restoration_tokens()),
            })
        if self.path == "/api/settings":
            from .chat import load_settings, public_settings
            return self._json(200, public_settings(load_settings(self.state.settings_dir)))
        if self.path == "/api/terms":
            try:
                literals = load_policy_data(self.state.policy_path).get("literals", [])
            except (OSError, ValueError):
                return self._json(200, {"terms": [], "error": "Your protected-words file could not be read."})
            return self._json(200, {"terms": [{"value": t["value"], "label": t["label"]} for t in literals]})
        return self._json(404, {"error": "Not found"})

    def do_POST(self):
        if not self._authorized():
            return self._json(401, {"error": "This window has expired. Close it and run maskcode app again."})
        try:
            data = self._body()
            if self.path == "/api/mask":
                text = data.get("text")
                if not isinstance(text, str):
                    raise ValueError("Paste some text first.")
                return self._json(200, self.state.mask(text))
            if self.path == "/api/restore":
                text = data.get("text")
                if not isinstance(text, str):
                    raise ValueError("Paste the AI reply first.")
                return self._json(200, self.state.restore(text))
            if self.path == "/api/chat":
                return self._chat(data)
            if self.path == "/api/settings":
                from .chat import save_settings, public_settings
                return self._json(200, public_settings(save_settings(self.state.settings_dir, data)))
            if self.path == "/api/reset":
                self.state.reset()
                return self._json(200, {"ok": True})
            if self.path == "/api/terms":
                saved = save_terms(data.get("terms"), self.state.policy_path)
                self.state.reset()
                return self._json(200, {"ok": True, "terms": len(saved["literals"])})
            if self.path == "/api/scan":
                from .scan import scan_paths
                raw = data.get("path")
                if not isinstance(raw, str) or not raw.strip():
                    raise ValueError("Enter a folder or file path.")
                target = Path(raw.strip().strip('"')).expanduser()
                if not target.exists():
                    raise ValueError("That folder or file does not exist.")
                try:
                    policy = Policy.from_dict(load_policy_data(self.state.policy_path))
                except (OSError, ValueError):
                    policy = None
                report = scan_paths([target], policy)
                for item in report["findings"]:
                    item["labels"] = {FRIENDLY.get(k, k.title()): v for k, v in item["labels"].items()}
                report["totals"] = {FRIENDLY.get(k, k.title()): v for k, v in report["totals"].items()}
                return self._json(200, report)
            return self._json(404, {"error": "Not found"})
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            message = str(exc) if isinstance(exc, ValueError) and not isinstance(exc, json.JSONDecodeError) else "Invalid request"
            return self._json(400, {"error": message})
        except OSError:
            return self._json(500, {"error": "MaskCode could not read or write a local file."})


    def _chat(self, data):
        from .chat import load_settings, stream_reply, safe_prefix, ProviderError
        text, chat_id = data.get("text"), data.get("chat")
        if not isinstance(text, str) or not text.strip():
            raise ValueError("Type a message first.")
        if not isinstance(chat_id, str) or not 1 <= len(chat_id) <= 64:
            raise ValueError("Invalid conversation")
        settings = load_settings(self.state.settings_dir)
        if not settings["api_key"]:
            raise ValueError("Add your AI provider and API key in Settings first.")
        masked = self.state.mask(text)
        history = self.state.chats.setdefault(chat_id, [])
        turn = history + [{"role": "user", "content": masked["masked"]}]
        self.send_response(200)
        self.send_header("Content-Type", "application/x-ndjson; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()

        def emit(obj):
            self.wfile.write((json.dumps(obj, ensure_ascii=False) + "\n").encode("utf-8"))
            self.wfile.flush()

        emit({"type": "masked", "masked": masked["masked"], "items": [
            {"kind": i["kind"], "token": i["token"]} for i in masked["items"]]})
        raw, sent = "", 0
        try:
            for delta in stream_reply(settings, turn):
                raw += delta
                ready = safe_prefix(raw)
                if len(ready) > sent:
                    emit({"type": "delta", "text": self.state.restore(ready[sent:])["restored"]})
                    sent = len(ready)
            if len(raw) > sent:
                emit({"type": "delta", "text": self.state.restore(raw[sent:])["restored"]})
            history.extend([{"role": "user", "content": masked["masked"]}, {"role": "assistant", "content": raw}])
            emit({"type": "done", "masked_reply": raw})
        except ProviderError as exc:
            emit({"type": "error", "error": str(exc)})
        except (BrokenPipeError, ConnectionResetError):
            pass


class AppServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, state: AppState, port: int = 0):
        self.state = state
        super().__init__(("127.0.0.1", port), AppHandler)

    @property
    def url(self) -> str:
        return "http://127.0.0.1:%d/#%s" % (self.server_port, self.state.token)


def main(argv=None) -> int:
    import argparse
    parser = argparse.ArgumentParser(prog="maskcode app", description="Open the MaskCode app in your browser.")
    parser.add_argument("--port", type=int, default=0, help="Local port (default: any free port)")
    parser.add_argument("--no-browser", action="store_true", help="Print the address instead of opening a browser")
    parser.add_argument("--policy", type=Path, help="Protected-words file (default: ~/.maskcode/policy.json)")
    args = parser.parse_args(argv)
    server = AppServer(AppState(args.policy.expanduser() if args.policy else None), args.port)
    print("MaskCode %s is running privately on this computer." % __version__, file=sys.stderr)
    print("Open: " + server.url, file=sys.stderr)
    print("Keep this window open while you use MaskCode. Press Ctrl+C to quit.", file=sys.stderr, flush=True)
    if not args.no_browser:
        threading.Timer(0.3, webbrowser.open, args=(server.url,)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
