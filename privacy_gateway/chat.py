"""Chat backend for the MaskCode app.

The browser sends the user's message in plain text to this loopback server.
The message is masked here, only masked text is sent to the AI provider, and the
reply is restored here before it reaches the browser. The browser can show the
masked version of every message on request.

Providers: any OpenAI-compatible Chat Completions endpoint (OpenAI, Azure-style
gateways, OpenRouter, local servers) and the Anthropic Messages API. The API key
is stored in ~/.maskcode/settings.json (owner-only permissions where supported)
or read from OPENAI_API_KEY / ANTHROPIC_API_KEY, and is never sent to the browser.
"""
from __future__ import annotations

import json
import os
import re
import ssl
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

PRESETS = {
    "openai": {"label": "OpenAI (ChatGPT)", "api": "openai", "base_url": "https://api.openai.com/v1",
               "model": "gpt-4o-mini", "env": "OPENAI_API_KEY"},
    "anthropic": {"label": "Anthropic (Claude)", "api": "anthropic", "base_url": "https://api.anthropic.com",
                  "model": "claude-sonnet-4-5", "env": "ANTHROPIC_API_KEY"},
    "custom": {"label": "Other (OpenAI-compatible)", "api": "openai", "base_url": "", "model": "", "env": ""},
}
SYSTEM = ("You are a helpful assistant. Some names, emails, numbers and other details in this "
          "conversation were replaced with placeholders like PG_PERSON_1a2b3c4d_0001 for privacy. "
          "Treat each placeholder as the real value it stands for, and copy placeholders exactly, "
          "character for character, whenever you refer to them. Never ask what they mean.")
MAX_HISTORY = 60
_PARTIAL = re.compile(r"P(?:G(?:_[A-Z0-9_]*)?)?\Z")


def settings_path(base: Path) -> Path:
    return base / "settings.json"


def load_settings(base: Path) -> dict:
    data = {}
    path = settings_path(base)
    if path.is_file():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = {}
    if not isinstance(data, dict):
        data = {}
    provider = data.get("provider") if data.get("provider") in PRESETS else None
    if provider is None:
        provider = "anthropic" if os.environ.get("ANTHROPIC_API_KEY") and not os.environ.get("OPENAI_API_KEY") else "openai"
    preset = PRESETS[provider]
    out = {"provider": provider,
           "base_url": str(data.get("base_url") or preset["base_url"]).rstrip("/"),
           "model": str(data.get("model") or preset["model"]),
           "api_key": str(data.get("api_key") or (os.environ.get(preset["env"]) if preset["env"] else "") or "")}
    return out


def public_settings(settings: dict) -> dict:
    return {"provider": settings["provider"], "base_url": settings["base_url"], "model": settings["model"],
            "has_key": bool(settings["api_key"]), "ready": bool(settings["api_key"] and settings["model"] and settings["base_url"]),
            "presets": {k: {"label": v["label"], "base_url": v["base_url"], "model": v["model"]} for k, v in PRESETS.items()}}


def save_settings(base: Path, update: dict) -> dict:
    if not isinstance(update, dict):
        raise ValueError("Invalid settings")
    current = load_settings(base)
    provider = update.get("provider", current["provider"])
    if provider not in PRESETS:
        raise ValueError("Choose a provider")
    base_url = str(update.get("base_url") or PRESETS[provider]["base_url"]).strip().rstrip("/")
    model = str(update.get("model") or PRESETS[provider]["model"]).strip()
    if not re.match(r"https?://[^\s]+\Z", base_url):
        raise ValueError("Enter the provider address, starting with https://")
    if base_url.startswith("http://") and not re.match(r"http://(127\.0\.0\.1|localhost)(:\d+)?(/|\Z)", base_url):
        raise ValueError("Use https:// for online providers")
    if not model or len(model) > 200:
        raise ValueError("Enter a model name")
    key = update.get("api_key")
    if key is None or key == "":
        key = current["api_key"] if provider == current["provider"] else ""
    key = str(key).strip()
    if len(key) > 4096 or any(c.isspace() for c in key):
        raise ValueError("That API key does not look right")
    data = {"provider": provider, "base_url": base_url, "model": model, "api_key": key}
    base.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".settings-", suffix=".json", dir=str(base))
    try:
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(data, stream, indent=2)
        os.replace(tmp, settings_path(base))
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return load_settings(base)


def safe_prefix(text: str) -> str:
    """Hold back a trailing fragment that could still grow into a placeholder."""
    m = re.search(r"PG_[A-Z0-9_a-f]*\Z", text) or _PARTIAL.search(text)
    return text[:m.start()] if m else text


class ProviderError(RuntimeError):
    pass


def _friendly(status: int, body: bytes) -> str:
    detail = ""
    try:
        j = json.loads(body)
        err = j.get("error") if isinstance(j, dict) else None
        detail = (err.get("message") if isinstance(err, dict) else err) or j.get("message") or ""
    except (ValueError, AttributeError):
        pass
    detail = str(detail)[:240]
    if status in (401, 403):
        return "The AI provider rejected your API key. Check it in Settings."
    if status == 404:
        return "The provider could not find that model. Check the model name in Settings." + (" (" + detail + ")" if detail else "")
    if status == 429:
        return "The AI provider says you have hit a rate or credit limit. Try again shortly."
    return "The AI provider returned an error (%d)%s" % (status, ": " + detail if detail else ".")


def stream_reply(settings: dict, history: list):
    """Yield text deltas from the provider for an already-masked history."""
    api = PRESETS[settings["provider"]]["api"]
    msgs = [{"role": m["role"], "content": m["content"]} for m in history[-MAX_HISTORY:]]
    if api == "anthropic":
        url = settings["base_url"] + "/v1/messages"
        body = {"model": settings["model"], "max_tokens": 4096, "system": SYSTEM, "messages": msgs, "stream": True}
        headers = {"x-api-key": settings["api_key"], "anthropic-version": "2023-06-01"}
    else:
        url = settings["base_url"] + "/chat/completions"
        body = {"model": settings["model"], "messages": [{"role": "system", "content": SYSTEM}] + msgs, "stream": True}
        headers = {"Authorization": "Bearer " + settings["api_key"]}
    headers.update({"Content-Type": "application/json", "Accept": "text/event-stream", "User-Agent": "MaskCode"})
    req = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"), headers=headers, method="POST")
    try:
        resp = urllib.request.urlopen(req, timeout=120, context=ssl.create_default_context())
    except urllib.error.HTTPError as exc:
        raise ProviderError(_friendly(exc.code, exc.read(4096))) from None
    except (urllib.error.URLError, OSError, ValueError):
        raise ProviderError("Could not reach the AI provider. Check your internet connection and the address in Settings.") from None
    with resp:
        ctype = resp.headers.get("Content-Type", "")
        if "event-stream" not in ctype:
            data = json.loads(resp.read() or b"{}")
            text = _non_stream_text(api, data)
            if text:
                yield text
            return
        for raw in resp:
            line = raw.decode("utf-8", "replace").strip()
            if not line.startswith("data:"):
                continue
            payload = line[5:].strip()
            if payload == "[DONE]":
                break
            try:
                event = json.loads(payload)
            except ValueError:
                continue
            if api == "anthropic":
                if event.get("type") == "content_block_delta":
                    delta = event.get("delta", {}).get("text")
                    if delta:
                        yield delta
                elif event.get("type") == "error":
                    raise ProviderError("The AI provider stopped the reply: " + str(event.get("error", {}).get("message", ""))[:200])
            else:
                for choice in event.get("choices") or []:
                    delta = (choice.get("delta") or {}).get("content")
                    if delta:
                        yield delta


def _non_stream_text(api: str, data: dict) -> str:
    if api == "anthropic":
        return "".join(b.get("text", "") for b in data.get("content", []) if isinstance(b, dict))
    try:
        return data["choices"][0]["message"]["content"] or ""
    except (KeyError, IndexError, TypeError):
        return ""
