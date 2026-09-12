"""Loopback-only privacy gateway. No request, credential, or vault disk logs."""
from __future__ import annotations

import hmac
import http.client
import json
import math
import re
import secrets
import socket
import threading
import time
from dataclasses import dataclass, field, replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from . import __version__
from .redaction import Policy, Redactor
from .protocol import (PrivacyBlocked, PUBLIC_PROTOCOL_TERMS, sanitize_payload, readable_fragments, restore_response, restore_sse,
                       collect_trusted_opaque, collect_sse_trusted_opaque)
from .streaming import AnthropicStream

CREDENTIAL_HEADERS = frozenset({"authorization", "x-api-key", "chatgpt-account-id"})

MAX_BODY = 8 * 1024 * 1024
MAX_RESPONSE = 32 * 1024 * 1024
UPSTREAMS = {
    "anthropic": ("api.anthropic.com", ""),
    "openai": ("api.openai.com", ""),
    "codex": ("chatgpt.com", "/backend-api/codex"),
}
ROUTES = {
    "anthropic": {"/v1/messages", "/v1/messages/count_tokens"},
    "openai": {"/v1/responses"},
    "codex": {"/responses", "/responses/compact"},
}
LIMITS = [
    "Pseudonymization is not a guarantee of anonymity: meaning, unknown identifiers and encoded text can remain.",
    "Rules, configured terms and enabled local AI detection mask recognized values; detection can miss sensitive content.",
    "Images, uploaded files, remote tools and unverified opaque history are blocked.",
    "Provider authentication still identifies your account. Original data remains in local client history and memory.",
    "Anthropic text streams incrementally; tool calls wait for complete validation. Other providers remain buffered.",
    "The macOS launcher restricts direct network sockets; it is not a hardened boundary against a hostile local process or OS helper.",
]


def strict_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("Duplicate JSON key")
            result[key] = value
        return result
    def constant(_):
        raise ValueError("Nonfinite JSON number")
    return json.loads(data, object_pairs_hook=pairs, parse_constant=constant)


@dataclass
class Pending:
    id: str
    preview: dict
    redactions: dict
    headers: dict = field(default_factory=dict)
    created: float = field(default_factory=time.time)
    status: str = "pending"
    event: threading.Event = field(default_factory=threading.Event)


class GatewayState:
    def __init__(self, provider="anthropic", policy=None, mode="review", review_timeout=600,
                 semantic_scanner=None, local_runtime=None):
        if provider not in UPSTREAMS or mode not in ("review", "auto"):
            raise ValueError("Unsupported provider or mode")
        self.provider = provider
        self.mode = mode
        self.policy = policy or Policy.from_dict({})
        self.redactor = Redactor(self.policy)
        self.proxy_token = secrets.token_urlsafe(32)
        self.review_token = secrets.token_urlsafe(32)
        if (not isinstance(review_timeout, (int, float)) or isinstance(review_timeout, bool)
                or not math.isfinite(review_timeout) or not 0 < review_timeout <= 3600):
            raise ValueError("Review timeout must be finite and between 0 and 3600 seconds")
        self.review_timeout = review_timeout
        self.closed = False
        self._credential_key = secrets.token_bytes(32)
        self._credential_fingerprint = None
        self.pending = {}
        self.trusted_opaque = set()
        self.lock = threading.RLock()
        self.requests = self.blocked = self.forwarded = 0
        self.network_isolation = False
        self.transport = self.send_upstream
        self.last_upstream_status = None
        self.semantic_scanner = semantic_scanner
        self.local_runtime = local_runtime
        self._scan_lock = threading.Lock()
        self._scan_started = False
        self._codex_public_instructions = None
        self.public_instruction_chars_skipped = 0

    def register_codex_instructions(self, model, text):
        """Register exact public base text from the launcher's bundled catalog.

        No HTTP route or request value can invoke this. Never register a
        normalized or already-redacted copy. Only semantic discovery may skip
        the exact model/text pair; all deterministic checks still run.
        """
        if (not isinstance(model, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", model)
                or not isinstance(text, str) or not text or len(text) > 262144 or "\0" in text):
            raise ValueError("Invalid public Codex instruction registration")
        with self._scan_lock, self.lock:
            if (self.provider != "codex" or self.closed or self._scan_started or self.forwarded
                    or self._codex_public_instructions is not None):
                raise ValueError("Public Codex instructions must be registered once before requests")
            self._codex_public_instructions = (model, text)

    @property
    def protocol_provider(self):
        return "openai" if self.provider == "codex" else self.provider

    def snapshot(self):
        semantic = (self.semantic_scanner.snapshot() if self.semantic_scanner is not None
                    else {"enabled": False})
        with self.lock:
            return {"mode": self.mode, "provider": self.provider, "closed": self.closed, "requests": self.requests,
                    "blocked": self.blocked, "forwarded": self.forwarded,
                    "network_isolation": self.network_isolation,
                    "redactions": self.redactor.counts(), "limits": LIMITS,
                    "semantic_scan": semantic,
                    "local_model": getattr(self.local_runtime, "model", None),
                    "local_isolation": getattr(self.local_runtime, "isolation_scope", None),
                    "last_upstream_status": self.last_upstream_status,
                    "public_instruction_chars_skipped": self.public_instruction_chars_skipped,
                    "pending": [{"id": p.id, "preview": p.preview, "headers": p.headers, "redactions": p.redactions,
                                 "created": p.created, "status": p.status}
                                for p in self.pending.values() if p.status == "pending"]}

    def sanitize(self, payload, trusted, headers=None):
        """Rules first, local entity discovery, then exact replacement and checks."""
        with self._scan_lock:
            self._scan_started = True
            if self.closed:
                raise PrivacyBlocked("Gateway session is closed")
            clean = sanitize_payload(payload, self.redactor, self.protocol_provider, trusted)
            if self.semantic_scanner is not None:
                from .semantic import SemanticScanError
                try:
                    inspection = clean
                    public = self._codex_public_instructions
                    if (self.provider == "codex" and public is not None
                            and clean.get("model") == public[0] and clean.get("instructions") == public[1]):
                        # Only this whole top-level field can match the exact
                        # installed public catalog. Prompts, nested copies,
                        # tool definitions/results and edited instructions are
                        # still scanned. Never change the outgoing payload.
                        inspection = {key: value for key, value in clean.items() if key != "instructions"}
                        with self.lock:
                            self.public_instruction_chars_skipped += len(public[1])
                    fragments = readable_fragments(inspection)
                    # Authentication and gateway-generated framing never enter
                    # the detector as anonymous user data. Client protocol
                    # headers still receive discovery and all fixed headers
                    # retain deterministic pre-send validation.
                    fragments.extend(value for key, value in (headers or {}).items()
                                     if key.lower() not in CREDENTIAL_HEADERS
                                     and key.lower() not in {"content-type", "accept", "accept-encoding", "user-agent"}
                                     and value not in PUBLIC_PROTOCOL_TERMS)
                    entities = [entity for entity in self.semantic_scanner.scan(fragments)
                                if entity[0] not in PUBLIC_PROTOCOL_TERMS
                                and entity[0] != "maskcode/" + __version__]
                    if self.closed:
                        raise PrivacyBlocked("Gateway session is closed")
                    self.redactor.protect_literals(entities)
                    clean = sanitize_payload(payload, self.redactor, self.protocol_provider, trusted)
                except SemanticScanError:
                    raise PrivacyBlocked("Local privacy scan did not complete safely. No cloud request was sent. Check /privacy and restart to retry.") from None
            return clean

    def decision(self, request_id, decision):
        if decision not in ("approve", "deny"):
            return False
        with self.lock:
            pending = self.pending.get(request_id)
            if not pending or pending.status != "pending":
                return False
            pending.status = "approved" if decision == "approve" else "denied"
            pending.event.set()
            return True

    def approve(self, payload, headers=None):
        preview_headers = {key: value for key, value in (headers or {}).items()
                           if key.lower() not in CREDENTIAL_HEADERS}
        pending = Pending(secrets.token_hex(12), payload, self.redactor.counts(), preview_headers)
        with self.lock:
            if self.closed:
                raise PrivacyBlocked("Gateway session is closed")
            if self.mode == "auto":
                return
            if len(self.pending) >= 16:
                raise PrivacyBlocked("Too many requests awaiting review")
            self.pending[pending.id] = pending
        pending.event.wait(self.review_timeout)
        with self.lock:
            self.pending.pop(pending.id, None)
            if self.closed:
                raise PrivacyBlocked("Gateway session is closed")
        if pending.status != "approved":
            raise PrivacyBlocked("Request denied or review timed out; nothing forwarded")

    def check_credentials(self, headers, establish=False):
        """Pin the first forwarded credential set without retaining plaintext.

        The first approved request establishes trust. Added, removed or changed
        credential headers require a fresh gateway session, including refresh.
        """
        selected = {key.lower(): value for key, value in headers.items()
                    if key.lower() in CREDENTIAL_HEADERS}
        encoded = json.dumps(selected, sort_keys=True, separators=(",", ":")).encode()
        fingerprint = hmac.digest(self._credential_key, encoded, "sha256")
        with self.lock:
            if self.closed:
                raise PrivacyBlocked("Gateway session is closed")
            if self._credential_fingerprint is not None:
                if not hmac.compare_digest(fingerprint, self._credential_fingerprint):
                    raise PrivacyBlocked("Provider credentials changed; restart the gateway session")
            elif establish:
                self._credential_fingerprint = fingerprint

    def close(self):
        with self.lock:
            self.closed = True
            for pending in self.pending.values():
                pending.status = "denied"
                pending.event.set()
        if self.semantic_scanner is not None:
            self.semantic_scanner.close()
        if self.local_runtime is not None:
            self.local_runtime.close()

    def send_upstream(self, path, body, headers):
        host, prefix = UPSTREAMS[self.provider]
        conn = http.client.HTTPSConnection(host, timeout=300)
        streaming = False
        try:
            conn.request("POST", prefix + path, body=body, headers=headers)
            response = conn.getresponse()
            if 300 <= response.status < 400:
                raise PrivacyBlocked("Upstream redirect blocked")
            if response.getheader("Content-Encoding", "identity").lower() != "identity":
                raise PrivacyBlocked("Compressed upstream response blocked")
            content_type = response.getheader("Content-Type", "")
            if (self.provider == "anthropic" and 200 <= response.status < 300
                    and content_type.split(";", 1)[0].strip().lower() == "text/event-stream"):
                streaming = True
                return response.status, content_type, UpstreamChunks(conn, response)
            data = response.read(MAX_RESPONSE + 1)
            if len(data) > MAX_RESPONSE:
                raise PrivacyBlocked("Upstream response exceeds local buffer limit")
            return response.status, response.getheader("Content-Type", ""), data
        finally:
            if not streaming:
                conn.close()


class UpstreamChunks:
    """Own an HTTP response until it is consumed or the downstream disconnects."""
    def __init__(self, connection, response):
        self.connection = connection
        self.response = response

    def __iter__(self):
        try:
            while True:
                data = self.response.read1(65536)
                if not data:
                    break
                yield data
        finally:
            self.close()

    def close(self):
        self.response.close()
        self.connection.close()


class GatewayServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, state, port=0):
        self.state = state
        super().__init__(("127.0.0.1", port), Handler)

    def handle_error(self, request, client_address):
        # Never dump handler tracebacks containing request objects.
        pass

    @property
    def base_url(self):
        return "http://127.0.0.1:%d" % self.server_port

    @property
    def console_url(self):
        return self.base_url + "/#" + self.state.review_token

    @property
    def proxy_url(self):
        return self.base_url + "/proxy/" + self.state.proxy_token


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "MaskCode"
    sys_version = ""

    def setup(self):
        super().setup()
        self.connection.settimeout(20)

    def log_message(self, *args):
        pass

    @property
    def state(self):
        return self.server.state

    def respond(self, status, data, content_type="application/json"):
        if not isinstance(data, bytes):
            data = json.dumps(data, ensure_ascii=True, allow_nan=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def respond_anthropic_stream(self, upstream):
        restorer = AnthropicStream(self.state.redactor, MAX_RESPONSE)
        chunks = [upstream] if isinstance(upstream, bytes) else upstream
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        try:
            for chunk in restorer.restore(chunks):
                # Completion establishes provenance before releasing tool calls
                # or message_stop, so an immediate follow-up can replay it.
                if restorer.trusted_opaque:
                    with self.state.lock:
                        self.state.trusted_opaque.update(restorer.trusted_opaque)
                self.wfile.write(chunk)
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as exc:
            with self.state.lock:
                self.state.blocked += 1
            message = (str(exc) if isinstance(exc, PrivacyBlocked) else
                       "Provider stream interrupted; no tool call or completion released")
            packet = {"type": "error", "error": {
                "type": "privacy_gateway_error", "message": message}}
            try:
                self.wfile.write(b"event: error\ndata: " + json.dumps(packet).encode() + b"\n\n")
                self.wfile.flush()
            except (OSError, ValueError):
                pass
        finally:
            close = getattr(upstream, "close", None)
            if close:
                try:
                    close()
                except Exception:
                    pass

    def error(self, status, message):
        self.respond(status, {"type": "error", "error": {"type": "privacy_gateway_error", "message": message}})

    def boundary_ok(self):
        port = self.server.server_port
        allowed = {"127.0.0.1:%d" % port, "localhost:%d" % port}
        if self.headers.get("Host") not in allowed:
            return False
        origin = self.headers.get("Origin")
        return not origin or origin in {"http://" + host for host in allowed}

    def reviewer_ok(self):
        return self.boundary_ok() and hmac.compare_digest(
            self.headers.get("X-Veil-Token", ""), self.state.review_token)

    def read_json(self):
        if self.headers.get("Transfer-Encoding") or len(self.headers.get_all("Content-Length", [])) != 1:
            raise PrivacyBlocked("Ambiguous or streaming request body blocked")
        if self.headers.get("Content-Encoding", "identity").lower() != "identity":
            raise PrivacyBlocked("Compressed request body blocked")
        if self.headers.get_content_type() != "application/json":
            raise PrivacyBlocked("Only inspectable JSON request bodies are supported")
        try:
            length = int(self.headers["Content-Length"])
        except (ValueError, TypeError):
            raise PrivacyBlocked("Invalid content length") from None
        if not 0 < length <= MAX_BODY:
            raise PrivacyBlocked("Request exceeds local size limit")
        data = self.rfile.read(length)
        if len(data) != length:
            raise PrivacyBlocked("Incomplete request body")
        try:
            parsed = strict_json(data)
        except (ValueError, UnicodeError, RecursionError):
            raise PrivacyBlocked("Invalid JSON request") from None
        if not isinstance(parsed, dict):
            raise PrivacyBlocked("JSON object required")
        return parsed

    def do_GET(self):
        if not self.boundary_ok():
            return self.error(403, "Local origin required")
        if self.path == "/":
            return self.respond(200, Path(__file__).with_name("console.html").read_bytes(), "text/html; charset=utf-8")
        if self.path == "/api/status" and self.reviewer_ok():
            return self.respond(200, self.state.snapshot())
        return self.error(403, "Route unavailable or local capability missing")

    def do_OPTIONS(self):
        self.error(403, "Cross-origin access blocked")

    def do_POST(self):
        try:
            if not self.boundary_ok():
                return self.error(403, "Local origin required")
            if self.path.startswith("/api/"):
                if not self.reviewer_ok():
                    return self.error(403, "Review capability required")
                body = self.read_json()
                if self.path == "/api/preview":
                    if not isinstance(body.get("text"), str) or len(body["text"]) > 200000:
                        return self.error(400, "Preview requires text under 200,000 characters")
                    try:
                        extra_policy = Policy.from_dict({"literals": body.get("literals", [])})
                        configured = self.state.policy
                        preview_redactor = Redactor(replace(configured,
                            literals=configured.literals + extra_policy.literals,
                            literal_rules=configured.literal_rules + extra_policy.literal_rules))
                        masked = preview_redactor.redact_text(body["text"])
                    except (ValueError, TypeError, KeyError):
                        return self.error(400, "Invalid local preview policy")
                    return self.respond(200, {"text": masked, "redactions": preview_redactor.counts()})
                if self.path == "/api/decision":
                    if not self.state.decision(body.get("id"), body.get("decision")):
                        return self.error(409, "Request no longer pending or decision invalid")
                    return self.respond(200, {"ok": True})
                return self.error(404, "Unknown console endpoint")
            self.proxy()
        except PrivacyBlocked as exc:
            with self.state.lock:
                self.state.blocked += 1
            self.error(400, str(exc))
        except (socket.timeout, TimeoutError):
            self.error(504, "Connection timed out; request was not retried")
        except Exception:
            # Intentionally no exception text: it may contain content or credentials.
            self.error(502, "Gateway failed closed; no automatic retry or direct fallback")

    def proxy(self):
        pieces = urlsplit(self.path)
        prefix = "/proxy/" + self.state.proxy_token
        if not pieces.path.startswith(prefix + "/"):
            return self.error(403, "Proxy capability required")
        route = pieces.path[len(prefix):]
        if route not in ROUTES[self.state.provider]:
            raise PrivacyBlocked("Unsupported inference route blocked")
        if pieces.query not in ("", "beta=true") or pieces.fragment:
            raise PrivacyBlocked("Unsupported query parameters blocked")
        # Fixed allowlist: client metadata, cookies, arbitrary headers never forwarded.
        forward_headers = {"Content-Type": "application/json", "Accept-Encoding": "identity",
                           "User-Agent": "maskcode/" + __version__}
        allowed = ["authorization", "x-api-key"]
        if self.state.provider == "anthropic":
            allowed += ["anthropic-version", "anthropic-beta"]
        if self.state.provider == "codex":
            allowed += ["chatgpt-account-id", "openai-beta", "originator"]
        # Header checks can learn contextual secrets too. Serialize every such
        # mutation with body scans and the final check-through-send boundary.
        with self.state._scan_lock:
            for name in allowed:
                value = self.headers.get(name)
                if value:
                    if len(value) > 16384 or len(self.headers.get_all(name, [])) != 1:
                        raise PrivacyBlocked("Invalid protocol header")
                    # Credentials necessarily reach the selected provider; do not alter them.
                    if name not in CREDENTIAL_HEADERS:
                        if self.state.redactor.redact_text(value) != value:
                            raise PrivacyBlocked("Protected value found in protocol header")
                    forward_headers[name] = value
        if not any(k in forward_headers for k in ("authorization", "x-api-key")):
            raise PrivacyBlocked("Client provider authentication is required")
        self.state.check_credentials(forward_headers)
        payload = self.read_json()
        # Match the native Responses client's content negotiation without
        # accepting an arbitrary client-controlled header as a data channel.
        forward_headers["Accept"] = "text/event-stream" if payload.get("stream") is True else "application/json"
        with self.state.lock:
            self.state.requests += 1
            trusted = set(self.state.trusted_opaque)
        clean = self.state.sanitize(payload, trusted, forward_headers)
        # Body discovery may learn a short credential after the first header scan.
        with self.state._scan_lock:
            for name in allowed:
                value = forward_headers.get(name)
                if value and name not in CREDENTIAL_HEADERS:
                    if self.state.redactor.redact_text(value) != value:
                        raise PrivacyBlocked("Protected value found in protocol header")
        # Do not persist Responses API conversations server-side by request.
        if self.state.provider in ("openai", "codex") and route.endswith("responses"):
            clean["store"] = False
        body = json.dumps(clean, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode()
        self.state.approve(clean, headers={key: value for key, value in forward_headers.items()
                                         if key.lower() not in CREDENTIAL_HEADERS})
        with self.state._scan_lock:
            # A concurrent request may have discovered another protected value
            # while this exact preview awaited approval. Never send that stale
            # preview or silently replace it after the user approved it.
            refreshed = sanitize_payload(clean, self.state.redactor, self.state.protocol_provider, trusted)
            if refreshed != clean:
                raise PrivacyBlocked("New sensitive data was discovered while this request waited. The stale request was blocked; retry to create a new preview.")
            for name, value in forward_headers.items():
                if name.lower() not in CREDENTIAL_HEADERS and self.state.redactor.redact_text(value) != value:
                    raise PrivacyBlocked("Protected value found in protocol header")
            with self.state.lock:
                self.state.check_credentials(forward_headers, establish=True)
                if self.state.closed:
                    raise PrivacyBlocked("Gateway session is closed")
                self.state.forwarded += 1
            status, content_type, upstream = self.state.transport(
                route + ("?beta=true" if pieces.query else ""), body, forward_headers)
            self.state.last_upstream_status = status
        if not 200 <= status < 300:
            # Provider bodies may echo text/headers; expose only status.
            return self.error(status if 400 <= status < 600 else 502,
                              "Provider returned HTTP %d; response body suppressed" % status)
        provider = self.state.protocol_provider
        media_type = content_type.split(";", 1)[0].strip().lower()
        if (not media_type and self.state.provider == "codex" and route == "/responses"
                and clean.get("stream") is True):
            # Some Codex subscription responses omit Content-Type despite
            # explicit SSE negotiation. Accept only a strictly validated,
            # complete Responses stream in this exact case; never sniff HTML
            # or override an explicit unsupported media type.
            from .codex_stream import validate_codex_sse
            validate_codex_sse(upstream)
            media_type = "text/event-stream"
        if media_type == "text/event-stream" and provider == "anthropic":
            return self.respond_anthropic_stream(upstream)
        if media_type == "text/event-stream":
            trust = collect_sse_trusted_opaque(upstream, provider)
            restored = restore_sse(upstream, self.state.redactor, provider)
            with self.state.lock:
                self.state.trusted_opaque.update(trust)
            return self.respond(200, restored, "text/event-stream")
        if media_type != "application/json":
            raise PrivacyBlocked("Unsupported upstream content type")
        try:
            parsed = strict_json(upstream)
        except (ValueError, UnicodeError, RecursionError):
            raise PrivacyBlocked("Invalid upstream JSON") from None
        trust = collect_trusted_opaque(parsed)
        restored = restore_response(parsed, self.state.redactor, provider)
        with self.state.lock:
            self.state.trusted_opaque.update(trust)
        self.respond(status, restored)
