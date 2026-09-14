"""A private, owned Ollama process for local text classification.

The macOS sandbox denies direct external network sockets. Ollama's unmodified
server launches runners on dynamically chosen loopback ports, so loopback TCP
remains available, including other local services. This is not an isolation
boundary against a hostile local user, OS-helper IPC, or the host operating
system (including swap). No tools are exposed to the local model.

Existing model weights are read-only. The child gets a temporary HOME, no
inherited credentials or proxies, and no stdout/stderr or conversation logs.
Only this module's own server is used; an existing Ollama service is untouched.
"""
from __future__ import annotations

import http.client
import json
import os
import platform
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path


DEFAULT_MODEL = "qwen2.5:1.5b"
MAX_REQUEST_BYTES = 131_072
MAX_RESPONSE_BYTES = 262_144
_MODEL_NAME = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,79}(?::[a-zA-Z0-9][a-zA-Z0-9_.-]{0,79})?\Z")


class OllamaRuntimeError(RuntimeError):
    """A fixed, safe error message that contains no prompt or provider payload."""


def _validate_model(model):
    # Deliberately accept local library names only, never URLs or registry names.
    if not isinstance(model, str) or not _MODEL_NAME.fullmatch(model):
        raise OllamaRuntimeError("Choose an installed local Ollama model name.")
    if any(part in model.lower() for part in ("cloud", "remote")):
        raise OllamaRuntimeError("Cloud and remote Ollama models are not allowed.")
    return model if ":" in model else model + ":latest"


def _profile(models, runtime_home):
    # JSON string escaping also safely quotes these absolute paths in SBPL.
    return (
        '(version 1)\n(allow default)\n(deny network*)\n'
        '(allow network-inbound (local tcp "localhost:*"))\n'
        '(allow network-outbound (remote tcp "localhost:*"))\n'
        '(deny file-write*)\n'
        '(allow file-write* (subpath %s) (literal "/dev/null"))\n'
        '(deny file-write* (subpath %s))\n'
        % (json.dumps(str(runtime_home)), json.dumps(str(models)))
    )


def _environment(binary, models, runtime_home, port):
    # Build an allowlist from scratch: even future cloud/proxy/auth variables
    # cannot leak in through the launching shell's environment.
    return {
        "PATH": str(Path(binary).parent) + ":/usr/bin:/bin:/usr/sbin:/sbin",
        "HOME": str(runtime_home),
        "TMPDIR": str(runtime_home) + "/",
        "LANG": "en_US.UTF-8",
        "OLLAMA_HOST": "127.0.0.1:%d" % port,
        "OLLAMA_MODELS": str(models),
        "OLLAMA_NO_CLOUD": "1",
        "OLLAMA_NOHISTORY": "1",
        "OLLAMA_NOPRUNE": "1",
        "OLLAMA_DEBUG": "false",
        "OLLAMA_NUM_PARALLEL": "1",
        "OLLAMA_MAX_LOADED_MODELS": "1",
        "OLLAMA_MAX_QUEUE": "4",
        "OLLAMA_CONTEXT_LENGTH": "8192",
        "OLLAMA_KEEP_ALIVE": "-1",
        "OLLAMA_LOAD_TIMEOUT": "90s",
        "OLLAMA_ORIGINS": "http://127.0.0.1",
        "NO_PROXY": "*",
    }


def _verify_isolation(profile, environment):
    """Probe the same child policy without sending any confidential data."""
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(2)
        probe = '''import errno,json,socket,sys
def check(host,port,udp=False):
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM if udp else socket.SOCK_STREAM)
    s.settimeout(2)
    try:
        if udp: s.sendto(b"",(host,port))
        else: s.connect((host,port))
        return "allowed"
    except OSError as e:
        return "blocked" if e.errno in (errno.EPERM,errno.EACCES) else "inconclusive"
    finally: s.close()
print(json.dumps([check("127.0.0.1",int(sys.argv[1])),check("1.1.1.1",443),check("1.1.1.1",53,True)]))
'''
        try:
            result = subprocess.run(
                ["/usr/bin/sandbox-exec", "-p", profile, sys.executable, "-I", "-S", "-c", probe,
                 str(listener.getsockname()[1])],
                env=environment, capture_output=True, text=True, timeout=12, close_fds=True,
            )
            findings = json.loads(result.stdout)
        except (OSError, ValueError, subprocess.SubprocessError):
            raise OllamaRuntimeError("Local scanner network isolation could not be verified.") from None
    if result.returncode or findings != ["allowed", "blocked", "blocked"]:
        raise OllamaRuntimeError("Local scanner network isolation could not be verified.")
    return True


class ManagedOllama:
    """Own one loopback Ollama server; fail closed on any local scanner failure."""

    isolation_scope = "external sockets blocked; loopback TCP and OS-helper IPC remain available"

    def __init__(self, model=DEFAULT_MODEL):
        self.model = _validate_model(model)
        self.port = None
        self.network_isolation = False
        self._process = None
        self._temporary_home = None
        self._lock = threading.Lock()
        self._closed = False
        self._warmup_state_lock = threading.Lock()
        self._warmup_status = "idle"
        self._warmup_done = threading.Event()
        self._warmup_done.set()
        self._warmup_thread = None

    @property
    def warmup_status(self):
        """Read startup state without waiting for model inference."""
        with self._warmup_state_lock:
            return self._warmup_status

    def prewarm(self):
        """Start loading without a prompt while the terminal is prepared.

        The existing generation lock serializes this request with real scans.
        No model, prompt, or compiler cache is persisted between sessions.
        Warmup is optional: a failed preload does not bypass or replace the
        fully validated local inference required by a later real scan.
        """
        with self._warmup_state_lock:
            if self._closed or not self.network_isolation:
                raise OllamaRuntimeError("The protected local scanner is not running.")
            if self._warmup_status != "idle":
                return self
            self._warmup_status = "loading"
            self._warmup_done.clear()
            self._warmup_thread = threading.Thread(
                target=self._prewarm, name="maskcode-local-warmup", daemon=True)
            self._warmup_thread.start()
        return self

    def _prewarm(self):
        try:
            with self._lock:
                if self._closed or not self.network_isolation:
                    raise OllamaRuntimeError("The protected local scanner is not running.")
                # Ollama's explicit load-only chat operation performs no token
                # generation. Match real scan options to keep the same runner.
                result = self._request("POST", "/api/chat", {
                    "model": self.model, "messages": [], "stream": False,
                    "keep_alive": -1,
                    "options": {"temperature": 0, "seed": 0, "num_ctx": 8192, "num_predict": 2048},
                })
            if result.get("done") is not True or result.get("done_reason") != "load":
                raise OllamaRuntimeError("The local scanner startup check failed.")
            with self._warmup_state_lock:
                if not self._closed:
                    self._warmup_status = "ready"
        except Exception:
            # Keep only the fixed state: runtime/model exceptions may contain
            # internal diagnostics and must not reach the terminal or a log.
            with self._warmup_state_lock:
                if not self._closed:
                    self._warmup_status = "failed"
        finally:
            self._warmup_done.set()

    def start(self):
        if self._closed:
            raise OllamaRuntimeError("The local scanner has stopped; restart MaskCode.")
        if self._process is not None:
            if self._process.poll() is None and self.network_isolation:
                return self
            raise OllamaRuntimeError("The local scanner has stopped; restart MaskCode.")
        if platform.system() != "Darwin" or not Path("/usr/bin/sandbox-exec").is_file():
            raise OllamaRuntimeError("The protected local scanner currently requires macOS.")
        binary = shutil.which("ollama")
        if not binary or not Path("/usr/sbin/lsof").is_file():
            raise OllamaRuntimeError("Install Ollama and a local model before using the local scanner.")
        binary = str(Path(binary).resolve())
        models = (Path.home() / ".ollama" / "models").resolve()
        name, tag = self.model.split(":", 1)
        manifest = models / "manifests" / "registry.ollama.ai" / "library" / name / tag
        if not manifest.is_file():
            raise OllamaRuntimeError("The selected local Ollama model is not installed. No download was started.")
        try:
            self._temporary_home = tempfile.TemporaryDirectory(prefix="maskcode-ollama-")
            runtime_home = Path(self._temporary_home.name).resolve()
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                self.port = reservation.getsockname()[1]
            environment = _environment(binary, models, runtime_home, self.port)
            profile = _profile(models, runtime_home)
            _verify_isolation(profile, environment)
            self._process = subprocess.Popen(
                ["/usr/bin/sandbox-exec", "-p", profile, binary, "serve"],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                env=environment, cwd=runtime_home, start_new_session=True, close_fds=True,
            )
            deadline = time.monotonic() + 20
            while True:
                if self._process.poll() is not None:
                    raise OllamaRuntimeError("The protected Ollama server could not start.")
                try:
                    self._request("GET", "/api/version", timeout=2)
                    break
                except OllamaRuntimeError:
                    if time.monotonic() >= deadline:
                        raise OllamaRuntimeError("The protected Ollama server did not become ready.") from None
                    time.sleep(0.1)
            shown = self._request("POST", "/api/show", {"model": self.model}, timeout=15)
            self._validate_local_model(shown)
            self.network_isolation = True
            return self
        except BaseException as error:
            self.close()
            if isinstance(error, (OllamaRuntimeError, KeyboardInterrupt, SystemExit)):
                raise
            raise OllamaRuntimeError("The protected local scanner could not start.") from None

    @staticmethod
    def _validate_local_model(shown):
        details = shown.get("details")
        if (any(shown.get(key) for key in ("remote_host", "remote_model", "remote", "cloud"))
                or not isinstance(details, dict) or details.get("format") != "gguf"
                or "completion" not in shown.get("capabilities", [])):
            raise OllamaRuntimeError("The selected model is not a verified local text model.")

    def _owns_listener(self):
        process = self._process
        if process is None or process.poll() is not None:
            return False
        try:
            result = subprocess.run(
                ["/usr/sbin/lsof", "-nP", "-a", "-p", str(process.pid),
                 "-iTCP:%d" % self.port, "-sTCP:LISTEN", "-Fpn"],
                capture_output=True, text=True, timeout=3, close_fds=True,
            )
            lines = result.stdout.splitlines()
            addresses = [line for line in lines if line.startswith("n")]
            return (result.returncode == 0 and ("p%d" % process.pid) in lines
                    and addresses == ["n127.0.0.1:%d" % self.port])
        except (OSError, subprocess.SubprocessError):
            return False

    def _request(self, method, path, payload=None, timeout=120):
        if path not in {"/api/version", "/api/show", "/api/chat"}:
            raise OllamaRuntimeError("Unsupported local scanner request.")
        if self._closed or self.port is None:
            raise OllamaRuntimeError("The local scanner has stopped; restart MaskCode.")
        try:
            body = None if payload is None else json.dumps(payload, ensure_ascii=False).encode("utf-8")
        except (TypeError, ValueError, UnicodeError):
            raise OllamaRuntimeError("The local scanner request was invalid.") from None
        if body is not None and len(body) > MAX_REQUEST_BYTES:
            raise OllamaRuntimeError("The local scanner request was too large; no cloud request was sent.")
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=timeout)
        try:
            connection.connect()
            # Validate ownership after connecting but before sending any bytes.
            # A port race at startup cannot send a prompt to an unowned listener.
            if not self._owns_listener():
                raise OllamaRuntimeError("The local scanner connection could not be verified.")
            connection.request(method, path, body=body, headers={"Content-Type": "application/json"})
            response = connection.getresponse()
            if response.status != 200:
                # Includes redirects: http.client never follows them.
                raise OllamaRuntimeError("The local scanner request failed; no cloud request was sent.")
            raw = response.read(MAX_RESPONSE_BYTES + 1)
            if len(raw) > MAX_RESPONSE_BYTES:
                raise OllamaRuntimeError("The local scanner response was too large.")
            parsed = json.loads(raw)
            if not isinstance(parsed, dict) or parsed.get("error"):
                raise OllamaRuntimeError("The local scanner returned an invalid response.")
            return parsed
        except OllamaRuntimeError:
            raise
        except (OSError, ValueError, http.client.HTTPException):
            raise OllamaRuntimeError("The local scanner did not respond; no cloud request was sent.") from None
        finally:
            connection.close()

    def chat(self, messages, schema, timeout=120):
        if not self.network_isolation or self._closed:
            raise OllamaRuntimeError("The protected local scanner is not running.")
        if (not isinstance(messages, list) or not 1 <= len(messages) <= 8
                or any(not isinstance(item, dict) or set(item) != {"role", "content"}
                       or item["role"] not in {"system", "user", "assistant"}
                       or not isinstance(item["content"], str) for item in messages)
                or not isinstance(schema, dict)
                or isinstance(timeout, bool) or not isinstance(timeout, (int, float))
                or not 1 <= timeout <= 300):
            raise OllamaRuntimeError("The local scanner request was invalid.")
        deadline = time.monotonic() + timeout
        if threading.current_thread() is not self._warmup_thread:
            if not self._warmup_done.wait(timeout):
                raise OllamaRuntimeError("The local scanner is still loading; no cloud request was sent.")
        remaining = deadline - time.monotonic()
        if self._closed or not self.network_isolation:
            raise OllamaRuntimeError("The protected local scanner is not running.")
        if remaining <= 0:
            raise OllamaRuntimeError("The local scanner did not respond; no cloud request was sent.")
        # Limit concurrency and cache to a single small model on modest Macs.
        with self._lock:
            if self._closed or not self.network_isolation:
                raise OllamaRuntimeError("The protected local scanner is not running.")
            result = self._request("POST", "/api/chat", {
                "model": self.model, "messages": messages, "format": schema,
                # Keep the owned detector loaded until MaskCode closes its
                # process. An idle chat must not repeat costly Metal startup.
                "stream": False, "keep_alive": -1,
                "options": {"temperature": 0, "seed": 0, "num_ctx": 8192, "num_predict": 2048},
            }, timeout=remaining)
        try:
            if result.get("done") is not True or result.get("done_reason") == "length":
                raise ValueError
            parsed = json.loads(result["message"]["content"])
            if not isinstance(parsed, dict):
                raise ValueError
            with self._warmup_state_lock:
                if not self._closed:
                    self._warmup_status = "ready"
            return parsed
        except (KeyError, TypeError, ValueError):
            raise OllamaRuntimeError("The local scanner returned incomplete structured data.") from None

    def generate_json(self, system, text, schema, timeout=120):
        return self.chat([{"role": "system", "content": system},
                          {"role": "user", "content": text}], schema, timeout=timeout)

    def close(self):
        with self._warmup_state_lock:
            if self._closed:
                return
            self._closed = True
            self.network_isolation = False
            self._warmup_status = "closed"
            # Wake scans waiting for warmup before terminating owned inference.
            self._warmup_done.set()
        process, self._process = self._process, None
        if process is not None:
            # start_new_session creates this group's identity. Never find/kill
            # pre-existing Ollama processes or the user's own Ollama service.
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=5)
        if self._temporary_home is not None:
            self._temporary_home.cleanup()
            self._temporary_home = None

    def __enter__(self):
        return self.start()

    def __exit__(self, *unused):
        self.close()
