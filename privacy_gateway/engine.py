"""Persistent, private stdio connection to the installed Claude Code engine.

The wire protocol follows Anthropic's open-source claude-agent-sdk-python
query/client implementation. No SDK, bundled CLI, credential reader, or terminal
emulator is needed. All model traffic still crosses the local masking gateway.
Callbacks run on a background reader thread and should enqueue UI work promptly.

Protocol reference:
https://github.com/anthropics/claude-agent-sdk-python/blob/main/src/claude_agent_sdk/_internal/query.py
"""
from __future__ import annotations

import copy
import json
import os
import select
import signal
import subprocess
import threading
import time
import uuid

from .client import build_claude_engine_command, claude_environment


MAX_LINE_BYTES = 16 * 1024 * 1024
MAX_PERMISSIONS = 32
CONTROL_TIMEOUT = 15.0
INITIALIZE_TIMEOUT = 60.0
PERMISSION_TIMEOUT = 300.0
WRITE_TIMEOUT = 10.0


class EngineError(RuntimeError):
    """A safe local diagnostic, never child stderr or a credential-bearing blob."""


class ClaudeEngine:
    def __init__(self, server, extra, cwd, on_event):
        self.server, self.extra, self.cwd = server, list(extra), cwd
        self.on_event = on_event
        self.session_id = None
        self.initialization = {}
        self.busy = False
        self.ready = False
        self._lock = threading.RLock()
        self._write_lock = threading.Lock()
        self._stopping = threading.Event()
        self._process = None
        self._threads = []
        self._controls = {}
        self._permissions = {}
        self._started = False
        self._closed = False

    def _emit(self, event):
        # A callback gets its own object: it cannot mutate a pending permission.
        try:
            self.on_event(copy.deepcopy(event))
        except Exception:
            # Rendering failures must never approve a tool or print raw data.
            pass

    def start(self):
        """Launch once, then wait for the bounded initialization handshake."""
        with self._lock:
            if self._started or self._closed:
                raise EngineError("The MaskCode engine has already been started or closed.")
            self._started = True
        try:
            argv = build_claude_engine_command(self.server, self.extra)
            env = claude_environment(self.server)
            with self._lock:
                if self._closed:
                    raise EngineError("The MaskCode engine was closed during startup.")
                self._process = subprocess.Popen(
                    argv, cwd=self.cwd, env=env, stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                    bufsize=0, close_fds=True, start_new_session=True,
                )
                os.set_blocking(self._process.stdin.fileno(), False)
            for target, name in ((self._read, "maskcode-engine-reader"),
                                 (self._wait, "maskcode-engine-process"),
                                 (self._watch_permissions, "maskcode-engine-permissions")):
                thread = threading.Thread(target=target, name=name, daemon=True)
                self._threads.append(thread)
                thread.start()
            response = self._control({"subtype": "initialize", "hooks": None}, INITIALIZE_TIMEOUT)
            with self._lock:
                if self._closed or self._process.poll() is not None:
                    raise EngineError("The MaskCode engine stopped during startup.")
                self.initialization = response
                self.ready = True
            return response
        except Exception as exc:
            self.close()
            if isinstance(exc, EngineError):
                raise
            # argv, cwd, CLI diagnostics, and env can contain private data.
            raise EngineError("MaskCode could not start the installed Claude engine. Check its installation and supported options.") from None

    def _write(self, message):
        try:
            body = (json.dumps(message, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
        except (TypeError, ValueError, UnicodeError):
            raise EngineError("The engine message could not be encoded.") from None
        if len(body) > MAX_LINE_BYTES:
            raise EngineError("The engine message exceeds the local size limit.")
        deadline = time.monotonic() + WRITE_TIMEOUT
        if not self._write_lock.acquire(timeout=WRITE_TIMEOUT):
            raise EngineError("The MaskCode engine input timed out.")
        try:
            with self._lock:
                process = self._process
                if self._closed or process is None or process.poll() is not None:
                    raise EngineError("The MaskCode engine is not running.")
                fd = process.stdin.fileno()
            sent = 0
            while sent < len(body):
                if self._stopping.is_set():
                    raise EngineError("The MaskCode engine is closing.")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    # A partially written JSON line cannot be safely retried.
                    self._terminate()
                    raise EngineError("The MaskCode engine input timed out.")
                _, writable, _ = select.select([], [fd], [], min(remaining, .2))
                if not writable:
                    continue
                try:
                    count = os.write(fd, body[sent:sent + 65536])
                except BlockingIOError:
                    continue
                if count <= 0:
                    raise OSError()
                sent += count
        except (OSError, ValueError):
            raise EngineError("The MaskCode engine input closed unexpectedly.") from None
        finally:
            self._write_lock.release()

    def _control(self, request, timeout=CONTROL_TIMEOUT):
        if threading.current_thread().name == "maskcode-engine-reader":
            raise EngineError("Engine control actions must run outside the event callback.")
        request_id = uuid.uuid4().hex
        pending = {"event": threading.Event(), "response": None}
        with self._lock:
            self._controls[request_id] = pending
        try:
            self._write({"type": "control_request", "request_id": request_id, "request": request})
            if not pending["event"].wait(timeout):
                raise EngineError("The MaskCode engine control request timed out.")
            response = pending["response"]
            if not isinstance(response, dict) or response.get("subtype") != "success":
                raise EngineError("The installed Claude engine could not complete this action.")
            result = response.get("response", {})
            return result if isinstance(result, dict) else {}
        finally:
            with self._lock:
                self._controls.pop(request_id, None)

    def send(self, prompt):
        if not isinstance(prompt, str) or not prompt.strip():
            raise EngineError("Enter a prompt before sending.")
        with self._lock:
            if not self.ready or self._closed:
                raise EngineError("The MaskCode engine is not ready.")
            if self.busy:
                raise EngineError("Wait for the current turn or interrupt it before sending another prompt.")
            self.busy = True
            session_id = self.session_id or "default"
        try:
            self._write({"type": "user", "message": {"role": "user", "content": prompt},
                         "parent_tool_use_id": None, "session_id": session_id})
        except EngineError:
            with self._lock:
                self.busy = False
            raise

    def interrupt(self):
        with self._lock:
            if not self.ready or self._closed:
                raise EngineError("The MaskCode engine is not ready.")
            permission_ids = list(self._permissions)
        for request_id in permission_ids:
            self.decide_permission(request_id, False)
        return self._control({"subtype": "interrupt"})

    def set_model(self, model):
        if model is not None and (not isinstance(model, str) or not model.strip()
                                  or len(model) > 256 or any(ord(c) < 32 for c in model)):
            raise EngineError("Enter a valid model name.")
        with self._lock:
            if not self.ready or self._closed:
                raise EngineError("The MaskCode engine is not ready.")
        return self._control({"subtype": "set_model", "model": model})

    def _permission_response(self, request_id, decision):
        self._write({"type": "control_response", "response": {
            "subtype": "success", "request_id": request_id, "response": decision}})

    def decide_permission(self, request_id, allowed):
        if type(allowed) is not bool or not isinstance(request_id, str):
            raise EngineError("A tool decision must explicitly allow or deny the pending request.")
        with self._lock:
            pending = self._permissions.pop(request_id, None)
        if pending is None:
            return False
        if allowed and pending["deadline"] > time.monotonic():
            decision = {"behavior": "allow", "updatedInput": pending["input"]}
        else:
            decision = {"behavior": "deny", "message": "The user did not approve this tool action."}
        self._permission_response(request_id, decision)
        return True

    def _incoming_control(self, message):
        request_id, request = message.get("request_id"), message.get("request")
        if not isinstance(request_id, str) or not request_id or len(request_id) > 256:
            raise EngineError("The installed Claude engine sent an invalid control request.")
        if not isinstance(request, dict) or request.get("subtype") != "can_use_tool":
            self._write({"type": "control_response", "response": {
                "subtype": "error", "request_id": request_id,
                "error": "This control request is not supported by MaskCode."}})
            return
        tool, inputs = request.get("tool_name"), request.get("input")
        if not isinstance(tool, str) or not tool or len(tool) > 256 or not isinstance(inputs, dict):
            self._permission_response(request_id, {"behavior": "deny", "message": "Invalid tool permission request."})
            return
        with self._lock:
            if request_id in self._permissions:
                raise EngineError("The installed Claude engine reused an active permission request.")
            if len(self._permissions) >= MAX_PERMISSIONS:
                too_many = True
            else:
                too_many = False
                self._permissions[request_id] = {
                    "input": copy.deepcopy(inputs), "deadline": time.monotonic() + PERMISSION_TIMEOUT}
        if too_many:
            self._permission_response(request_id, {"behavior": "deny", "message": "Too many pending tool requests."})
            return
        self._emit({"type": "permission_request", "id": request_id, "tool": tool, "input": inputs})

    def _dispatch(self, message):
        kind = message.get("type")
        if kind == "control_response":
            response = message.get("response")
            if not isinstance(response, dict) or not isinstance(response.get("request_id"), str):
                raise EngineError("The installed Claude engine sent an invalid control response.")
            with self._lock:
                pending = self._controls.get(response["request_id"])
                if pending:
                    pending["response"] = response
                    pending["event"].set()
        elif kind == "control_request":
            self._incoming_control(message)
        elif kind == "control_cancel_request":
            request_id = message.get("request_id")
            if isinstance(request_id, str):
                with self._lock:
                    pending = self._permissions.pop(request_id, None)
                if pending:
                    self._emit({"type": "permission_cancelled", "id": request_id})
        elif kind in {"system", "assistant", "user", "result", "stream_event", "tool_progress",
                      "tool_use_summary", "auth_status", "rate_limit_event"}:
            with self._lock:
                if isinstance(message.get("session_id"), str):
                    self.session_id = message["session_id"]
                if kind == "result":
                    self.busy = False
            self._emit(message)
        # Unexpected telemetry/transcript-mirroring messages are not displayed.

    def _read(self):
        pending = bytearray()
        try:
            while not self._stopping.is_set():
                chunk = os.read(self._process.stdout.fileno(), 65536)
                if not chunk:
                    if pending.strip():
                        raise EngineError("The installed Claude engine returned an incomplete response.")
                    return
                pending.extend(chunk)
                while b"\n" in pending:
                    newline = pending.index(b"\n")
                    if newline > MAX_LINE_BYTES:
                        raise EngineError("The engine response exceeds the local size limit.")
                    line = bytes(pending[:newline]).strip()
                    del pending[:newline + 1]
                    if not line:
                        continue
                    if not line.startswith(b"{"):
                        # Some CLI versions write startup debug notices to stdout.
                        # Never render these unstructured, potentially private lines.
                        continue
                    message = json.loads(line)
                    if not isinstance(message, dict):
                        raise ValueError()
                    self._dispatch(message)
                if len(pending) > MAX_LINE_BYTES:
                    raise EngineError("The engine response exceeds the local size limit.")
        except (OSError, ValueError, UnicodeError, RecursionError, EngineError):
            if not self._stopping.is_set():
                self._emit({"type": "engine_error", "message": "The installed Claude engine returned an invalid or interrupted response."})
                self._terminate()

    def _watch_permissions(self):
        while not self._stopping.wait(.2):
            with self._lock:
                expired = [key for key, pending in self._permissions.items()
                           if pending["deadline"] <= time.monotonic()]
            for request_id in expired:
                try:
                    if self.decide_permission(request_id, False):
                        self._emit({"type": "permission_cancelled", "id": request_id})
                except EngineError:
                    return

    def _finish_pending(self):
        with self._lock:
            self.ready = False
            self.busy = False
            self._permissions.clear()
            for pending in self._controls.values():
                pending["event"].set()

    def _wait(self):
        code = self._process.wait()
        # Drain remaining result frames before emitting exit and clearing busy.
        reader = next((t for t in self._threads if t.name == "maskcode-engine-reader"), None)
        if reader and reader is not threading.current_thread():
            reader.join(2)
        self._stopping.set()
        self._finish_pending()
        self._emit({"type": "engine_exit", "code": code})

    def _terminate(self):
        self._stopping.set()
        self._finish_pending()
        with self._lock:
            process = self._process
        if process and process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass

    def close(self):
        with self._lock:
            self._closed = True
        self._terminate()
        process = self._process
        if process:
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=2)
            for stream in (process.stdin, process.stdout):
                if stream:
                    stream.close()
        for thread in self._threads:
            if thread is not threading.current_thread():
                thread.join(timeout=2)
