"""MaskCode's terminal workspace, inspired by Hermes Agent's warm CLI palette.

Only plain text is rendered. Conversation, drafts and history stay in memory.
The UI is independent of the installed provider client and never rewrites it.
"""
import asyncio
from dataclasses import dataclass
import difflib
import json
from pathlib import Path
import queue
import re
import threading

from prompt_toolkit.application import Application
from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.filters import Condition
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout import (
    ConditionalContainer, DynamicContainer, Float, FloatContainer, HSplit,
    Layout, Window,
)
from prompt_toolkit.layout.controls import FormattedTextControl
from prompt_toolkit.layout.dimension import Dimension
from prompt_toolkit.layout.menus import CompletionsMenu
from prompt_toolkit.lexers import Lexer
from prompt_toolkit.styles import Style
from prompt_toolkit.widgets import Button, Dialog, TextArea

from . import __version__


_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f\ud800-\udfff\u202a-\u202e\u2066-\u2069]")


def safe_text(value):
    """Make control codes visible without interpreting ANSI, HTML or markup."""
    return _CONTROL.sub(lambda match: "\\u%04x" % ord(match.group()), str(value)).expandtabs(4)


def pretty(value):
    return safe_text(json.dumps(value, indent=2, ensure_ascii=False, default=str))


def preview_text(value, *, lines=12, chars=2400, suffix="tool output shortened"):
    """Bound display previews only; engine messages and permission inputs stay intact."""
    text = safe_text(value)
    parts = text.splitlines(keepends=True)
    shown = "".join(parts[:lines])[:chars]
    if len(shown) < len(text):
        return shown.rstrip() + "\n… (" + suffix + ")"
    return text


def tool_description(name, inputs, *, cwd=None, review=False):
    """Readable activity and permission previews, without interpreting tool content."""
    if not isinstance(inputs, dict):
        return pretty(inputs) if review else preview_text(pretty(inputs))
    if not inputs:
        return "No input options." if review else "Preparing…"
    remaining = dict(inputs)
    parts = []
    path = remaining.pop("file_path") if "file_path" in remaining else remaining.pop("path", None)
    if path is not None:
        display = str(path)
        if not review and cwd is not None:
            try:
                display = str(Path(display).relative_to(cwd))
            except ValueError:
                pass
        parts.append(("File: " if review else "") + safe_text(display))
    clip = {"lines": 30, "chars": 6000,
            "suffix": "preview shortened; Ctrl+O shows the complete exact input"} if review else {
                "lines": 7, "chars": 1000, "suffix": "activity preview shortened"}
    if name == "Bash":
        command = remaining.pop("command", "")
        description = remaining.pop("description", "")
        if description:
            parts.append(safe_text(description))
        # A permission request must never silently abbreviate the command.
        parts.append("$ " + (safe_text(command) if review else preview_text(command, **clip)))
    elif name == "Write":
        content = remaining.pop("content", "")
        parts.append("Write " + str(len(str(content).splitlines())) + " lines")
        if content:
            parts.append(preview_text(content, **clip))
    elif name == "Edit":
        old = remaining.pop("old_string", "")
        new = remaining.pop("new_string", "")
        if isinstance(old, str) and isinstance(new, str):
            change = "\n".join(difflib.unified_diff(old.splitlines(), new.splitlines(),
                                fromfile="before", tofile="after", lineterm="", n=2))
            if not change:
                change = "Line-ending change; Ctrl+O shows exact input." if old != new and review else (
                    "Line-ending change" if old != new else "No text change")
            parts.append(preview_text(change, **clip))
        else:
            parts.append(preview_text(pretty({"old_string": old, "new_string": new}), **clip))
    elif name in ("Grep", "Glob"):
        pattern = remaining.pop("pattern", "")
        parts.append("Pattern: " + safe_text(json.dumps(pattern, ensure_ascii=False)))
    # Keep every extra option visible during a permission decision. This
    # includes execution settings and options not recognized by this UI.
    if remaining:
        options = "\n".join(safe_text(key.replace("_", " ")) + ": " +
                            safe_text(json.dumps(value, ensure_ascii=False, default=str))
                            for key, value in remaining.items())
        parts.append(options if review else preview_text(options, lines=4, chars=700,
                                                         suffix="activity options shortened"))
    description = "\n\n".join(parts) or pretty(inputs)
    return description if review else preview_text(description, lines=16, chars=3000,
                                                    suffix="activity preview shortened")


COMMANDS = {
    "/help": "Keyboard shortcuts and commands",
    "/about": "Credits and personal-use scope",
    "/model": "Show or change the engine model",
    "/clear": "Clear the display; conversation remains with the engine",
    "/privacy": "Inspect this session's masking and network status",
    "/restart": "Start a fresh conversation; keep the unsent draft",
    "/login": "Open official Claude login, then start a fresh conversation",
    "/quit": "Close MaskCode",
    "/exit": "Close MaskCode",
}


class SlashCompleter(Completer):
    def get_completions(self, document, complete_event):
        text = document.text_before_cursor
        if not text.startswith("/") or "\n" in text or " " in text:
            return
        for command, description in COMMANDS.items():
            if command.startswith(text):
                yield Completion(command, start_position=-len(text), display_meta=description)


class TranscriptLexer(Lexer):
    def lex_document(self, document):
        def line(index):
            value = document.lines[index]
            if value.startswith("  YOU"):
                style = "class:role.user"
            elif value.startswith("  MASKCODE"):
                style = "class:role.assistant"
            elif value.startswith("  TOOL"):
                style = "class:role.tool"
            elif value.startswith("  ERROR"):
                style = "class:role.error"
            elif value.startswith("  SESSION"):
                style = "class:role.system"
            else:
                style = "class:transcript"
            return [(style, value)]
        return line


@dataclass
class Entry:
    role: str
    text: str
    label: str = ""


class TerminalApp:
    def __init__(self, cwd, mode="auto", model=None, *, input=None, output=None):
        self.cwd = Path(cwd)
        self.engine_cwd_known = False
        self.mode = mode
        self.model = model or "configured model"
        self.engine = None
        self.gateway_state = None
        self.events = queue.Queue()
        self.entries = []
        self.status = "Starting engine"
        self.busy = False
        self.ready = False
        self.restart_requested = False
        self.login_requested = False
        self.resume_draft = ""
        self._engine_exited = False
        self._startup_failed = False
        self._login_required = False
        self._closing = False
        self._exit_code = 0
        self._dirty = True
        self._follow_tail = True
        self._snapshot = {}
        self._dialog = None
        self._approval = None
        self._approval_text = None
        self._approval_summary = None
        self._approval_details = None
        self._approval_expanded = False
        self._deny_button = None
        self._approve_button = None
        self._tool_pending = []
        self._decided = set()
        self._message_id = None
        self._blocks = {}
        self._tool_entries = {}
        self._tool_names = {}
        self._seen_results = set()
        self._full_texts = set()
        self._streamed_turn_text = False
        self._initial_prompt = None
        self._started_initial = False
        self._pump_task = None
        self.history = InMemoryHistory()
        self.input = TextArea(
            height=Dimension(min=1, max=6), multiline=True, wrap_lines=True,
            history=self.history, completer=SlashCompleter(), complete_while_typing=True,
            prompt=[("class:prompt", "❯ ")], scrollbar=False,
            style="class:composer", name="maskcode-composer",
        )
        self.transcript = TextArea(
            text="", read_only=True, scrollbar=True, wrap_lines=True,
            lexer=TranscriptLexer(), focusable=True, name="maskcode-conversation",
            style="class:transcript",
        )
        self._kb = self._key_bindings()
        self._root = self._layout()
        self.app = Application(
            layout=Layout(self._root, focused_element=self.input),
            key_bindings=self._kb, full_screen=True, mouse_support=True,
            style=self._style(), input=input, output=output,
            min_redraw_interval=0.035,
        )

    def bind(self, engine, gateway_state):
        self.engine = engine
        self.gateway_state = gateway_state
        return self

    def post_event(self, event):
        """Safe to invoke from the engine's reader and callback threads."""
        self.events.put(event)

    @staticmethod
    def _style():
        return Style.from_dict({
            "": "bg:#121315 #eee7d6",
            "header": "bg:#121315 #cd7f32",
            "brand": "#ffd166 bold",
            "logo": "#ffbf69 bold",
            "muted": "#938b7d",
            "subtitle": "#d7b984",
            "rule": "#725232",
            "status": "bg:#21201d #d0b984",
            "status.key": "bg:#21201d #ffcc80 bold",
            "composer": "bg:#191a1c #fff8dc",
            "prompt": "bg:#191a1c #ffbf69 bold",
            "transcript": "#eee7d6",
            "role.user": "#ffbf69 bold",
            "role.assistant": "#ffd166 bold",
            "role.tool": "#95c9bf bold",
            "role.error": "#ff9b89 bold",
            "role.system": "#938b7d bold",
            "bottom": "#938b7d",
            "frame.border": "#cd7f32",
            "dialog": "bg:#191a1c #fff8dc",
            "dialog.body": "bg:#191a1c #fff8dc",
            "dialog.body label": "#fff8dc",
            "dialog frame.label": "#ffd166 bold",
            "approval": "bg:#191a1c #fff8dc",
            "button": "bg:#33312a #e8d6b9",
            "button.focused": "bg:#ffd166 #191a1c bold",
            "scrollbar.background": "bg:#222326",
            "scrollbar.button": "bg:#725232",
            "completion-menu.completion": "bg:#292822 #ded4bf",
            "completion-menu.completion.current": "bg:#805b30 #fff8dc",
            "completion-menu.meta.completion": "bg:#24231f #aa9f8a",
            "completion-menu.meta.completion.current": "bg:#684a29 #fff8dc",
        })

    def _layout(self):
        header = Window(FormattedTextControl(self._header), height=4, style="class:header")
        welcome = ConditionalContainer(
            Window(FormattedTextControl(self._welcome), height=5),
            filter=Condition(lambda: not self.entries),
        )
        body = HSplit([
            header,
            Window(height=1, char="─", style="class:rule"),
            welcome,
            self.transcript,
            Window(FormattedTextControl(self._status_line), height=1, style="class:status"),
            Window(height=1, char="─", style="class:rule"),
            self.input,
            Window(FormattedTextControl(self._footer), height=1, style="class:bottom"),
        ])
        approval = ConditionalContainer(
            DynamicContainer(lambda: self._dialog or Window()),
            filter=Condition(lambda: self._dialog is not None),
        )
        return FloatContainer(body, floats=[
            Float(xcursor=True, ycursor=True, content=CompletionsMenu(max_height=7, scroll_offset=1)),
            Float(left=1, right=1, top=1, bottom=1, content=approval),
        ])

    def _header(self):
        width = self.app.output.get_size().columns if hasattr(self, "app") else 80
        directory = safe_text(str(self.cwd))
        if width < 60:
            return [("class:brand", "  ◈ MASKCODE "), ("class:muted", "v" + __version__ + "\n"),
                    ("class:subtitle", "  Your local coding workspace\n"),
                    ("class:muted", "  " + directory + "\n"),
                    ("class:muted", "  Powered by Claude · Hermes-inspired")]
        return [
            ("class:logo", "  ╭──────╮   "), ("class:brand", "M A S K C O D E"),
            ("class:muted", "   v" + __version__ + "\n"),
            ("class:logo", "  │ ◇  ◇ │   "), ("class:subtitle", "Your code. Your terminal. Your boundaries.\n"),
            ("class:logo", "  ╰─╮──╭─╯   "), ("class:muted", directory + "\n"),
            ("class:logo", "    ╰──╯     "), ("class:muted", "Powered by Claude · Hermes-inspired workspace"),
        ]

    def _welcome(self):
        return [("class:subtitle", "\n  What are we building?\n"),
                ("class:muted", "  Ask me to read files, fix a bug, run tests, or make a change.\n"),
                ("class:muted", "  /help commands   /model select model   /privacy inspect protection\n"),
                ("class:muted", "  " + ("Outgoing requests pause here for your review." if self.mode == "review"
                                        else "Masking runs automatically. File and command permissions stay with you."))]

    def _status_line(self):
        count = sum(v for v in self._snapshot.get("redactions", {}).values()
                    if isinstance(v, (int, float)))
        mode = "REVIEW" if self.mode == "review" else "MASKING"
        scan = self._snapshot.get("semantic_scan", {})
        status = self.status
        if scan.get("enabled"):
            mode = "AI + " + mode
            if scan.get("status") == "blocked":
                status = "Local privacy scan blocked · /privacy"
            elif scan.get("warmup_status") == "loading":
                status = "Loading local privacy model" if self.busy else "Preparing local privacy model · you can type"
            elif scan.get("status") == "scanning":
                status = "Checking sensitive data locally · " + str(scan.get("completed_chunks", 0)) + "/" + str(scan.get("current_chunks", 0)) + " chunks checked"
        if not self.busy and self._snapshot.get("last_upstream_status") == 429:
            status = "Provider rate limit (429) · try later or /model"
        return [("class:status.key", " " + mode + " "),
                ("class:status", "│ " + safe_text(self.model) + " │ " + str(count) + " masked │ " + safe_text(status))]

    def _footer(self):
        width = self.app.output.get_size().columns
        if width < 48:
            text = " enter send · ^J newline · /help · ^D exit"
        elif width < 70:
            text = " enter send · alt+enter ↵ · /help · ^C stop · ^D exit"
        else:
            text = "  enter send · alt+enter ↵ · / help · pgup scroll · ^C stop · ^D exit"
        return [("class:bottom", text)]

    def _key_bindings(self):
        kb = KeyBindings()
        composing = Condition(lambda: self._dialog is None and self.app.layout.has_focus(self.input))
        normal = Condition(lambda: self._dialog is None)
        reviewing = Condition(lambda: self._dialog is not None)

        @kb.add("enter", filter=composing, eager=True)
        def submit(event):
            self.submit()

        @kb.add("escape", "enter", filter=composing, eager=True)
        @kb.add("c-j", filter=composing, eager=True)
        def newline(event):
            self.input.buffer.insert_text("\n")

        @kb.add("c-c", eager=True)
        def interrupt(event):
            if self._dialog:
                self._resolve_approval(False)
            elif self.busy:
                self._worker(self.engine.interrupt)
                self.status = "Interrupting"
            elif self.input.text:
                self.input.text = ""
            else:
                self.status = "Ctrl+D to exit"

        @kb.add("c-d", eager=True)
        def leave(event):
            if self._dialog:
                self._resolve_approval(False)
            elif not self.input.text:
                self._request_exit()
            else:
                self.input.buffer.delete()

        @kb.add("f5", filter=normal, eager=True)
        def restart(event):
            self._request_restart()

        # Own review navigation at app level. Dynamic dialogs can receive a
        # key before a redraw refreshes prompt_toolkit's parent-container map;
        # inherited Dialog bindings must not decide whether Tab works.
        @kb.add("tab", filter=reviewing, eager=True)
        @kb.add("s-tab", filter=reviewing, eager=True)
        def review_select(event):
            selected = self._approve_button if self.app.layout.has_focus(self._deny_button) else self._deny_button
            self.app.layout.focus(selected)

        @kb.add("enter", filter=reviewing, eager=True)
        def review_confirm(event):
            self._resolve_approval(self.app.layout.has_focus(self._approve_button))

        @kb.add("escape", filter=reviewing, eager=True)
        def deny(event):
            self._resolve_approval(False)

        @kb.add("c-o", filter=reviewing, eager=True)
        def permission_details(event):
            if self._approval and self._approval["kind"] == "tool":
                self._approval_expanded = not self._approval_expanded
                self._approval_text.text = (self._approval_details if self._approval_expanded
                                           else self._approval_summary)
                self._approval_text.buffer.cursor_position = 0
                self.app.invalidate()

        @kb.add("pageup", filter=normal, eager=True)
        def page_up(event):
            self._scroll(-1)

        @kb.add("pagedown", filter=normal, eager=True)
        def page_down(event):
            self._scroll(1)

        @kb.add("pageup", filter=reviewing, eager=True)
        def review_up(event):
            self._approval_scroll(-1)

        @kb.add("pagedown", filter=reviewing, eager=True)
        def review_down(event):
            self._approval_scroll(1)

        @kb.add("escape", filter=normal)
        def return_to_input(event):
            self.app.layout.focus(self.input)

        return kb

    def _scroll(self, direction):
        self._follow_tail = False
        self.app.layout.focus(self.transcript)
        amount = max(3, self.app.output.get_size().rows - 12)
        if direction < 0:
            self.transcript.buffer.cursor_up(amount)
        else:
            self.transcript.buffer.cursor_down(amount)
            if self.transcript.buffer.document.is_cursor_at_the_end:
                self._follow_tail = True

    def _approval_scroll(self, direction):
        if self._approval_text:
            amount = max(3, self.app.output.get_size().rows - 12)
            if direction < 0:
                self._approval_text.buffer.cursor_up(amount)
            else:
                self._approval_text.buffer.cursor_down(amount)

    def _worker(self, function, *args, success=None):
        def work():
            try:
                value = function(*args)
                if success:
                    self.post_event({"type": success, "value": value})
            except Exception as exc:
                self.post_event({"type": "engine_error", "message": str(exc) or type(exc).__name__})
        threading.Thread(target=work, name="maskcode-ui-action", daemon=True).start()

    def submit(self):
        text = self.input.text
        if not text.strip():
            return
        if self._dialog:
            return
        # An absolute file path is ordinary prompt content. Only commands this
        # interface implements are intercepted; pasted paths reach the agent.
        if text.startswith("/") and text.split(maxsplit=1)[0] in COMMANDS:
            self.input.buffer.append_to_history()
            self.input.text = ""
            self._command(text)
            return
        if not self.ready or self.busy:
            self.status = "Wait for this turn, or Ctrl+C to interrupt" if self.busy else self._unready_status()
            self.app.invalidate()
            return
        self.input.buffer.append_to_history()
        self.input.text = ""
        self._send(text)

    def _send(self, text):
        self._append("user", text)
        self.busy = True
        self._streamed_turn_text = False
        self.status = "Working"
        self._follow_tail = True
        self.app.layout.focus(self.input)
        self._worker(self.engine.send, text)

    def _command(self, text):
        parts = text.split(maxsplit=1)
        command = parts[0]
        argument = parts[1].strip() if len(parts) > 1 else ""
        if command in ("/quit", "/exit"):
            self._request_exit()
        elif command in ("/restart", "/login"):
            self._request_restart(login=command == "/login")
        elif command == "/help":
            self._append("system", "\n".join(name.ljust(10) + description for name, description in COMMANDS.items())
                         + "\n\nEnter sends · Alt+Enter / Ctrl+J adds a line · Tab completes commands"
                         + "\nUp/Down recalls drafts · PageUp/PageDown scrolls · Escape returns to input"
                         + "\nCtrl+C interrupts a turn or denies a review · Ctrl+D exits with an empty draft"
                         + "\nF5 / /restart starts a fresh conversation and keeps the unsent draft; no prompt is resent."
                         + "\n/login opens official Claude login, then starts a fresh conversation. Restart and login require an idle engine."
                         + "\nIn permissions: Tab selects; Enter confirms. Deny is selected first. Ctrl+O shows exact input.")
        elif command == "/about":
            self._append("system", "MaskCode " + __version__ + " · Powered by Claude"
                         "\nIndependent terminal for personal use on this Mac with your own account."
                         "\nRuns the separately installed, unmodified Claude Code executable."
                         "\nHermes-inspired interface; prompt_toolkit and wcwidth provide terminal rendering."
                         "\nNot affiliated with or endorsed by Anthropic, OpenAI or Nous Research."
                         "\nSee THIRD_PARTY_NOTICES.md and LEGAL_REVIEW.md for licenses and scope."
                         "\nMasking is reversible and does not guarantee anonymity or legal compliance.")
        elif command == "/clear":
            if self.busy:
                self._append("system", "Wait until the current turn finishes before clearing the display.")
                return
            self.entries.clear()
            self._blocks.clear()
            self._tool_entries.clear()
            self._tool_names.clear()
            self._seen_results.clear()
            self._full_texts.clear()
            self._dirty = True
            self.status = "Display cleared · engine conversation retained"
        elif command == "/privacy":
            self._refresh_snapshot()
            self._append("system", "Privacy mode: " + self.mode + "\n" +
                         "Direct network restriction: " + ("active" if self._snapshot.get("network_isolation") else "not confirmed") +
                         "\nRequests forwarded: " + str(self._snapshot.get("forwarded", 0)) +
                         "\nRequests blocked: " + str(self._snapshot.get("blocked", 0)) +
                         "\nMasked values: " + pretty(self._snapshot.get("redactions", {})) +
                         "\nLocal AI detector: " + (str(self._snapshot.get("local_model") or "active")
                             if self._snapshot.get("semantic_scan", {}).get("enabled") else "off (rules only)") +
                         "\nLocal scan: " + pretty(self._snapshot.get("semantic_scan", {})) +
                         "\nLocal detector isolation: " + str(self._snapshot.get("local_isolation") or "not active") +
                         "\nDetected spans and restoration mappings stay in memory. Local scan failure blocks cloud forwarding." +
                         "\n\nMasking can miss confidential meaning. Use maskcode --mask-review to inspect every outgoing request."
                         "\nThe account still authenticates with the provider. Terminal history is memory-only;"
                         " the provider client may retain its own local session files."
                         "\nProtected Claude disables customizations, plugins, hooks, MCP and remote integrations.")
        elif command == "/model":
            if not argument:
                self._append("system", "Current model: " + safe_text(self.model) + "\nUse /model NAME to change the model.")
            elif self.busy or not self.ready:
                self._append("system", "Wait until the current turn finishes before changing model.")
            else:
                self.status = "Changing model"
                self.busy = True
                self._requested_model = argument
                self._worker(self.engine.set_model, argument, success="ui_model_changed")
        else:
            self._append("system", "Unknown command: " + safe_text(command) + ". Use /help.")

    def _unready_status(self):
        if self._login_required:
            return "Login required · /login · draft kept"
        if self._engine_exited or self._startup_failed:
            return "Engine stopped · /restart or F5 · draft kept"
        return "Engine is starting; your draft is kept"

    def _request_restart(self, *, login=False):
        if self.busy or self._dialog:
            self._append("system", "Wait until the current turn finishes, or Ctrl+C to interrupt, before "
                         + ("logging in." if login else "starting a fresh conversation."))
            return
        self.restart_requested = not login
        self.login_requested = login
        self._keep_unsent_initial_prompt()
        self.resume_draft = self.input.text
        self._request_exit()

    def _keep_unsent_initial_prompt(self):
        if self._initial_prompt and not self._started_initial:
            draft = self.input.text
            if not draft:
                self.input.text = self._initial_prompt
            elif draft != self._initial_prompt:
                self.input.text = self._initial_prompt + "\n\n" + draft
        self._started_initial = True

    @staticmethod
    def _authentication_error(text):
        text = text.casefold()
        return any(marker in text for marker in (
            "not logged in", "authentication_error", "authentication failed", "invalid api key",
            "invalid oauth token", "oauth token has expired", "please run /login", "run /login",
        ))

    def _append(self, role, text, label=""):
        entry = Entry(role, safe_text(text), safe_text(label))
        self.entries.append(entry)
        self._dirty = True
        return entry

    def transcript_text(self):
        labels = {"user": "YOU", "assistant": "MASKCODE", "tool": "TOOL", "error": "ERROR", "system": "SESSION"}
        return "\n\n".join("  " + labels.get(entry.role, "SESSION") +
                           ("  ·  " + entry.label if entry.label else "") + "\n" +
                           "\n".join("  " + line for line in entry.text.split("\n"))
                           for entry in self.entries)

    def _render_transcript(self):
        if not self._dirty:
            return
        old = self.transcript.buffer.cursor_position
        self.transcript.text = self.transcript_text()
        self.transcript.buffer.cursor_position = len(self.transcript.text) if self._follow_tail else min(old, len(self.transcript.text))
        self._dirty = False

    def _refresh_snapshot(self):
        if self.gateway_state:
            self._snapshot = self.gateway_state.snapshot()
            self.mode = self._snapshot.get("mode", self.mode)

    def _next_approval(self):
        if self._engine_exited or self._startup_failed or self._closing:
            # An in-flight HTTP worker can enqueue review after engine exit.
            # A stopped session cannot present or approve that late request.
            for pending in self._snapshot.get("pending", []):
                self._decided.add(("gateway", pending["id"]))
                self.gateway_state.decision(pending["id"], "deny")
            if self._approval:
                self._close_approval()
            self._tool_pending.clear()
            return
        if self._approval:
            if self._approval["kind"] == "gateway":
                current = {item["id"] for item in self._snapshot.get("pending", [])}
                if self._approval["id"] not in current:
                    self._close_approval()
                    self._append("system", "Outgoing review expired or was decided elsewhere.")
            return
        for pending in self._snapshot.get("pending", []):
            key = ("gateway", pending["id"])
            if key not in self._decided:
                self._show_approval("gateway", pending)
                return
        while self._tool_pending:
            pending = self._tool_pending.pop(0)
            if ("tool", pending["id"]) not in self._decided:
                self._show_approval("tool", pending)
                return

    def _show_approval(self, kind, pending):
        self.input.buffer.cancel_completion()
        self._approval = {"kind": kind, "id": pending["id"]}
        if kind == "gateway":
            title = " MASKCODE · Review outgoing request "
            detail = "Approval sends the body and headers below to the provider. Credentials are excluded from this view.\n" \
                     "Inspect the complete content for confidential information. Esc / Ctrl+C denies."
            content = "HEADERS (excluding authentication)\n" + pretty(pending.get("headers", {})) + \
                      "\n\nREQUEST BODY\n" + pretty(pending.get("preview", {}))
        else:
            name = pending.get("tool", pending.get("tool_name", "Unknown"))
            title = " MASKCODE · Allow " + safe_text(name) + "? "
            detail = "Allow this action on your Mac?\n" \
                     "Ctrl+O shows the complete exact input. Esc / Ctrl+C denies."
            content = tool_description(name, pending.get("input", {}), review=True)
            self._approval_details = "TOOL: " + safe_text(name) + "\n\nEXACT INPUT\n" + pretty(pending.get("input", {}))
        self._approval_summary = content
        self._approval_expanded = False
        self._approval_text = TextArea(text=content, read_only=True, scrollbar=True, wrap_lines=True,
                                       style="class:approval", focusable=True)
        self._deny_button = Button("Deny", handler=lambda: self._resolve_approval(False))
        self._approve_button = Button("Approve", handler=lambda: self._resolve_approval(True))
        self._dialog = Dialog(
            title=title,
            body=HSplit([
                Window(FormattedTextControl(detail), height=Dimension(min=2, max=4), wrap_lines=True),
                Window(height=1, char="─", style="class:rule"),
                self._approval_text,
                Window(FormattedTextControl(self._approval_footer),
                       height=1, wrap_lines=False),
            ]),
            buttons=[self._deny_button, self._approve_button],
            modal=True, with_background=True,
        )
        self.app.layout.focus(self._deny_button)
        self.status = "Review outgoing request" if kind == "gateway" else "Tool permission requested"
        self.app.invalidate()

    def _approval_footer(self):
        text = "PgUp/PgDn scroll · Tab choose · Enter confirm · default: Deny"
        if self._approval and self._approval["kind"] == "tool":
            text += " · Ctrl+O " + ("summary" if self._approval_expanded else "details")
        return text

    def _close_approval(self):
        self._approval = None
        self._dialog = None
        self._approval_text = None
        self._approval_summary = None
        self._approval_details = None
        self._approval_expanded = False
        self.app.layout.focus(self.input)
        self.status = "Working" if self.busy else "Ready"
        self.app.invalidate()

    def _resolve_approval(self, approved):
        if not self._approval:
            return
        item = self._approval
        self._decided.add((item["kind"], item["id"]))
        if item["kind"] == "gateway":
            result = self.gateway_state.decision(item["id"], "approve" if approved else "deny")
            self._append("system", ("Outgoing request approved." if approved else "Outgoing request denied. Nothing sent.")
                         if result else "Review already expired or was decided elsewhere.")
        else:
            self._worker(self.engine.decide_permission, item["id"], bool(approved))
            self._append("system", "Tool permitted." if approved else "Tool denied.")
        self._close_approval()

    def _handle_stream(self, event):
        kind = event.get("type")
        if kind == "message_start":
            self._message_id = event.get("message", {}).get("id") or "stream-" + str(len(self.entries))
            model = event.get("message", {}).get("model")
            if model:
                self.model = safe_text(model)
        elif kind == "content_block_start":
            index = event.get("index", 0)
            block = event.get("content_block", {})
            state = {"block": block, "json": "", "entry": None}
            self._blocks[(self._message_id, index)] = state
            if block.get("type") == "text":
                state["entry"] = self._append("assistant", block.get("text", ""))
                self._streamed_turn_text = True
            elif block.get("type") == "tool_use":
                ident = block.get("id", "")
                state["entry"] = self._tool_entry(ident, block.get("name", "tool"), block.get("input", {}))
        elif kind == "content_block_delta":
            state = self._blocks.get((self._message_id, event.get("index", 0)))
            if state:
                delta = event.get("delta", {})
                if delta.get("type") == "text_delta" and state["entry"]:
                    state["entry"].text += safe_text(delta.get("text", ""))
                    self._dirty = True
                elif delta.get("type") == "input_json_delta":
                    state["json"] += delta.get("partial_json", "")
        elif kind == "content_block_stop":
            state = self._blocks.get((self._message_id, event.get("index", 0)))
            if state and state["json"] and state["entry"]:
                try:
                    state["entry"].text = tool_description(state["block"].get("name", "tool"),
                                                            json.loads(state["json"]), cwd=self.cwd)
                except (TypeError, ValueError):
                    state["entry"].text = preview_text(state["json"], suffix="activity preview shortened")
                self._dirty = True

    def _tool_entry(self, ident, name, inputs):
        self._tool_names[ident] = name
        description = tool_description(name, inputs, cwd=self.cwd)
        if ident in self._tool_entries:
            entry = self._tool_entries[ident]
            entry.text = description
            self._dirty = True
            return entry
        entry = self._append("tool", description, name)
        self._tool_entries[ident] = entry
        return entry

    def _handle_message(self, event):
        message = event.get("message", {})
        content = message.get("content", [])
        if isinstance(content, str):
            content = [{"type": "text", "text": content}]
        if not isinstance(content, list):
            return
        for block in content:
            if not isinstance(block, dict):
                continue
            kind = block.get("type")
            if kind == "text" and event.get("type") == "assistant":
                text = safe_text(block.get("text", ""))
                ident = (message.get("id"), text)
                candidates = [state["entry"] for (mid, _), state in self._blocks.items()
                              if mid == message.get("id") and state["block"].get("type") == "text"]
                if text and ident not in self._full_texts:
                    self._full_texts.add(ident)
                    if not any(entry and entry.text == text for entry in candidates):
                        self._append("assistant", text)
                    self._streamed_turn_text = True
            elif kind == "tool_use":
                self._tool_entry(block.get("id", ""), block.get("name", "tool"), block.get("input", {}))
            elif kind == "tool_result":
                ident = block.get("tool_use_id", "")
                value = block.get("content", "")
                if isinstance(value, list):
                    text = "\n".join(part.get("text", "") if isinstance(part, dict) and part.get("type") == "text"
                                     else pretty(part) for part in value)
                else:
                    text = value if isinstance(value, str) else pretty(value)
                key = (ident, text)
                if key not in self._seen_results:
                    self._seen_results.add(key)
                    label = self._tool_names.get(ident, "tool") + (" · failed" if block.get("is_error") else " · result")
                    self._append("tool", preview_text(text, lines=30 if block.get("is_error") else 10,
                                                       chars=6000 if block.get("is_error") else 2000), label)

    def handle_event(self, event):
        if not isinstance(event, dict):
            return
        kind = event.get("type")
        if kind == "ui_engine_ready":
            # The start worker and process-exit callback run on different
            # threads. A delayed completion must not revive a dead session.
            if self._closing or self._engine_exited or self._startup_failed or self._login_required:
                return
            self.ready = True
            self.status = "Ready"
            initialization = getattr(self.engine, "initialization", {}) or {}
            if isinstance(initialization, dict) and initialization.get("model"):
                self.model = safe_text(initialization["model"])
        elif kind == "ui_model_changed":
            if self._closing or self._engine_exited or self._startup_failed or self._login_required:
                return
            self.busy = False
            self.model = safe_text(self._requested_model)
            self.status = "Ready"
            self._append("system", "Model changed to " + self.model)
        elif kind == "system":
            if event.get("subtype") == "init":
                if event.get("model"):
                    self.model = safe_text(event["model"])
                directory = event.get("cwd")
                if isinstance(directory, str):
                    try:
                        actual = Path(directory)
                        if actual.is_absolute() and actual.is_dir():
                            self.cwd = actual.resolve()
                            self.engine_cwd_known = True
                    except (OSError, ValueError):
                        pass
            elif event.get("subtype") == "status" and not (self._engine_exited or self._startup_failed or self._login_required):
                self.status = safe_text(event.get("status") or ("Working" if self.busy else "Ready"))
        elif kind == "stream_event":
            self._handle_stream(event.get("event", {}))
        elif kind in ("assistant", "user"):
            self._handle_message(event)
        elif kind == "result":
            self.busy = False
            if event.get("is_error") or event.get("subtype", "success") not in ("success",):
                errors = event.get("errors") or [event.get("result") or "The engine could not complete this turn."]
                if isinstance(errors, str):
                    errors = [errors]
                message = "\n".join(map(str, errors))
                if self._authentication_error(message):
                    self._login_required = True
                    self.ready = False
                    message += "\nUse /login to sign in through Claude's official login and start a fresh conversation."
                else:
                    message += "\nYou can send a new request, or use /restart for a fresh conversation. No prompt was retried."
                self.status = self._unready_status() if not self.ready else "Turn failed · /restart for a fresh conversation"
                self._append("error", message)
            else:
                self.status = "Ready" if self.ready else self._unready_status()
                if event.get("result") and not self._streamed_turn_text:
                    self._append("assistant", event["result"])
        elif kind == "permission_request":
            if self._engine_exited or self._closing:
                self._decided.add(("tool", event.get("id")))
            else:
                self._tool_pending.append(event)
        elif kind == "permission_cancelled":
            ident = event.get("id")
            self._decided.add(("tool", ident))
            self._tool_pending = [item for item in self._tool_pending if item["id"] != ident]
            if self._approval == {"kind": "tool", "id": ident}:
                self._close_approval()
                self._append("system", "Tool permission expired or was cancelled; it was not approved.")
        elif kind == "engine_error":
            self.busy = False
            if not self.ready:
                self._startup_failed = True
            self._keep_unsent_initial_prompt()
            message = str(event.get("message", "The engine reported an error."))
            if self._authentication_error(message):
                self._login_required = True
                self.ready = False
            self.status = self._unready_status() if not self.ready else "Engine error · /restart for a fresh conversation"
            self._append("error", message + ("\nUse /login to sign in through Claude's official login."
                         if self._login_required else "\nUse /restart or F5 for a fresh conversation. Your unsent draft is kept."))
        elif kind == "engine_exit":
            self._engine_exited = True
            self.ready = False
            self.busy = False
            self._keep_unsent_initial_prompt()
            if self._approval:
                self._decided.add((self._approval["kind"], self._approval["id"]))
                self._close_approval()
            for pending in self._tool_pending:
                self._decided.add(("tool", pending["id"]))
            self._tool_pending.clear()
            if self.gateway_state:
                for pending in self.gateway_state.snapshot().get("pending", []):
                    self._decided.add(("gateway", pending["id"]))
                    self.gateway_state.decision(pending["id"], "deny")
                self.gateway_state.close()
            code = event.get("code", 0)
            self.status = self._unready_status()
            if not self._closing:
                self._append("error" if code else "system", "Engine exited with code " + str(code)
                             + ". Use /restart or F5 for a fresh conversation; /login if sign-in is needed."
                             + " Your unsent draft is kept. /quit closes MaskCode.")
        self._dirty = True

    def _request_exit(self):
        self._closing = True
        if self._approval:
            self._resolve_approval(False)
        if self.gateway_state:
            for pending in self.gateway_state.snapshot().get("pending", []):
                self.gateway_state.decision(pending["id"], "deny")
        for pending in self._tool_pending:
            self._worker(self.engine.decide_permission, pending["id"], False)
        self._tool_pending.clear()
        if self.gateway_state and hasattr(self.gateway_state, "close"):
            self.gateway_state.close()
        if self.app.is_running:
            self.app.exit(result=self._exit_code)

    async def _pump(self):
        try:
            while not self._closing:
                changed = False
                for _ in range(250):
                    try:
                        event = self.events.get_nowait()
                    except queue.Empty:
                        break
                    self.handle_event(event)
                    changed = True
                before = self._snapshot
                self._refresh_snapshot()
                changed = changed or before != self._snapshot
                self._next_approval()
                if self.ready and not (self._engine_exited or self._startup_failed or self._closing) and self._initial_prompt and not self._started_initial:
                    self._started_initial = True
                    self._send(self._initial_prompt)
                changed = changed or self._dirty
                self._render_transcript()
                if changed:
                    self.app.invalidate()
                await asyncio.sleep(0.08)
        except asyncio.CancelledError:
            pass

    async def run_async(self, initial_prompt=None, initial_draft=None):
        if self.engine is None or self.gateway_state is None:
            raise RuntimeError("MaskCode terminal requires an engine and gateway")
        self._initial_prompt = initial_prompt
        if initial_draft is not None and not self.input.text:
            self.input.text = initial_draft
        def start():
            self._pump_task = self.app.create_background_task(self._pump())
            self._worker(self.engine.start, success="ui_engine_ready")
        try:
            return await self.app.run_async(pre_run=start)
        except EOFError:
            self._request_exit()
            return 0
        finally:
            self._closing = True
            # The engine owns its subprocess. Closing also denies any unresolved
            # tool permissions; gateway requests are explicitly denied locally.
            for pending in self.gateway_state.snapshot().get("pending", []):
                self.gateway_state.decision(pending["id"], "deny")
            if hasattr(self.gateway_state, "close"):
                self.gateway_state.close()
            await asyncio.to_thread(self.engine.close)

    def run(self, initial_prompt=None, initial_draft=None):
        return asyncio.run(self.run_async(initial_prompt, initial_draft))
