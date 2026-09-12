"""MaskCode terminal entrypoint; native machine-readable modes stay untouched."""
from pathlib import Path
import sys
import webbrowser

from . import __version__
from .client import (ClientConfigurationError, _FLAGS, _VALUES, _OPTIONAL,
                     _MULTIPLE, _COMMANDS, validate_claude_arguments)
from .isolation import self_test
from .native import parse_native
from .ollama_runtime import OllamaRuntimeError


HELP = """MaskCode — a coding agent with background masking

Usage: maskcode [options] [prompt]

  maskcode                         Open the MaskCode terminal
  maskcode 'fix the failing tests'  Read files, make changes and verify them
  maskcode --model sonnet           Choose the Claude backend model
  maskcode --resume SESSION_ID      Resume a saved Claude conversation
  maskcode -p 'explain this file'   Print one response without the interface
  maskcode auth login              Open the official Claude sign-in flow
  maskcode --model claude-fable-5-1 Use Fable behind local AI masking
  maskcode --mask-backend codex    Use Astra in the installed Codex terminal

Privacy options:
  --mask-local-model NAME  Installed Ollama privacy model (qwen2.5:1.5b by default)
  --mask-rules-only     Explicitly use masking rules without local AI detection
  --mask-backend NAME   claude (MaskCode interface) or codex (native Codex interface)
  --mask-policy FILE    Protect local confidential terms and patterns
  --mask-cwd DIRECTORY  Start in this project directory
  --mask-review         Inspect and approve each outgoing model request
  --mask-auto           Mask and forward requests in the background (default)
  --mask-dashboard      Also open the optional browser companion
  --mask-port NUMBER    Choose the local gateway port
  --mask-native         Use the original Claude Code terminal

Terminal: Enter sends · Alt+Enter/Ctrl+J adds a line · Tab completes commands
          Ctrl+C interrupts · Ctrl+D exits an empty prompt · F5 restarts
Commands: /help · /about · /model · /clear · /privacy · /restart · /login · /quit

--help and --version describe MaskCode. Use --mask-native --help for the engine.
Gateway utilities: maskcode gateway serve|preview|doctor|demo

Hermes-inspired interface; installed Claude Code supplies the coding engine.
Ollama finds sensitive spans locally; rules replace and restore exact values.
Normal file and command permissions stay active. No per-request review by default.
Local scan failures block forwarding. Detection can still miss confidential data.
"""


def split_arguments(arguments):
    """Return engine options, positional prompt, and machine-mode indicator.

    Classify option values before looking for print flags so a quoted prompt or
    system instruction containing '--print' is never mistaken for a mode switch.
    """
    validate_claude_arguments(arguments)
    values = list(arguments)
    options, positional = [], []
    machine = False
    index = 0
    while index < len(values):
        arg = values[index]
        if arg == "--":
            positional.extend(values[index + 1:])
            break
        if not arg.startswith("-") or arg == "-":
            positional.append(arg)
            index += 1
            continue
        if not arg.startswith("--") and len(arg) > 2:
            expanded = []
            for offset, letter in enumerate(arg[1:], 1):
                flag = "-" + letter
                expanded.append(flag)
                if flag in _VALUES | _OPTIONAL:
                    if arg[offset + 1:]:
                        expanded.append(arg[offset + 1:])
                    break
            values[index:index + 1] = expanded
            continue
        name, separator, _ = arg.partition("=")
        options.append(arg)
        if name in {"-p", "--print", "--output-format", "--input-format"}:
            machine = True
        if not separator:
            if name in _VALUES:
                index += 1
                options.append(values[index])
            elif name in _OPTIONAL:
                if index + 1 < len(values) and not values[index + 1].startswith("-"):
                    index += 1
                    options.append(values[index])
            elif name in _MULTIPLE:
                while index + 1 < len(values) and not values[index + 1].startswith("-"):
                    index += 1
                    options.append(values[index])
        index += 1
    return options, positional, machine


def model_hint(options):
    """Read only a real model flag, never an option's text value."""
    selected = None
    index = 0
    while index < len(options):
        name, separator, value = options[index].partition("=")
        if name == "--model":
            selected = value if separator else options[index + 1]
        if not separator:
            if name in _VALUES:
                index += 1
            elif name in _OPTIONAL:
                if index + 1 < len(options) and not options[index + 1].startswith("-"):
                    index += 1
            elif name in _MULTIPLE:
                while index + 1 < len(options) and not options[index + 1].startswith("-"):
                    index += 1
        index += 1
    return selected


def option_groups(options):
    """Walk already-validated options without mistaking their values for flags."""
    index = 0
    while index < len(options):
        start = index
        name, separator, _ = options[index].partition("=")
        if not separator:
            if name in _VALUES:
                index += 1
            elif name in _OPTIONAL:
                if index + 1 < len(options) and not options[index + 1].startswith("-"):
                    index += 1
            elif name in _MULTIPLE:
                while index + 1 < len(options) and not options[index + 1].startswith("-"):
                    index += 1
        yield options[start:index + 1]
        index += 1


def fresh_session_arguments(options):
    """Keep preferences; do not replay a session or create another worktree."""
    removed = {"--resume", "-r", "--continue", "-c", "--session-id", "--fork-session", "--worktree", "-w"}
    return [value for group in option_groups(options)
            if group[0].partition("=")[0] not in removed for value in group]


def _terminal_session(args, extra, initial_prompt=None, initial_draft=None, notice=None):
    """Close the entire protected session before returning a recovery request."""
    from .cli import start_gateway
    from .terminal import TerminalApp
    from .engine import ClaudeEngine
    server = None
    engine = None
    try:
        server = start_gateway(args)
        self_test(server.server_port)
        server.state.network_isolation = True
        if args.dashboard and not args.no_browser:
            webbrowser.open(server.console_url)
        app = TerminalApp(cwd=args.cwd, mode=args.mode, model=model_hint(extra))
        engine = ClaudeEngine(server, extra, args.cwd, on_event=app.post_event)
        app.bind(engine, server.state)
        if notice:
            app._append("system", notice)
        return app.run(initial_prompt=initial_prompt, initial_draft=initial_draft), app
    finally:
        if server is not None:
            server.state.close()
        if engine is not None:
            engine.close()
        if server is not None:
            server.shutdown()
            server.server_close()


def run(argv):
    from . import native
    try:
        args = parse_native(list(argv))
        if args.native_ui and args.backend == "claude":
            return native.run(argv)
        if args.mask_help or args.args in (["--help"], ["-h"]):
            print(HELP)
            return 0
        if args.mask_version or args.args in (["--version"], ["-v"]):
            print("MaskCode " + __version__)
            return 0
        if args.backend == "codex":
            return native.run_codex(args)
        if args.args == ["auth", "login"]:
            from .auth import official_login
            if not args.cwd.is_dir():
                raise ClientConfigurationError("Project directory does not exist")
            return official_login(args.cwd)
        extra, positional, machine = split_arguments(args.args)
        if machine or (positional and positional[0] in _COMMANDS):
            return native.run(argv)
        if not args.cwd.is_dir():
            raise ClientConfigurationError("Project directory does not exist")
        if not sys.stdin.isatty() or not sys.stdout.isatty():
            print("MaskCode needs an interactive terminal. Use maskcode -p 'your prompt' for scripts.", file=sys.stderr)
            return 2
        # Keep dependency imports out of gateway and machine-readable commands.
        try:
            from .terminal import TerminalApp
            from .engine import ClaudeEngine
        except ImportError:
            print("MaskCode terminal dependencies are missing. Install this project with pip, or use --mask-native.", file=sys.stderr)
            return 2
        initial_prompt = " ".join(positional) if positional else None
        initial_draft = notice = None
        while True:
            result, app = _terminal_session(args, extra, initial_prompt, initial_draft, notice)
            if app.restart_requested is not True and app.login_requested is not True:
                return result
            # No initial task or previous tool action is submitted a second time.
            initial_prompt = None
            initial_draft = app.resume_draft
            had_worktree = any(group[0].partition("=")[0] in {"--worktree", "-w"}
                               for group in option_groups(extra))
            extra = fresh_session_arguments(extra)
            if isinstance(app.cwd, Path):
                args.cwd = app.cwd
            if isinstance(app.model, str) and app.model != "configured model":
                extra = [value for group in option_groups(extra)
                         if group[0].partition("=")[0] != "--model" for value in group]
                extra += ["--model", app.model]
            notice = "Started a fresh conversation. Files on disk are kept; previous conversation context is not replayed."
            if had_worktree and app.engine_cwd_known is not True:
                notice += " The engine had not reported a worktree directory; recovery uses the original project directory shown above."
            if app.login_requested is True:
                from .auth import official_login
                if official_login(args.cwd) != 0:
                    notice = "Sign-in was not completed. Your draft is kept. Use /login to try again. " + notice
            if initial_draft:
                notice += " Review your draft and press Enter to send it."
    except KeyboardInterrupt:
        return 130
    except ClientConfigurationError as exc:
        print("MaskCode: " + str(exc), file=sys.stderr)
        return 2
    except OllamaRuntimeError as exc:
        print("MaskCode: " + str(exc), file=sys.stderr)
        return 1
    except (ValueError, TypeError, OSError, RuntimeError):
        print("MaskCode could not start its protected terminal. Check the local privacy model, policy and installed Claude login. No direct fallback was started.", file=sys.stderr)
        return 1
