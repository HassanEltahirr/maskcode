"""Transparent Claude Code terminal launch with a local masking gateway.

The child inherits the user's terminal. No PTY emulation, prompt loop, key
handling, output rewriting, or headless conversion is performed here.
"""
from pathlib import Path
import shutil
import subprocess
import sys
from types import SimpleNamespace
import webbrowser

from . import __version__
from .client import ClientConfigurationError, build_claude_command, claude_environment
from .isolation import isolated_environment, self_test


HELP = """MaskCode — Claude Code's terminal with local masking

Usage: maskcode [MaskCode options] [Claude options] [prompt]

Native Claude flags and arguments are passed through in order:
  maskcode
  maskcode 'fix the failing tests'
  maskcode --model sonnet
  maskcode -p 'explain this function'
  maskcode --resume

MaskCode options:
  --mask-policy FILE    Local JSON policy of confidential terms
  --mask-cwd DIRECTORY  Project directory (default: current directory)
  --mask-review         Inspect and approve each outgoing model request
  --mask-auto           Mask and forward requests in the background (default)
  --mask-dashboard      Open the optional local inspection dashboard
  --mask-port NUMBER    Gateway port (default: automatically assigned)
  --mask-help           Show these options
  --mask-version        Show the MaskCode version
  --mask-native         Use the original Claude Code terminal interface
  --mask-local-model NAME  Choose the installed Ollama privacy model
  --mask-rules-only     Explicitly disable local AI detection; keep masking rules
  --mask-backend codex  Run the installed Codex terminal through the same masking

Use -- to stop parsing MaskCode options. --help shows Claude's native help.
Gateway utilities: maskcode gateway serve|preview|doctor|demo

Masking runs in the background. --mask-review enables exact-request inspection.
Unknown confidential meaning may remain even after masking.
The launcher restricts direct network access and disables custom integrations.
"""


def parse_native(argv):
    options = SimpleNamespace(action="claude", provider="anthropic", backend="claude", mode="auto",
                              local_model="qwen2.5:1.5b",
                              policy=None, cwd=Path.cwd(), port=0, dashboard=False,
                              mask_help=False, mask_version=False, native_ui=False, no_browser=False, args=[])
    values = {"--mask-policy": "policy", "--mask-cwd": "cwd", "--mask-port": "port",
              "--mask-local-model": "local_model",
              "--mask-backend": "backend",
              # Compatibility for the initially installed MaskCode commands.
              "--policy": "policy", "--cwd": "cwd", "--port": "port", "--mode": "mode"}
    index = 0
    while index < len(argv):
        arg = argv[index]
        if arg == "--":
            options.args.extend(argv[index:])
            break
        name, separator, value = arg.partition("=")
        if name in values:
            if not separator:
                index += 1
                if index >= len(argv):
                    raise ValueError("A MaskCode option is missing its value; see --mask-help")
                value = argv[index]
            field = values[name]
            if field in ("cwd", "policy"):
                if not value:
                    raise ValueError("A MaskCode path option is empty")
                value = Path(value).expanduser()
            elif field == "port":
                try:
                    value = int(value)
                except ValueError:
                    raise ValueError("The gateway port must be a number") from None
                if not 0 <= value <= 65535:
                    raise ValueError("The gateway port must be between 0 and 65535")
            elif field == "mode" and value not in ("review", "auto"):
                raise ValueError("The masking mode must be review or auto")
            elif field == "backend" and value not in ("claude", "codex"):
                raise ValueError("The MaskCode backend must be claude or codex")
            setattr(options, field, value)
        elif arg == "--mask-review":
            options.mode = "review"
        elif arg == "--mask-auto":
            options.mode = "auto"
        elif arg in ("--mask-dashboard", "--dashboard"):
            options.dashboard = True
        elif arg == "--mask-help":
            options.mask_help = True
        elif arg == "--mask-version":
            options.mask_version = True
        elif arg == "--mask-native":
            options.native_ui = True
        elif arg == "--mask-rules-only":
            options.local_model = None
        elif arg == "--no-browser":
            options.no_browser = True
        elif name.startswith("--mask-"):
            raise ValueError("Unknown MaskCode option; see --mask-help")
        else:
            options.args.append(arg)
        index += 1
    if options.backend == "codex":
        options.action = options.provider = "codex"
    return options


def run_codex(args):
    """Use the installed Codex terminal with MaskCode's shared local scanner."""
    from .cli import start_gateway, launch_codex
    from .codex_client import validate_codex_arguments
    validate_codex_arguments(args.args)
    if not args.cwd.is_dir():
        raise ClientConfigurationError("Project directory does not exist")
    server = None
    try:
        server = start_gateway(args)
        self_test(server.server_port)
        server.state.network_isolation = True
        privacy = "local AI + masking" if server.state.semantic_scanner is not None else "rules-only masking"
        print("MaskCode · " + privacy + " · powered by the installed Codex terminal", file=sys.stderr)
        print("MaskCode enforces the outer sandbox: selected project/state/temp writes; network only through the masking gateway.", file=sys.stderr)
        if args.mode == "review" or args.dashboard:
            print("MaskCode local review: " + server.console_url, file=sys.stderr, flush=True)
            if not args.no_browser:
                webbrowser.open(server.console_url)
        return launch_codex(server, args)
    finally:
        if server is not None:
            server.state.close()
            server.shutdown()
            server.server_close()


def run(argv):
    from .cli import start_gateway
    try:
        args = parse_native(list(argv))
    except ValueError as exc:
        print("MaskCode: " + str(exc), file=sys.stderr)
        return 2
    if args.mask_help:
        print(HELP)
        return 0
    if args.mask_version:
        print("MaskCode " + __version__)
        return 0
    if not args.cwd.is_dir():
        print("MaskCode: project directory does not exist.", file=sys.stderr)
        return 2
    # Purely informational native calls cannot send a model request. Preserve
    # their output exactly and avoid unnecessary gateway startup.
    if args.args in (["--help"], ["-h"], ["--version"], ["-v"]):
        binary = shutil.which("claude")
        if not binary:
            print("MaskCode: install Claude Code first.", file=sys.stderr)
            return 1
        try:
            return subprocess.call([binary, *args.args], cwd=args.cwd, env=isolated_environment())
        except OSError:
            print("MaskCode: could not launch the installed Claude Code executable.", file=sys.stderr)
            return 1
    server = None
    try:
        server = start_gateway(args)
        self_test(server.server_port)
        server.state.network_isolation = True
        if args.mode == "review" or args.dashboard:
            print("MaskCode local review: " + server.console_url, file=sys.stderr, flush=True)
            if args.mode == "review":
                print("Outgoing requests wait for your approval in that dashboard.", file=sys.stderr)
            if not args.no_browser:
                webbrowser.open(server.console_url)
        elif sys.stderr.isatty() and sys.stdout.isatty():
            print("MaskCode · background masking · tool permissions remain active", file=sys.stderr)
        # Inherit all three terminal descriptors. Claude owns raw input, paste,
        # cursor movement, resize, slash menus, diffs, and permission prompts.
        return subprocess.call(build_claude_command(server, args.args), cwd=args.cwd,
                               env=claude_environment(server))
    except KeyboardInterrupt:
        return 130
    except ClientConfigurationError as exc:
        print("MaskCode: " + str(exc), file=sys.stderr)
        return 2
    except (RuntimeError, OSError, ValueError, TypeError, subprocess.SubprocessError):
        print("MaskCode could not start its protected Claude session. Check installation, policy and gateway port. No direct fallback was started.", file=sys.stderr)
        return 1
    finally:
        if server is not None:
            server.state.close()
            server.shutdown()
            server.server_close()
