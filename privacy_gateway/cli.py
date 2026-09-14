from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import threading
import webbrowser
from pathlib import Path

from . import __version__
from .redaction import Policy, Redactor
from .server import GatewayServer, GatewayState
from .isolation import command, self_test
from .client import build_claude_command, claude_environment


def options(parser, default_mode="review"):
    parser.add_argument("--policy", type=Path, help="Local JSON protected terms / regex policy")
    parser.add_argument("--mode", choices=("review", "auto"), default=default_mode,
                        help="review each outgoing body, or mask automatically (default: " + default_mode + ")")
    parser.add_argument("--port", type=int, default=0, help="Loopback port; default chooses a free port")
    parser.add_argument("--no-browser", action="store_true", help="Print console URL instead of opening browser")
    parser.add_argument("--local-model", default="qwen2.5:1.5b", help="Installed Ollama privacy model (default: qwen2.5:1.5b)")
    parser.add_argument("--rules-only", dest="local_model", action="store_const", const=None,
                        help="Explicitly disable local AI detection; keep deterministic rules")


def build_parser():
    parser = argparse.ArgumentParser(prog="maskcode gateway", description="MaskCode local gateway utilities.",
        epilog="Start the MaskCode terminal: maskcode")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="action", required=True)
    preview = sub.add_parser("preview", help="Mask stdin locally without making a network request")
    preview.add_argument("--policy", type=Path)
    preview.add_argument("--json", action="store_true", help="Treat stdin as a JSON document")
    sub.add_parser("demo", help="Show a synthetic masking and restoration example offline")
    sub.add_parser("doctor", help="Check runtimes and macOS network restriction without reading credentials")
    serve = sub.add_parser("serve", help="Start local console and gateway (does not isolate existing clients)")
    options(serve)
    serve.add_argument("--provider", choices=("anthropic", "openai", "codex"), default="anthropic")
    for name in ("claude", "codex"):
        child = sub.add_parser(name, help="Launch %s through the gateway with macOS direct-network restrictions" % name)
        options(child, default_mode="auto")
        child.add_argument("--cwd", type=Path, default=Path.cwd(), help="Working project directory")
        child.add_argument("args", nargs=argparse.REMAINDER, help="Client flags after --")
    return parser


def start_gateway(args):
    from .project_paths import directory_literals, with_directory_literals
    configured = Policy.from_file(args.policy) if args.policy else Policy.from_dict({})
    paths = directory_literals([Path.home()], "LOCAL_HOME")
    if getattr(args, "cwd", None) is not None:
        paths.extend(directory_literals([args.cwd]))
    policy = with_directory_literals(configured, paths)
    provider = getattr(args, "provider", "anthropic" if args.action == "claude" else "codex")
    runtime = scanner = state = server = None
    try:
        if getattr(args, "local_model", None) is not None:
            from .ollama_runtime import ManagedOllama
            from .semantic import SemanticScanner
            runtime = ManagedOllama(model=args.local_model).start()
            runtime.prewarm()
            scanner = SemanticScanner(runtime)
        state = GatewayState(provider, policy, args.mode, semantic_scanner=scanner, local_runtime=runtime)
        server = GatewayServer(state, args.port)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server
    except BaseException:
        if state is not None:
            state.close()
        elif runtime is not None:
            runtime.close()
        if server is not None:
            server.server_close()
        raise


def explain(server, args):
    print("MaskCode | %s | %s mode" % (server.state.provider, server.state.mode), file=sys.stderr)
    if server.state.semantic_scanner is not None:
        print("Ollama detects sensitive spans locally; MaskCode replaces and restores exact values.", file=sys.stderr)
    else:
        print("Rules-only masking: local AI detection is disabled.", file=sys.stderr)
    print("Detection can miss confidential information. The provider receives the masked context.", file=sys.stderr)
    if server.state.mode == "review":
        print("Requests wait in the console until you approve the sanitized body.", file=sys.stderr)
    else:
        print("Automatic forwarding enabled: inspect your policy with synthetic data before using confidential files.", file=sys.stderr)
    # Review capability is never put in the launched child's environment.
    print("Local review console: " + server.console_url, file=sys.stderr, flush=True)
    if not args.no_browser:
        webbrowser.open(server.console_url)


def launch_claude(server, args):
    extra = args.args[1:] if args.args[:1] == ["--"] else args.args
    return subprocess.call(build_claude_command(server, extra), cwd=args.cwd, env=claude_environment(server))


def launch_codex(server, args):
    from .codex_client import protected_codex_launch
    extra = args.args[1:] if args.args[:1] == ["--"] else args.args
    with protected_codex_launch(server, extra, cwd=args.cwd,
                                reasoning_effort=getattr(args, "reasoning_effort", None)) as (argv, env):
        return subprocess.call(argv, cwd=args.cwd, env=env)


def gateway_main(argv):
    args = build_parser().parse_args(argv)
    try:
        if args.action == "demo":
            r = Redactor(Policy.from_dict({"literals": [{"value": "Cedar Example LLC", "label": "ORG"}]}))
            original = "Cedar Example LLC contact: sample.person@example.com; +971 50 123 4567"
            masked = r.redact_text(original)
            print(json.dumps({"original_synthetic": original, "provider_would_receive": masked,
                              "restored_locally": r.restore_text(masked), "redactions": r.counts()}, indent=2))
            return 0
        if args.action == "preview":
            r = Redactor(Policy.from_file(args.policy) if args.policy else None)
            content = sys.stdin.read(8 * 1024 * 1024 + 1)
            if len(content) > 8 * 1024 * 1024:
                raise ValueError("Input exceeds local size limit")
            if args.json:
                print(json.dumps(r.redact_json(json.loads(content)), ensure_ascii=False, indent=2))
            else:
                print(r.redact_text(content), end="" if content.endswith("\n") else "\n")
            return 0
        if args.action == "doctor":
            from .codex_client import find_codex_binary
            print("Python: " + sys.version.split()[0])
            for name in ("claude", "codex"):
                binary = find_codex_binary() if name == "codex" else shutil.which(name)
                print(name + ": " + ("installed (" + binary + ")" if binary else "not found"))
            server = GatewayServer(GatewayState())
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                self_test(server.server_port)
                print("macOS direct sockets: gateway allowed; other loopback and public address blocked")
            finally:
                server.shutdown()
                server.server_close()
            print("No credentials read. No model call made. Provider login compatibility is a separate test.")
            return 0
        server = start_gateway(args)
        try:
            if args.action != "serve":
                if not args.cwd.is_dir():
                    raise ValueError("Working project directory does not exist")
                self_test(server.server_port)
                server.state.network_isolation = True
            explain(server, args)
            if args.action == "serve":
                suffix = "/v1" if args.provider in ("openai",) else ""
                print("Client base URL: " + server.proxy_url + suffix, file=sys.stderr, flush=True)
                print("Standalone server does not restrict other apps' network access.", file=sys.stderr)
                threading.Event().wait()
            if args.action == "claude":
                return launch_claude(server, args)
            return launch_codex(server, args)
        finally:
            server.state.close()
            server.shutdown()
            server.server_close()
    except KeyboardInterrupt:
        return 130
    except RuntimeError as exc:
        # Launcher RuntimeErrors are fixed local diagnostic strings.
        print("MaskCode: " + str(exc), file=sys.stderr)
        return 1
    except (ValueError, TypeError, OSError, RuntimeError, subprocess.SubprocessError):
        # A policy/parser error can include confidential values; don't echo it.
        print("MaskCode could not start or process input. Check the policy, runtime, working directory and available port. No direct fallback was started.", file=sys.stderr)
        return 1


def main(argv=None):
    from .lifecycle import graceful_termination, TerminationRequested
    raw = list(sys.argv[1:] if argv is None else argv)
    with graceful_termination() as termination:
        try:
            if raw[:1] == ["gateway"]:
                result = gateway_main(raw[1:])
            else:
                from .terminal_entry import run
                result = run(raw)
        except TerminationRequested:
            result = termination.exit_code
    # Existing launchers catch KeyboardInterrupt and return130. Preserve the
    # originating TERM/HUP status while letting all their finally blocks run.
    return termination.exit_code if termination.exit_code is not None else result


if __name__ == "__main__":
    raise SystemExit(main())
