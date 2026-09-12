"""Manual installed-CLI integration check. Uses a fake upstream, never a model.

Run: python3 tests/cli_smoke.py
Optional live subscription test: python3 tests/cli_smoke.py --live-subscription
The opt-in flag sends one synthetic prompt through your existing Claude login.
Real local clients connect to the gateway under its network restriction. Only
synthetic test prompts and dummy provider credentials are used.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from privacy_gateway.server import GatewayServer, GatewayState
from privacy_gateway.redaction import Policy
from privacy_gateway.isolation import self_test
from privacy_gateway.client import build_claude_command, claude_environment


def run():
    live = "--live-subscription" in sys.argv
    state = GatewayState(mode="auto", policy=Policy.from_dict({"literals": [
        {"value": "Cedar Example LLC", "label": "ORG"},
        {"value": str(Path.home()), "label": "LOCAL_HOME"}]}))
    captured = []
    diagnostics = []
    upstream = state.send_upstream
    def fake(path, body, headers):
        captured.append(json.loads(body))
        if b"sample.person@example.com" in body or b"Cedar Example LLC" in body:
            raise AssertionError("Synthetic protected original reached transport")
        if live:
            response = upstream(path, body, headers)
            diagnostics.append({"status": response[0], "content_type": response[1]})
            if response[0] >= 400:
                try:
                    error = json.loads(response[2]).get("error", {})
                    diagnostics[-1]["error_type"] = error.get("type")
                except (ValueError, AttributeError):
                    pass
            return response
        if path.startswith("/v1/messages/count_tokens"):
            return 200, "application/json", b'{"input_tokens":100}'
        token = state.redactor.redact_text("sample.person@example.com")
        events = [
            {"type": "message_start", "message": {"id": "msg_synthetic", "type": "message", "role": "assistant",
                "model": "claude-sonnet-4-6", "content": [], "stop_reason": None, "stop_sequence": None,
                "usage": {"input_tokens": 20, "output_tokens": 1}}},
            {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}},
            {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": token[:7]}},
            {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": token[7:]}},
            {"type": "content_block_stop", "index": 0},
            {"type": "message_delta", "delta": {"stop_reason": "end_turn", "stop_sequence": None}, "usage": {"output_tokens": 8}},
            {"type": "message_stop"},
        ]
        data = "".join("event: " + event["type"] + "\ndata: " + json.dumps(event) + "\n\n" for event in events).encode()
        return 200, "text/event-stream", data
    state.transport = fake
    server = GatewayServer(state)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    env = claude_environment(server)
    for key in ("ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_CUSTOM_HEADERS",
                "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        env.pop(key, None)
    env.update({"ANTHROPIC_BASE_URL": server.proxy_url,
                "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1", "CLAUDE_CODE_SAFE_MODE": "1",
                "CLAUDE_CODE_DISABLE_OFFICIAL_MARKETPLACE_AUTOINSTALL": "1"})
    if live:
        env.pop("ANTHROPIC_API_KEY", None)
    else:
        env["ANTHROPIC_API_KEY"] = "sk-ant-synthetic-local-test-only"
    try:
        self_test(server.server_port)
        with tempfile.TemporaryDirectory(prefix="veil-synthetic-") as work:
            argv = build_claude_command(server, ["--tools", "", "--no-session-persistence",
                    "--system-prompt", "This is a synthetic local integration test. Echo the requested email.",
                    "-p", "Cedar Example LLC uses sample.person@example.com. Echo that email."])
            result = subprocess.run(argv, env=env, cwd=work,
                                    capture_output=True, text=True, timeout=45)
        report = {"client": "installed Claude Code", "upstream": "Anthropic (synthetic prompt)" if live else "local fake only",
                  "captured_requests": len(captured), "exit_code": result.returncode,
                  "restored_email_received": "sample.person@example.com" in result.stdout,
                  "blocked_requests": state.blocked,
                  "provider_diagnostics": diagnostics,
                  "request_top_level_fields": sorted(captured[0]) if captured else []}
        print(json.dumps(report, indent=2))
        if result.returncode or not captured or not report["restored_email_received"]:
            # Output is not printed: even a synthetic client can emit environment paths.
            print("CLI smoke check failed; client stdout/stderr intentionally suppressed.")
            return 1
        return 0
    finally:
        state.close()
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    raise SystemExit(run())
