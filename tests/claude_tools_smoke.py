"""Manual real-Claude-Code Read/Edit/Bash check against a synthetic local upstream.

Run: python3 tests/claude_tools_smoke.py

This is intentionally outside unittest discovery. It never calls a real model,
uses a dummy API key, restricts network sockets, and permits Read/Edit/Bash.
All files created by the test live in a temporary directory and are removed.
The report contains fixed diagnostics and booleans, never paths or credentials.
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
from privacy_gateway.isolation import command, self_test
from privacy_gateway.client import build_claude_command, claude_environment
from privacy_gateway.redaction import Policy
from privacy_gateway.server import GatewayServer, GatewayState


EMAIL = "sample.person@example.com"
COMPANY = "Cedar Example LLC"
FINISHED = "Synthetic Read and Edit completed."


def response(model, tool_name=None, tool_id=None, arguments=None):
    events = [{"type": "message_start", "message": {
        "id": "msg_synthetic_local_tools", "type": "message", "role": "assistant",
        "model": model, "content": [], "stop_reason": None, "stop_sequence": None,
        "usage": {"input_tokens": 40, "output_tokens": 1}}}]
    if tool_name:
        encoded = json.dumps(arguments, ensure_ascii=False)
        boundary = len(encoded) // 2
        events.append({"type": "content_block_start", "index": 0, "content_block": {
            "type": "tool_use", "id": tool_id, "name": tool_name, "input": {}}})
        for piece in (encoded[:boundary], encoded[boundary:]):
            events.append({"type": "content_block_delta", "index": 0, "delta": {
                "type": "input_json_delta", "partial_json": piece}})
        stop_reason = "tool_use"
    else:
        events += [
            {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}},
            {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": FINISHED}},
        ]
        stop_reason = "end_turn"
    events += [
        {"type": "content_block_stop", "index": 0},
        {"type": "message_delta", "delta": {"stop_reason": stop_reason, "stop_sequence": None},
         "usage": {"output_tokens": 30}},
        {"type": "message_stop"},
    ]
    body = "".join("event: " + event["type"] + "\ndata: " + json.dumps(event)
                   + "\n\n" for event in events).encode()
    return 200, "text/event-stream", body


def find_tool_result(payload, tool_id):
    for message in reversed(payload.get("messages", [])):
        content = message.get("content", [])
        if not isinstance(content, list):
            continue
        for block in content:
            if isinstance(block, dict) and block.get("type") == "tool_result" and block.get("tool_use_id") == tool_id:
                return block
    return None


def run():
    report = {
        "client": "installed Claude Code", "upstream": "synthetic local transport only",
        "dummy_authentication": True, "network_restriction_verified": False,
        "model_requests": 0, "token_count_requests": 0, "blocked_requests": 0,
        "read_result_received": False, "read_result_pseudonymized": False,
        "edit_result_received": False, "bash_result_received": False,
        "bash_result_pseudonymized": False, "originals_absent_on_wire": True,
        "email_preserved_and_updated": False, "company_preserved": False,
        "final_message_received": False, "exit_code": None, "failure_code": None,
    }
    binary = shutil.which("claude")
    if not binary:
        report["failure_code"] = "claude_not_installed"
        print(json.dumps(report, indent=2))
        return 1
    with tempfile.TemporaryDirectory(prefix="veil-synthetic-tools-") as work:
        contact = Path(work) / "contact ' private.txt"
        contact.write_text(COMPANY + " contact: " + EMAIL + "\n", encoding="utf-8")
        policy = Policy.from_dict({"literals": [
            {"value": COMPANY, "label": "ORG"},
            {"value": str(contact), "label": "FILE_PATH"},
            {"value": work, "label": "LOCAL_PATH"},
            {"value": str(Path.home()), "label": "LOCAL_HOME"},
        ]})
        state = GatewayState(mode="auto", policy=policy)
        path_token = state.redactor.redact_text(str(contact))
        email_token = state.redactor.redact_text(EMAIL)
        company_token = state.redactor.redact_text(COMPANY)

        def fail(code):
            report["failure_code"] = report["failure_code"] or code
            return 400, "application/json", b'{"type":"error","error":{"type":"invalid_request_error","message":"Synthetic local test rejected request."}}'

        def fake(path, body, headers):
            # Credentials are neither examined nor retained by this fake.
            if EMAIL.encode() in body or COMPANY.encode() in body or str(contact).encode() in body:
                report["originals_absent_on_wire"] = False
                return fail("protected_original_reached_mock")
            payload = json.loads(body)
            if path.startswith("/v1/messages/count_tokens"):
                report["token_count_requests"] += 1
                if report["token_count_requests"] > 5:
                    return fail("token_count_request_limit")
                return 200, "application/json", b'{"input_tokens":100}'
            report["model_requests"] += 1
            step = report["model_requests"]
            model = payload.get("model", "claude-sonnet-4-6")
            if step == 1:
                offered = {tool.get("name") for tool in payload.get("tools", [])}
                if not {"Read", "Edit", "Bash"} <= offered:
                    return fail("required_tools_not_offered")
                return response(model, "Read", "toolu_synthetic_read", {"file_path": path_token})
            if step == 2:
                read = find_tool_result(payload, "toolu_synthetic_read")
                report["read_result_received"] = read is not None
                if read is None:
                    return fail("read_result_missing")
                if read.get("is_error"):
                    return fail("read_tool_reported_error")
                encoded_read = json.dumps(read)
                report["read_result_pseudonymized"] = email_token in encoded_read and company_token in encoded_read
                if not report["read_result_pseudonymized"]:
                    return fail("read_result_missing_expected_pseudonyms")
                return response(model, "Edit", "toolu_synthetic_edit", {
                    "file_path": path_token, "old_string": email_token,
                    "new_string": email_token + " updated", "replace_all": False})
            if step == 3:
                edited = find_tool_result(payload, "toolu_synthetic_edit")
                report["edit_result_received"] = edited is not None
                if edited is None:
                    return fail("edit_result_missing")
                if edited.get("is_error"):
                    return fail("edit_tool_reported_error")
                return response(model, "Bash", "toolu_synthetic_bash", {
                    "command": "cat " + path_token, "description": "Read the updated synthetic file"})
            if step == 4:
                bash = find_tool_result(payload, "toolu_synthetic_bash")
                report["bash_result_received"] = bash is not None
                if bash is None or bash.get("is_error"):
                    return fail("bash_read_result_missing_or_error")
                report["bash_result_pseudonymized"] = (email_token in json.dumps(bash)
                                                      and company_token in json.dumps(bash))
                if not report["bash_result_pseudonymized"]:
                    return fail("bash_read_result_missing_expected_pseudonyms")
                return response(model)
            return fail("model_request_limit")

        state.transport = fake
        server = GatewayServer(state)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            self_test(server.server_port)
            report["network_restriction_verified"] = True
            # Keep only runtime basics; provider credentials and custom routes
            # cannot be inherited from the parent shell.
            env = claude_environment(server)
            for key in ("ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN", "CLAUDE_CODE_OAUTH_REFRESH_TOKEN"):
                env.pop(key, None)
            env.update({"ANTHROPIC_API_KEY": "sk-ant-synthetic-local-test-only",
                        "ANTHROPIC_BASE_URL": server.proxy_url,
                        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
                        "CLAUDE_CODE_DISABLE_OFFICIAL_MARKETPLACE_AUTOINSTALL": "1",
                        "CLAUDE_CODE_SAFE_MODE": "1", "DISABLE_AUTOUPDATER": "1"})
            argv = build_claude_command(server, ["--tools", "Read,Edit,Bash", "--allowedTools", "Read,Edit,Bash",
                    "--no-session-persistence", "--system-prompt",
                    "This is a synthetic local file integration test. Use only the supplied tools.",
                    "-p", "Read the contact file, append ' updated' to its email using Edit, then check it with cat."])
            result = subprocess.run(argv, cwd=work, env=env,
                                    capture_output=True, text=True, timeout=60)
            report["exit_code"] = result.returncode
            report["final_message_received"] = FINISHED in result.stdout
            if result.returncode and not report["failure_code"]:
                report["failure_code"] = "client_nonzero_exit"
        except subprocess.TimeoutExpired:
            report["failure_code"] = report["failure_code"] or "client_timeout"
        except RuntimeError:
            report["failure_code"] = report["failure_code"] or "network_restriction_check_failed"
        except (OSError, ValueError):
            report["failure_code"] = report["failure_code"] or "local_test_setup_failed"
        finally:
            report["blocked_requests"] = state.blocked
            updated = contact.read_text(encoding="utf-8")
            report["email_preserved_and_updated"] = EMAIL + " updated" in updated
            report["company_preserved"] = COMPANY in updated
            state.close()
            server.shutdown()
            server.server_close()
    success = (report["exit_code"] == 0 and report["model_requests"] == 4
        and report["network_restriction_verified"] and report["originals_absent_on_wire"]
        and report["read_result_pseudonymized"] and report["edit_result_received"]
        and report["bash_result_received"] and report["bash_result_pseudonymized"]
        and report["email_preserved_and_updated"] and report["company_preserved"]
        and report["final_message_received"] and not report["failure_code"])
    if not success and not report["failure_code"]:
        report["failure_code"] = "expected_round_trip_not_completed"
    print(json.dumps(report, indent=2))
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(run())
