"""One bounded live subscription coding check on disposable synthetic files.

Run explicitly:
    MASKCODE_RUN_LIVE_AGENTIC=1 python3 tests/live_agentic_smoke.py

This uses the installed Claude CLI's existing official claude.ai login. It never
reads credential stores or uses an API-key account. The actual MaskCode terminal
and engine run with automatic masking, normal tool permissions, and at most
eight model requests. Only narrowly scoped tool permissions are approved by
keyboard. Output contains fixed diagnostics and counts, never prompts, paths,
responses, account details, or credentials.
"""
import asyncio
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from prompt_toolkit.input import create_pipe_input
from prompt_toolkit.output import DummyOutput

from privacy_gateway.client import claude_environment
from privacy_gateway.engine import ClaudeEngine
from privacy_gateway.isolation import self_test
from privacy_gateway.protocol import PrivacyBlocked
from privacy_gateway.redaction import Policy
from privacy_gateway.server import GatewayServer, GatewayState
from privacy_gateway.terminal import TerminalApp


class CheckFailed(RuntimeError):
    pass


def require(condition, code):
    if not condition:
        raise CheckFailed(code)


async def run():
    report = {
        "official_subscription_login": False,
        "network_restriction_verified": False,
        "baseline_test_failed": False,
        "model_requests": 0, "token_count_requests": 0,
        "read_tools": 0, "edit_tools": 0, "bash_tools": 0,
        "explicit_tool_approvals": 0, "unexpected_tools_denied": 0,
        "originals_absent_on_wire": True,
        "no_outgoing_review_dialogs": True,
        "no_browser_opened": True,
        "tests_unchanged": False, "synthetic_contacts_preserved": False,
        "independent_tests_passed": False,
        "streamed_text_received": False, "final_received": False,
        "completed": False, "failure_code": None,
    }
    server, state, thread, engine, ui, task = None, None, None, None, None, None
    local_runtime = None
    hybrid = os.environ.get("MASKCODE_LIVE_SEMANTIC") == "1"
    selected_model = os.environ.get("MASKCODE_LIVE_MODEL", "sonnet")
    report["local_ai_detection"] = hybrid
    try:
        require(os.environ.get("MASKCODE_RUN_LIVE_AGENTIC") == "1", "explicit_live_opt_in_required")
        require(shutil.which("claude"), "claude_not_installed")
        require(not any(os.environ.get(name) for name in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN")),
                "api_key_or_custom_auth_environment_not_allowed")
        # The official client reports login status; MaskCode does not extract
        # its credentials. Refuse to spend against an API-key account.
        auth = await asyncio.to_thread(subprocess.run, ["claude", "auth", "status"],
            capture_output=True, text=True, timeout=15)
        try:
            status = json.loads(auth.stdout)
        except (ValueError, TypeError):
            raise CheckFailed("official_subscription_login_unavailable") from None
        report["official_subscription_login"] = bool(auth.returncode == 0
            and status.get("loggedIn") and status.get("authMethod") == "claude.ai")
        require(report["official_subscription_login"], "official_subscription_login_unavailable")

        email = "sample.person@example.com"
        company = "Taldor Systems" if hybrid else "Cedar Example LLC"
        original = ('CONTACT = ' + repr(email) + '\nORGANIZATION = ' + repr(company)
                    + '\n\ndef inclusive_total(n):\n'
                      '    """Return the sum of the integers from 1 through n, inclusive."""\n'
                      '    return sum(range(n))\n')
        test_source = ('import unittest\nfrom totals import inclusive_total\n\n'
                       'class TotalTests(unittest.TestCase):\n'
                       '    def test_inclusive_total(self):\n'
                       '        self.assertEqual(inclusive_total(4), 10)\n'
                       '        self.assertEqual(inclusive_total(10), 55)\n'
                       '        self.assertEqual(inclusive_total(0), 0)\n')
        with tempfile.TemporaryDirectory(prefix="maskcode-live-synthetic-") as temporary, \
                create_pipe_input() as pipe:
            work = Path(temporary).resolve()
            source, tests = work / "totals.py", work / "test_totals.py"
            source.write_text(original, encoding="utf-8")
            tests.write_text(test_source, encoding="utf-8")
            baseline = await asyncio.to_thread(subprocess.run,
                [sys.executable, "-m", "unittest", "-q"], cwd=work,
                capture_output=True, text=True, timeout=10)
            report["baseline_test_failed"] = baseline.returncode != 0 and "FAILED (failures=1)" in baseline.stderr
            require(report["baseline_test_failed"], "fixture_did_not_start_with_failing_test")
            protected = (email, company, str(work), temporary, str(Path.home()))
            scanner = None
            if hybrid:
                from privacy_gateway.ollama_runtime import ManagedOllama
                from privacy_gateway.semantic import SemanticScanner
                local_runtime = await asyncio.to_thread(ManagedOllama().start)
                scanner = SemanticScanner(local_runtime)
            state = GatewayState(mode="auto", semantic_scanner=scanner, local_runtime=local_runtime,
                policy=Policy.from_dict({"literals": ([{"value": company, "label": "ORG"}] if not hybrid else []) + [
                {"value": str(work), "label": "SYNTHETIC_PATH"},
                {"value": temporary, "label": "SYNTHETIC_PATH"},
                {"value": str(Path.home()), "label": "LOCAL_HOME"},
            ]}))
            send_upstream = state.transport
            failures, events, observed_tools = [], [], {}

            def transport(path, body, headers):
                if any(value.encode() in body for value in protected):
                    report["originals_absent_on_wire"] = False
                    failures.append("protected_original_in_outbound_request")
                    raise PrivacyBlocked("Synthetic live check stopped before forwarding")
                count_key = "token_count_requests" if path.startswith("/v1/messages/count_tokens") else "model_requests"
                report[count_key] += 1
                if report[count_key] > 8:
                    failures.append("live_request_bound_reached")
                    raise PrivacyBlocked("Synthetic live request limit reached")
                return send_upstream(path, body, headers)

            state.transport = transport
            server = GatewayServer(state)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            await asyncio.to_thread(self_test, server.server_port)
            state.network_isolation = report["network_restriction_verified"] = True
            ui = TerminalApp(work, mode="auto", model=selected_model, input=pipe, output=DummyOutput())

            def allowed(name, inputs):
                if not isinstance(inputs, dict):
                    return False
                if name in ("Read", "Edit", "Write"):
                    filename = inputs.get("file_path")
                    if not isinstance(filename, str):
                        return False
                    target = Path(filename)
                    if not target.is_absolute():
                        target = work / target
                    permitted = (source, tests) if name == "Read" else (source,)
                    return target.resolve() in permitted
                if name == "Bash":
                    return (inputs.get("command") == "python3 -m unittest -q"
                            and not inputs.get("run_in_background"))
                return False

            def on_event(event):
                events.append(event)
                if event.get("type") == "assistant":
                    for block in event.get("message", {}).get("content", []):
                        if isinstance(block, dict) and block.get("type") == "tool_use":
                            observed_tools[block.get("id")] = block
                            if not allowed(block.get("name"), block.get("input")):
                                failures.append("unexpected_tool_input")
                ui.post_event(event)

            engine = ClaudeEngine(server, ["--tools", "Read,Edit,Bash", "--model", selected_model,
                "--max-turns", "8", "--no-session-persistence", "--system-prompt",
                "You are completing one small coding task inside the current temporary project. "
                "Read only totals.py and test_totals.py using Read. Fix totals.py using Edit. "
                "Keep the tests and metadata unchanged. Run tests with Bash using exactly "
                "python3 -m unittest -q, with no cd, prefix, suffix, or shell composition. "
                "Do not read other files or run any other command. End with a brief result."],
                str(work), on_event)
            ui.bind(engine, state)

            async def eventually(predicate, timeout=300 if hybrid else 90):
                deadline = asyncio.get_running_loop().time() + timeout
                while not predicate():
                    require(not failures, failures[0] if failures else "live_check_failed")
                    require(not (task and task.done()), "terminal_closed_early")
                    if (ui._approval or {}).get("kind") == "gateway":
                        report["no_outgoing_review_dialogs"] = False
                        raise CheckFailed("unexpected_outgoing_review_dialog")
                    require(asyncio.get_running_loop().time() < deadline, "live_check_timeout")
                    await asyncio.sleep(.02)

            with patch("webbrowser.open") as browser, \
                    patch.object(state, "decision", wraps=state.decision) as outgoing_decision:
                task = asyncio.create_task(ui.run_async())
                await eventually(lambda: ui.ready)
                pipe.send_text("Read totals.py and test_totals.py, fix inclusive_total's off-by-one bug "
                               "without changing the tests or CONTACT/ORGANIZATION metadata, then run "
                               "python3 -m unittest -q and report the result.\r")
                while True:
                    await eventually(lambda: ui._approval is not None
                                     or any(event.get("type") == "result" for event in events))
                    if ui._approval is None:
                        break
                    require(ui._approval["kind"] == "tool", "unexpected_outgoing_review_dialog")
                    permission = next(event for event in events
                        if event.get("type") == "permission_request"
                        and event.get("id") == ui._approval["id"])
                    approved = allowed(permission.get("tool"), permission.get("input"))
                    require(ui.app.layout.has_focus(ui._deny_button), "tool_dialog_default_focus_changed")
                    if not approved:
                        report["unexpected_tools_denied"] += 1
                        pipe.send_text("\r")
                        raise CheckFailed("unexpected_tool_permission_denied")
                    approval_id = ui._approval["id"]
                    pipe.send_text("\t")
                    await eventually(lambda: ui.app.layout.has_focus(ui._approve_button), timeout=3)
                    pipe.send_text("\r")
                    await eventually(lambda: (ui._approval or {}).get("id") != approval_id, timeout=5)
                    report["explicit_tool_approvals"] += 1
                await eventually(lambda: not ui.busy)
                report["read_tools"] = sum(tool.get("name") == "Read" for tool in observed_tools.values())
                report["edit_tools"] = sum(tool.get("name") in ("Edit", "Write") for tool in observed_tools.values())
                report["bash_tools"] = sum(tool.get("name") == "Bash" for tool in observed_tools.values())
                report["streamed_text_received"] = any(event.get("type") == "stream_event"
                    and event.get("event", {}).get("delta", {}).get("type") == "text_delta" for event in events)
                report["final_received"] = any(event.get("type") == "result" and not event.get("is_error")
                    and event.get("subtype") == "success" for event in events)
                require(report["final_received"], "model_did_not_complete_task")
                require(all(report[key] for key in ("read_tools", "edit_tools", "bash_tools")),
                        "model_did_not_use_required_tools")
                report["tests_unchanged"] = tests.read_text(encoding="utf-8") == test_source
                result_source = source.read_text(encoding="utf-8")
                report["synthetic_contacts_preserved"] = all(line in result_source for line in original.splitlines()[:2])
                after = await asyncio.to_thread(subprocess.run,
                    [sys.executable, "-m", "unittest", "-q"], cwd=work,
                    capture_output=True, text=True, timeout=10)
                report["independent_tests_passed"] = after.returncode == 0 and "OK" in after.stderr
                report["no_outgoing_review_dialogs"] = outgoing_decision.call_count == 0 and not state.snapshot()["pending"]
                report["no_browser_opened"] = browser.call_count == 0
                require(all(report[key] for key in ("tests_unchanged", "synthetic_contacts_preserved",
                    "independent_tests_passed", "no_outgoing_review_dialogs", "no_browser_opened",
                    "originals_absent_on_wire", "streamed_text_received")), "live_result_validation_failed")
                require(not failures, failures[0] if failures else "live_result_validation_failed")
                if scanner:
                    report["local_scanner"] = scanner.snapshot()
                    report["local_network_restriction_verified"] = local_runtime.network_isolation
                pipe.send_text("/quit\r")
                require(await asyncio.wait_for(task, 5) == 0, "terminal_exit_failed")
                report["completed"] = True
    except CheckFailed as exc:
        report["failure_code"] = str(exc)
    except Exception:
        report["failure_code"] = "live_check_runtime_failure"
    finally:
        if task and not task.done():
            ui._request_exit()
            try:
                await asyncio.wait_for(task, 5)
            except Exception:
                pass
        if engine:
            await asyncio.to_thread(engine.close)
        if state:
            state.close()
        elif local_runtime:
            local_runtime.close()
        if server:
            await asyncio.to_thread(server.shutdown)
            server.server_close()
        if thread:
            thread.join(2)
    print(json.dumps(report, indent=2))
    return 0 if report["completed"] else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(run()))
