"""Provider provenance affects local discovery only; entirely synthetic tests."""
import copy
import io
import json
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from privacy_gateway.codex_streaming import CodexStream
from privacy_gateway.protocol import PrivacyBlocked, readable_fragments
from privacy_gateway.provider_ids import (ProviderIdRegistry, collect_event_ids,
    collect_response_ids, discovery_view, MAX_PROVIDER_CORE_CHARS, MAX_PROVIDER_ID_CHARS)
from privacy_gateway.redaction import Policy, Redactor
from privacy_gateway.server import GatewayState, Handler
from privacy_gateway.streaming import AnthropicStream
from tests.test_codex_streaming import wire, start, end, patch_events, delta
from tests.test_streaming import wire as anthropic_wire, start as anthropic_start
from tests.test_streaming import block as anthropic_block, end as anthropic_end


def function_call(**changes):
    return {"type": "function_call", "id": "fc_synthetic", "call_id": "call_synthetic",
            "name": "exec_command", "namespace": "functions",
            "arguments": '{"cmd": "true", "max_output_tokens": 2000}', **changes}


def response(*items, **changes):
    return {"object": "response", "status": "completed", "output": list(items), **changes}


def trusted(*items):
    return collect_response_ids(response(*items), "codex")


class ProviderDiscoveryTests(unittest.TestCase):
    def test_registry_is_bounded_hash_only_and_releases_all_entries(self):
        registry = ProviderIdRegistry()
        with patch("privacy_gateway.provider_ids.MAX_PROVIDER_IDS", 5):
            for index in range(20):
                registry.remember(trusted(function_call(id="fc_" + str(index),
                    call_id="call_" + str(index))))
            self.assertEqual(len(registry.snapshot()), 5)
            self.assertTrue(all(isinstance(value, bytes) and len(value) == 32
                                for _, value in registry.snapshot()))
            old = {"input": [function_call(id="fc_0", call_id="call_0")]}
            self.assertEqual(discovery_view(old, "codex", registry.snapshot()), old)
        registry.remember([None, ([], b"x" * 32), ("unknown", b"x" * 32),
                           ("openai.message", "not a digest")])
        registry.clear()
        self.assertFalse(registry.snapshot())

    def test_only_complete_direct_response_slots_supply_ids(self):
        call = function_call()
        self.assertTrue(trusted(call))
        for payload in (response(call, status="in_progress"), response(call, status="failed"),
                        response(call, error={"type": "failed"}), response(call, incomplete_details={}),
                        {"nested": response(call)}, {"object": "response", "status": "completed",
                          "output": [{"type": "message", "role": "user", "id": "fc_synthetic",
                                      "content": [call]}]}):
            with self.subTest(payload=payload.get("status")):
                self.assertFalse(collect_response_ids(payload, "codex"))
        malformed = function_call(id="x" * (MAX_PROVIDER_ID_CHARS + 1),
                                  call_id="not an identifier")
        self.assertFalse(trusted(malformed))

    def test_known_ids_are_scoped_by_protocol_role_and_item_family(self):
        call = function_call()
        message = {"type": "message", "role": "assistant", "id": "msg_synthetic", "content": []}
        payload = {"input": [
            {"type": "message", "role": "assistant", "id": "msg_synthetic", "content": []},
            {"type": "message", "role": "user", "id": "msg_synthetic", "content": []},
            {"type": "function_call_output", "call_id": call["call_id"], "output": "2000"},
            {"type": "custom_tool_call_output", "call_id": call["call_id"], "output": "2000"},
            {"type": "unknown", "id": call["id"], "call_id": call["call_id"]}]}
        original = copy.deepcopy(payload)
        view = discovery_view(payload, "codex", trusted(call, message))
        self.assertNotIn("id", view["input"][0])
        self.assertEqual(view["input"][1], payload["input"][1])
        self.assertNotIn("call_id", view["input"][2])
        self.assertEqual(view["input"][2]["output"], "2000")
        self.assertEqual(view["input"][3:], payload["input"][3:])
        self.assertEqual(payload, original)

    def test_exact_core_is_omitted_but_changed_optional_metadata_remains(self):
        call = function_call(status="completed")
        replay = {**call, "id": "private-new-id", "status": "Confidential status"}
        payload = {"input": [replay]}
        view = discovery_view(payload, "codex", trusted(call))
        self.assertEqual(view, {"input": [{"id": "private-new-id", "status": "Confidential status"}]})
        self.assertEqual(payload["input"][0], replay)
        self.assertNotIn("2000", readable_fragments(view))
        self.assertIn("Confidential status", readable_fragments(view))

    def test_matching_calls_do_not_exempt_tool_results_or_content_copies(self):
        call = function_call()
        output = {"type": "function_call_output", "call_id": call["call_id"],
                  "output": json.dumps(call)}
        payload = {"input": [call, output, {"role": "user", "content": [call]}],
                   "extra": {"input": [call]}, "copy": json.dumps(call)}
        view = discovery_view(payload, "codex", trusted(call))
        self.assertEqual(view["input"][0], {})
        self.assertEqual(view["input"][1]["output"], output["output"])
        self.assertEqual(view["input"][2:], payload["input"][2:])
        self.assertEqual(view["extra"], payload["extra"])
        self.assertEqual(view["copy"], payload["copy"])
        self.assertGreaterEqual(readable_fragments(view).count("2000"), 4)

    def test_changed_core_or_unknown_field_gets_no_body_exemption(self):
        original = function_call()
        for changes in ({"arguments": '{"cmd":"true","max_output_tokens":2001}'},
                        {"arguments": '{"cmd":"true","max_output_tokens":"2000"}'},
                        {"arguments": '{"max_output_tokens":2000,"cmd":"true"}'},
                        {"name": "private_tool"}, {"namespace": "private_namespace"},
                        {"call_id": "call_other"}, {"metadata": "private metadata"}):
            with self.subTest(fields=list(changes)):
                replay = {**original, **changes}
                view = discovery_view({"input": [replay]}, "codex", trusted(original))
                self.assertEqual(view["input"][0]["arguments"], replay["arguments"])
        replay = {key: value for key, value in original.items() if key != "namespace"}
        self.assertIn("arguments", discovery_view({"input": [replay]}, "codex", trusted(original))["input"][0])
        unknown = {**original, "metadata": "private metadata"}
        self.assertIn("arguments", discovery_view({"input": [unknown]}, "codex", trusted(unknown))["input"][0])

    def test_only_exact_sanitizer_compaction_is_added_for_arguments(self):
        call = function_call()
        compact = {**call, "arguments": '{"cmd":"true","max_output_tokens":2000}'}
        self.assertEqual(discovery_view({"input": [compact]}, "codex", trusted(call)), {"input": [{}]})
        for arguments in ('{"x":1,"x":2}', '{"x":NaN}', '{"x":Infinity}', '{"x":1e999}',
                          'not JSON', '"' + 'a' * MAX_PROVIDER_CORE_CHARS + '"'):
            with self.subTest(argument_size=len(arguments)):
                malformed = function_call(arguments=arguments)
                self.assertIn("arguments", discovery_view({"input": [malformed]}, "codex",
                    trusted(malformed))["input"][0])

    def test_custom_patch_core_is_exact_and_tool_output_is_retained(self):
        call = {"type": "custom_tool_call", "id": "ct_synthetic", "call_id": "call_patch",
                "name": "apply_patch", "input": "*** Begin Patch\n*** End Patch\n"}
        self.assertEqual(discovery_view({"input": [call]}, "codex", trusted(call)), {"input": [{}]})
        for changed in ({**call, "input": call["input"] + "\n"}, {**call, "name": "another_tool"}):
            self.assertEqual(discovery_view({"input": [changed]}, "codex", trusted(call))["input"][0]["input"],
                             changed["input"])
        output = {"type": "custom_tool_call_output", "call_id": call["call_id"], "output": call["input"]}
        self.assertEqual(discovery_view({"input": [output]}, "codex", trusted(call))["input"][0]["output"],
                         call["input"])

    def test_anthropic_ids_are_direct_role_scoped_and_inputs_stay_inspected(self):
        tool = {"type": "tool_use", "id": "tool_synthetic", "name": "Read", "input": {"path": "private.txt"}}
        identities = collect_response_ids({"type": "message", "role": "assistant", "content": [tool]}, "anthropic")
        result = {"type": "tool_result", "tool_use_id": "tool_synthetic", "content": json.dumps(tool)}
        payload = {"messages": [{"role": "assistant", "content": [tool]},
                                {"role": "user", "content": [result, tool]}]}
        view = discovery_view(payload, "anthropic", identities)
        self.assertNotIn("id", view["messages"][0]["content"][0])
        self.assertEqual(view["messages"][0]["content"][0]["input"], tool["input"])
        self.assertNotIn("tool_use_id", view["messages"][1]["content"][0])
        self.assertEqual(view["messages"][1]["content"][0]["content"], result["content"])
        self.assertEqual(view["messages"][1]["content"][1], tool)


class GatewayProviderDiscoveryTests(unittest.TestCase):
    def state(self, policy=None):
        scanner = Mock()
        scanner.scan.return_value = []
        state = GatewayState(provider="codex", mode="auto", policy=policy, semantic_scanner=scanner)
        self.addCleanup(state.close)
        return state, scanner

    def test_scanner_skips_clean_provider_core_but_wire_payload_preserves_it(self):
        state, scanner = self.state()
        call = function_call()
        state.provider_ids.remember(trusted(call))
        payload = {"model": "gpt-6-astra", "input": [call]}
        clean = state.sanitize(payload, set())
        self.assertNotIn("2000", scanner.scan.call_args.args[0])
        self.assertNotIn("call_synthetic", scanner.scan.call_args.args[0])
        self.assertEqual(json.loads(clean["input"][0]["arguments"])["max_output_tokens"], 2000)
        self.assertEqual(clean["input"][0]["call_id"], "call_synthetic")
        state.close()
        self.assertFalse(state.provider_ids.snapshot())

    def test_explicit_numeric_and_identifier_policies_still_block_before_discovery(self):
        for value in ("2000", "call_synthetic", "exec_command"):
            with self.subTest(value=value):
                policy = Policy.from_dict({"literals": [{"value": value, "label": "CONFIDENTIAL"}]})
                state, scanner = self.state(policy)
                call = function_call()
                state.provider_ids.remember(trusted(call))
                with self.assertRaises(PrivacyBlocked):
                    state.sanitize({"model": "gpt-6-astra", "input": [call]}, set())
                scanner.scan.assert_not_called()

    def test_new_local_detection_in_another_fragment_still_rechecks_proven_ids(self):
        state, scanner = self.state()
        call = function_call()
        state.provider_ids.remember(trusted(call))
        scanner.scan.return_value = [(call["call_id"], "CONFIDENTIAL")]
        with self.assertRaises(PrivacyBlocked):
            state.sanitize({"model": "gpt-6-astra", "input": [call,
                {"role": "user", "content": "private " + call["call_id"]}]}, set())

    def test_changed_clean_arguments_do_not_inherit_provider_core_exemption(self):
        policy = Policy.from_dict({"literals": [{"value": "known private value", "label": "CONFIDENTIAL"}]})
        state, scanner = self.state(policy)
        call = function_call(name="Read", arguments='{"path":"known private value"}')
        state.provider_ids.remember(trusted(call))
        clean = state.sanitize({"model": "gpt-6-astra", "input": [call]}, set())
        self.assertNotIn("known private value", clean["input"][0]["arguments"])
        # Rule masking changed the provider bytes; the sanitized argument stays
        # in inspection (protected tokens are later blanked by SemanticScanner).
        self.assertTrue(any("PG_" in fragment for fragment in scanner.scan.call_args.args[0]))


class ProviderCompletionTests(unittest.TestCase):
    def setUp(self):
        self.redactor = Redactor(Policy.from_dict({}))
        self.patch_text = "*** Begin Patch\n*** Add File: safe.txt\n+okay\n*** End Patch\n"

    def test_codex_admits_only_after_complete_validation_and_clean_eof(self):
        restorer = CodexStream(self.redactor)
        prefix = wire(*start(), delta("Done"), *patch_events(self.patch_text), *end("Done"))
        def chunks():
            yield prefix
            self.assertFalse(restorer.trusted_provider_ids)
        list(restorer.restore(chunks()))
        self.assertTrue(restorer.trusted_provider_ids)
        call = {"type": "custom_tool_call", "id": "ct_1", "call_id": "call_1", "name": "apply_patch",
                "input": self.patch_text}
        self.assertEqual(discovery_view({"input": [call]}, "codex", restorer.trusted_provider_ids), {"input": [{}]})
        for broken in (wire(*start(), *patch_events(self.patch_text)), prefix + b"not SSE\n\n"):
            invalid = CodexStream(self.redactor)
            with self.assertRaises(PrivacyBlocked):
                list(invalid.restore([broken]))
            self.assertFalse(invalid.trusted_provider_ids)

    def test_anthropic_ids_not_admitted_on_incomplete_or_failed_tail(self):
        prefix = anthropic_wire(anthropic_start(), anthropic_block("tool_use", id="tool_1", name="Read",
            input={"path": "safe.txt"}))
        suffix = anthropic_wire(*anthropic_end("tool_use"))
        valid = AnthropicStream(self.redactor)
        def chunks():
            yield prefix + suffix
            self.assertFalse(valid.trusted_provider_ids)
        list(valid.restore(chunks()))
        self.assertTrue(valid.trusted_provider_ids)
        for broken in (prefix, prefix + suffix + b"not SSE\n\n"):
            invalid = AnthropicStream(self.redactor)
            with self.assertRaises(PrivacyBlocked):
                list(invalid.restore([broken]))
            self.assertFalse(invalid.trusted_provider_ids)

    def test_gateway_admits_before_releasing_tool_and_closed_state_stays_empty(self):
        for closed in (False, True):
            with self.subTest(closed=closed):
                state = GatewayState(provider="codex", mode="auto")
                self.addCleanup(state.close)
                if closed:
                    state.close()
                handler = object.__new__(Handler)
                handler.server = SimpleNamespace(state=state)
                for name in ("send_response", "send_header", "end_headers"):
                    setattr(handler, name, Mock())
                seen = []
                class Writer(io.BytesIO):
                    def write(writer, data):
                        if b'"custom_tool_call"' in data:
                            seen.append(bool(state.provider_ids.snapshot()))
                        return super().write(data)
                handler.wfile = Writer()
                handler.respond_provider_stream(wire(*start(), delta("Done"), *patch_events(self.patch_text), *end("Done")),
                                                CodexStream(state.redactor))
                self.assertTrue(seen)
                self.assertEqual(set(seen), {not closed})
                state.close()
                self.assertFalse(state.provider_ids.snapshot())


if __name__ == "__main__":
    unittest.main()
