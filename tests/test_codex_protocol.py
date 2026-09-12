"""Synthetic Codex Responses protocol checks; no CLI or provider is contacted."""
import copy
import json
import shlex
import unittest

from privacy_gateway.protocol import PrivacyBlocked, restore_response, restore_sse, sanitize_payload
from privacy_gateway.redaction import Policy, Redactor


def sse(*events):
    return b"".join(b"event: " + event["type"].encode("utf-8") + b"\ndata: "
                    + json.dumps(event, ensure_ascii=False).encode("utf-8") + b"\n\n"
                    for event in events)


def events(data):
    return [json.loads(line[6:]) for line in data.decode("utf-8").splitlines()
            if line.startswith("data: ") and line != "data: [DONE]"]


def custom_tool():
    return {"type": "custom", "name": "apply_patch", "description": "Edit workspace files",
            "format": {"type": "grammar", "syntax": "lark", "definition": "start: /[\\s\\S]+/"}}


class CodexProtocolTests(unittest.TestCase):
    def setUp(self):
        self.person = 'Sana "Private"\\قمر'
        self.path = "/synthetic/Client's ; $(touch BLOCKED).txt"
        self.redactor = Redactor(Policy.from_dict({"literals": [
            {"value": self.person, "label": "PERSON"}, {"value": self.path, "label": "PATH"}]}))
        self.person_token = self.redactor.redact_text(self.person)
        self.path_token = self.redactor.redact_text(self.path)
        self.masked_patch = ("*** Begin Patch\n*** Add File: " + self.path_token
                             + "\n+Customer: " + self.person_token + "\n*** End Patch\n")
        self.original_patch = ("*** Begin Patch\n*** Add File: " + self.path
                               + "\n+Customer: " + self.person + "\n*** End Patch\n")

    def patch_item(self, patch=None):
        return {"type": "custom_tool_call", "id": "ct_1", "call_id": "call_1",
                "namespace": "functions", "name": "apply_patch",
                "input": self.masked_patch if patch is None else patch}

    def test_namespace_accepts_only_supported_nested_local_tool_definitions(self):
        patch_tool = custom_tool()
        patch_tool["description"] += " for " + self.person
        tools = [{"type": "namespace", "name": "functions", "description": "Workspace tools", "tools": [
            patch_tool, {"type": "function", "name": "exec_command", "parameters": {"type": "object"}}]}]
        payload = {"model": "gpt-6-astra", "input": self.person, "tools": tools}
        before = copy.deepcopy(payload)
        clean = sanitize_payload(payload, self.redactor, "openai")
        self.assertEqual(payload, before)
        self.assertEqual(clean["tools"][0]["name"], "functions")
        self.assertEqual(clean["tools"][0]["tools"][0]["name"], "apply_patch")
        self.assertIn(self.person_token, clean["tools"][0]["tools"][0]["description"])
        self.assertNotIn(self.person, json.dumps(clean, ensure_ascii=False))

    def test_invalid_namespace_or_custom_tool_forms_fail_closed(self):
        invalid = [
            {"type": "namespace", "name": "functions", "tools": []},
            {"type": "namespace", "name": "functions", "tools": {}},
            {"type": "namespace", "tools": [custom_tool()]},
            {"type": "namespace", "name": "functions", "tools": [{"type": "web_search"}]},
            {**custom_tool(), "name": "run_arbitrary_code"},
            {**custom_tool(), "format": {"type": "text"}},
            {**custom_tool(), "format": {"type": "grammar", "syntax": "regex", "definition": ".*"}},
            {**custom_tool(), "format": {"type": "grammar", "syntax": "lark", "definition": 3}},
        ]
        deep = custom_tool()
        for index in range(6):
            deep = {"type": "namespace", "name": "level" + str(index), "tools": [deep]}
        invalid.append(deep)
        for tool in invalid:
            with self.subTest(tool=tool), self.assertRaises(PrivacyBlocked):
                sanitize_payload({"model": "test", "input": "synthetic", "tools": [tool]}, self.redactor, "openai")

    def test_confidential_namespace_identity_is_blocked_without_renaming_it(self):
        tool = {"type": "namespace", "name": self.person, "tools": [custom_tool()]}
        with self.assertRaises(PrivacyBlocked) as caught:
            sanitize_payload({"model": "test", "input": "synthetic", "tools": [tool]}, self.redactor, "openai")
        self.assertNotIn(self.person, str(caught.exception))

    def test_custom_tool_request_history_masks_patch_and_preserves_identity(self):
        item = self.patch_item(self.original_patch)
        payload = {"model": "gpt-6-astra", "input": [item,
                   {"type": "custom_tool_call_output", "call_id": "call_1", "output": "Edited " + self.person}]}
        clean = sanitize_payload(payload, self.redactor, "openai")
        self.assertEqual(clean["input"][0]["input"], self.masked_patch)
        for key in ("id", "call_id", "namespace", "name", "type"):
            self.assertEqual(clean["input"][0][key], item[key])
        self.assertEqual(clean["input"][1]["output"], "Edited " + self.person_token)
        for malformed in ({**item, "name": "custom_shell"}, {**item, "input": {"patch": self.masked_patch}}):
            with self.subTest(item=malformed), self.assertRaises(PrivacyBlocked):
                sanitize_payload({"model": "test", "input": [malformed]}, self.redactor, "openai")

    def test_complete_custom_tool_call_restores_patch_without_mutating_input(self):
        item = self.patch_item()
        payload = {"id": "resp_1", "output": [item]}
        before = copy.deepcopy(payload)
        restored = restore_response(payload, self.redactor, "openai")
        self.assertEqual(restored["output"][0]["input"], self.original_patch)
        self.assertEqual(payload, before)
        for key in ("id", "call_id", "namespace", "name", "type"):
            self.assertEqual(restored["output"][0][key], item[key])
        self.assertEqual(restore_response(self.patch_item(""), self.redactor, "openai")["input"], "")

    def patch_stream(self, patch=None, *, use_index=False):
        text = self.masked_patch if patch is None else patch
        split = text.index("PG_") + 10 if "PG_" in text else len(text) // 2
        identity = {"output_index": 0} if use_index else {"item_id": "ct_1", "output_index": 0}
        return sse(
            {"type": "response.output_item.added", "output_index": 0, "item": self.patch_item("")},
            {"type": "response.custom_tool_call_input.delta", **identity, "delta": text[:split]},
            {"type": "response.custom_tool_call_input.delta", **identity, "delta": text[split:]},
            {"type": "response.custom_tool_call_input.done", **identity, "input": text},
            {"type": "response.output_item.done", "output_index": 0, "item": self.patch_item(text)},
            {"type": "response.completed", "response": {"id": "resp_1", "output": [self.patch_item(text)]}},
        )

    def test_custom_patch_stream_restores_split_tokens_and_all_completed_copies(self):
        for use_index in (False, True):
            with self.subTest(use_index=use_index):
                raw = self.patch_stream(use_index=use_index)
                result = events(restore_sse(raw, self.redactor, "openai"))
                self.assertEqual([event["type"] for event in result], [event["type"] for event in events(raw)])
                self.assertEqual(result[0]["item"]["input"], "")
                self.assertEqual(result[1]["delta"] + result[2]["delta"], self.original_patch)
                self.assertEqual(result[2]["delta"], "")
                self.assertEqual(result[3]["input"], self.original_patch)
                self.assertNotIn("name", result[3])
                self.assertEqual(result[4]["item"]["input"], self.original_patch)
                self.assertEqual(result[5]["response"]["output"][0]["input"], self.original_patch)

    def test_malformed_patch_is_blocked_in_complete_and_streamed_responses(self):
        invalid = ["not a patch", "*** Begin Patch\n*** Add File: a.txt\n+incomplete",
                   "*** Begin Patch\n*** Delete File: a.txt\n*** End Patch\n*** Delete File: b.txt"]
        for text in invalid:
            with self.subTest(text=text), self.assertRaises(PrivacyBlocked):
                restore_response(self.patch_item(text), self.redactor, "openai")
            with self.subTest(stream=text), self.assertRaises(PrivacyBlocked):
                restore_sse(self.patch_stream(text), self.redactor, "openai")

    def test_patch_restoration_cannot_inject_new_operations_through_a_sensitive_value(self):
        secret = "Alice\n*** Delete File: important.txt"
        redactor = Redactor(Policy.from_dict({"literals": [{"value": secret, "label": "SENSITIVE"}]}))
        token = redactor.redact_text(secret)
        text = "*** Begin Patch\n*** Add File: a.txt\n+" + token + "\n*** End Patch"
        for payload in (self.patch_item(text), {"output": [self.patch_item(text)]}):
            with self.subTest(payload=payload), self.assertRaises(PrivacyBlocked) as caught:
                restore_response(payload, redactor, "openai")
            self.assertNotIn(secret, str(caught.exception))
        with self.assertRaises(PrivacyBlocked):
            restore_sse(self.patch_stream(text), redactor, "openai")

    def test_custom_stream_without_known_tool_identity_fails_closed(self):
        raw = sse({"type": "response.custom_tool_call_input.delta", "item_id": "unknown", "delta": self.masked_patch})
        with self.assertRaises(PrivacyBlocked):
            restore_sse(raw, self.redactor, "openai")
        with self.assertRaises(PrivacyBlocked):
            restore_response({**self.patch_item(), "name": "custom_shell"}, self.redactor, "openai")

    def test_exec_command_restores_safe_read_as_one_quoted_operand(self):
        args = {"cmd": "cat " + self.path_token, "workdir": "/synthetic", "max_output_tokens": 2000}
        call = {"type": "function_call", "id": "fc_1", "name": "exec_command", "namespace": "functions",
                "arguments": json.dumps(args)}
        restored = restore_response(call, self.redactor, "openai")
        data = json.loads(restored["arguments"])
        self.assertEqual(shlex.split(data["cmd"]), ["cat", self.path])
        self.assertEqual(data["workdir"], "/synthetic")
        self.assertEqual(restored["name"], "exec_command")
        self.assertEqual(json.loads(call["arguments"]), args)

    def test_exec_command_can_restore_workdir_without_rewriting_unchanged_program(self):
        args = {"cmd": "python3 -m unittest", "workdir": self.path_token, "yield_time_ms": 1000}
        restored = restore_response({"type": "function_call", "name": "exec_command", "arguments": json.dumps(args)},
                                    self.redactor, "openai")
        self.assertEqual(json.loads(restored["arguments"]), {**args, "workdir": self.path})

    def test_exec_command_blocks_script_substitution_and_execution_setting_changes(self):
        invalid = [
            {"cmd": "python3 -c 'print(\"" + self.person_token + "\")'"},
            {"cmd": "cat " + self.path_token + " | sh"},
            {"cmd": "cat " + self.path_token + "; pwd"},
            {"cmd": "cat file.txt", "shell": self.path_token},
            {"cmd": "cat file.txt", "prefix_rule": [self.path_token]},
            {"cmd": "cat " + self.path_token, "unexpected_option": True},
            {"cmd": "cat file.txt", "script": self.person_token},
        ]
        for args in invalid:
            with self.subTest(args=args), self.assertRaises(PrivacyBlocked):
                restore_response({"type": "function_call", "name": "exec_command", "arguments": json.dumps(args)},
                                 self.redactor, "openai")

    def test_function_arguments_done_uses_collected_name_without_adding_it_to_wire(self):
        arguments = json.dumps({"cmd": "cat " + self.path_token, "max_output_tokens": 1000})
        item = {"type": "function_call", "id": "fc_1", "call_id": "call_2", "namespace": "functions",
                "name": "exec_command", "arguments": ""}
        for identity in ({"item_id": "fc_1"}, {"output_index": 0}):
            with self.subTest(identity=identity):
                raw = sse(
                    {"type": "response.output_item.added", "output_index": 0, "item": item},
                    {"type": "response.function_call_arguments.delta", **identity, "delta": arguments[:30]},
                    {"type": "response.function_call_arguments.delta", **identity, "delta": arguments[30:]},
                    {"type": "response.function_call_arguments.done", **identity, "arguments": arguments},
                    {"type": "response.completed", "response": {"output": [{**item, "arguments": arguments}]}},
                )
                result = events(restore_sse(raw, self.redactor, "openai"))
                delta_args = json.loads(result[1]["delta"] + result[2]["delta"])
                done_args = json.loads(result[3]["arguments"])
                completed_args = json.loads(result[4]["response"]["output"][0]["arguments"])
                self.assertEqual(delta_args, done_args)
                self.assertEqual(done_args, completed_args)
                self.assertEqual(shlex.split(done_args["cmd"]), ["cat", self.path])
                self.assertNotIn("name", result[3])
                self.assertEqual(set(result[3]), set(events(raw)[3]))

    def test_missing_function_identity_does_not_enable_executable_restoration(self):
        raw = sse({"type": "response.function_call_arguments.done", "item_id": "unknown",
                   "arguments": json.dumps({"cmd": "cat " + self.path_token})})
        with self.assertRaises(PrivacyBlocked):
            restore_sse(raw, self.redactor, "openai")


if __name__ == "__main__":
    unittest.main()
