"""Private Ollama lifecycle, socket ownership, and fail-closed JSON handling."""
import json
import os
from pathlib import Path
import signal
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from privacy_gateway import ollama_runtime as local


class LocalModelTests(unittest.TestCase):
    def test_only_local_library_names_are_accepted(self):
        self.assertEqual(local.ManagedOllama().model, "qwen2.5:1.5b")
        self.assertEqual(local.ManagedOllama("llama3.2").model, "llama3.2:latest")
        for name in ("https://example.com/model", "localhost:1234/model", "user/model",
                     "../model", "qwen:cloud", "qwen:remote", "qwen:1b-cloud", "qwen\n", "", None):
            with self.subTest(name=name), self.assertRaises(local.OllamaRuntimeError):
                local.ManagedOllama(name)

    def test_model_metadata_must_confirm_local_text_weights(self):
        valid = {"details": {"format": "gguf"}, "capabilities": ["completion"]}
        local.ManagedOllama._validate_local_model(valid)
        for invalid in ({}, {"details": {"format": "gguf"}},
                        {**valid, "details": {"format": "remote"}},
                        {**valid, "remote_host": "https://example.com"},
                        {**valid, "remote_model": "remote-model"},
                        {**valid, "cloud": True}):
            with self.subTest(invalid=invalid), self.assertRaises(local.OllamaRuntimeError):
                local.ManagedOllama._validate_local_model(invalid)

    def test_environment_has_no_inherited_auth_proxy_or_ollama_override(self):
        malicious = {"OLLAMA_HOST": "https://example.com", "OLLAMA_API_KEY": "private",
                     "HTTPS_PROXY": "http://example.com", "DYLD_INSERT_LIBRARIES": "/x",
                     "OLLAMA_MODELS": "/x", "OLLAMA_REMOTE": "yes", "ANTHROPIC_API_KEY": "secret"}
        with patch.dict(os.environ, malicious):
            env = local._environment("/opt/bin/ollama", "/models", "/temporary", 12345)
        self.assertEqual(env["OLLAMA_HOST"], "127.0.0.1:12345")
        self.assertEqual(env["OLLAMA_MODELS"], "/models")
        self.assertEqual(env["OLLAMA_NO_CLOUD"], "1")
        self.assertEqual(env["OLLAMA_NOHISTORY"], "1")
        self.assertEqual(env["OLLAMA_KEEP_ALIVE"], "-1")
        self.assertEqual(env["HOME"], "/temporary")
        for key in malicious:
            if key not in {"OLLAMA_HOST", "OLLAMA_MODELS"}:
                self.assertNotIn(key, env)

    def test_profile_denies_external_sockets_and_model_writes(self):
        profile = local._profile('/models/"quoted', "/temporary")
        self.assertIn("(deny network*)", profile)
        self.assertIn('(remote tcp "localhost:*")', profile)
        self.assertIn('(local tcp "localhost:*")', profile)
        self.assertNotIn("udp", profile)
        self.assertIn("(deny file-write*)", profile)
        self.assertIn('(deny file-write* (subpath "/models/\\\"quoted"))', profile)

    def test_isolation_is_false_before_verified_start(self):
        runtime = local.ManagedOllama()
        self.assertFalse(runtime.network_isolation)
        with self.assertRaises(local.OllamaRuntimeError):
            runtime.generate_json("instructions", "confidential", {})


class RequestTests(unittest.TestCase):
    def setUp(self):
        self.runtime = local.ManagedOllama()
        self.runtime.port = 12345
        self.runtime.network_isolation = True
        self.connection = MagicMock()
        self.response = self.connection.getresponse.return_value
        self.response.status = 200
        self.response.read.return_value = b'{"version":"test"}'

    def request(self):
        return self.runtime._request("POST", "/api/chat", {"secret": "fixture"})

    def test_owned_connection_is_verified_before_body_is_sent(self):
        order = []
        self.connection.connect.side_effect = lambda: order.append("connect")
        self.connection.request.side_effect = lambda *a, **k: order.append("send")
        def owns():
            order.append("verify")
            return True
        with patch.object(self.runtime, "_owns_listener", side_effect=owns), \
                patch.object(local.http.client, "HTTPConnection", return_value=self.connection) as factory:
            self.assertEqual(self.request(), {"version": "test"})
        self.assertEqual(order, ["connect", "verify", "send"])
        factory.assert_called_once_with("127.0.0.1", 12345, timeout=120)
        self.connection.close.assert_called_once()

    def test_unowned_listener_never_receives_prompt(self):
        with patch.object(self.runtime, "_owns_listener", return_value=False), \
                patch.object(local.http.client, "HTTPConnection", return_value=self.connection):
            with self.assertRaises(local.OllamaRuntimeError):
                self.request()
        self.connection.request.assert_not_called()
        self.connection.close.assert_called_once()

    def test_errors_and_redirects_are_not_followed_or_echoed(self):
        for status in (301, 302, 307, 400, 500):
            self.response.status = status
            self.response.read.return_value = b'{"error":"confidential fixture"}'
            with self.subTest(status=status), \
                    patch.object(self.runtime, "_owns_listener", return_value=True), \
                    patch.object(local.http.client, "HTTPConnection", return_value=self.connection):
                with self.assertRaises(local.OllamaRuntimeError) as failure:
                    self.request()
                self.assertNotIn("confidential", str(failure.exception))
        self.response.read.assert_not_called()

    def test_response_limit_and_invalid_json_fail_closed(self):
        for raw in (b"x" * (local.MAX_RESPONSE_BYTES + 1), b"not json", b"[]",
                    b'{"error":"confidential fixture"}'):
            self.response.read.return_value = raw
            with self.subTest(size=len(raw)), \
                    patch.object(self.runtime, "_owns_listener", return_value=True), \
                    patch.object(local.http.client, "HTTPConnection", return_value=self.connection):
                with self.assertRaises(local.OllamaRuntimeError) as failure:
                    self.request()
                self.assertNotIn("confidential", str(failure.exception))
        self.response.read.assert_called_with(local.MAX_RESPONSE_BYTES + 1)

    def test_request_size_rejected_before_opening_socket(self):
        with patch.object(local.http.client, "HTTPConnection") as connection:
            with self.assertRaises(local.OllamaRuntimeError):
                self.runtime._request("POST", "/api/chat", {"text": "x" * local.MAX_REQUEST_BYTES})
        connection.assert_not_called()

    def test_management_and_remote_paths_are_unavailable(self):
        for path in ("/api/pull", "/api/create", "/api/delete", "https://example.com/api/chat"):
            with self.subTest(path=path), self.assertRaises(local.OllamaRuntimeError):
                self.runtime._request("POST", path, {})

    def test_lsof_requires_exact_owned_pid_and_live_process(self):
        process = self.runtime._process = MagicMock(pid=1234)
        process.poll.return_value = None
        for output, expected in (("p1234\nn127.0.0.1:12345\n", True),
                                 ("p12345\nn127.0.0.1:12345\n", False),
                                 ("p1234\nn*:12345\n", False),
                                 ("p1234\nn127.0.0.1:12346\n", False), ("", False)):
            with patch.object(local.subprocess, "run", return_value=MagicMock(returncode=0, stdout=output)):
                self.assertEqual(self.runtime._owns_listener(), expected)
        process.poll.return_value = 1
        with patch.object(local.subprocess, "run") as run:
            self.assertFalse(self.runtime._owns_listener())
            run.assert_not_called()

    def test_chat_requests_schema_and_returns_only_parsed_content(self):
        response = {"done": True, "message": {"content": '{"entities":["Example Name"]}'}}
        with patch.object(self.runtime, "_request", return_value=response) as request:
            result = self.runtime.generate_json("Find entities", "Example Name", {"type": "object"})
        self.assertEqual(result, {"entities": ["Example Name"]})
        args = request.call_args.args
        self.assertEqual(args[:2], ("POST", "/api/chat"))
        self.assertEqual(args[2]["model"], "qwen2.5:1.5b")
        self.assertFalse(args[2]["stream"])
        self.assertEqual(args[2]["keep_alive"], -1)
        self.assertEqual(args[2]["format"], {"type": "object"})
        self.assertEqual(args[2]["options"]["temperature"], 0)
        self.assertNotIn("tools", args[2])

    def test_invalid_and_incomplete_model_output_does_not_pass(self):
        for response in ({}, {"done": True}, {"done": False, "message": {"content": "{}"}},
                         {"done": True, "done_reason": "length", "message": {"content": "{}"}},
                         {"done": True, "message": {"content": "[]"}},
                         {"done": True, "message": {"content": "confidential response"}}):
            with self.subTest(response=response), patch.object(self.runtime, "_request", return_value=response):
                with self.assertRaises(local.OllamaRuntimeError) as failure:
                    self.runtime.generate_json("instructions", "input", {})
                self.assertNotIn("confidential", str(failure.exception))

    def test_images_tools_and_bad_timeouts_are_rejected(self):
        for messages in ([], [{"role": "user", "content": "x", "images": ["x"]}],
                         [{"role": "tool", "content": "x"}], [{"role": "user", "content": 1}]):
            with self.subTest(messages=messages), self.assertRaises(local.OllamaRuntimeError):
                self.runtime.chat(messages, {})
        for timeout in (0, 301, True, "30", float("nan"), float("inf")):
            with self.subTest(timeout=timeout), self.assertRaises(local.OllamaRuntimeError):
                self.runtime.generate_json("system", "text", {}, timeout=timeout)


class LifecycleTests(unittest.TestCase):
    def test_failed_network_probe_stops_before_ollama_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            model = Path(directory) / ".ollama/models/manifests/registry.ollama.ai/library/qwen2.5/1.5b"
            model.parent.mkdir(parents=True)
            model.write_text("{}")
            runtime = local.ManagedOllama()
            with patch.object(local.Path, "home", return_value=Path(directory)), \
                    patch.object(local.shutil, "which", return_value="/opt/homebrew/bin/ollama"), \
                    patch.object(local.platform, "system", return_value="Darwin"), \
                    patch.object(local.Path, "is_file", return_value=True), \
                    patch.object(local, "_verify_isolation", side_effect=local.OllamaRuntimeError("probe failed")), \
                    patch.object(local.subprocess, "Popen") as popen:
                with self.assertRaises(local.OllamaRuntimeError):
                    runtime.start()
                popen.assert_not_called()
            self.assertFalse(runtime.network_isolation)
            self.assertIsNone(runtime._temporary_home)

    def test_missing_model_never_pulls_or_starts_process(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(local.Path, "home", return_value=Path(directory)), \
                patch.object(local.subprocess, "Popen") as popen:
            with self.assertRaises(local.OllamaRuntimeError):
                local.ManagedOllama("does-not-exist:1b").start()
            popen.assert_not_called()

    def test_close_only_signals_owned_process_group_and_is_idempotent(self):
        runtime = local.ManagedOllama()
        process = runtime._process = MagicMock(pid=12345)
        runtime.network_isolation = True
        with patch.object(local.os, "killpg") as kill:
            runtime.close()
            runtime.close()
        kill.assert_called_once_with(12345, signal.SIGTERM)
        process.wait.assert_called_once_with(timeout=5)
        self.assertFalse(runtime.network_isolation)
        self.assertIsNone(runtime._process)
        with self.assertRaises(local.OllamaRuntimeError):
            runtime.start()

    def test_verification_does_not_accept_inconclusive_probe(self):
        for findings in (["allowed", "allowed", "blocked"], ["allowed", "blocked", "inconclusive"]):
            with patch.object(local.subprocess, "run", return_value=MagicMock(
                    returncode=0, stdout=json.dumps(findings))):
                with self.assertRaises(local.OllamaRuntimeError):
                    local._verify_isolation("policy", {})


@unittest.skipUnless(os.environ.get("MASKCODE_TEST_LOCAL_OLLAMA") == "1",
                     "Set MASKCODE_TEST_LOCAL_OLLAMA=1 for installed-model inference")
class InstalledOllamaTests(unittest.TestCase):
    def test_real_private_model_extracts_synthetic_entities_then_stops(self):
        schema = {"type": "object", "properties": {"person": {"type": "string"},
                  "company": {"type": "string"}}, "required": ["person", "company"],
                  "additionalProperties": False}
        with local.ManagedOllama() as runtime:
            self.assertTrue(runtime.network_isolation)
            process = runtime._process
            temporary_home = runtime._temporary_home.name
            result = runtime.generate_json(
                "Return the exact person name and company mentioned in the text.",
                "Mira Zorvan is the CFO at Taldor Systems.", schema)
            self.assertEqual(result, {"person": "Mira Zorvan", "company": "Taldor Systems"})
        self.assertIsNotNone(process.poll())
        self.assertFalse(Path(temporary_home).exists())
        self.assertFalse(runtime.network_isolation)


if __name__ == "__main__":
    unittest.main()
