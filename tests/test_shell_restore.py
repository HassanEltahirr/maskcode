"""Adversarial shell substitution tests; commands execute only on temp fixtures."""
import json
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

from privacy_gateway.protocol import PrivacyBlocked, restore_response
from privacy_gateway.redaction import Policy, Redactor
from privacy_gateway.shell_restore import ShellRestoreBlocked, restore_simple_command


class ShellRestorationTests(unittest.TestCase):
    def redactor(self, secret):
        r = Redactor(Policy.from_dict({"literals": [{"value": secret, "label": "PATH"}]}))
        return r, r.redact_text(secret)

    def test_metacharacters_in_restored_path_stay_one_inert_argument(self):
        secret = "customer' ; touch SHOULD_NOT_EXIST ; echo ' $(id) `whoami` &"
        r, token = self.redactor(secret)
        for program in ("cat", "ls", "head", "tail", "wc", "file", "cd"):
            with self.subTest(program=program):
                result = restore_simple_command(program + " " + token, r)
                self.assertEqual(shlex.split(result), [program, secret])

    def test_actual_shell_reads_specially_named_file_without_running_injected_command(self):
        with tempfile.TemporaryDirectory() as directory:
            # The apparent command injection is a literal valid filename.
            name = "data'; touch SHOULD_NOT_EXIST; echo '"
            path = Path(directory) / name
            path.write_text("synthetic file contents", encoding="utf-8")
            r, token = self.redactor(str(path))
            command = restore_simple_command("cat " + token, r)
            result = subprocess.run(["/bin/sh", "-c", command], cwd=directory,
                                    capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stdout, "synthetic file contents")
            self.assertFalse((Path(directory) / "SHOULD_NOT_EXIST").exists())

    def test_option_injection_and_controls_are_blocked(self):
        for secret in ("--help", "-n", "a\nb", "a\x00b"):
            r, token = self.redactor(secret)
            with self.subTest(secret=repr(secret)), self.assertRaises(ShellRestoreBlocked):
                restore_simple_command("cat " + token, r)

    def test_complex_shell_and_interpreters_remain_blocked(self):
        r, token = self.redactor("/synthetic/private path")
        for command in ("cat " + token + " | sh", "cat " + token + "; pwd",
                        "python " + token, "bash " + token, "eval " + token,
                        "cat $(echo " + token + ")", "cat " + token + "/*",
                        "rg --pre " + token + " pattern .", "ls --unknown " + token):
            with self.subTest(command=command), self.assertRaises(ShellRestoreBlocked):
                restore_simple_command(command, r)

    def test_native_bash_restores_only_command_and_description(self):
        r, token = self.redactor("/synthetic/private path")
        payload = {"content": [{"type": "tool_use", "name": "Bash", "input": {
            "command": "head -n 12 " + token, "description": "Read " + token, "timeout": 1000}}]}
        restored = restore_response(payload, r)
        data = restored["content"][0]["input"]
        self.assertEqual(shlex.split(data["command"]), ["head", "-n", "12", "/synthetic/private path"])
        self.assertEqual(data["description"], "Read /synthetic/private path")
        self.assertEqual(data["timeout"], 1000)
        self.assertIn(token, json.dumps(payload))

    def test_custom_exec_unknown_fields_and_option_values_fail_closed(self):
        r, token = self.redactor("/synthetic/private path")
        cases = [("Bash", {"command": "cat " + token, "script": token}),
                 ("exec_command", {"command": "cat " + token}),
                 ("Bash", {"command": "head -n " + token + " file.txt"})]
        for name, data in cases:
            with self.subTest(name=name, data=data), self.assertRaises(PrivacyBlocked):
                restore_response({"content": [{"type": "tool_use", "name": name, "input": data}]}, r)


if __name__ == "__main__":
    unittest.main()
