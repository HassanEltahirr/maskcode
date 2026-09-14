"""Selected local directory masking, using synthetic paths and no models."""
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from privacy_gateway.cli import start_gateway
from privacy_gateway.project_paths import (directory_literals, register_project_directories,
                                           with_directory_literals)
from privacy_gateway.redaction import Policy
from privacy_gateway.server import GatewayState


class ProjectPathTests(unittest.TestCase):
    def test_gateway_protects_external_project_before_its_first_request(self):
        with tempfile.TemporaryDirectory(prefix="maskcode-project-path-") as temporary:
            root = Path(temporary).resolve()
            home, project = root / "synthetic-home", root / "external-project"
            home.mkdir()
            project.mkdir()
            args = SimpleNamespace(policy=None, cwd=project, provider="codex", action="codex",
                                   local_model=None, mode="auto", port=0)
            with patch("privacy_gateway.cli.Path.home", return_value=home):
                server = start_gateway(args)
            try:
                self.assertEqual(server.state.requests, 0)
                self.assertIn((str(home), "LOCAL_HOME"), server.state.policy.literals)
                self.assertIn((str(project), "LOCAL_PROJECT"), server.state.policy.literals)
                body = {"model": "synthetic-model", "input": f"Read {project}/main.py from {home}."}
                clean = server.state.sanitize(body, set())
                self.assertNotIn(str(project), clean["input"])
                self.assertNotIn(str(home), clean["input"])
                self.assertEqual(server.state.redactor.restore_json(clean), body)
            finally:
                server.state.close()
                server.shutdown()
                server.server_close()

    def test_home_and_repeated_project_keep_configured_label_and_issued_token(self):
        with tempfile.TemporaryDirectory(prefix="maskcode-project-policy-") as temporary:
            home = str(Path(temporary).resolve())
            configured = Policy.from_dict({"literals": [{"value": home, "label": "CONFIGURED_HOME"}]})
            paths = directory_literals([home], "LOCAL_HOME") + directory_literals([home, home])
            policy = with_directory_literals(configured, paths)
            self.assertIs(policy, configured)
            state = GatewayState(provider="codex", policy=policy, mode="auto")
            try:
                token = state.redactor.redact_text(home)
                before = state.redactor.counts()
                register_project_directories(state, [home, home])
                self.assertEqual(state.policy.literals, ((home, "CONFIGURED_HOME"),))
                self.assertEqual(state.redactor.redact_text(home), token)
                self.assertEqual(state.redactor.restore_text(token), home)
                self.assertEqual(state.redactor.counts(), before)
            finally:
                state.close()

    def test_canonical_and_explicit_symlink_spellings_are_protected_without_parents(self):
        with tempfile.TemporaryDirectory(prefix="maskcode-project-alias-") as temporary:
            root = Path(temporary).resolve()
            project, alias = root / "project", root / "selected-alias"
            project.mkdir()
            alias.symlink_to(project, target_is_directory=True)
            literals = directory_literals([alias / ".." / alias.name, project, alias])
            self.assertEqual(literals, [(str(project), "LOCAL_PROJECT"), (str(alias), "LOCAL_PROJECT")])
            self.assertNotIn(str(root), [value for value, _ in literals])

    def test_shared_roots_are_not_automatically_added(self):
        for value in ("/", "/private", "/var", "/private/var", "/tmp", "/Users", "/home"):
            if Path(value).is_dir():
                with self.subTest(root=value):
                    self.assertEqual(directory_literals([value]), [])
                    self.assertEqual(directory_literals([Path(value).resolve()]), [])

    def test_project_registration_is_rejected_after_requests_or_close(self):
        with tempfile.TemporaryDirectory(prefix="maskcode-project-late-") as temporary:
            for closed in (False, True):
                with self.subTest(closed=closed):
                    state = GatewayState(provider="codex", mode="auto")
                    try:
                        if closed:
                            state.close()
                        else:
                            state.sanitize({"model": "synthetic-model", "input": "hello"}, set())
                        with self.assertRaises(ValueError):
                            register_project_directories(state, [temporary])
                        self.assertEqual(state.policy.literals, ())
                    finally:
                        state.close()

    def test_invalid_selected_directory_has_no_path_in_its_error(self):
        with tempfile.TemporaryDirectory(prefix="maskcode-project-invalid-") as temporary:
            invalid = Path(temporary) / "synthetic-private-filename"
            invalid.write_text("synthetic fixture")
            with self.assertRaises(ValueError) as caught:
                directory_literals([invalid])
            self.assertNotIn(str(invalid), str(caught.exception))
