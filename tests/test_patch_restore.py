import unittest
from unittest.mock import patch

from privacy_gateway import patch_restore
from privacy_gateway.patch_restore import PatchRestoreBlocked, restore_patch
from privacy_gateway.redaction import Policy, Redactor


class MappingRedactor:
    def __init__(self, values=None):
        self.values = values or {}
        self.calls = []

    def restore_text(self, text):
        self.calls.append(text)
        for token, original in self.values.items():
            text = text.replace(token, original)
        return text


class PatchRestoreTests(unittest.TestCase):
    def test_real_redactor_restores_multifile_unicode_patch_without_changing_structure(self):
        name, person = "بيانات العملاء", "Alice Example"
        redactor = Redactor(Policy.from_dict({"literals": [
            {"value": name, "label": "PROJECT"}, {"value": person, "label": "PERSON"}]}))
        name_token, person_token = redactor.redact_text(name), redactor.redact_text(person)
        original = "\n".join([
            "*** Begin Patch", "*** Add File: " + name + "/new file.txt", "+Customer: " + person,
            "+مرحبا", "*** Update File: " + name + "/old file.txt", "*** Move to: " + name + "/renamed file.txt",
            "@@ Customer: " + person, " unchanged", "-Old " + person, "+New " + person,
            "*** End of File", "*** Delete File: " + name + "/obsolete.txt", "*** End Patch", "",
        ])
        masked = original.replace(name, name_token).replace(person, person_token)
        self.assertEqual(restore_patch(masked, redactor), original)
        self.assertIn(name_token, masked)

    def test_valid_unchanged_patches_keep_exact_newline_format_and_optional_trailing_newline(self):
        cases = [
            "*** Begin Patch\n*** Add File: empty.txt\n*** End Patch",
            "*** Begin Patch\n*** Add File: a.txt\n+line\n+\n*** End Patch",
            "*** Begin Patch\n*** Delete File: a.txt\n*** End Patch",
            "*** Begin Patch\n*** Update File: a.txt\n-before\n+after\n*** End Patch",
            "*** Begin Patch\n*** Update File: a.txt\n@@\n context\n-old\n+new\n@@ second\n-old2\n+new2\n*** End of File\n*** End Patch",
            "*** Begin Patch\n*** Update File: old.txt\n*** Move to: new.txt\n*** End Patch",
        ]
        for source in cases:
            for newline in ("\n", "\r\n"):
                for trailing in (False, True):
                    with self.subTest(source=source, newline=newline, trailing=trailing):
                        text = source.replace("\n", newline) + (newline if trailing else "")
                        self.assertEqual(restore_patch(text, MappingRedactor()), text)

    def test_empty_stream_placeholder_is_allowed_but_empty_patch_is_not(self):
        self.assertEqual(restore_patch("", MappingRedactor()), "")
        with self.assertRaises(PatchRestoreBlocked):
            restore_patch("*** Begin Patch\n*** End Patch", MappingRedactor())

    def test_body_prefix_is_not_restored_and_header_like_content_remains_inert(self):
        token = "PG_SENSITIVE_deadbeef_0001"
        original = "*** Delete File: important.txt"
        redactor = MappingRedactor({token: original})
        source = "*** Begin Patch\n*** Add File: example.txt\n+" + token + "\n*** End Patch"
        self.assertEqual(restore_patch(source, redactor), source.replace(token, original))
        self.assertNotIn("*** Begin Patch", redactor.calls)
        self.assertNotIn("*** End Patch", redactor.calls)
        self.assertIn("+*** Delete File: important.txt", restore_patch(source, redactor))

    def test_existing_indentation_tabs_survive_but_restoration_cannot_insert_tabs(self):
        source = "*** Begin Patch\n*** Update File: a.py\n@@\n-\told\n+\tPG_PERSON_deadbeef_0001\n*** End Patch"
        self.assertEqual(restore_patch(source, MappingRedactor({"PG_PERSON_deadbeef_0001": "Alice"})),
                         source.replace("PG_PERSON_deadbeef_0001", "Alice"))
        with self.assertRaises(PatchRestoreBlocked):
            restore_patch(source, MappingRedactor({"PG_PERSON_deadbeef_0001": "Alice\tExample"}))

    def test_restored_newlines_controls_and_extra_operation_injections_are_blocked(self):
        token = "PG_SENSITIVE_deadbeef_0001"
        secrets = ["secret\n*** Delete File: important.txt", "secret\rnew line", "a\x00b",
                   "a\x1bb", "a\x7fb", "a\x85b", "a\u2028b", "a\u202eb", "a\tb"]
        templates = [
            "*** Begin Patch\n*** Add File: " + token + "\n+safe\n*** End Patch",
            "*** Begin Patch\n*** Update File: old.txt\n*** Move to: " + token + "\n*** End Patch",
            "*** Begin Patch\n*** Add File: a.txt\n+" + token + "\n*** End Patch",
            "*** Begin Patch\n*** Update File: a.txt\n@@ " + token + "\n-old\n+new\n*** End Patch",
        ]
        for secret in secrets:
            for source in templates:
                with self.subTest(secret=repr(secret), source=source):
                    with self.assertRaises(PatchRestoreBlocked) as caught:
                        restore_patch(source, MappingRedactor({token: secret}))
                    self.assertNotIn(secret, str(caught.exception))

    def test_empty_ambiguous_or_colliding_paths_are_blocked_after_restoration(self):
        token = "PG_PATH_deadbeef_0001"
        source = "*** Begin Patch\n*** Add File: " + token + "\n+safe\n*** End Patch"
        for value in ("", " ", " leading.txt", "trailing.txt ", ".", "..", "/", "folder/", "*** Delete File: a"):
            with self.subTest(value=value), self.assertRaises(PatchRestoreBlocked):
                restore_patch(source, MappingRedactor({token: value}))
        collision = "*** Begin Patch\n*** Delete File: a.txt\n*** Add File: " + token + "\n+safe\n*** End Patch"
        for value in ("a.txt", "./a.txt", "folder/../a.txt"):
            with self.subTest(value=value), self.assertRaises(PatchRestoreBlocked):
                restore_patch(collision, MappingRedactor({token: value}))
        move = "*** Begin Patch\n*** Update File: a.txt\n*** Move to: " + token + "\n*** End Patch"
        with self.assertRaises(PatchRestoreBlocked):
            restore_patch(move, MappingRedactor({token: "a.txt"}))

    def test_unknown_and_malformed_formats_are_rejected_even_without_tokens(self):
        invalid = [
            "--- a.txt\n+++ a.txt\n@@\n-old\n+new",
            "```\n*** Begin Patch\n*** Delete File: a.txt\n*** End Patch\n```",
            " *** Begin Patch\n*** Delete File: a.txt\n*** End Patch",
            "*** Begin Patch\n*** Delete File: a.txt\n*** End Patch\n\n",
            "*** Begin Patch\n*** Add File:a.txt\n+line\n*** End Patch",
            "*** Begin Patch\n*** Add File: a.txt\nnot prefixed\n*** End Patch",
            "*** Begin Patch\n*** Delete File: a.txt\n+line\n*** End Patch",
            "*** Begin Patch\n*** Update File: a.txt\n*** End Patch",
            "*** Begin Patch\n*** Update File: a.txt\n@@\n*** End Patch",
            "*** Begin Patch\n*** Update File: a.txt\n@@\n@@ second\n+line\n*** End Patch",
            "*** Begin Patch\n*** Update File: a.txt\n@@bad\n+line\n*** End Patch",
            "*** Begin Patch\n*** Update File: a.txt\n*** End of File\n*** End Patch",
            "*** Begin Patch\n*** Update File: a.txt\n-old\n+new\n*** End of File\n+extra\n*** End Patch",
            "*** Begin Patch\n*** Update File: a.txt\n-old\n+new\n*** Move to: b.txt\n*** End Patch",
            "*** Begin Patch\n*** Delete File: a.txt\n*** End Patch\n*** Delete File: b.txt\n*** End Patch",
            "*** Begin Patch\n*** Delete File: a.txt\n*** Delete File: a.txt\n*** End Patch",
            "*** Begin Patch\n*** Add File: a.txt\n+bad\x00text\n*** End Patch",
            "*** Begin Patch\r\n*** Delete File: a.txt\n*** End Patch\r\n",
        ]
        for source in invalid:
            with self.subTest(source=source), self.assertRaises(PatchRestoreBlocked):
                restore_patch(source, MappingRedactor())

    def test_size_line_operation_and_hunk_limits_fail_closed(self):
        simple = "*** Begin Patch\n*** Add File: a.txt\n+value\n*** End Patch"
        with patch.object(patch_restore, "MAX_PATCH_BYTES", 10), self.assertRaises(PatchRestoreBlocked):
            restore_patch(simple, MappingRedactor())
        with patch.object(patch_restore, "MAX_LINES", 3), self.assertRaises(PatchRestoreBlocked):
            restore_patch(simple, MappingRedactor())
        operations = "*** Begin Patch\n*** Delete File: a\n*** Delete File: b\n*** End Patch"
        with patch.object(patch_restore, "MAX_OPERATIONS", 1), self.assertRaises(PatchRestoreBlocked):
            restore_patch(operations, MappingRedactor())
        hunks = "*** Begin Patch\n*** Update File: a\n@@\n-old\n+new\n@@ second\n-old\n+new\n*** End Patch"
        with patch.object(patch_restore, "MAX_HUNKS", 1), self.assertRaises(PatchRestoreBlocked):
            restore_patch(hunks, MappingRedactor())
        with patch.object(patch_restore, "MAX_PATCH_BYTES", 100), self.assertRaises(PatchRestoreBlocked):
            restore_patch(simple, MappingRedactor({"value": "x" * 200}))

    def test_invalid_input_or_redactor_failure_has_only_a_fixed_safe_diagnostic(self):
        class BrokenRedactor:
            def restore_text(self, text):
                raise RuntimeError("Private customer Alice")
        for text in (None, b"private", "\ud800"):
            with self.subTest(text_type=type(text).__name__), self.assertRaises(PatchRestoreBlocked):
                restore_patch(text, MappingRedactor())
        with self.assertRaises(PatchRestoreBlocked) as caught:
            restore_patch("*** Begin Patch\n*** Delete File: private.txt\n*** End Patch", BrokenRedactor())
        self.assertNotIn("Alice", str(caught.exception))
        self.assertNotIn("private.txt", str(caught.exception))
        self.assertTrue(caught.exception.__suppress_context__)

    def test_restore_does_not_read_or_execute_files(self):
        source = "*** Begin Patch\n*** Delete File: /synthetic/path.txt\n*** End Patch"
        with patch("builtins.open", side_effect=AssertionError("No file access")), \
                patch("os.open", side_effect=AssertionError("No file access")), \
                patch("subprocess.Popen", side_effect=AssertionError("No process execution")):
            self.assertEqual(restore_patch(source, MappingRedactor()), source)


if __name__ == "__main__":
    unittest.main()
