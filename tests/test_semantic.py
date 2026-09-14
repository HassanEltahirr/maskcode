import json
import threading
import time
import unittest
from unittest.mock import patch

from privacy_gateway import semantic
from privacy_gateway.semantic import SemanticScanner, SemanticScanError


class FakeRuntime:
    def __init__(self, handler=None):
        self.calls = []
        self.closed = False
        self.handler = handler or (lambda text: {"entities": []})

    def generate_json(self, system, text, schema):
        self.calls.append((system, text, schema))
        return self.handler(text)

    def close(self):
        self.closed = True


def response(*pairs):
    return {"entities": [{"value": value, "label": label} for value, label in pairs]}


class SemanticScannerTests(unittest.TestCase):
    def test_snapshot_progress_is_available_while_runtime_is_blocked(self):
        entered, release = threading.Event(), threading.Event()
        runtime = FakeRuntime()
        def generate(text):
            if len(runtime.calls) == 2:
                entered.set()
                release.wait(3)
            return response()
        runtime.handler = generate
        scanner = SemanticScanner(runtime)
        initial = scanner.snapshot()
        for key in ("last_scan_seconds", "total_scan_seconds", "current_chunks",
                    "completed_chunks", "current_cache_hits"):
            self.assertEqual(initial[key], 0)
        outcomes, observed = [], []
        def scan():
            try:
                outcomes.append(scanner.scan(["a" * 3000, "b" * 3000]))
            except Exception as error:
                outcomes.append(error)
        worker = threading.Thread(target=scan)
        reader = threading.Thread(target=lambda: observed.append(scanner.snapshot()))
        worker.start()
        try:
            self.assertTrue(entered.wait(2))
            reader.start()
            reader.join(.5)
            self.assertFalse(reader.is_alive(), "Snapshot waited for local inference")
            self.assertEqual(observed[0]["status"], "scanning")
            self.assertEqual(observed[0]["current_chunks"], 2)
            self.assertEqual(observed[0]["completed_chunks"], 1)
            self.assertEqual(observed[0]["current_cache_hits"], 0)
        finally:
            release.set()
            worker.join(2)
            if reader.ident is not None:
                reader.join(2)
        self.assertFalse(worker.is_alive())
        self.assertEqual(outcomes, [[]])
        self.assertEqual(scanner.snapshot()["completed_chunks"], 2)
        self.assertEqual(scanner.snapshot()["status"], "ready")

    def test_cached_and_empty_scans_reset_progress_and_accumulate_monotonic_time(self):
        runtime = FakeRuntime()
        scanner = SemanticScanner(runtime)
        payload = ["a" * 3000, "b" * 3000]
        with patch.object(semantic.time, "monotonic", side_effect=[10, 12.25, 20, 20.125, 30, 30.0625]):
            scanner.scan(payload)
            first = scanner.snapshot()
            self.assertEqual((first["current_chunks"], first["completed_chunks"], first["current_cache_hits"]), (2, 2, 0))
            self.assertAlmostEqual(first["last_scan_seconds"], 2.25)
            self.assertAlmostEqual(first["total_scan_seconds"], 2.25)
            scanner.scan(payload)
            cached = scanner.snapshot()
            self.assertEqual(len(runtime.calls), 2)
            self.assertEqual((cached["current_chunks"], cached["completed_chunks"], cached["current_cache_hits"]), (2, 2, 2))
            self.assertAlmostEqual(cached["last_scan_seconds"], .125)
            self.assertAlmostEqual(cached["total_scan_seconds"], 2.375)
            scanner.scan([])
            empty = scanner.snapshot()
            self.assertEqual((empty["current_chunks"], empty["completed_chunks"], empty["current_cache_hits"]), (0, 0, 0))
            self.assertEqual(empty["cache_hits"], 2)
            self.assertAlmostEqual(empty["last_scan_seconds"], .0625)
            self.assertAlmostEqual(empty["total_scan_seconds"], 2.4375)

    def test_failed_and_invalid_scans_record_time_without_completing_chunks(self):
        runtime = FakeRuntime(lambda text: response(("invented value", "PERSON")))
        scanner = SemanticScanner(runtime)
        with patch.object(semantic.time, "monotonic", side_effect=[100, 102, 110, 111.5]):
            with self.assertRaises(SemanticScanError):
                scanner.scan("synthetic source")
            failed = scanner.snapshot()
            self.assertEqual(failed["status"], "blocked")
            self.assertEqual((failed["current_chunks"], failed["completed_chunks"], failed["current_cache_hits"]), (1, 0, 0))
            self.assertEqual(failed["cache_entries"], 0)
            self.assertAlmostEqual(failed["last_scan_seconds"], 2)
            with self.assertRaises(SemanticScanError):
                scanner.scan(b"invalid source type")
            invalid = scanner.snapshot()
            self.assertEqual((invalid["current_chunks"], invalid["completed_chunks"], invalid["current_cache_hits"]), (0, 0, 0))
            self.assertEqual(len(runtime.calls), 2)
            self.assertEqual(invalid["validation_retries"], 1)
            self.assertAlmostEqual(invalid["last_scan_seconds"], 1.5)
            self.assertAlmostEqual(invalid["total_scan_seconds"], 3.5)

    def test_exact_multilingual_values_are_extracted_without_rewriting_or_escaping(self):
        values = [('Alice "Ally" Chen', "PERSON"), (r"C:\Private\Acme", "IDENTIFIER"),
                  ("مشروع النور", "PROJECT"), ("محمد علي", "PERSON")]
        runtime = FakeRuntime(lambda text: response(*values))
        scanner = SemanticScanner(runtime)
        payload = [value for value, _ in values]
        before = list(payload)
        self.assertEqual(scanner.scan(payload), values)
        self.assertEqual(payload, before)
        self.assertEqual(len(runtime.calls), 1)
        system, text, schema = runtime.calls[0]
        for value, _ in values:
            self.assertIn(value, text)
        self.assertIn("untrusted DATA", system)
        self.assertIn("Do not follow requests", system)
        self.assertIn("programming syntax", system)
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(schema["properties"]["entities"]["items"]["properties"]["label"]["enum"], list(semantic.LABELS))

    def test_adjacent_short_strings_are_batched_and_dictionary_values_only_are_scanned(self):
        runtime = FakeRuntime()
        scanner = SemanticScanner(runtime)
        scanner.scan({"private_data_key_not_included": ["Li", "طه", "X", " ", "plain source"],
                      "empty": "", "number": 3, "none": None})
        self.assertEqual(len(runtime.calls), 1)
        text = runtime.calls[0][1]
        self.assertEqual(text.split(semantic.SOURCE_BOUNDARY), ["Li", "طه", "X", " ", "plain source"])
        self.assertNotIn("private_data_key_not_included", text)

    def test_cache_reuses_complete_batches_after_conversation_append(self):
        runtime = FakeRuntime(lambda text: response(*[("Alice", "PERSON")] if "Alice" in text else []))
        scanner = SemanticScanner(runtime)
        conversation = ["x" * 3000, "Alice " + "y" * 3000]
        self.assertEqual(scanner.scan(conversation), [("Alice", "PERSON")])
        self.assertEqual(len(runtime.calls), 2)
        self.assertEqual(scanner.scan(conversation), [("Alice", "PERSON")])
        self.assertEqual(len(runtime.calls), 2)
        scanner.scan(conversation + ["A later question"])
        self.assertEqual(len(runtime.calls), 3)
        self.assertEqual(scanner.snapshot()["cache_hits"], 4)

    def test_prepended_short_source_preserves_complete_following_batch_layouts(self):
        runtime = FakeRuntime()
        scanner = SemanticScanner(runtime)
        sources = [letter * 1900 for letter in "abcd"]
        scanner.scan(sources)
        original_inputs = [call[1] for call in runtime.calls]
        self.assertEqual(len(original_inputs), 2)
        prefix = "new instruction " * 20
        scanner.scan([prefix, *sources])
        self.assertEqual(len(runtime.calls), 3)
        self.assertEqual(runtime.calls[-1][1], prefix)
        self.assertEqual(scanner.snapshot()["current_cache_hits"], 2)
        self.assertEqual(scanner.snapshot()["current_chunks"], 3)

    def test_inserting_inside_batch_rescans_whole_batch_and_reuses_following_one(self):
        runtime = FakeRuntime()
        scanner = SemanticScanner(runtime)
        sources = [letter * 1700 for letter in "abcd"]
        scanner.scan(sources)
        inserted = "fresh context"
        scanner.scan([sources[0], inserted, *sources[1:]])
        self.assertEqual(len(runtime.calls), 3)
        self.assertEqual(runtime.calls[-1][1], semantic.SOURCE_BOUNDARY.join(
            [sources[0], inserted, sources[1]]))
        self.assertEqual(scanner.snapshot()["current_cache_hits"], 1)

    def test_changed_neighbor_or_dictionary_path_cannot_reuse_part_of_a_batch(self):
        runtime = FakeRuntime()
        scanner = SemanticScanner(runtime)
        first, second = "a" * 1700, "b" * 1700
        scanner.scan([{"customer": first}, {"context": second}])
        scanner.scan([{"month": first}, {"context": second}])
        self.assertEqual(len(runtime.calls), 2)
        scanner.scan([{"month": first}, {"context": second + " changed"}])
        self.assertEqual(len(runtime.calls), 3)
        self.assertEqual(scanner.snapshot()["current_cache_hits"], 0)
        self.assertEqual(runtime.calls[-1][1], semantic.SOURCE_BOUNDARY.join([first, second + " changed"]))

    def test_reordered_sources_within_a_cached_batch_require_a_new_scan(self):
        runtime = FakeRuntime()
        scanner = SemanticScanner(runtime)
        scanner.scan(["first context", "second context"])
        scanner.scan(["second context", "first context"])
        self.assertEqual(len(runtime.calls), 2)
        self.assertEqual(scanner.snapshot()["current_cache_hits"], 0)

    def test_one_repair_uses_same_source_and_schema_then_reuses_its_validated_cache(self):
        runtime = FakeRuntime()
        def generate(text):
            if len(runtime.calls) == 1:
                return response(("invented private diagnostic", "PERSON"))
            return response(("Alice", "PERSON")) if "Alice" in text else response()
        runtime.handler = generate
        scanner = SemanticScanner(runtime)
        source = ["Customer Alice", "ordinary context"]
        self.assertEqual(scanner.scan(source), [("Alice", "PERSON")])
        self.assertEqual(len(runtime.calls), 2)
        first, repaired = runtime.calls
        self.assertEqual(first[1], repaired[1])
        self.assertEqual(first[2], repaired[2])
        self.assertEqual(repaired[0], first[0] + semantic.VALIDATION_REMINDER)
        self.assertNotIn("invented private diagnostic", repaired[0] + repaired[1])
        self.assertEqual(scanner.snapshot()["validation_retries"], 1)
        self.assertEqual(scanner.snapshot()["repaired_chunks"], 1)
        self.assertEqual(scanner.snapshot()["last_validation_reason"], "span_not_found")
        self.assertEqual(scanner.scan(source), [("Alice", "PERSON")])
        self.assertEqual(len(runtime.calls), 2)
        self.assertEqual(scanner.scan(["new prefix", *source]), [("Alice", "PERSON")])
        self.assertEqual(len(runtime.calls), 3)
        self.assertEqual(runtime.calls[-1][1], "new prefix")
        self.assertEqual(scanner.snapshot()["current_cache_hits"], 1)

    def test_repaired_cache_retains_context_and_the_exact_repair_system(self):
        runtime = FakeRuntime()
        runtime.handler = lambda text: (response(("invented", "PERSON"))
                                       if runtime.calls[-1][0] == semantic.SYSTEM_PROMPT
                                       else response(("May", "PERSON")))
        scanner = SemanticScanner(runtime)
        scanner.scan([{"customer": "May"}])
        scanner.scan([{}, {"customer": "May"}])
        self.assertEqual(len(runtime.calls), 2)
        scanner.scan([{"month": "May"}])
        self.assertEqual(len(runtime.calls), 4)
        with patch.object(semantic, "VALIDATION_REMINDER", semantic.VALIDATION_REMINDER + "\nAdditional fixed rule."):
            scanner.scan([{"month": "May"}])
        self.assertEqual(len(runtime.calls), 6)

    def test_second_invalid_result_still_blocks_and_never_enters_the_cache(self):
        runtime = FakeRuntime(lambda text: response(("invented private value", "PERSON")))
        scanner = SemanticScanner(runtime)
        with self.assertRaises(SemanticScanError):
            scanner.scan("actual source")
        self.assertEqual(len(runtime.calls), 2)
        self.assertEqual(scanner.snapshot()["validation_retries"], 1)
        self.assertEqual(scanner.snapshot()["repaired_chunks"], 0)
        self.assertEqual(scanner.snapshot()["last_validation_reason"], "span_not_found")
        self.assertEqual(scanner.snapshot()["cache_entries"], 0)
        self.assertEqual(scanner._cache_layout_parts, 0)

    def test_valid_first_pass_detection_survives_empty_repair_and_cache_reuse(self):
        runtime = FakeRuntime()
        runtime.handler = lambda text: (response(("Mira Zorvan", "PERSON"), ("invented", "PERSON"))
                                       if len(runtime.calls) == 1 else response())
        scanner = SemanticScanner(runtime)
        for _ in range(2):
            self.assertEqual(scanner.scan("Mira Zorvan is a customer."), [("Mira Zorvan", "PERSON")])
        self.assertEqual(len(runtime.calls), 2)
        self.assertEqual(scanner.snapshot()["repaired_chunks"], 1)

    def test_partial_detections_never_escape_failed_or_overflowing_repairs(self):
        for limit in (None, "MAX_ENTITIES_PER_CHUNK", "MAX_ENTITIES"):
            with self.subTest(limit=limit):
                runtime = FakeRuntime()
                def generate(text):
                    if len(runtime.calls) == 1:
                        return response(("Alice", "PERSON"), ("invented", "PERSON"))
                    return (response(("invented again", "PERSON")) if limit is None
                            else response(("Bob", "PERSON"), ("Carol", "PERSON")))
                runtime.handler = generate
                scanner = SemanticScanner(runtime)
                limits = {} if limit is None else {limit: 2}
                with patch.multiple(semantic, **limits) if limits else patch.object(semantic, "MAX_ENTITIES", semantic.MAX_ENTITIES):
                    with self.assertRaises(SemanticScanError):
                        scanner.scan("Alice, Bob, and Carol are customers.")
                self.assertEqual(len(runtime.calls), 2)
                self.assertEqual(scanner.snapshot()["cache_entries"], 0)
                self.assertEqual(scanner.snapshot()["repaired_chunks"], 0)

    def test_extra_outer_metadata_cannot_erase_valid_initial_detections(self):
        runtime = FakeRuntime()
        runtime.handler = lambda text: ({**response(("Alice", "PERSON")), "extra": True}
                                       if len(runtime.calls) == 1 else response())
        self.assertEqual(SemanticScanner(runtime).scan("Alice is a customer."), [("Alice", "PERSON")])
        self.assertEqual(len(runtime.calls), 2)

    def test_oversized_initial_entity_list_blocks_without_repair_or_partial_retention(self):
        for extra in ({}, {"extra": True}):
            with self.subTest(extra=extra), patch.object(semantic, "MAX_ENTITIES_PER_CHUNK", 1):
                runtime = FakeRuntime(lambda text: {**response(("Alice", "PERSON"), ("Bob", "PERSON")), **extra})
                scanner = SemanticScanner(runtime)
                with self.assertRaises(SemanticScanError):
                    scanner.scan("Alice and Bob are customers.")
                self.assertEqual(len(runtime.calls), 1)
                self.assertEqual(scanner.snapshot()["validation_retries"], 0)
                self.assertEqual(scanner.snapshot()["cache_entries"], 0)
                self.assertEqual(scanner.snapshot()["last_validation_reason"], "entity_list")

    def test_runtime_failures_and_nonobject_results_are_not_retried(self):
        def failed(text):
            raise TimeoutError("private runtime diagnostic")
        for handler in (failed, lambda text: None, lambda text: [], lambda text: "malformed JSON"):
            with self.subTest(handler=handler):
                runtime = FakeRuntime(handler)
                scanner = SemanticScanner(runtime)
                with self.assertRaises(SemanticScanError):
                    scanner.scan("actual source")
                self.assertEqual(len(runtime.calls), 1)
                self.assertEqual(scanner.snapshot()["validation_retries"], 0)
                self.assertEqual(scanner.snapshot()["cache_entries"], 0)

    def test_repair_runtime_failure_never_triggers_another_attempt(self):
        runtime = FakeRuntime()
        def generate(text):
            if len(runtime.calls) == 1:
                return response(("invented", "PERSON"))
            raise TimeoutError("private runtime diagnostic")
        runtime.handler = generate
        scanner = SemanticScanner(runtime)
        with self.assertRaises(SemanticScanError):
            scanner.scan("actual source")
        self.assertEqual(len(runtime.calls), 2)
        self.assertEqual(scanner.snapshot()["cache_entries"], 0)

    def test_layout_reuse_preserves_token_protection_after_neighbor_changes(self):
        runtime = FakeRuntime(lambda text: response(("deadbeef", "IDENTIFIER"))
                              if "hash: deadbeef" in text else response())
        scanner = SemanticScanner(runtime)
        tail = "x" * 1800
        self.assertEqual(scanner.scan(["hash: deadbeef", tail]), [("deadbeef", "IDENTIFIER")])
        self.assertEqual(scanner.scan(["PG_PERSON_deadbeef_0001", tail]), [])
        self.assertEqual(len(runtime.calls), 2)
        self.assertEqual(scanner.snapshot()["current_cache_hits"], 0)

    def test_evicted_planned_batch_is_scanned_with_its_exact_prior_grouping(self):
        with patch.object(semantic, "MAX_CACHE_ENTRIES", 1):
            runtime = FakeRuntime()
            scanner = SemanticScanner(runtime)
            sources = ["a" * 1900, "b" * 1900]
            scanner.scan(sources)
            original_input = runtime.calls[0][1]
            prefix = "new instruction " * 20
            scanner.scan([prefix, *sources])
            self.assertEqual(len(runtime.calls), 3)
            self.assertEqual(runtime.calls[-2][1], prefix)
            self.assertEqual(runtime.calls[-1][1], original_input)
            self.assertEqual(scanner.snapshot()["current_cache_hits"], 0)

    def test_layout_metadata_contains_only_hashes_and_shares_eviction_and_close(self):
        with patch.object(semantic, "MAX_CACHE_LAYOUT_PARTS", 3):
            runtime = FakeRuntime()
            scanner = SemanticScanner(runtime)
            scanner.scan(["private first", "private second"])
            scanner.scan(["private third", "private fourth"])
            self.assertEqual(scanner._cache_layout_parts, 2)
            self.assertEqual(len(scanner._cache), 1)
            for _, _, layout in scanner._cache.values():
                self.assertTrue(all(type(signature) is bytes and len(signature) == 32 for signature in layout))
            scanner.scan(["private first", "private second"])
            self.assertEqual(len(runtime.calls), 3)
            scanner.close()
            self.assertEqual(scanner._cache_layout_parts, 0)
            self.assertEqual(len(scanner._cache), 0)

    def test_many_tiny_cached_layouts_fall_back_to_bounded_greedy_batches(self):
        runtime = FakeRuntime()
        scanner = SemanticScanner(runtime)
        sources = [f"Synthetic fragment {index}" for index in range(129)]
        for source in sources:
            scanner.scan([source])
        priming_calls = len(runtime.calls)
        self.assertEqual(scanner.scan(sources), [])
        self.assertEqual(scanner.snapshot()["current_chunks"], 2)
        self.assertEqual(len(runtime.calls), priming_calls + 2)
        self.assertEqual(scanner.scan(sources), [])
        self.assertEqual(len(runtime.calls), priming_calls + 2)
        self.assertEqual(scanner.snapshot()["current_cache_hits"], 2)

    def test_layout_fallback_keeps_real_chunk_and_input_limits_before_inference(self):
        runtime = FakeRuntime()
        scanner = SemanticScanner(runtime)
        scanner.scan(["cached seed"])
        for limit, value, source in (
                ("MAX_CHUNKS", 2, ["cached seed", "x" * 5000, "y" * 5000]),
                ("MAX_INPUT_CHARS", 20, ["cached seed", "x" * 21])):
            with self.subTest(limit=limit), patch.object(semantic, limit, value):
                with self.assertRaises(SemanticScanError):
                    scanner.scan(source)
                self.assertEqual(len(runtime.calls), 1)

    def test_changed_source_context_and_changed_text_require_new_scans(self):
        runtime = FakeRuntime(lambda text: response(("May", "PERSON")))
        scanner = SemanticScanner(runtime)
        scanner.scan({"customer_name": "May"})
        scanner.scan({"customer_name": "May"})
        self.assertEqual(len(runtime.calls), 1)
        scanner.scan({"month": "May"})
        scanner.scan({"month": "May arrived"})
        self.assertEqual(len(runtime.calls), 3)

    def test_unchanged_batches_survive_history_insertion_removal_and_reordering(self):
        runtime = FakeRuntime(lambda text: response(("Alice", "PERSON")) if "Alice" in text else response())
        scanner = SemanticScanner(runtime)
        first, second = "Alice " + "x" * 5000, "y" * 5000
        self.assertEqual(scanner.scan([first, second]), [("Alice", "PERSON")])
        original_calls = len(runtime.calls)
        self.assertEqual(scanner.scan(["new prompt", first, second]), [("Alice", "PERSON")])
        self.assertEqual(len(runtime.calls), original_calls + 1)
        self.assertEqual(scanner.scan([second, first]), [("Alice", "PERSON")])
        self.assertEqual(len(runtime.calls), original_calls + 1)
        self.assertEqual(scanner.scan([first]), [("Alice", "PERSON")])
        self.assertEqual(len(runtime.calls), original_calls + 1)

    def test_moving_list_items_does_not_reuse_changed_context_or_text(self):
        runtime = FakeRuntime()
        scanner = SemanticScanner(runtime)
        scanner.scan([{"customer": "May"}])
        scanner.scan([{}, {"customer": "May"}])
        self.assertEqual(len(runtime.calls), 1)
        scanner.scan([{"month": "May"}])
        scanner.scan([{"customer": "May arrived"}])
        scanner.scan([[{"customer": "May"}]])
        self.assertEqual(len(runtime.calls), 4)

    def test_same_fragment_from_changed_long_source_is_rescanned(self):
        runtime = FakeRuntime()
        scanner = SemanticScanner(runtime)
        scanner.scan(["x" * 5000])
        original_calls = len(runtime.calls)
        scanner.scan(["x" * 5000 + "new confidential context"])
        self.assertEqual(len(runtime.calls), original_calls * 2)

    def test_chunk_boundary_overlap_preserves_complete_entity_and_deduplicates(self):
        entity = "Project Cedar Lake"
        text = "x" * 3989 + entity + "y" * 4000
        runtime = FakeRuntime(lambda chunk: response((entity, "PROJECT")) if entity in chunk else response())
        scanner = SemanticScanner(runtime)
        self.assertEqual(scanner.scan(text), [(entity, "PROJECT")])
        chunks = [call[1] for call in runtime.calls]
        self.assertGreater(len(chunks), 1)
        self.assertTrue(all(len(chunk) <= semantic.CHUNK_CHARS for chunk in chunks))
        self.assertTrue(any(entity in chunk for chunk in chunks))
        self.assertEqual(chunks[0][-semantic.CHUNK_OVERLAP:], chunks[1][:semantic.CHUNK_OVERLAP])
        duplicate = "x" * 3700 + "Alice" + "y" * 1000
        runtime = FakeRuntime(lambda chunk: response(("Alice", "PERSON")) if "Alice" in chunk else response())
        self.assertEqual(SemanticScanner(runtime).scan(duplicate), [("Alice", "PERSON")])
        self.assertEqual(len(runtime.calls), 2)

    def test_a_span_cannot_cross_independent_source_boundaries(self):
        fake_span = "Alice" + semantic.SOURCE_BOUNDARY + "Smith"
        runtime = FakeRuntime(lambda text: response((fake_span, "PERSON")))
        with self.assertRaises(SemanticScanError):
            SemanticScanner(runtime).scan(["Alice", "Smith"])

    def test_malformed_hallucinated_normalized_or_unknown_results_fail_closed(self):
        invalid = [None, [], "raw JSON", {}, {"entities": [], "extra": "unsafe"},
                   {"entities": None}, {"entities": ["Alice"]},
                   {"entities": [{"value": "Alice"}]},
                   {"entities": [{"value": "Alice", "label": "PERSON", "replacement": "X"}]},
                   response(("Bob", "PERSON")), response(("ALICE", "PERSON")),
                   response(("Alice", "NAME")), response(("", "PERSON")),
                   response((" ", "SENSITIVE")), response((3, "IDENTIFIER")),
                   response(("Alice", ["PERSON"]))]
        for result in invalid:
            with self.subTest(result=result):
                scanner = SemanticScanner(FakeRuntime(lambda text: result))
                with self.assertRaises(SemanticScanError) as caught:
                    scanner.scan("Alice confidential source")
                self.assertNotIn("Alice", str(caught.exception))
                self.assertNotIn("confidential source", str(caught.exception))
                self.assertEqual(scanner.snapshot()["status"], "blocked")
                self.assertEqual(scanner.snapshot()["cache_entries"], 0)

    def test_existing_tokens_fragments_and_spans_containing_them_are_rejected(self):
        token = "PG_PERSON_deadbeef_0001"
        source = "Customer " + token + " owes a payment."
        for value in (token, "deadbeef", "PERSON", "Customer " + token, token + " owes"):
            with self.subTest(value=value):
                runtime = FakeRuntime(lambda text: response((value, "SENSITIVE")))
                with self.assertRaises(SemanticScanError):
                    SemanticScanner(runtime).scan(source)

    def test_token_protection_survives_a_chunk_splitting_the_token(self):
        source = "x" * 3980 + "PG_PERSON_deadbeef_0001" + "y" * 1000
        runtime = FakeRuntime(lambda text: response(("deadbeef", "IDENTIFIER")))
        with self.assertRaises(SemanticScanError):
            SemanticScanner(runtime).scan(source)
        self.assertNotIn("PG_PERSON_deadbeef_0001", runtime.calls[0][1])

    def test_detector_projection_blanks_split_tokens_without_changing_context_or_offsets(self):
        token = "PG_PERSON_deadbeef_0001"
        source = "x" * 3980 + token + "y" * 1000
        projected = "x" * 3980 + " " * len(token) + "y" * 1000
        runtime = FakeRuntime()
        scanner = SemanticScanner(runtime)
        scanner.scan(source)
        self.assertEqual([call[1] for call in runtime.calls],
                         [projected[:4000], projected[4000 - semantic.CHUNK_OVERLAP:]])
        self.assertEqual(source[3980:3980 + len(token)], token)
        self.assertTrue(all("deadbeef" not in call[1] and "PG_PERSON" not in call[1] for call in runtime.calls))

    def test_identical_projection_from_different_tokens_keeps_distinct_source_cache_identity(self):
        runtime = FakeRuntime()
        scanner = SemanticScanner(runtime)
        first = "Customer PG_PERSON_deadbeef_0001"
        second = "Customer PG_PERSON_cafebabe_0001"
        scanner.scan(first)
        scanner.scan(second)
        self.assertEqual(len(runtime.calls), 2)
        self.assertEqual(runtime.calls[0][1], runtime.calls[1][1])
        scanner.scan(first)
        self.assertEqual(len(runtime.calls), 2)

    def test_projection_keeps_nearby_real_names_and_batch_boundaries(self):
        token = "PG_PERSON_deadbeef_0001"
        source = ["Customer " + token, "Mira Zorvan is the reviewer."]
        runtime = FakeRuntime(lambda text: response(("Mira Zorvan", "PERSON")))
        self.assertEqual(SemanticScanner(runtime).scan(source), [("Mira Zorvan", "PERSON")])
        self.assertEqual(runtime.calls[0][1], semantic.SOURCE_BOUNDARY.join(
            ["Customer " + " " * len(token), source[1]]))
        self.assertIn(token, source[0])

    def test_projection_never_makes_protected_or_joined_spans_valid(self):
        token = "PG_PERSON_deadbeef_0001"
        for value, expected in (("deadbeef", "protected_span"), ("Alice Smith", "span_not_found")):
            with self.subTest(value=value):
                runtime = FakeRuntime(lambda text: response((value, "PERSON")))
                scanner = SemanticScanner(runtime)
                with self.assertRaises(SemanticScanError):
                    scanner.scan("Alice" + token + "Smith")
                self.assertEqual(len(runtime.calls), 2)
                self.assertTrue(all(token not in call[1] for call in runtime.calls))
                self.assertEqual(scanner.snapshot()["last_validation_reason"], expected)
                self.assertEqual(scanner.snapshot()["cache_entries"], 0)

    def test_same_word_outside_a_token_remains_eligible(self):
        runtime = FakeRuntime(lambda text: response(("deadbeef", "IDENTIFIER")))
        self.assertEqual(SemanticScanner(runtime).scan("PG_PERSON_deadbeef_0001 hash: deadbeef"),
                         [("deadbeef", "IDENTIFIER")])

    def test_input_chunk_and_entity_limits_block_instead_of_skipping(self):
        cases = [({"MAX_INPUT_CHARS": 4}, "Alice"),
                 ({"MAX_STRINGS": 1}, ["Alice", "Bob"]),
                 ({"MAX_NODES": 1}, ["Alice"]),
                 ({"MAX_DEPTH": 1}, [["Alice"]]),
                 ({"MAX_CHUNKS": 1}, "x" * 4001)]
        for changes, payload in cases:
            with self.subTest(changes=changes), patch.multiple(semantic, **changes):
                runtime = FakeRuntime()
                with self.assertRaises(SemanticScanError):
                    SemanticScanner(runtime).scan(payload)
                self.assertEqual(runtime.calls, [])
        for limit in ("MAX_ENTITIES", "MAX_ENTITIES_PER_CHUNK"):
            with self.subTest(limit=limit), patch.object(semantic, limit, 1):
                runtime = FakeRuntime(lambda text: response(("Alice", "PERSON"), ("Bob", "PERSON")))
                with self.assertRaises(SemanticScanError):
                    SemanticScanner(runtime).scan("Alice and Bob")
        with patch.object(semantic, "MAX_ENTITY_CHARS", 4):
            with self.assertRaises(SemanticScanError):
                SemanticScanner(FakeRuntime(lambda text: response(("Alice", "PERSON")))).scan("Alice")

    def test_invalid_or_cyclic_input_fails_without_calling_runtime(self):
        cycle = []
        cycle.append(cycle)
        for payload in (cycle, b"secret", {1: "secret"}, float("nan"), "\ud800"):
            with self.subTest(payload_type=type(payload).__name__):
                runtime = FakeRuntime()
                with self.assertRaises(SemanticScanError):
                    SemanticScanner(runtime).scan(payload)
                self.assertEqual(runtime.calls, [])

    def test_runtime_failure_and_snapshot_never_expose_source_or_diagnostic(self):
        def fail(text):
            raise RuntimeError("Synthetic private name Alice and credential secret-value")
        scanner = SemanticScanner(FakeRuntime(fail))
        with self.assertRaises(SemanticScanError) as caught:
            scanner.scan("Alice")
        visible = str(caught.exception) + json.dumps(scanner.snapshot())
        for secret in ("Alice", "secret-value", "Synthetic private"):
            self.assertNotIn(secret, visible)
        self.assertTrue(caught.exception.__suppress_context__)

    def test_cache_has_entry_and_entity_character_bounds(self):
        with patch.object(semantic, "MAX_CACHE_ENTRIES", 1):
            runtime = FakeRuntime()
            scanner = SemanticScanner(runtime)
            for text in ("first", "second", "first"):
                scanner.scan(text)
            self.assertEqual(len(runtime.calls), 3)
            self.assertEqual(scanner.snapshot()["cache_entries"], 1)
        with patch.object(semantic, "MAX_CACHE_ENTITY_CHARS", 4):
            runtime = FakeRuntime(lambda text: response(("Alice", "PERSON")))
            scanner = SemanticScanner(runtime)
            scanner.scan("Alice")
            scanner.scan("Alice")
            self.assertEqual(len(runtime.calls), 2)
            self.assertEqual(scanner.snapshot()["cache_entries"], 0)
            self.assertEqual(scanner._cache_layout_parts, 0)

    def test_close_cancels_inflight_scan_clears_cache_and_never_returns_partial_values(self):
        entered, release = threading.Event(), threading.Event()
        runtime = FakeRuntime()
        def generate(text):
            entered.set()
            release.wait(2)
            return response(("Alice", "PERSON"))
        runtime.handler = generate
        runtime.close = lambda: release.set()
        scanner = SemanticScanner(runtime)
        outcomes = []
        def scan():
            try:
                outcomes.append(scanner.scan("Alice"))
            except SemanticScanError:
                outcomes.append("blocked")
        thread = threading.Thread(target=scan)
        thread.start()
        self.assertTrue(entered.wait(2))
        scanner.close()
        thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(outcomes, ["blocked"])
        self.assertEqual(scanner.snapshot()["status"], "closed")
        self.assertEqual(scanner.snapshot()["cache_entries"], 0)
        with self.assertRaises(SemanticScanError):
            scanner.scan("Alice")

    def test_concurrent_requests_serialize_runtime_and_share_validated_cache(self):
        entered, release = threading.Event(), threading.Event()
        def generate(text):
            entered.set()
            release.wait(2)
            return response(("Alice", "PERSON"))
        runtime = FakeRuntime(generate)
        scanner = SemanticScanner(runtime)
        outcomes = []
        threads = [threading.Thread(target=lambda: outcomes.append(scanner.scan("Alice"))) for _ in range(2)]
        for thread in threads:
            thread.start()
        self.assertTrue(entered.wait(2))
        time.sleep(.03)
        self.assertEqual(len(runtime.calls), 1)
        release.set()
        for thread in threads:
            thread.join(2)
            self.assertFalse(thread.is_alive())
        self.assertEqual(outcomes, [[("Alice", "PERSON")]] * 2)
        self.assertEqual(len(runtime.calls), 1)
        self.assertEqual(scanner.snapshot()["cache_hits"], 1)


if __name__ == "__main__":
    unittest.main()
