"""Test the event parser independently of future detection and correlation."""

import copy
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from triage.parser import DATA_DIRECTORY, ParseError, load_events, main, parse_dataset


class ParserTests(unittest.TestCase):
    def setUp(self):
        self.dataset = json.loads((DATA_DIRECTORY / "suspicious" / "events.json").read_text())

    def test_suspicious_fixture_is_sorted_and_deduplicated_with_provenance(self):
        result = parse_dataset(self.dataset)
        self.assertEqual((result["inputRecordCount"], result["uniqueEventCount"], result["duplicateRecordCount"]), (7, 6, 1))
        ids = [item["record"]["eventId"] for item in result["events"]]
        self.assertEqual(ids, [f"suspicious-{n:03}" for n in (1, 2, 3, 4, 6, 5)])
        self.assertEqual(result["events"][-1]["sourceRecordIndices"], [0, 5])

    def test_authorized_fixture_has_three_unique_events(self):
        result = load_events(DATA_DIRECTORY / "authorized" / "events.json")
        self.assertEqual(result["datasetId"], "demo-authorized")
        self.assertEqual(result["uniqueEventCount"], 3)
        self.assertEqual(result["duplicateRecordCount"], 0)

    def test_offsets_are_normalized_without_overwriting_original_time(self):
        self.dataset["events"] = [copy.deepcopy(self.dataset["events"][0])]
        self.dataset["events"][0]["occurredAt"] = "2026-11-17T02:00:00-07:00"
        item = parse_dataset(self.dataset)["events"][0]
        self.assertEqual(item["occurredAtUtc"], "2026-11-17T09:00:00Z")
        self.assertEqual(item["record"]["occurredAt"], "2026-11-17T02:00:00-07:00")

    def test_equal_instants_use_id_tiebreak_not_input_order(self):
        first = copy.deepcopy(self.dataset["events"][0])
        second = copy.deepcopy(first)
        first["eventId"] = "b"
        second["eventId"] = "a"
        second["occurredAt"] = "2026-11-17T02:00:00-07:00"
        self.dataset["events"] = [first, second]
        result = parse_dataset(self.dataset)
        self.assertEqual([r["record"]["eventId"] for r in result["events"]], ["a", "b"])

    def test_conflicting_duplicate_ids_reject_the_dataset(self):
        self.dataset["events"][5]["recipient"] = "user:someone.else@example.com"
        with self.assertRaisesRegex(ParseError, "Conflicting"):
            parse_dataset(self.dataset)

    def test_object_key_order_does_not_create_a_conflict(self):
        self.dataset["events"][5] = dict(reversed(list(self.dataset["events"][5].items())))
        self.assertEqual(parse_dataset(self.dataset)["duplicateRecordCount"], 1)

    def test_changed_extra_values_are_not_silently_deduplicated(self):
        self.dataset["events"][0]["extra"] = True
        self.dataset["events"][5]["extra"] = 1
        with self.assertRaisesRegex(ParseError, "Conflicting"):
            parse_dataset(self.dataset)

    def test_missing_common_and_iam_fields_are_rejected_with_record_index(self):
        for field in ("eventId", "eventType", "occurredAt", "actor", "sourceIp", "outcome", "resource", "changeAction", "role", "recipient"):
            dataset = copy.deepcopy(self.dataset)
            del dataset["events"][0][field]
            with self.subTest(field=field):
                with self.assertRaisesRegex(ParseError, "Record index 0"):
                    parse_dataset(dataset)

    def test_invalid_or_timezone_free_timestamps_are_rejected(self):
        for stamp in (None, "bad", "2026-11-17T09:00:00", "2026-02-30T09:00:00Z", "2026-11-17", "2026-11-17T09:00:00.1234567Z"):
            dataset = copy.deepcopy(self.dataset)
            dataset["events"][0]["occurredAt"] = stamp
            with self.subTest(stamp=stamp):
                with self.assertRaises(ParseError):
                    parse_dataset(dataset)

    def test_invalid_ips_text_types_and_event_enums_are_rejected(self):
        for field, value in (("sourceIp", "999.1.1.1"), ("actor", None), ("actor", " "),
                             ("actor", "user\n@example.com"), ("actor", " user@example.com"),
                             ("eventType", "unknown"), ("outcome", True), ("changeAction", "GRANT")):
            dataset = copy.deepcopy(self.dataset)
            dataset["events"][0][field] = value
            with self.subTest(field=field, value=value):
                with self.assertRaises(ParseError):
                    parse_dataset(dataset)

    def test_ipv6_is_validated_and_normalized(self):
        self.dataset["events"] = [copy.deepcopy(self.dataset["events"][0])]
        self.dataset["events"][0]["sourceIp"] = "2001:0db8:0000::1"
        item = parse_dataset(self.dataset)["events"][0]
        self.assertEqual(item["sourceIpNormalized"], "2001:db8::1")
        self.assertEqual(item["record"]["sourceIp"], "2001:0db8:0000::1")

    def test_failed_operations_removes_and_other_roles_remain_in_timeline(self):
        self.dataset["events"] = [copy.deepcopy(self.dataset["events"][0])]
        event = self.dataset["events"][0]
        event.update(outcome="failure", changeAction="REMOVE", role="roles/viewer")
        self.assertEqual(parse_dataset(self.dataset)["uniqueEventCount"], 1)

    def test_envelope_and_record_types_are_checked(self):
        for dataset in ([], {}, {"schemaVersion": "999", "fictional": True},
                        dict(self.dataset, fictional="true"), dict(self.dataset, events={}),
                        dict(self.dataset, events=["not an object"])):
            with self.subTest(dataset_type=type(dataset).__name__):
                with self.assertRaises(ParseError):
                    parse_dataset(dataset)

    def test_input_and_returned_raw_records_do_not_share_mutable_objects(self):
        before = copy.deepcopy(self.dataset)
        result = parse_dataset(self.dataset)
        self.assertEqual(self.dataset, before)
        result["events"][0]["record"]["actor"] = "changed@example.com"
        self.assertEqual(self.dataset, before)

    def test_file_loading_rejects_ambiguous_or_invalid_json(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.json"
            for raw in (b"not JSON", b"\xff", b'{"events": [], "events": []}', b'{"value": NaN}'):
                path.write_bytes(raw)
                with self.subTest(raw=raw):
                    with self.assertRaises(ParseError):
                        load_events(path)
            with self.assertRaises(ParseError):
                load_events(Path(directory) / "missing.json")

    def test_cli_prints_expected_counts_and_failure_exit(self):
        with patch("sys.argv", ["parser", "--scenario", "suspicious"]):
            output = io.StringIO()
            with redirect_stdout(output):
                main()
            self.assertIn("Unique events: 6", output.getvalue())
            self.assertIn("Exact duplicates removed: 1", output.getvalue())
            self.assertIn("No threat detection", output.getvalue())
        with patch("sys.argv", ["parser", "--file", "missing-events.json"]):
            with patch("sys.stderr", new_callable=io.StringIO):
                with self.assertRaises(SystemExit) as raised:
                    main()
            self.assertEqual(raised.exception.code, 1)

    def test_empty_event_list_is_not_interpreted_as_a_clean_environment(self):
        self.dataset["events"] = []
        with patch("sys.argv", ["parser"]):
            with patch("triage.parser.load_events", return_value=parse_dataset(self.dataset)):
                output = io.StringIO()
                with redirect_stdout(output):
                    main()
                self.assertIn("does not establish that no activity occurred", output.getvalue())


if __name__ == "__main__":
    unittest.main()
