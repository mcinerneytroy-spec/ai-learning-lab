"""Verify evidence retention, CSV accuracy, and failed-run behavior."""

import base64
import copy
import csv
import hashlib
import io
import json
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

from monitor.client import CollectionError, fetch_snapshot
from monitor.collect import main, run_collection
from monitor.mock_server import DATA_DIRECTORY, create_server
from monitor.reporting import csv_rows, safe_csv_cell, write_csv


class ReportingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = create_server(port=0)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.thread.join(timeout=5)
        cls.server.server_close()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.output = Path(self.temporary.name)

    def collect(self, day=2):
        return run_collection(day=day, port=self.server.server_port, output_directory=self.output)

    def test_http_run_saves_all_controls_and_exact_response_bytes(self):
        directory, evidence = self.collect()
        self.assertEqual(evidence["runStatus"], "COMPLETED")
        self.assertEqual(len(evidence["controls"]), 3)
        self.assertEqual(len(evidence["sources"]), 2)
        saved = json.loads((directory / "evidence.json").read_text())
        self.assertEqual(saved, evidence)
        for record in saved["sources"]:
            raw = base64.b64decode(record["rawBodyBase64"], validate=True)
            self.assertEqual(hashlib.sha256(raw).hexdigest(), record["rawBodySha256"])
            self.assertEqual(json.loads(raw), record["snapshot"])
            self.assertEqual(record["validationStatus"], "VALIDATED")
            self.assertFalse(record["bodyTruncated"])
            self.assertEqual(record["httpStatus"], 200)
            self.assertEqual(record["method"], "GET")
        self.assertLessEqual(datetime.fromisoformat(saved["collectionStartedAt"]),
                             datetime.fromisoformat(saved["collectionCompletedAt"]))
        self.assertEqual(saved["controls"][0]["sourceObservedAt"], "2026-11-16T12:00:00Z")

    def test_csv_contains_findings_control_summaries_and_grant_attribution(self):
        directory, evidence = self.collect()
        with (directory / "controls.csv").open(newline="") as file:
            rows = list(csv.DictReader(file))
        summaries = [r for r in rows if r["recordType"] == "CONTROL_SUMMARY"]
        findings = [r for r in rows if r["recordType"] == "OBSERVATION"]
        self.assertEqual(len(summaries), 3)
        self.assertEqual(len(findings), 7)
        self.assertEqual({r["runId"] for r in rows}, {evidence["runId"]})
        self.assertEqual({r["runStatus"] for r in rows}, {"COMPLETED"})
        self.assertEqual([r["status"] for r in summaries], ["FAIL", "REVIEW", "FAIL"])
        grant = next(r for r in findings if r["controlId"] == "NEW_ADMINISTRATORS")
        self.assertEqual(grant["actor"], "user:casey.rivera@example.com")
        self.assertEqual(grant["eventTime"], "2026-11-16T09:00:00Z")
        self.assertEqual(grant["eventId"], "fictional-event-001")
        for row in findings:
            self.assertTrue(row["evidencePointer"].startswith("evidence.json#/controls/"))
            if row["controlId"] != "NEW_ADMINISTRATORS":
                self.assertEqual(row["actor"], "UNKNOWN")
                self.assertEqual(row["eventTime"], "UNKNOWN")

    def test_baseline_does_not_require_previous_snapshot(self):
        _, evidence = self.collect(day=1)
        self.assertEqual(len(evidence["sources"]), 1)
        self.assertEqual(evidence["controls"][1]["comparisonStatus"], "BASELINE")

    def test_repeated_runs_do_not_overwrite_each_other(self):
        first_dir, first = self.collect(day=1)
        second_dir, second = self.collect(day=1)
        self.assertNotEqual(first_dir, second_dir)
        self.assertNotEqual(first["runId"], second["runId"])
        self.assertTrue((first_dir / "evidence.json").exists())

    def test_collection_failure_is_saved_and_controls_not_marked_pass(self):
        with patch("monitor.collect.fetch_snapshot", side_effect=CollectionError("Server stopped")):
            directory, evidence = self.collect()
        self.assertEqual(evidence["runStatus"], "FAILED")
        self.assertEqual(evidence["sources"][0]["validationStatus"], "FAILED")
        self.assertEqual(json.loads((directory / "evidence.json").read_text())["error"], "Server stopped")
        self.assertEqual([r["status"] for r in csv_rows(evidence)], ["NOT_EVALUATED"] * 3)

    def test_failed_baseline_fetch_keeps_successfully_collected_current_source(self):
        real_fetch = fetch_snapshot
        def fetch(day, **kwargs):
            if day == 1:
                raise CollectionError("Previous source unavailable")
            return real_fetch(day=day, **kwargs)
        with patch("monitor.collect.fetch_snapshot", side_effect=fetch):
            _, evidence = self.collect()
        self.assertEqual(evidence["runStatus"], "FAILED")
        self.assertIn("rawBodyBase64", evidence["sources"][0])
        self.assertEqual(len(evidence["sources"]), 2)
        self.assertEqual(evidence["controls"], [])

    def test_evaluation_failure_retains_partial_results_and_sources(self):
        with patch("monitor.collect.evaluate_new_admins", side_effect=ValueError("Bad event history")):
            _, evidence = self.collect()
        self.assertEqual(evidence["runStatus"], "FAILED")
        self.assertEqual(len(evidence["sources"]), 2)
        self.assertEqual(len(evidence["controls"]), 1)
        summaries = [r for r in csv_rows(evidence) if r["recordType"] == "CONTROL_SUMMARY"]
        self.assertEqual([r["status"] for r in summaries], ["FAIL", "NOT_EVALUATED", "NOT_EVALUATED"])

    def test_raw_invalid_response_is_retained_before_validation(self):
        from tests.test_client import FakeResponse
        capture = {}
        with patch("monitor.client.build_opener") as opener:
            response = FakeResponse(b"not JSON")
            response.code = 200
            opener.return_value.open.return_value = response
            with self.assertRaises(CollectionError):
                fetch_snapshot(capture=capture)
        self.assertEqual(base64.b64decode(capture["rawBodyBase64"]), b"not JSON")
        self.assertEqual(capture["validationStatus"], "NOT_VALIDATED")

    def test_http_error_body_is_retained(self):
        from urllib.error import HTTPError
        from email.message import Message
        capture = {}
        with patch("monitor.client.build_opener") as opener:
            opener.return_value.open.side_effect = HTTPError(
                "http://127.0.0.1", 500, "Error", Message(), io.BytesIO(b'{"error":"demo"}'))
            with self.assertRaises(CollectionError):
                fetch_snapshot(capture=capture)
        self.assertEqual(capture["httpStatus"], 500)
        self.assertEqual(base64.b64decode(capture["rawBodyBase64"]), b'{"error":"demo"}')

    def test_declared_length_mismatch_is_not_accepted_as_complete_delivery(self):
        from tests.test_client import FakeResponse
        with patch("monitor.client.build_opener") as opener:
            response = FakeResponse(b"{}")
            response.headers["Content-Length"] = "200"
            opener.return_value.open.return_value = response
            with self.assertRaisesRegex(CollectionError, "declared length"):
                fetch_snapshot()

    def test_csv_neutralizes_formulas_and_quotes_commas_and_newlines(self):
        for value in ("=1+1", "+SUM(A1)", "-1", "@formula", "  =2", "\tformula"):
            self.assertTrue(safe_csv_cell(value).startswith("'"))
        directory, evidence = self.collect(day=1)
        evidence["controls"][0]["results"][0]["principal"] = '=HYPERLINK("demo")'
        reason = "A reason, with a comma\nand another line"
        evidence["controls"][0]["results"][0]["reason"] = reason
        original = copy.deepcopy(evidence)
        write_csv(directory, evidence)
        with (directory / "controls.csv").open(newline="") as file:
            rows = list(csv.DictReader(file))
        self.assertEqual(rows[1]["subject"], "'" + evidence["controls"][0]["results"][0]["principal"])
        self.assertEqual(rows[1]["reason"], reason)
        self.assertEqual(evidence, original)

    def test_coverage_gaps_and_exclusions_are_not_lost_from_csv(self):
        _, evidence = self.collect(day=1)
        evidence["controls"][2]["coverageGaps"] = ["Inventory gap"]
        evidence["controls"][2]["excludedDeviceIds"] = ["excluded-device"]
        evidence["controls"][2]["unmatchedEdrDeviceIds"] = ["orphan-device"]
        rows = list(csv_rows(evidence))
        self.assertIn("COVERAGE_GAP", {r["recordType"] for r in rows})
        self.assertIn("EXCLUSION", {r["recordType"] for r in rows})
        self.assertIn("UNMATCHED", {r["recordType"] for r in rows})

    def test_cli_returns_failure_status_for_failed_run(self):
        with patch("sys.argv", ["collect", "--output-dir", str(self.output)]):
            with patch("monitor.collect.fetch_snapshot", side_effect=CollectionError("Server stopped")):
                with patch("sys.stderr", new_callable=io.StringIO):
                    with redirect_stdout(io.StringIO()):
                        with self.assertRaises(SystemExit) as raised:
                            main()
        self.assertEqual(raised.exception.code, 1)
        self.assertEqual(len(list(self.output.glob("*/evidence.json"))), 1)

    def test_csv_write_failure_marks_retained_json_as_failed(self):
        with patch("monitor.collect.write_csv", side_effect=OSError("Disk write failed")):
            with self.assertRaises(OSError):
                self.collect(day=1)
        files = list(self.output.glob("*/evidence.json"))
        self.assertEqual(len(files), 1)
        saved = json.loads(files[0].read_text())
        self.assertEqual(saved["runStatus"], "FAILED")
        self.assertIn("CSV report could not be saved", saved["error"])
        self.assertEqual(len(saved["controls"]), 3)


if __name__ == "__main__":
    unittest.main()
