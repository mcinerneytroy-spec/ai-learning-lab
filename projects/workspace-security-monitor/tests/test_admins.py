"""Test baseline handling, grant detection, attribution, and coverage gaps."""

import copy
import io
import json
import threading
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from monitor.admin_control import evaluate_new_admins
from monitor.check_admins import main
from monitor.client import CollectionError
from monitor.mock_server import create_server


SCENARIOS = Path(__file__).resolve().parent.parent / "data" / "scenarios"


class AdministratorTests(unittest.TestCase):
    def setUp(self):
        self.first = json.loads((SCENARIOS / "day_1.json").read_text())
        self.second = json.loads((SCENARIOS / "day_2.json").read_text())

    def test_first_collection_is_baseline_not_a_new_grant(self):
        report = evaluate_new_admins(self.first)
        self.assertEqual(report["comparisonStatus"], "BASELINE")
        self.assertEqual(len(report["results"]), 1)
        row = report["results"][0]
        self.assertEqual(row["principal"], "user:casey.rivera@example.com")
        self.assertEqual(row["status"], "BASELINE")
        self.assertEqual(row["grantEvents"], [])
        self.assertIsNone(row["newSincePreviousSnapshot"])

    def test_new_grant_identifies_recipient_actor_role_and_event_time(self):
        report = evaluate_new_admins(self.second, self.first)
        self.assertEqual(report["comparisonStatus"], "REVIEW")
        self.assertEqual(report["coverageGaps"], [])
        self.assertEqual(len(report["results"]), 1)
        row = report["results"][0]
        self.assertEqual(row["principal"], "user:blair.chen@example.com")
        self.assertEqual(row["role"], "roles/iam.securityAdmin")
        self.assertIs(row["newSincePreviousSnapshot"], True)
        self.assertEqual(row["grantEvents"][0]["actor"], "user:casey.rivera@example.com")
        self.assertEqual(row["grantEvents"][0]["eventTime"], "2026-11-16T09:00:00Z")

    def test_missing_event_keeps_new_assignment_but_does_not_invent_attribution(self):
        self.second["adminEvents"] = []
        report = evaluate_new_admins(self.second, self.first)
        self.assertEqual(report["comparisonStatus"], "UNKNOWN")
        self.assertEqual(report["results"][0]["status"], "REVIEW")
        self.assertEqual(report["results"][0]["grantEvents"], [])
        self.assertTrue(report["coverageGaps"])

    def test_missing_actor_does_not_hide_an_observed_grant(self):
        del self.second["adminEvents"][0]["actor"]
        report = evaluate_new_admins(self.second, self.first)
        self.assertIsNone(report["results"][0]["grantEvents"][0]["actor"])
        self.assertEqual(report["comparisonStatus"], "UNKNOWN")

    def test_event_detects_access_granted_and_removed_between_snapshots(self):
        self.second["iamPolicy"] = copy.deepcopy(self.first["iamPolicy"])
        report = evaluate_new_admins(self.second, self.first)
        row = report["results"][0]
        self.assertEqual(row["status"], "REVIEW")
        self.assertIs(row["presentInCurrentSnapshot"], False)
        self.assertIs(row["newSincePreviousSnapshot"], False)
        self.assertEqual(len(row["grantEvents"]), 1)

    def test_no_changes_are_not_described_as_a_global_pass(self):
        self.second["iamPolicy"] = copy.deepcopy(self.first["iamPolicy"])
        self.second["adminEvents"] = []
        report = evaluate_new_admins(self.second, self.first)
        self.assertEqual(report["comparisonStatus"], "NO_NEW_GRANTS_OBSERVED")
        self.assertEqual(report["results"], [])

    def test_duplicate_events_are_deduplicated_and_conflicts_rejected(self):
        event = self.second["adminEvents"][0]
        self.second["adminEvents"].append(copy.deepcopy(event))
        report = evaluate_new_admins(self.second, self.first)
        self.assertEqual(len(report["results"][0]["grantEvents"]), 1)
        self.second["adminEvents"][1]["actor"] = "user:someone.else@example.com"
        with self.assertRaisesRegex(ValueError, "Conflicting"):
            evaluate_new_admins(self.second, self.first)

    def test_resource_order_and_incomplete_iam_prevent_comparison(self):
        with self.assertRaisesRegex(ValueError, "older"):
            evaluate_new_admins(self.first, self.second)
        self.first["resource"] = "projects/a-different-project"
        with self.assertRaisesRegex(ValueError, "same project"):
            evaluate_new_admins(self.second, self.first)
        self.first["resource"] = self.second["resource"]
        self.first["sourceStatus"]["iamPolicy"] = "failed"
        with self.assertRaisesRegex(ValueError, "IAM source"):
            evaluate_new_admins(self.second, self.first)

    def test_incomplete_event_source_and_window_gaps_are_visible(self):
        self.second["sourceStatus"]["adminEvents"] = "incomplete"
        self.second["adminEventWindow"]["startExclusive"] = "2026-11-16T00:00:00Z"
        report = evaluate_new_admins(self.second, self.first)
        self.assertEqual(report["comparisonStatus"], "UNKNOWN")
        self.assertEqual(len(report["coverageGaps"]), 2)
        self.assertEqual(report["results"][0]["status"], "REVIEW")

    def test_malformed_and_unrelated_events_do_not_supply_false_attribution(self):
        for field, value in (("eventTime", None), ("eventTime", "2026-11-17T09:00:00Z"),
                             ("resource", "projects/elsewhere"), ("role", "roles/viewer"),
                             ("member", "user:alex.morgan@example.com")):
            second = copy.deepcopy(self.second)
            second["adminEvents"][0][field] = value
            report = evaluate_new_admins(second, self.first)
            blair = next(row for row in report["results"] if row["principal"] == "user:blair.chen@example.com")
            with self.subTest(field=field, value=value):
                self.assertEqual(blair["grantEvents"], [])
                self.assertEqual(report["comparisonStatus"], "UNKNOWN")

    def test_conditional_and_nonhuman_bindings_are_disclosed(self):
        self.second["iamPolicy"]["bindings"][-1]["condition"] = {"expression": "true"}
        self.second["adminEvents"][0]["condition"] = {"expression": "true"}
        self.second["iamPolicy"]["bindings"][1]["members"].append("group:admins@example.com")
        report = evaluate_new_admins(self.second, self.first)
        self.assertEqual(report["comparisonStatus"], "UNKNOWN")
        self.assertEqual(report["excludedPrincipals"], ["group:admins@example.com"])
        self.assertEqual(report["results"], [])

    def test_evaluation_does_not_mutate_either_snapshot(self):
        first, second = copy.deepcopy(self.first), copy.deepcopy(self.second)
        evaluate_new_admins(self.second, self.first)
        self.assertEqual((self.first, self.second), (first, second))

    def test_cli_and_real_http_flow(self):
        server = create_server(port=0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            # The actual CLI fetches both snapshots over local HTTP.
            with patch("sys.argv", ["check_admins", "--day", "2", "--port", str(server.server_port)]):
                output = io.StringIO()
                with redirect_stdout(output):
                    main()
                self.assertIn("Comparison status: REVIEW", output.getvalue())
                self.assertIn("Actor: user:casey.rivera@example.com", output.getvalue())
                self.assertIn("Grant time: 2026-11-16T09:00:00Z", output.getvalue())
        finally:
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()
        with patch("sys.argv", ["check_admins", "--day", "1"]):
            with patch("monitor.check_admins.fetch_snapshot", return_value=self.first):
                output = io.StringIO()
                with redirect_stdout(output):
                    main()
                self.assertIn("Comparison status: BASELINE", output.getvalue())
            with patch("monitor.check_admins.fetch_snapshot", side_effect=CollectionError("Server stopped")):
                with patch("sys.stderr", new_callable=io.StringIO):
                    with self.assertRaises(SystemExit) as raised:
                        main()
                self.assertEqual(raised.exception.code, 1)


if __name__ == "__main__":
    unittest.main()
