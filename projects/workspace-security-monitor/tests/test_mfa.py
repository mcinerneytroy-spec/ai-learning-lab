"""Test MFA policy decisions separately from transport and file operations."""

import copy
import io
import json
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from monitor.check_mfa import main
from monitor.client import CollectionError
from monitor.controls import evaluate_mfa


SCENARIOS = Path(__file__).resolve().parent.parent / "data" / "scenarios"


class MFATests(unittest.TestCase):
    def setUp(self):
        self.snapshot = json.loads((SCENARIOS / "day_1.json").read_text())

    def result_for(self, email="alex.morgan@example.com"):
        report = evaluate_mfa(self.snapshot)
        return next(r for r in report["results"] if r["principal"] == f"user:{email}")

    def test_both_scenarios_match_expected_user_outcomes(self):
        for day, expected in ((1, {"Alex": "PASS", "Blair": "FAIL", "Casey": "PASS", "Indigo": "FAIL"}),
                              (2, {"Alex": "PASS", "Blair": "PASS", "Casey": "PASS", "Indigo": "FAIL"})):
            snapshot = json.loads((SCENARIOS / f"day_{day}.json").read_text())
            report = evaluate_mfa(snapshot)
            actual = {r["principal"].split(":")[1].split(".")[0].title(): r["status"] for r in report["results"]}
            with self.subTest(day=day):
                self.assertEqual(actual, expected)
                self.assertEqual(report["sourceObservedAt"], snapshot["observedAt"])
                self.assertEqual(report["policyVersion"], "mfa-v1")

    def test_boolean_policy_matrix_and_missing_values(self):
        for enrolled, enforced, expected in (
            (True, True, "PASS"), (False, True, "FAIL"), (True, False, "FAIL"),
            (False, False, "FAIL"), (None, True, "UNKNOWN"), (True, None, "UNKNOWN"),
            ("true", True, "UNKNOWN"), (1, True, "UNKNOWN"), (True, 0, "UNKNOWN"),
            (False, None, "FAIL"), (None, False, "FAIL"),
        ):
            with self.subTest(enrolled=enrolled, enforced=enforced):
                user = self.snapshot["directoryUsers"][0]
                user["isEnrolledIn2Sv"] = enrolled
                user["isEnforcedIn2Sv"] = enforced
                self.assertEqual(self.result_for()["status"], expected)
        del self.snapshot["directoryUsers"][0]["isEnrolledIn2Sv"]
        self.snapshot["directoryUsers"][0]["isEnforcedIn2Sv"] = True
        self.assertEqual(self.result_for()["status"], "UNKNOWN")

    def test_iam_user_without_directory_record_remains_in_results(self):
        self.snapshot["directoryUsers"].pop(0)
        result = self.result_for()
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertIsNone(result["userId"])

    def test_ambiguous_directory_match_is_unknown(self):
        self.snapshot["directoryUsers"].append(copy.deepcopy(self.snapshot["directoryUsers"][0]))
        self.assertEqual(self.result_for()["status"], "UNKNOWN")

    def test_non_iam_users_are_not_added_and_roles_are_deduplicated(self):
        self.snapshot["directoryUsers"].append({"id": "other", "primaryEmail": "other@example.com"})
        self.snapshot["iamPolicy"]["bindings"].append({
            "role": "roles/owner", "members": ["user:alex.morgan@example.com"]
        })
        report = evaluate_mfa(self.snapshot)
        self.assertEqual(len(report["results"]), 4)
        self.assertEqual(self.result_for()["roles"], ["roles/owner", "roles/viewer"])

    def test_groups_and_service_accounts_are_explicitly_excluded(self):
        principals = ["group:team@example.com", "serviceAccount:demo@example.iam.gserviceaccount.com"]
        self.snapshot["iamPolicy"]["bindings"][0]["members"].extend(principals)
        report = evaluate_mfa(self.snapshot)
        self.assertEqual(report["excludedPrincipals"], sorted(principals))
        self.assertEqual(len(report["results"]), 4)

    def test_conditional_bindings_are_unknown(self):
        self.snapshot["iamPolicy"]["bindings"][0]["condition"] = {"expression": "true"}
        self.assertEqual(self.result_for()["status"], "UNKNOWN")

    def test_suspension_does_not_automatically_exempt_a_user(self):
        self.snapshot["directoryUsers"][1]["suspended"] = True
        result = self.result_for("blair.chen@example.com")
        self.assertEqual(result["status"], "FAIL")
        self.assertIs(result["evidence"]["suspended"], True)

    def test_incomplete_sources_prevent_assessment(self):
        for source in ("directoryUsers", "iamPolicy"):
            snapshot = copy.deepcopy(self.snapshot)
            snapshot["sourceStatus"][source] = "failed"
            with self.subTest(source=source):
                with self.assertRaises(ValueError):
                    evaluate_mfa(snapshot)

    def test_evaluation_does_not_modify_source_data(self):
        before = copy.deepcopy(self.snapshot)
        evaluate_mfa(self.snapshot)
        self.assertEqual(self.snapshot, before)

    def test_cli_prints_findings_and_exits_cleanly_on_collection_error(self):
        with patch("sys.argv", ["check_mfa", "--day", "1"]):
            with patch("monitor.check_mfa.fetch_snapshot", return_value=self.snapshot):
                output = io.StringIO()
                with redirect_stdout(output):
                    main()
                self.assertIn("PASS=2 FAIL=2 UNKNOWN=0", output.getvalue())
            with patch("monitor.check_mfa.fetch_snapshot", side_effect=CollectionError("Server stopped")):
                with redirect_stdout(io.StringIO()):
                    with patch("sys.stderr", new_callable=io.StringIO):
                        with self.assertRaises(SystemExit) as raised:
                            main()
                self.assertEqual(raised.exception.code, 1)

    def test_empty_scope_is_not_described_as_an_overall_pass(self):
        self.snapshot["iamPolicy"]["bindings"] = []
        with patch("sys.argv", ["check_mfa"]):
            with patch("monitor.check_mfa.fetch_snapshot", return_value=self.snapshot):
                output = io.StringIO()
                with redirect_stdout(output):
                    main()
        self.assertIn("No direct human users found", output.getvalue())


if __name__ == "__main__":
    unittest.main()
