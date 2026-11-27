"""Test grant selection and actor/time correlation, without severity decisions."""

import copy
import io
import json
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from triage.detection import correlate_grants, main
from triage.parser import DATA_DIRECTORY, load_events, parse_dataset


class DetectionTests(unittest.TestCase):
    def setUp(self):
        self.dataset = json.loads((DATA_DIRECTORY / "suspicious" / "events.json").read_text())

    def report(self):
        return correlate_grants(parse_dataset(self.dataset))

    def test_suspicious_grant_correlates_four_sign_ins_without_duplicate_inflation(self):
        report = self.report()
        self.assertEqual(report["grantCount"], 1)
        candidate = report["candidates"][0]
        self.assertEqual(candidate["grant"]["record"]["eventId"], "suspicious-005")
        self.assertEqual(candidate["grant"]["sourceRecordIndices"], [0, 5])
        self.assertEqual(candidate["failedSignInCount"], 3)
        self.assertEqual(candidate["successfulSignInCount"], 1)
        self.assertEqual([s["record"]["eventId"] for s in candidate["actorSignIns"]],
                         ["suspicious-001", "suspicious-002", "suspicious-003", "suspicious-004"])
        self.assertTrue(all(s["sameSourceIpAsGrant"] for s in candidate["actorSignIns"]))
        self.assertEqual(report["skippedIamEvents"][0]["eventId"], "suspicious-006")

    def test_authorized_label_does_not_bypass_review_or_invent_approval_match(self):
        report = correlate_grants(load_events(DATA_DIRECTORY / "authorized" / "events.json"))
        self.assertEqual(report["grantCount"], 1)
        candidate = report["candidates"][0]
        self.assertEqual(candidate["status"], "REVIEW")
        self.assertEqual(candidate["successfulSignInCount"], 1)
        self.assertEqual(candidate["failedSignInCount"], 0)
        for field in ("approvalStatus", "priority", "contextCoverage"):
            self.assertEqual(candidate[field], "NOT_EVALUATED")

    def test_failed_remove_untracked_other_project_and_nonhuman_grants_are_not_selected(self):
        original = copy.deepcopy(self.dataset)
        for field, value in (("outcome", "failure"), ("changeAction", "REMOVE"),
                             ("role", "roles/viewer"), ("resource", "projects/elsewhere"),
                             ("recipient", "group:admins@example.com"),
                             ("recipient", "serviceAccount:demo@example.iam.gserviceaccount.com"),
                             ("recipient", "user:"), ("condition", {"expression": "true"})):
            self.dataset = copy.deepcopy(original)
            for index in (0, 5):
                self.dataset["events"][index][field] = value
            with self.subTest(field=field, value=value):
                report = self.report()
                self.assertEqual(report["grantCount"], 0)
                self.assertEqual(len(report["skippedIamEvents"]), 2)

    def test_recipient_sign_ins_are_not_mistaken_for_granting_actor_activity(self):
        for event in self.dataset["events"]:
            if event["eventType"] == "sign_in":
                event["actor"] = "blair.chen@example.com"
        candidate = self.report()["candidates"][0]
        self.assertEqual(candidate["actorSignIns"], [])
        self.assertEqual(candidate["contextCoverage"], "NOT_EVALUATED")

    def test_window_includes_exact_boundaries_but_excludes_earlier_and_later_events(self):
        template = copy.deepcopy(self.dataset["events"][1])
        self.dataset["events"] = [copy.deepcopy(self.dataset["events"][0])]
        stamps = ("2026-11-17T08:29:59.999999Z", "2026-11-17T08:30:00Z",
                  "2026-11-17T09:00:00Z", "2026-11-17T09:00:00.000001Z")
        for index, stamp in enumerate(stamps):
            event = copy.deepcopy(template)
            event.update(eventId=f"boundary-{index}", occurredAt=stamp)
            self.dataset["events"].append(event)
        candidate = self.report()["candidates"][0]
        self.assertEqual([s["record"]["eventId"] for s in candidate["actorSignIns"]], ["boundary-1", "boundary-2"])
        self.assertFalse(candidate["actorSignIns"][0]["sameTimeAsGrant"])
        self.assertTrue(candidate["actorSignIns"][1]["sameTimeAsGrant"])

    def test_timezone_offsets_are_compared_as_instants(self):
        event = self.dataset["events"][1]
        event["occurredAt"] = "2026-11-17T01:30:00-07:00"
        candidate = self.report()["candidates"][0]
        matched = next(s for s in candidate["actorSignIns"] if s["record"]["eventId"] == event["eventId"])
        self.assertEqual(matched["occurredAtUtc"], "2026-11-17T08:30:00Z")

    def test_other_source_ips_remain_context_but_are_not_labeled_same_ip(self):
        self.dataset["events"][1]["sourceIp"] = "192.0.2.99"
        candidate = self.report()["candidates"][0]
        self.assertEqual(len(candidate["actorSignIns"]), 4)
        match = next(s for s in candidate["actorSignIns"] if s["record"]["eventId"] == "suspicious-002")
        self.assertFalse(match["sameSourceIpAsGrant"])

    def test_normalized_ipv6_addresses_are_used_for_ip_comparison(self):
        for index in (0, 5):
            self.dataset["events"][index]["sourceIp"] = "2001:db8::1"
        self.dataset["events"][1]["sourceIp"] = "2001:0db8:0000::1"
        candidate = self.report()["candidates"][0]
        match = next(s for s in candidate["actorSignIns"] if s["record"]["eventId"] == "suspicious-002")
        self.assertTrue(match["sameSourceIpAsGrant"])

    def test_duplicate_sign_ins_do_not_increase_failure_counts(self):
        self.dataset["events"].append(copy.deepcopy(self.dataset["events"][1]))
        candidate = self.report()["candidates"][0]
        self.assertEqual(candidate["failedSignInCount"], 3)
        match = next(s for s in candidate["actorSignIns"] if s["record"]["eventId"] == "suspicious-002")
        self.assertEqual(match["sourceRecordIndices"], [1, 7])

    def test_each_grant_uses_its_own_actor_and_time_window(self):
        other = copy.deepcopy(self.dataset["events"][0])
        other.update(eventId="other-grant", actor="devon.patel@example.com", occurredAt="2026-11-17T09:05:00Z")
        self.dataset["events"].append(other)
        report = self.report()
        self.assertEqual(report["grantCount"], 2)
        self.assertEqual(len(report["candidates"][0]["actorSignIns"]), 4)
        self.assertEqual(report["candidates"][1]["actorSignIns"], [])

    def test_inputs_and_returned_evidence_do_not_share_mutable_records(self):
        timeline = parse_dataset(self.dataset)
        before = copy.deepcopy(timeline)
        report = correlate_grants(timeline)
        self.assertEqual(timeline, before)
        report["candidates"][0]["grant"]["record"]["actor"] = "changed@example.com"
        report["candidates"][0]["actorSignIns"][0]["record"]["outcome"] = "success"
        self.assertEqual(timeline, before)

    def test_cli_reports_no_candidate_without_all_clear_claim(self):
        self.dataset["events"] = []
        with patch("sys.argv", ["detection"]):
            with patch("triage.detection.load_events", return_value=parse_dataset(self.dataset)):
                output = io.StringIO()
                with redirect_stdout(output):
                    main()
        self.assertIn("not an all-clear conclusion", output.getvalue())

    def test_cli_prints_candidates_and_rejects_missing_files(self):
        with patch("sys.argv", ["detection", "--scenario", "suspicious"]):
            output = io.StringIO()
            with redirect_stdout(output):
                main()
            self.assertIn("Privileged grant candidates: 1", output.getvalue())
            self.assertIn("Actor sign-ins: 4 | Failed: 3 | Successful: 1", output.getvalue())
            self.assertIn("NOT_EVALUATED", output.getvalue())
        with patch("sys.argv", ["detection", "--file", "missing-events.json"]):
            with patch("sys.stderr", new_callable=io.StringIO):
                with self.assertRaises(SystemExit) as raised:
                    main()
                self.assertEqual(raised.exception.code, 1)


if __name__ == "__main__":
    unittest.main()
