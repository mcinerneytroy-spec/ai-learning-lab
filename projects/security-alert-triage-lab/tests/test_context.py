"""Exercise priority, sequence, approval, and uncertainty decisions."""

import copy
import json
import unittest

from triage.context import analyze
from triage.parser import DATA_DIRECTORY, ParseError, parse_dataset


class ContextTests(unittest.TestCase):
    def setUp(self):
        self.events = json.loads((DATA_DIRECTORY / "suspicious/events.json").read_text())
        self.context = json.loads((DATA_DIRECTORY / "suspicious/context.json").read_text())

    def authorized(self):
        self.events = json.loads((DATA_DIRECTORY / "authorized/events.json").read_text())
        self.context = json.loads((DATA_DIRECTORY / "authorized/context.json").read_text())

    def case(self):
        return analyze(parse_dataset(self.events), self.context)["cases"][0]

    def test_suspicious_sequence_is_elevated_but_compromise_unconfirmed(self):
        case = self.case()
        self.assertEqual(case["priority"], "ELEVATED")
        self.assertEqual(case["recommendation"], "ESCALATE_FOR_VALIDATION")
        self.assertEqual(case["incidentVerdict"], "UNCONFIRMED")
        self.assertEqual(case["approvalStatus"], "NOT_FOUND_IN_SUPPLIED_RECORDS")
        self.assertEqual(case["contextCoverage"], "DECLARED_COMPLETE")
        self.assertEqual(case["signalSequences"][0]["failureEventIds"], ["suspicious-001", "suspicious-002", "suspicious-003"])

    def test_authorized_case_is_routine_review_with_matching_ticket(self):
        self.authorized()
        case = self.case()
        self.assertEqual(case["priority"], "ROUTINE")
        self.assertEqual(case["approvalStatus"], "MATCHED")
        self.assertEqual(case["matchingApprovals"][0]["record"]["changeId"], "CHG-DEMO-001")
        self.assertEqual(case["analystDisposition"], "PENDING")

    def test_matching_approval_does_not_suppress_an_elevated_signal(self):
        approved = json.loads((DATA_DIRECTORY / "authorized/context.json").read_text())["changeRecords"][0]
        approved.update(recipient="user:blair.chen@example.com", role="roles/owner")
        self.context["changeRecords"] = [approved]
        case = self.case()
        self.assertEqual(case["approvalStatus"], "MATCHED")
        self.assertEqual(case["priority"], "ELEVATED")

    def test_missing_baseline_is_unknown_and_never_routine(self):
        self.authorized()
        self.context["actorBaselines"] = []
        case = self.case()
        self.assertEqual(case["ipFamiliarity"], "UNKNOWN")
        self.assertEqual(case["priority"], "REVIEW")
        self.assertEqual(case["contextCoverage"], "INCOMPLETE_OR_UNKNOWN")

    def test_incomplete_sources_block_routine_but_keep_positive_elevated_signal(self):
        self.context["declaredCoverage"]["identityEvents"] = "incomplete"
        case = self.case()
        self.assertEqual(case["priority"], "ELEVATED")
        self.assertEqual(case["contextCoverage"], "INCOMPLETE_OR_UNKNOWN")
        self.authorized()
        self.context["declaredCoverage"]["identityEvents"] = "incomplete"
        self.assertEqual(self.case()["priority"], "REVIEW")

    def test_incomplete_actor_baseline_does_not_establish_unfamiliarity(self):
        self.context["declaredCoverage"]["actorBaselines"] = "unknown"
        self.assertEqual(self.case()["ipFamiliarity"], "UNKNOWN")
        self.assertEqual(self.case()["priority"], "REVIEW")

    def test_invalid_duplicate_and_empty_baselines_are_visible(self):
        for rows in ([{"actor": "casey.rivera@example.com", "knownSourceCidrs": ["bad"]}],
                     [{"actor": "casey.rivera@example.com", "knownSourceCidrs": []}],
                     [self.context["actorBaselines"][0], self.context["actorBaselines"][0]], None):
            context = copy.deepcopy(self.context)
            context["actorBaselines"] = rows
            result = analyze(parse_dataset(self.events), context)["cases"][0]
            with self.subTest(rows=rows):
                self.assertEqual(result["ipFamiliarity"], "UNKNOWN")
                self.assertTrue(result["coverageGaps"])

    def test_missing_or_invalid_change_list_is_unknown(self):
        for value in (None, {}, [{"changeId": "bad"}]):
            context = copy.deepcopy(self.context)
            context["changeRecords"] = value
            with self.subTest(value=value):
                self.assertEqual(analyze(parse_dataset(self.events), context)["cases"][0]["approvalStatus"], "UNKNOWN")

    def test_approval_must_match_all_subject_fields(self):
        self.authorized()
        for field, value in (("actor", "someone@example.com"), ("recipient", "user:someone@example.com"),
                             ("role", "roles/owner"), ("resource", "projects/other"), ("status", "revoked")):
            context = copy.deepcopy(self.context)
            context["changeRecords"][0][field] = value
            with self.subTest(field=field):
                case = analyze(parse_dataset(self.events), context)["cases"][0]
                self.assertEqual(case["approvalStatus"], "NOT_FOUND_IN_SUPPLIED_RECORDS")
                self.assertEqual(case["priority"], "REVIEW")

    def test_approval_time_and_half_open_window_boundaries(self):
        self.authorized()
        original = copy.deepcopy(self.context)
        for field, stamp, expected in (
            ("approvedAt", "2026-11-17T09:00:00Z", "NOT_FOUND_IN_SUPPLIED_RECORDS"),
            ("approvedAt", "2026-11-17T09:01:00Z", "NOT_FOUND_IN_SUPPLIED_RECORDS"),
            ("windowStartInclusive", "2026-11-17T09:00:00Z", "MATCHED"),
            ("windowEndExclusive", "2026-11-17T09:00:00Z", "NOT_FOUND_IN_SUPPLIED_RECORDS"),
        ):
            self.context = copy.deepcopy(original)
            self.context["changeRecords"][0][field] = stamp
            with self.subTest(field=field, stamp=stamp):
                self.assertEqual(self.case()["approvalStatus"], expected)

    def test_exact_duplicate_approvals_deduplicate_and_conflicts_reject(self):
        self.authorized()
        self.context["changeRecords"].append(copy.deepcopy(self.context["changeRecords"][0]))
        self.assertEqual(len(self.case()["matchingApprovals"]), 1)
        self.context["changeRecords"][1]["approvedBy"] = "someone@example.com"
        with self.assertRaises(ParseError):
            self.case()

    def test_failures_must_strictly_precede_success_and_share_ip(self):
        for event in self.events["events"]:
            if event["eventType"] == "sign_in" and event["outcome"] == "failure":
                event["occurredAt"] = "2026-11-17T08:50:00Z"
        self.assertEqual(self.case()["signalSequences"], [])
        self.setUp()
        self.events["events"][1]["sourceIp"] = "192.0.2.30"
        self.assertEqual(self.case()["signalSequences"], [])

    def test_success_at_grant_time_is_not_assumed_to_precede_grant(self):
        self.events["events"][3]["occurredAt"] = "2026-11-17T09:00:00Z"
        case = self.case()
        self.assertFalse(case["elevatedSignalObserved"])
        self.assertTrue(any("timestamp" in gap for gap in case["coverageGaps"]))

    def test_duplicate_failures_do_not_reach_threshold(self):
        failure = copy.deepcopy(self.events["events"][1])
        self.events["events"] = [self.events["events"][0], failure, copy.deepcopy(failure), copy.deepcopy(failure), self.events["events"][3]]
        self.assertEqual(self.case()["signalSequences"], [])

    def test_missing_success_does_not_produce_routine_review(self):
        self.authorized()
        self.events["events"] = self.events["events"][1:]
        self.assertEqual(self.case()["priority"], "REVIEW")

    def test_known_ip_with_failure_chain_still_requires_review(self):
        self.context["actorBaselines"][0]["knownSourceCidrs"] = ["203.0.113.0/24"]
        approved = json.loads((DATA_DIRECTORY / "authorized/context.json").read_text())["changeRecords"][0]
        approved.update(recipient="user:blair.chen@example.com", role="roles/owner")
        self.context["changeRecords"] = [approved]
        self.assertEqual(self.case()["priority"], "REVIEW")

    def test_unknown_and_short_event_windows_are_visible(self):
        self.authorized()
        for window in (None, {}, {"startInclusive": "2026-11-17T08:45:00Z", "endExclusive": "2026-11-17T10:00:00Z"}):
            context = copy.deepcopy(self.context)
            context["eventWindow"] = window
            with self.subTest(window=window):
                case = analyze(parse_dataset(self.events), context)["cases"][0]
                self.assertEqual(case["priority"], "REVIEW")
                self.assertTrue(case["coverageGaps"])

    def test_wrong_dataset_and_nonfictional_context_are_rejected(self):
        for field, value in (("datasetId", "other"), ("fictional", False), ("schemaVersion", "999")):
            context = copy.deepcopy(self.context)
            context[field] = value
            with self.subTest(field=field):
                with self.assertRaises(ParseError):
                    analyze(parse_dataset(self.events), context)

    def test_empty_candidates_keep_global_coverage_gaps(self):
        self.events["events"] = []
        self.context["declaredCoverage"] = {}
        result = analyze(parse_dataset(self.events), self.context)
        self.assertEqual(result["cases"], [])
        self.assertTrue(result["coverageGaps"])

    def test_analysis_preserves_both_inputs(self):
        timeline = parse_dataset(self.events)
        before = copy.deepcopy((timeline, self.context))
        result = analyze(timeline, self.context)
        result["cases"][0]["grant"]["record"]["actor"] = "changed@example.com"
        self.assertEqual((timeline, self.context), before)


if __name__ == "__main__":
    unittest.main()
