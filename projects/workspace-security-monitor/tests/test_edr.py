"""Test inventory reconciliation, agent health, timing, and collection failures."""

import copy
import io
import json
import threading
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from monitor.check_edr import main
from monitor.client import CollectionError
from monitor.edr_control import evaluate_edr
from monitor.mock_server import create_server


SCENARIOS = Path(__file__).resolve().parent.parent / "data" / "scenarios"


class EDRTests(unittest.TestCase):
    def setUp(self):
        self.snapshot = json.loads((SCENARIOS / "day_1.json").read_text())

    def vm_result(self):
        return evaluate_edr(self.snapshot)["results"][0]

    def test_both_scenarios_match_expected_device_outcomes(self):
        expected = {1: ["PASS", "FAIL"], 2: ["FAIL", "PASS"]}
        for day in (1, 2):
            snapshot = json.loads((SCENARIOS / f"day_{day}.json").read_text())
            report = evaluate_edr(snapshot)
            with self.subTest(day=day):
                self.assertEqual([row["status"] for row in report["results"]], expected[day])
                self.assertEqual(report["sourceObservedAt"], snapshot["observedAt"])
                self.assertEqual(report["policyVersion"], "edr-v1")
                self.assertEqual(report["coverageGaps"], [])
                self.assertEqual(len(report["results"]), 2)

    def test_check_in_boundary_uses_full_elapsed_time(self):
        for stamp, expected in (("2026-11-14T12:00:00Z", "PASS"),
                                ("2026-11-14T11:59:59.999999Z", "FAIL"),
                                ("2026-11-15T12:00:00Z", "PASS")):
            with self.subTest(stamp=stamp):
                self.snapshot["edrObservations"][0]["lastSeenAt"] = stamp
                self.assertEqual(self.vm_result()["status"], expected)

    def test_timezone_offsets_are_compared_as_instants(self):
        self.snapshot["edrObservations"][0]["lastSeenAt"] = "2026-11-15T04:55:00-07:00"
        result = self.vm_result()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["evidence"]["checkInAgeSeconds"], 300)

    def test_missing_invalid_timezone_free_and_future_times_are_unknown(self):
        for stamp in (None, "not a time", "2026-11-15T11:55:00", "2026-11-15T12:01:00Z"):
            with self.subTest(stamp=stamp):
                self.snapshot["edrObservations"][0]["lastSeenAt"] = stamp
                self.assertEqual(self.vm_result()["status"], "UNKNOWN")
        del self.snapshot["edrObservations"][0]["lastSeenAt"]
        self.assertEqual(self.vm_result()["status"], "UNKNOWN")

    def test_recognized_unhealthy_status_fails_even_when_time_is_missing(self):
        for status in ("unhealthy", "disabled", "offline"):
            with self.subTest(status=status):
                agent = self.snapshot["edrObservations"][0]
                agent["status"] = status
                agent.pop("lastSeenAt", None)
                result = self.vm_result()
                self.assertEqual(result["status"], "FAIL")
                self.assertIn("timestamp", result["reason"])

    def test_unrecognized_status_and_invalid_agent_ids_do_not_pass(self):
        for status in (None, "unknown", "HEALTHY", True, {}):
            with self.subTest(status=status):
                self.snapshot["edrObservations"][0]["status"] = status
                self.assertEqual(self.vm_result()["status"], "UNKNOWN")
        self.snapshot["edrObservations"][0]["status"] = "healthy"
        for agent_id in (None, "", "  ", 12):
            with self.subTest(agent_id=agent_id):
                self.snapshot["edrObservations"][0]["agentId"] = agent_id
                self.assertEqual(self.vm_result()["status"], "UNKNOWN")

    def test_required_device_missing_from_complete_edr_response_fails(self):
        result = evaluate_edr(self.snapshot)["results"][1]
        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(result["evidence"]["matchedAgentCount"], 0)
        self.assertEqual(result["evidence"]["agentObservations"], [])

    def test_incomplete_inventory_or_edr_prevents_assessment(self):
        for source in ("devices", "edrObservations"):
            snapshot = copy.deepcopy(self.snapshot)
            snapshot["sourceStatus"][source] = "incomplete"
            with self.subTest(source=source):
                with self.assertRaisesRegex(ValueError, source):
                    evaluate_edr(snapshot)

    def test_duplicate_agent_matches_and_reused_ids_are_unknown(self):
        duplicate = copy.deepcopy(self.snapshot["edrObservations"][0])
        duplicate["agentId"] = "another-agent"
        self.snapshot["edrObservations"].append(duplicate)
        self.assertEqual(self.vm_result()["status"], "UNKNOWN")
        self.snapshot["edrObservations"].pop()
        duplicate["agentId"] = self.snapshot["edrObservations"][0]["agentId"]
        duplicate["deviceId"] = self.snapshot["devices"][1]["deviceId"]
        self.snapshot["edrObservations"].append(duplicate)
        self.assertEqual([r["status"] for r in evaluate_edr(self.snapshot)["results"]], ["UNKNOWN", "UNKNOWN"])

    def test_orphan_and_unidentifiable_edr_records_are_disclosed(self):
        self.snapshot["edrObservations"].extend([
            {"deviceId": "unlisted-device", "agentId": "orphan-agent"},
            {"agentId": "unidentifiable-agent"},
        ])
        report = evaluate_edr(self.snapshot)
        self.assertEqual(report["unmatchedEdrDeviceIds"], ["unlisted-device"])
        self.assertEqual(len(report["coverageGaps"]), 2)
        self.assertEqual(len(report["results"]), 2)

    def test_applicability_requires_actual_booleans_and_exclusions_are_explicit(self):
        self.snapshot["devices"][0]["edrRequired"] = False
        report = evaluate_edr(self.snapshot)
        self.assertEqual(report["excludedDeviceIds"], ["fictional-device-001"])
        self.assertEqual(len(report["results"]), 1)
        for invalid in (None, "false", 0, 1):
            with self.subTest(invalid=invalid):
                self.snapshot["devices"][0]["edrRequired"] = invalid
                self.assertEqual(self.vm_result()["status"], "UNKNOWN")

    def test_invalid_observation_time_and_duplicate_inventory_are_rejected(self):
        self.snapshot["observedAt"] = "not a time"
        with self.assertRaises(ValueError):
            evaluate_edr(self.snapshot)
        self.snapshot["observedAt"] = "2026-11-15T12:00:00Z"
        self.snapshot["devices"].append(copy.deepcopy(self.snapshot["devices"][0]))
        with self.assertRaisesRegex(ValueError, "Duplicate inventory"):
            evaluate_edr(self.snapshot)

    def test_evaluation_preserves_input(self):
        before = copy.deepcopy(self.snapshot)
        evaluate_edr(self.snapshot)
        self.assertEqual(self.snapshot, before)

    def test_empty_scope_is_not_reported_as_an_overall_pass(self):
        self.snapshot["devices"] = []
        self.snapshot["edrObservations"] = []
        with patch("sys.argv", ["check_edr"]):
            with patch("monitor.check_edr.fetch_snapshot", return_value=self.snapshot):
                output = io.StringIO()
                with redirect_stdout(output):
                    main()
                self.assertIn("No devices assessed", output.getvalue())

    def test_real_http_cli_both_days_and_collection_failure(self):
        server = create_server(port=0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            for day in (1, 2):
                with patch("sys.argv", ["check_edr", "--day", str(day), "--port", str(server.server_port)]):
                    output = io.StringIO()
                    with redirect_stdout(output):
                        main()
                    self.assertIn("PASS=1 FAIL=1 UNKNOWN=0", output.getvalue())
                    self.assertIn("demo-gcp-vm-01", output.getvalue())
                    self.assertIn("demo-laptop-01", output.getvalue())
        finally:
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()
        with patch("sys.argv", ["check_edr"]):
            with patch("monitor.check_edr.fetch_snapshot", side_effect=CollectionError("Server stopped")):
                with patch("sys.stderr", new_callable=io.StringIO):
                    with self.assertRaises(SystemExit) as raised:
                        main()
                    self.assertEqual(raised.exception.code, 1)


if __name__ == "__main__":
    unittest.main()
