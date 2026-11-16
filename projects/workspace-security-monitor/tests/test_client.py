"""Check real local retrieval plus controlled bad responses and source data."""

import copy
import io
import json
import threading
import unittest
from contextlib import redirect_stdout
from email.message import Message
from unittest.mock import patch
from urllib.error import HTTPError, URLError

from monitor.client import CollectionError, NoRedirects, fetch_snapshot, main, validate_snapshot
from monitor.mock_server import DATA_DIRECTORY, create_server


class FakeResponse(io.BytesIO):
    def __init__(self, body, content_type="application/json", status=200):
        super().__init__(body)
        self.status = status
        self.headers = Message()
        self.headers["Content-Type"] = content_type


class ClientTests(unittest.TestCase):
    def setUp(self):
        self.snapshot = json.loads((DATA_DIRECTORY / "day_1.json").read_text())

    def test_real_http_retrieves_both_snapshots_without_changing_sources(self):
        before = {p.name: p.read_bytes() for p in DATA_DIRECTORY.glob("*.json")}
        server = create_server(port=0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            for day in (1, 2):
                with self.subTest(day=day):
                    result = fetch_snapshot(day=day, port=server.server_port)
                    expected = json.loads(before[f"day_{day}.json"])
                    self.assertEqual(result, expected)
        finally:
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()
        self.assertEqual(before, {p.name: p.read_bytes() for p in DATA_DIRECTORY.glob("*.json")})

    def test_cli_reports_counts_but_does_not_claim_control_results(self):
        with patch("monitor.client.fetch_snapshot", return_value=self.snapshot):
            with patch("sys.argv", ["client", "--day", "1"]):
                output = io.StringIO()
                with redirect_stdout(output):
                    main()
        self.assertIn("Directory users: 4", output.getvalue())
        self.assertIn("Inventory devices: 2", output.getvalue())
        self.assertIn("No security controls evaluated", output.getvalue())

    def test_invalid_http_response_is_rejected(self):
        cases = (
            (b"not JSON", "application/json", 200),
            (b"\xff", "application/json", 200),
            (b"{}", "text/html", 200),
            (b"{}", "application/json", 204),
            (b"x" * 1_000_001, "application/json", 200),
        )
        for body, content_type, status in cases:
            with self.subTest(content_type=content_type, status=status, size=len(body)):
                with patch("monitor.client.build_opener") as opener:
                    opener.return_value.open.return_value = FakeResponse(body, content_type, status)
                    with self.assertRaises(CollectionError):
                        fetch_snapshot()

    def test_http_and_network_failures_are_reported(self):
        failures = (
            HTTPError("http://127.0.0.1", 404, "Not found", {}, None),
            HTTPError("http://127.0.0.1", 500, "Server error", {}, None),
            URLError("Connection refused"),
            TimeoutError("Read timed out"),
        )
        for failure in failures:
            with self.subTest(failure=type(failure).__name__):
                with patch("monitor.client.build_opener") as opener:
                    opener.return_value.open.side_effect = failure
                    with self.assertRaises(CollectionError):
                        fetch_snapshot()

    def test_incomplete_sources_are_not_reported_as_success(self):
        for status in ("failed", "incomplete", None):
            with self.subTest(status=status):
                snapshot = copy.deepcopy(self.snapshot)
                snapshot["sourceStatus"]["edrObservations"] = status
                with self.assertRaisesRegex(CollectionError, "edrObservations"):
                    validate_snapshot(snapshot, day=1)

    def test_missing_sections_duplicate_ids_and_bad_times_are_rejected(self):
        variants = []
        for section in ("directoryUsers", "iamPolicy", "devices", "adminEvents", "adminEventWindow"):
            snapshot = copy.deepcopy(self.snapshot)
            del snapshot[section]
            variants.append(snapshot)
        snapshot = copy.deepcopy(self.snapshot)
        snapshot["directoryUsers"].append(copy.deepcopy(snapshot["directoryUsers"][0]))
        variants.append(snapshot)
        for stamp in ("not a date", "2026-11-15T12:00:00", None):
            snapshot = copy.deepcopy(self.snapshot)
            snapshot["observedAt"] = stamp
            variants.append(snapshot)
        for snapshot in variants + [[], {"schemaVersion": "999"}]:
            with self.subTest(snapshot_type=type(snapshot).__name__):
                with self.assertRaises(CollectionError):
                    validate_snapshot(snapshot, day=1)

    def test_wrong_day_is_rejected(self):
        with self.assertRaisesRegex(CollectionError, "Wrong snapshot"):
            validate_snapshot(self.snapshot, day=2)

    def test_redirects_cannot_change_the_destination(self):
        with self.assertRaisesRegex(CollectionError, "Redirect refused"):
            NoRedirects().redirect_request(None, None, 302, "Found", {}, "https://example.com")


if __name__ == "__main__":
    unittest.main()
