"""Exercise the mock API over real loopback HTTP, using temporary fixtures."""

import json
import shutil
import tempfile
import threading
import unittest
from http.client import HTTPConnection
from pathlib import Path

from monitor.mock_server import DATA_DIRECTORY, ROUTES, create_server


class MockServerTests(unittest.TestCase):
    def setUp(self):
        # Mutating error fixtures in tests must never change the learning data.
        self.temp_directory = tempfile.TemporaryDirectory()
        self.data_directory = Path(self.temp_directory.name)
        for filename in ROUTES.values():
            shutil.copyfile(DATA_DIRECTORY / filename, self.data_directory / filename)
        self.server = create_server(port=0, data_directory=self.data_directory)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.thread.join(timeout=5)
        self.server.server_close()
        self.temp_directory.cleanup()

    def request(self, method, path, body=None):
        connection = HTTPConnection(*self.server.server_address, timeout=3)
        try:
            connection.request(method, path, body=body)
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def test_both_endpoints_return_the_complete_fixture(self):
        self.assertEqual(self.server.server_address[0], "127.0.0.1")
        for route, filename in ROUTES.items():
            with self.subTest(route=route):
                status, headers, body = self.request("GET", route)
                self.assertEqual(status, 200)
                self.assertEqual(headers["Content-Type"], "application/json; charset=utf-8")
                self.assertEqual(int(headers["Content-Length"]), len(body))
                self.assertEqual(headers["Cache-Control"], "no-store")
                expected = json.loads((self.data_directory / filename).read_text())
                self.assertEqual(json.loads(body), expected)

    def test_unknown_paths_do_not_serve_files_or_directory_listings(self):
        for path in ("/", "/README.md", "/../README.md", "/api/v1/snapshots/day-3"):
            with self.subTest(path=path):
                status, _, body = self.request("GET", path)
                self.assertEqual(status, 404)
                self.assertEqual(json.loads(body), {"error": "Endpoint not found"})

    def test_query_strings_are_not_supported(self):
        status, _, _ = self.request("GET", "/api/v1/snapshots/day-1?day=2")
        self.assertEqual(status, 404)

    def test_write_requests_are_rejected_and_source_files_stay_unchanged(self):
        before = {p.name: p.read_bytes() for p in self.data_directory.iterdir()}
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            with self.subTest(method=method):
                status, headers, body = self.request(
                    method, "/api/v1/snapshots/day-1", body='{"fictional": false}'
                )
                self.assertEqual(status, 405)
                self.assertEqual(headers["Allow"], "GET")
                self.assertIn("error", json.loads(body))
        self.request("GET", "/api/v1/snapshots/day-1")
        after = {p.name: p.read_bytes() for p in self.data_directory.iterdir()}
        self.assertEqual(before, after)

    def test_head_has_no_body_and_options_is_rejected(self):
        for method in ("HEAD", "OPTIONS"):
            with self.subTest(method=method):
                status, headers, body = self.request(method, "/api/v1/snapshots/day-1")
                self.assertEqual(status, 405)
                self.assertEqual(headers["Allow"], "GET")
                if method == "HEAD":
                    self.assertEqual(body, b"")
                else:
                    self.assertIn("error", json.loads(body))

    def test_missing_snapshot_returns_an_error_instead_of_success(self):
        (self.data_directory / "day_1.json").unlink()
        status, _, body = self.request("GET", "/api/v1/snapshots/day-1")
        self.assertEqual(status, 500)
        self.assertEqual(json.loads(body), {"error": "Unable to read fictional snapshot"})

    def test_invalid_json_or_encoding_returns_a_safe_error(self):
        for invalid_data in (b"not JSON", b"\xff"):
            with self.subTest(invalid_data=invalid_data):
                (self.data_directory / "day_1.json").write_bytes(invalid_data)
                status, _, body = self.request("GET", "/api/v1/snapshots/day-1")
                self.assertEqual(status, 500)
                self.assertEqual(json.loads(body), {"error": "Unable to read fictional snapshot"})


if __name__ == "__main__":
    unittest.main()
