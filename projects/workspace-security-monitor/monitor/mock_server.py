"""Serve fictional daily snapshots over a local, read-only HTTP API.

Run from the project folder with: python3 -m monitor.mock_server
"""

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


HOST = "127.0.0.1"
PORT = 8000
DATA_DIRECTORY = Path(__file__).resolve().parent.parent / "data" / "scenarios"

# Only these URLs can access files. Request paths never become filesystem paths.
ROUTES = {
    "/api/v1/snapshots/day-1": "day_1.json",
    "/api/v1/snapshots/day-2": "day_2.json",
}


def make_handler(data_directory):
    """Build a request handler using the supplied scenario directory."""

    class SnapshotHandler(BaseHTTPRequestHandler):
        """Respond to HTTP requests without changing source records."""

        def send_json(self, status_code, payload):
            body = json.dumps(payload, indent=2).encode("utf-8")
            self.send_response(status_code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            if status_code == 405:
                self.send_header("Allow", "GET")
            self.end_headers()

            # HTTP HEAD responses contain headers but must not contain a body.
            if self.command != "HEAD":
                self.wfile.write(body)

        def do_GET(self):
            filename = ROUTES.get(self.path)
            if filename is None:
                self.send_json(404, {"error": "Endpoint not found"})
                return

            try:
                with (Path(data_directory) / filename).open(encoding="utf-8") as file:
                    snapshot = json.load(file)
            except (OSError, UnicodeError, json.JSONDecodeError):
                # Keep local filesystem details out of API responses.
                self.send_json(500, {"error": "Unable to read fictional snapshot"})
                return

            self.send_json(200, snapshot)

        def reject_method(self):
            self.send_json(405, {"error": "This mock API only supports GET"})

        do_POST = reject_method
        do_PUT = reject_method
        do_PATCH = reject_method
        do_DELETE = reject_method
        do_HEAD = reject_method
        do_OPTIONS = reject_method

    return SnapshotHandler


def create_server(port=PORT, data_directory=DATA_DIRECTORY):
    """Create a loopback-only server; port 0 lets tests choose a free port."""
    return ThreadingHTTPServer((HOST, port), make_handler(data_directory))


def main():
    try:
        with create_server() as server:
            print(f"Fictional snapshot API listening on http://{HOST}:{PORT}")
            for route in ROUTES:
                print(f"  GET http://{HOST}:{PORT}{route}")
            print("Press Control+C to stop.", flush=True)
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                print("\nStopping mock API.")
    except OSError as error:
        raise SystemExit(f"Could not start the local server: {error}") from error


if __name__ == "__main__":
    main()
