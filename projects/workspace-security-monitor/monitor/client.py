"""Retrieve a fictional snapshot over HTTP and check its basic structure."""

import argparse
import base64
import hashlib
import json
from datetime import datetime, timezone
from http.client import HTTPException
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener


class CollectionError(Exception):
    """The client could not retrieve an acceptable snapshot."""


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise CollectionError("Redirect refused: this client only contacts localhost.")


def validate_snapshot(snapshot, day):
    """Check the demo envelope, source status, and basic record types.

    This is not proof of population completeness or a security control result.
    Detailed field interpretation belongs in the later control checks.
    """
    def require(condition, message):
        if not condition:
            raise CollectionError(message)

    require(isinstance(snapshot, dict), "Snapshot must be a JSON object.")
    require(snapshot.get("schemaVersion") == "1.0", "Unsupported snapshot schema.")
    require(snapshot.get("fictional") is True, "Expected fictional training data.")
    require(snapshot.get("snapshotId") == f"demo-day-{day}", "Wrong snapshot returned.")
    require(snapshot.get("identityProvider") == "google-managed", "Unexpected identity source.")
    resource = snapshot.get("resource")
    require(isinstance(resource, str) and resource.startswith("projects/"), "Missing project resource.")
    try:
        observed = datetime.fromisoformat(snapshot["observedAt"])
        require(observed.utcoffset() is not None, "Observation time needs a timezone.")
    except (KeyError, TypeError, ValueError) as error:
        raise CollectionError("Missing or invalid observation timestamp.") from error

    sources = ("directoryUsers", "iamPolicy", "adminEvents", "devices", "edrObservations")
    status = snapshot.get("sourceStatus")
    require(isinstance(status, dict), "Missing source collection status.")
    for source in sources:
        require(status.get(source) == "complete", f"Source not declared complete: {source}.")
    for section in ("directoryUsers", "adminEvents", "devices", "edrObservations"):
        records = snapshot.get(section)
        require(isinstance(records, list), f"{section} must be a list.")
        require(all(isinstance(record, dict) for record in records), f"Invalid record in {section}.")

    for section, keys in (("directoryUsers", ("id", "primaryEmail")), ("devices", ("deviceId",))):
        for key in keys:
            values = [record.get(key) for record in snapshot[section]]
            require(all(isinstance(value, str) and value for value in values), f"Invalid {section}.{key}.")
            require(len(values) == len(set(values)), f"Duplicate {section}.{key}.")

    policy = snapshot.get("iamPolicy")
    require(isinstance(policy, dict), "IAM policy must be an object.")
    bindings = policy.get("bindings")
    require(isinstance(bindings, list), "IAM bindings must be a list.")
    for binding in bindings:
        require(isinstance(binding, dict), "Invalid IAM binding.")
        require(isinstance(binding.get("role"), str) and bool(binding["role"]), "Missing IAM role.")
        members = binding.get("members")
        require(isinstance(members, list), "IAM members must be a list.")
        require(all(isinstance(member, str) and member for member in members), "Invalid IAM member.")

    window = snapshot.get("adminEventWindow")
    require(isinstance(window, dict), "Missing administrator event window.")
    try:
        start = datetime.fromisoformat(window["startExclusive"])
        end = datetime.fromisoformat(window["endInclusive"])
        require(start.utcoffset() is not None and end.utcoffset() is not None, "Event window needs timezones.")
        require(start < end == observed, "Event window must end at the observation time.")
    except (KeyError, TypeError, ValueError) as error:
        raise CollectionError("Invalid administrator event window.") from error


def fetch_snapshot(day=1, port=8000, timeout=5, capture=None):
    """GET and validate a snapshot; optionally retain transport evidence.

    When supplied, capture is a dictionary filled even on collection failure.
    Older callers still receive only the parsed snapshot dictionary.
    """
    if day not in (1, 2) or not 1 <= port <= 65535:
        raise CollectionError("Choose day 1 or 2 and a port between 1 and 65535.")
    url = f"http://127.0.0.1:{port}/api/v1/snapshots/day-{day}"
    if capture is not None:
        capture.update({
            "url": url, "method": "GET",
            "collectionStartedAt": datetime.now(timezone.utc).isoformat(),
            "validationStatus": "NOT_VALIDATED",
        })

    def retain_response(response, body):
        if capture is not None:
            capture.update({
                "httpStatus": response.code,
                "contentType": response.headers.get("Content-Type"),
                "responseReceivedAt": datetime.now(timezone.utc).isoformat(),
                "bodyTruncated": len(body) > 1_000_000,
                "rawBodyBase64": base64.b64encode(body).decode("ascii"),
                "rawBodySha256": hashlib.sha256(body).hexdigest(),
            })
    # Ignore system proxies so fictional records stay on loopback.
    opener = build_opener(ProxyHandler({}), NoRedirects())
    request = Request(url, headers={"Accept": "application/json"}, method="GET")
    try:
        with opener.open(request, timeout=timeout) as response:
            body = response.read(1_000_001)
            retain_response(response, body)
            if response.status != 200:
                raise CollectionError(f"Expected HTTP 200; received {response.status}.")
            if response.headers.get_content_type() != "application/json":
                raise CollectionError("Expected a JSON response.")
            if len(body) > 1_000_000:
                raise CollectionError("Snapshot exceeds the 1 MB demo limit.")
            declared_length = response.headers.get("Content-Length")
            if declared_length is not None:
                if not declared_length.isdecimal() or int(declared_length) != len(body):
                    raise CollectionError("Response body does not match its declared length.")
    except HTTPError as error:
        try:
            retain_response(error, error.read(1_000_001))
        except (OSError, HTTPException):
            pass
        finally:
            error.close()
        raise CollectionError(f"Server returned HTTP {error.code}.") from error
    except (URLError, OSError, HTTPException) as error:
        raise CollectionError("Could not retrieve snapshot. Check that the server is running.") from error
    try:
        snapshot = json.loads(body.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise CollectionError("Response is not valid UTF-8 JSON.") from error
    validate_snapshot(snapshot, day)
    if capture is not None:
        capture["validationStatus"] = "VALIDATED"
    return snapshot


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--day", type=int, choices=(1, 2), default=1)
    parser.add_argument("--port", type=int, default=8000)
    arguments = parser.parse_args()
    try:
        snapshot = fetch_snapshot(day=arguments.day, port=arguments.port)
    except CollectionError as error:
        parser.exit(1, f"Collection failed: {error}\n")
    print(f"Retrieved {snapshot['snapshotId']} over HTTP GET")
    print(f"Source observation time: {snapshot['observedAt']}")
    print(f"Directory users: {len(snapshot['directoryUsers'])}")
    print(f"IAM role bindings: {len(snapshot['iamPolicy']['bindings'])}")
    print(f"Administrator events: {len(snapshot['adminEvents'])}")
    print(f"Inventory devices: {len(snapshot['devices'])}")
    print(f"EDR observations: {len(snapshot['edrObservations'])}")
    print("Basic validation passed; source completeness is declared by the mock.")
    print("No security controls evaluated. No evidence files saved.")


if __name__ == "__main__":
    main()
