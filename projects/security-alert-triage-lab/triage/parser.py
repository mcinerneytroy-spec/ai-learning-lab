"""Validate fictional events, deduplicate source IDs, and build a timeline."""

import argparse
import copy
import ipaddress
import json
import re
from datetime import datetime, timezone
from pathlib import Path


DATA_DIRECTORY = Path(__file__).resolve().parent.parent / "data"
TIMESTAMP_PATTERN = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$"
)


class ParseError(ValueError):
    """The input does not meet the lab's event contract."""


def parse_timestamp(value):
    """Require an explicit timezone and return a UTC datetime."""
    if not isinstance(value, str) or not TIMESTAMP_PATTERN.fullmatch(value):
        raise ParseError("occurredAt needs an ISO timestamp with seconds and an explicit timezone.")
    try:
        return datetime.fromisoformat(value).astimezone(timezone.utc)
    except ValueError as error:
        raise ParseError("occurredAt is not a valid date/time.") from error


def require_text(record, field):
    value = record.get(field)
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise ParseError(f"{field} must be nonblank text without surrounding whitespace.")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ParseError(f"{field} must not contain control characters.")
    return value


def parse_dataset(dataset):
    """Return validated unique events with UTC times and source record indices.

    No input is modified. Any invalid record or conflicting event ID rejects the
    dataset, rather than silently dropping evidence and returning a clean result.
    """
    if not isinstance(dataset, dict):
        raise ParseError("Dataset must be a JSON object.")
    if dataset.get("schemaVersion") != "1.0" or dataset.get("fictional") is not True:
        raise ParseError("Expected schemaVersion 1.0 and fictional=true.")
    dataset_id = require_text(dataset, "datasetId")
    records = dataset.get("events")
    if not isinstance(records, list):
        raise ParseError("events must be a list.")

    unique = {}
    fingerprints = {}
    for index, record in enumerate(records):
        try:
            if not isinstance(record, dict):
                raise ParseError("Event must be a JSON object.")
            event_id = require_text(record, "eventId")
            event_type = require_text(record, "eventType")
            if event_type not in ("sign_in", "iam_binding_change"):
                raise ParseError("Unsupported eventType.")
            if record.get("outcome") not in ("success", "failure"):
                raise ParseError("outcome must be success or failure.")
            require_text(record, "actor")
            stamp = parse_timestamp(record.get("occurredAt"))
            try:
                source_ip = str(ipaddress.ip_address(require_text(record, "sourceIp")))
            except ValueError as error:
                raise ParseError("sourceIp must be a valid IPv4 or IPv6 address.") from error
            if event_type == "iam_binding_change":
                for field in ("resource", "role", "recipient"):
                    require_text(record, field)
                if record.get("changeAction") not in ("ADD", "REMOVE"):
                    raise ParseError("changeAction must be ADD or REMOVE.")
            try:
                # Stable JSON comparison ignores object key order, not changed values.
                fingerprint = json.dumps(record, sort_keys=True, allow_nan=False)
            except (TypeError, ValueError) as error:
                raise ParseError("Event contains values outside the JSON contract.") from error
            if event_id in unique:
                if fingerprint != fingerprints[event_id]:
                    raise ParseError(f"Conflicting records share eventId {event_id}.")
                unique[event_id]["sourceRecordIndices"].append(index)
                continue
            fingerprints[event_id] = fingerprint
            unique[event_id] = {
                "record": copy.deepcopy(record),
                "occurredAtUtc": stamp.isoformat().replace("+00:00", "Z"),
                "sourceIpNormalized": source_ip,
                "sourceRecordIndices": [index],
            }
        except ParseError as error:
            raise ParseError(f"Record index {index}: {error}") from error

    ordered = sorted(unique.values(), key=lambda item: (
        parse_timestamp(item["occurredAtUtc"]), item["record"]["eventId"]
    ))
    return {
        "datasetId": dataset_id,
        "inputRecordCount": len(records),
        "uniqueEventCount": len(ordered),
        "duplicateRecordCount": len(records) - len(ordered),
        "events": ordered,
    }


def reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ParseError(f"Duplicate JSON object key: {key}.")
        result[key] = value
    return result


def reject_non_json_constant(value):
    raise ParseError(f"Nonstandard JSON constant: {value}.")


def load_events(path):
    """Read UTF-8 JSON once, reject ambiguous JSON, then validate the dataset."""
    try:
        text = Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise ParseError("Could not read the UTF-8 event file. Check the file path and encoding.") from error
    try:
        dataset = json.loads(text, object_pairs_hook=reject_duplicate_keys, parse_constant=reject_non_json_constant)
    except json.JSONDecodeError as error:
        raise ParseError(f"Invalid JSON at line {error.lineno}, column {error.colno}.") from error
    return parse_dataset(dataset)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("--scenario", choices=("suspicious", "authorized"))
    selection.add_argument("--file", type=Path, help="Read a lab-schema event file instead of a bundled scenario.")
    arguments = parser.parse_args()
    path = arguments.file if arguments.file is not None else DATA_DIRECTORY / (arguments.scenario or "suspicious") / "events.json"
    try:
        timeline = load_events(path)
    except ParseError as error:
        parser.exit(1, f"Parsing failed: {error}\n")
    print(f"Dataset: {timeline['datasetId']}")
    print(f"Input records: {timeline['inputRecordCount']}")
    print(f"Unique events: {timeline['uniqueEventCount']}")
    print(f"Exact duplicates removed: {timeline['duplicateRecordCount']}")
    for item in timeline["events"]:
        event = item["record"]
        detail = ""
        if event["eventType"] == "iam_binding_change":
            detail = f" | {event['changeAction']} {event['role']} -> {event['recipient']}"
        print(f"{item['occurredAtUtc']} | {event['eventId']} | {event['eventType']} | {event['actor']} | {event['outcome']}{detail}")
    if not timeline["events"]:
        print("No events supplied; this does not establish that no activity occurred.")
    print("Parsed timeline only. No threat detection, context matching, or report files yet.")


if __name__ == "__main__":
    main()
