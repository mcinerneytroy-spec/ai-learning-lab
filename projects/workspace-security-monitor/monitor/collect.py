"""Run all three controls and save timestamped evidence and a CSV report."""

import argparse
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from monitor.admin_control import evaluate_new_admins
from monitor.client import CollectionError, fetch_snapshot
from monitor.controls import evaluate_mfa
from monitor.edr_control import evaluate_edr
from monitor.reporting import write_csv, write_evidence


OUTPUT_DIRECTORY = Path(__file__).resolve().parent.parent / "outputs"


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def run_collection(day=2, port=8000, collector_id="local-demo-collector", output_directory=OUTPUT_DIRECTORY):
    """Persist RUNNING first; retain collected responses even if a later step fails."""
    if day not in (1, 2) or not 1 <= port <= 65535:
        raise ValueError("Choose day 1 or 2 and a port between 1 and 65535.")
    if not isinstance(collector_id, str) or not collector_id.strip():
        raise ValueError("Collector ID must not be blank.")
    started = utc_now()
    run_id = uuid4().hex
    directory = Path(output_directory) / f"{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}_{run_id}"
    directory.mkdir(parents=True, exist_ok=False)
    evidence = {
        "evidenceSchemaVersion": "1.0", "fictional": True, "runId": run_id,
        "collectorId": collector_id, "collectorIdentityAssurance": "Self-declared demo label; not authenticated identity.",
        "collectionStartedAt": started, "collectionCompletedAt": None,
        "runStatus": "RUNNING", "sources": [], "controls": [], "error": None,
        "limitations": [
            "Fictional observations; source completeness is declared, not independently established.",
            "Source observation/event times differ from actual collection times; demo dates are fixed.",
            "Local files are not signed or tamper-evident. SHA-256 is a body fingerprint, not authentication.",
            "Scope exclusions are not approved exceptions. No compliance or approval conclusion is implied.",
            "Day 2 re-fetches the Day 1 fixture; persistent baseline selection and scheduling are not implemented.",
        ],
    }
    write_evidence(directory, evidence)

    def collect_source(source_day):
        record = {"day": source_day}
        evidence["sources"].append(record)
        try:
            snapshot = fetch_snapshot(day=source_day, port=port, capture=record)
            record["snapshot"] = snapshot
            return snapshot
        except CollectionError as error:
            record["validationStatus"] = "FAILED"
            record["error"] = str(error)
            raise
        finally:
            record["collectionCompletedAt"] = utc_now()
            write_evidence(directory, evidence)

    try:
        current = collect_source(day)
        previous = collect_source(1) if day == 2 else None
        for evaluate in (
            lambda: evaluate_mfa(current),
            lambda: evaluate_new_admins(current, previous),
            lambda: evaluate_edr(current),
        ):
            evidence["controls"].append(evaluate())
            write_evidence(directory, evidence)
        evidence["runStatus"] = "COMPLETED"
    except (CollectionError, ValueError) as error:
        evidence["runStatus"] = "FAILED"
        evidence["error"] = str(error)
    finally:
        evidence["collectionCompletedAt"] = utc_now()
        write_evidence(directory, evidence)
    try:
        write_csv(directory, evidence)
    except OSError as error:
        evidence["runStatus"] = "FAILED"
        evidence["error"] = f"CSV report could not be saved: {error}"
        write_evidence(directory, evidence)
        raise
    return directory, evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--day", type=int, choices=(1, 2), default=2)
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--collector-id", default="local-demo-collector")
    parser.add_argument("--output-dir", type=Path, default=OUTPUT_DIRECTORY)
    arguments = parser.parse_args()
    try:
        directory, evidence = run_collection(arguments.day, arguments.port, arguments.collector_id, arguments.output_dir)
    except (OSError, ValueError) as error:
        parser.exit(1, f"Could not save collection run: {error}\n")
    print(f"Run status: {evidence['runStatus']}")
    print(f"Evidence: {directory / 'evidence.json'}")
    print(f"CSV report: {directory / 'controls.csv'}")
    if evidence["runStatus"] == "FAILED":
        parser.exit(1, f"Collection failed: {evidence['error']}\n")
    print("COMPLETED means execution finished; inspect FAIL, REVIEW, and UNKNOWN findings.")


if __name__ == "__main__":
    main()
