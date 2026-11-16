"""Write local evidence and spreadsheet-friendly CSV observations."""

import csv
import io
import json
import os
import tempfile
from pathlib import Path


CONTROL_IDS = ("MFA_COVERAGE", "NEW_ADMINISTRATORS", "EDR_COVERAGE")
CSV_FIELDS = (
    "runId", "runStatus", "collectorId", "collectionStartedAt", "collectionCompletedAt",
    "snapshotId", "sourceObservedAt", "resource", "controlId", "policyVersion",
    "recordType", "subject", "role", "status", "actor", "eventTime", "eventId",
    "reason", "evidencePointer",
)


def atomic_write(path, text):
    """Replace one complete file, rather than exposing a half-written file."""
    path = Path(path)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="", dir=path.parent, delete=False) as file:
            temporary = Path(file.name)
            file.write(text)
            file.flush()
            os.fsync(file.fileno())
        temporary.replace(path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def write_evidence(directory, evidence):
    atomic_write(Path(directory) / "evidence.json", json.dumps(evidence, indent=2, allow_nan=False) + "\n")


def scoped_summary(control):
    if "comparisonStatus" in control:
        return control["comparisonStatus"]
    statuses = {row["status"] for row in control["results"]}
    if control.get("coverageGaps") or "UNKNOWN" in statuses:
        return "UNKNOWN"
    if "FAIL" in statuses:
        return "FAIL"
    return "PASS_IN_SCOPE" if statuses else "NO_IN_SCOPE_SUBJECTS"


def csv_rows(evidence):
    """Include control summaries, findings, exclusions, and coverage gaps."""
    base = {key: evidence.get(key, "") for key in (
        "runId", "runStatus", "collectorId", "collectionStartedAt", "collectionCompletedAt"
    )}
    reports = {report["controlId"]: (index, report) for index, report in enumerate(evidence["controls"])}
    for control_id in CONTROL_IDS:
        if control_id not in reports:
            yield dict(base, controlId=control_id, recordType="CONTROL_SUMMARY", status="NOT_EVALUATED",
                       reason=evidence.get("error") or "Run has not evaluated this control.", evidencePointer="evidence.json#/runStatus")
            continue
        index, control = reports[control_id]
        prefix = f"evidence.json#/controls/{index}"
        common = dict(base, controlId=control_id, policyVersion=control["policyVersion"],
                      snapshotId=control["snapshotId"], resource=control["resource"],
                      sourceObservedAt=control["sourceObservedAt"])
        yield dict(common, recordType="CONTROL_SUMMARY", status=scoped_summary(control),
                   reason=control["scope"], evidencePointer=prefix)
        for row_index, row in enumerate(control["results"]):
            events = row.get("grantEvents") or [{}]
            for event in events:
                yield dict(common, recordType="OBSERVATION", subject=row.get("principal", row.get("deviceId", "")),
                           role=row.get("role", "; ".join(row.get("roles", []))), status=row["status"],
                           actor=event.get("actor") or "UNKNOWN", eventTime=event.get("eventTime") or "UNKNOWN",
                           eventId=event.get("eventId", ""), reason=row["reason"],
                           evidencePointer=f"{prefix}/results/{row_index}")
        for gap_index, gap in enumerate(control.get("coverageGaps", [])):
            yield dict(common, recordType="COVERAGE_GAP", status="UNKNOWN", reason=gap,
                       evidencePointer=f"{prefix}/coverageGaps/{gap_index}")
        for field in ("excludedPrincipals", "excludedDeviceIds", "unmatchedEdrDeviceIds"):
            for item_index, subject in enumerate(control.get(field, [])):
                unmatched = field == "unmatchedEdrDeviceIds"
                yield dict(common, recordType="UNMATCHED" if unmatched else "EXCLUSION", subject=subject,
                           status="UNKNOWN" if unmatched else "EXCLUDED", reason=field,
                           evidencePointer=f"{prefix}/{field}/{item_index}")


def safe_csv_cell(value):
    """Neutralize formula-like cells; JSON retains original unmodified values."""
    text = str(value)
    if text.lstrip().startswith(("=", "+", "-", "@")) or text.startswith(("\t", "\r", "\n")):
        return "'" + text
    return text


def write_csv(directory, evidence):
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=CSV_FIELDS)
    writer.writeheader()
    for row in csv_rows(evidence):
        writer.writerow({key: safe_csv_cell(value) for key, value in row.items()})
    atomic_write(Path(directory) / "controls.csv", output.getvalue())
