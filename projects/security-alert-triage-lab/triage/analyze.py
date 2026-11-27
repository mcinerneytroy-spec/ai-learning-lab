"""Run local triage end to end and retain source evidence and execution failures."""

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from uuid import uuid4

from triage.context import analyze
from triage.parser import DATA_DIRECTORY, ParseError, parse_dataset, reject_duplicate_keys, reject_non_json_constant
from triage.reporting import save_json, save_markdown


OUTPUT_DIRECTORY = Path(__file__).resolve().parent.parent / "outputs"


def now():
    return datetime.now(timezone.utc).isoformat()


def run_analysis(scenario="suspicious", output_directory=OUTPUT_DIRECTORY, analyst_label="demo-analyst", events_path=None, context_path=None):
    if scenario not in ("suspicious", "authorized") or not isinstance(analyst_label, str) or not analyst_label.strip():
        raise ValueError("Choose a bundled scenario and a nonblank analyst label.")
    if (events_path is None) != (context_path is None):
        raise ValueError("Custom input requires both events and context paths.")
    run_id = uuid4().hex
    directory = Path(output_directory) / f"{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}_{run_id}"
    directory.mkdir(parents=True, exist_ok=False)
    report = {"reportSchemaVersion": "1.0", "fictional": True, "runId": run_id,
              "runStatus": "RUNNING", "analystLabel": analyst_label,
              "analysisStartedAt": now(), "analysisCompletedAt": None,
              "sources": [], "analysis": None, "error": None}
    save_json(directory, report)

    def read_source(kind, path):
        evidence = {"kind": kind, "fileName": Path(path).name, "readStartedAt": now()}
        report["sources"].append(evidence)
        try:
            body = Path(path).read_bytes()
            evidence.update(rawBodyBase64=base64.b64encode(body).decode("ascii"),
                            sha256=hashlib.sha256(body).hexdigest())
            value = json.loads(body.decode("utf-8"), object_pairs_hook=reject_duplicate_keys,
                               parse_constant=reject_non_json_constant)
            evidence["parsedInput"] = value
            return value
        finally:
            evidence["readCompletedAt"] = now()
            save_json(directory, report)

    try:
        raw_events = read_source("events", events_path if events_path is not None else DATA_DIRECTORY / scenario / "events.json")
        raw_context = read_source("context", context_path if context_path is not None else DATA_DIRECTORY / scenario / "context.json")
        timeline = parse_dataset(raw_events)
        report["analysis"] = analyze(timeline, raw_context)
        report["runStatus"] = "COMPLETED"
    except (OSError, UnicodeError, ValueError, TypeError) as error:
        report["runStatus"] = "FAILED"
        # Avoid publishing personal filesystem paths in retained error messages.
        report["error"] = "An input file could not be read." if isinstance(error, OSError) else str(error)
    finally:
        report["analysisCompletedAt"] = now()
        save_json(directory, report)
    try:
        save_markdown(directory, report)
    except OSError:
        report.update(runStatus="FAILED", error="Markdown report could not be written.")
        save_json(directory, report)
        raise
    return directory, report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", choices=("suspicious", "authorized"), default="suspicious")
    parser.add_argument("--events", type=Path)
    parser.add_argument("--context", type=Path)
    parser.add_argument("--output-dir", type=Path, default=OUTPUT_DIRECTORY)
    parser.add_argument("--analyst-label", default="demo-analyst")
    args = parser.parse_args()
    try:
        directory, report = run_analysis(args.scenario, args.output_dir, args.analyst_label, args.events, args.context)
    except (OSError, ValueError) as error:
        parser.exit(1, f"Could not execute or save analysis: {error}\n")
    print(f"Run status: {report['runStatus']}")
    print(f"JSON report: {directory / 'report.json'}")
    print(f"Readable report: {directory / 'report.md'}")
    if report["runStatus"] == "FAILED":
        parser.exit(1, f"Analysis failed: {report['error']}\n")
    for case in report["analysis"]["cases"]:
        print(f"{case['priority']}: {case['caseId']} | {case['recommendation']} | Approval: {case['approvalStatus']}")
    if not report["analysis"]["cases"]:
        print("No scoped candidates supplied; this is not an all-clear conclusion.")
    print("Execution completed. Incident verdicts remain UNCONFIRMED; no actions were executed.")


if __name__ == "__main__":
    main()
