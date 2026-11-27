"""Save complete JSON and readable Markdown, escaping untrusted display text."""

import html
import json
import os
from pathlib import Path
import tempfile


def atomic_write(path, content):
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
    finally:
        if temporary:
            temporary.unlink(missing_ok=True)


def save_json(directory, report):
    atomic_write(Path(directory) / "report.json", json.dumps(report, indent=2, allow_nan=False) + "\n")


def display(value):
    text = html.escape(str(value), quote=False)
    for character in ("\\", "`", "*", "_", "[", "]", "|", "#"):
        text = text.replace(character, "\\" + character)
    return text.replace("\r", "").replace("\n", "<br>")


def markdown_report(report):
    lines = ["# Security Alert Triage Report", "", "Fictional local demonstration; no incident actions executed.", "",
             f"- Run ID: {display(report['runId'])}", f"- Status: {display(report['runStatus'])}",
             f"- Analyst label: {display(report['analystLabel'])} (self-declared; not authenticated)",
             f"- Analysis started: {display(report['analysisStartedAt'])}",
             f"- Analysis finished: {display(report['analysisCompletedAt'])}", ""]
    if report.get("error"):
        lines += [f"Execution error: {display(report['error'])}", "", "Analysis was not completed; this is not a clean result.", ""]
    analysis = report.get("analysis")
    if analysis is None:
        return "\n".join(lines)
    lines += [f"Policy: {display(analysis['policyVersion'])}. Cases: {len(analysis['cases'])}.", "",
              "## Dataset timeline", "", "| Event time (UTC) | Event ID | Actor | Event | Outcome |",
              "| --- | --- | --- | --- | --- |"]
    for item in analysis["timeline"]["events"]:
        event = item["record"]
        lines.append("| " + " | ".join(display(v) for v in (item["occurredAtUtc"], event["eventId"], event["actor"], event["eventType"], event["outcome"])) + " |")
    lines.append("")
    if not analysis["cases"]:
        lines += ["No scoped candidates were supplied; this is not an all-clear conclusion.", ""]
    for index, case in enumerate(analysis["cases"]):
        grant = case["grant"]["record"]
        lines += [f"## Case {index + 1}: {display(case['caseId'])}", "",
                  f"- Priority: {display(case['priority'])}", f"- Recommendation: {display(case['recommendation'])}",
                  f"- Why: {display(case['priorityReason'])}",
                  f"- Actor: {display(grant['actor'])}; recipient: {display(grant['recipient'])}",
                  f"- Role: {display(grant['role'])}; resource: {display(grant['resource'])}",
                  f"- Grant time: {display(case['grant']['occurredAtUtc'])}; source IP: {display(case['grant']['sourceIpNormalized'])}",
                  f"- IP familiarity: {display(case['ipFamiliarity'])}", f"- Approval: {display(case['approvalStatus'])}",
                  f"- Coverage: {display(case['contextCoverage'])}",
                  "- Incident verdict: UNCONFIRMED; analyst disposition: PENDING",
                  f"- JSON evidence pointer: report.json#/analysis/cases/{index}", "", "### Evidence and uncertainty", ""]
        for sequence in case["signalSequences"]:
            lines.append(f"- Source events: {display(', '.join(sequence['failureEventIds']))} → {display(sequence['successEventId'])} → {display(sequence['grantEventId'])}.")
        for approval in case["matchingApprovals"]:
            record = approval["record"]
            lines.append(f"- Approval {display(record['changeId'])}, approved by {display(record['approvedBy'])} at {display(record['approvedAt'])}; context index {approval['contextRecordIndex']}.")
        for gap in case["coverageGaps"]:
            lines.append(f"- Gap: {display(gap)}")
        lines += ["", "### Suggested analyst actions", ""]
        lines.extend(f"- {display(action)}" for action in case["nextActions"])
        lines.append("")
    lines += ["## Dataset coverage gaps", ""]
    lines.extend(f"- {display(gap)}" for gap in analysis["coverageGaps"])
    if not analysis["coverageGaps"]:
        lines.append("No dataset-level gaps detected in the supplied context; case-specific gaps may still apply.")
    lines += ["", "## IAM events not selected by this rule", ""]
    lines.extend(f"- {display(item['eventId'])}: {display(item['reason'])}" for item in analysis["skippedIamEvents"])
    lines += ["", "## Limitations", ""]
    lines.extend(f"- {display(value)}" for value in analysis["limitations"])
    lines += ["- Local report files and adjacent hashes are editable, not authenticated or tamper-evident evidence.", ""]
    return "\n".join(lines)


def save_markdown(directory, report):
    atomic_write(Path(directory) / "report.md", markdown_report(report))
