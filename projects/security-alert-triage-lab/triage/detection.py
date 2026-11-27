"""Select privileged grants and correlate the granting actor's earlier sign-ins."""

import argparse
import copy
from datetime import timedelta
from pathlib import Path

from triage.parser import DATA_DIRECTORY, ParseError, load_events, parse_timestamp


RULE_VERSION = "privileged-grant-correlation-v1"
TARGET_RESOURCE = "projects/demo-triage-project"
TRACKED_ROLES = ("roles/owner", "roles/iam.securityAdmin")
LOOKBACK_MINUTES = 30


def grant_exclusion_reason(event):
    """Explain why an IAM change is not a supported grant candidate."""
    if event["outcome"] != "success":
        return "Operation did not succeed."
    if event["changeAction"] != "ADD":
        return "Operation is not an ADD."
    if event["role"] not in TRACKED_ROLES:
        return "Role is not in the tracked administrator-role list."
    if event["resource"] != TARGET_RESOURCE:
        return "Resource is outside the scoped project."
    if not event["recipient"].startswith("user:") or not event["recipient"][5:].strip():
        return "Recipient is outside the direct human-user scope."
    if "condition" in event:
        return "Conditional grant is outside this rule's scope."
    return None


def correlate_grants(timeline):
    """Accept parse_dataset/load_events output and return evidence-linked candidates.

    Sign-ins are correlated by granting actor and event time, not by recipient.
    Context completeness, IP familiarity, approvals, and severity are not evaluated.
    The input timeline is never changed and no files or services are accessed.
    """
    sign_ins_by_actor = {}
    for item in timeline["events"]:
        event = item["record"]
        if event["eventType"] == "sign_in":
            sign_ins_by_actor.setdefault(event["actor"], []).append(item)

    candidates = []
    skipped = []
    for item in timeline["events"]:
        event = item["record"]
        if event["eventType"] != "iam_binding_change":
            continue
        reason = grant_exclusion_reason(event)
        if reason is not None:
            skipped.append({"eventId": event["eventId"], "reason": reason})
            continue

        grant_time = parse_timestamp(item["occurredAtUtc"])
        window_start = grant_time - timedelta(minutes=LOOKBACK_MINUTES)
        matched = []
        for sign_in in sign_ins_by_actor.get(event["actor"], []):
            sign_in_time = parse_timestamp(sign_in["occurredAtUtc"])
            if window_start <= sign_in_time <= grant_time:
                evidence = copy.deepcopy(sign_in)
                evidence["sameSourceIpAsGrant"] = sign_in["sourceIpNormalized"] == item["sourceIpNormalized"]
                evidence["sameTimeAsGrant"] = sign_in_time == grant_time
                matched.append(evidence)

        candidates.append({
            "status": "REVIEW",
            "reason": "Successful tracked administrator grant; sign-in context gathered for review.",
            "grant": copy.deepcopy(item),
            "windowStartInclusive": window_start.isoformat().replace("+00:00", "Z"),
            "windowEndInclusive": item["occurredAtUtc"],
            "actorSignIns": matched,
            "failedSignInCount": sum(sign_in["record"]["outcome"] == "failure" for sign_in in matched),
            "successfulSignInCount": sum(sign_in["record"]["outcome"] == "success" for sign_in in matched),
            "approvalStatus": "NOT_EVALUATED",
            "priority": "NOT_EVALUATED",
            "contextCoverage": "NOT_EVALUATED",
        })

    return {
        "datasetId": timeline["datasetId"], "ruleVersion": RULE_VERSION,
        "resource": TARGET_RESOURCE, "trackedRoles": list(TRACKED_ROLES),
        "lookbackMinutes": LOOKBACK_MINUTES,
        "inputRecordCount": timeline["inputRecordCount"],
        "uniqueEventCount": timeline["uniqueEventCount"],
        "duplicateRecordCount": timeline["duplicateRecordCount"],
        "grantCount": len(candidates), "candidates": candidates,
        "skippedIamEvents": skipped,
        "limitations": [
            "Only the named project, roles, and direct human recipients are assessed.",
            "Source coverage is not assessed; missing sign-ins do not prove no sign-ins occurred.",
            "Equal timestamps do not establish ordering; matching IPs do not establish a shared session.",
            "No IP baseline, approval, severity, compromise, or remediation decision is made.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("--scenario", choices=("suspicious", "authorized"))
    selection.add_argument("--file", type=Path)
    arguments = parser.parse_args()
    path = arguments.file if arguments.file is not None else DATA_DIRECTORY / (arguments.scenario or "suspicious") / "events.json"
    try:
        report = correlate_grants(load_events(path))
    except ParseError as error:
        parser.exit(1, f"Detection could not run: {error}\n")

    print(f"Dataset: {report['datasetId']} | Rule: {report['ruleVersion']}")
    print(f"Privileged grant candidates: {report['grantCount']}")
    for candidate in report["candidates"]:
        grant = candidate["grant"]["record"]
        print(f"REVIEW {grant['eventId']}: {grant['actor']} -> {grant['recipient']} | {grant['role']}")
        print(f"  Window: {candidate['windowStartInclusive']} through {candidate['windowEndInclusive']} (inclusive)")
        print(f"  Actor sign-ins: {len(candidate['actorSignIns'])} | Failed: {candidate['failedSignInCount']} | Successful: {candidate['successfulSignInCount']}")
        for sign_in in candidate["actorSignIns"]:
            event = sign_in["record"]
            print(f"    {sign_in['occurredAtUtc']} | {event['eventId']} | {event['outcome']} | Same IP as grant: {sign_in['sameSourceIpAsGrant']}")
            if sign_in["sameTimeAsGrant"]:
                print("      Same timestamp as grant; ordering cannot be established.")
        if not candidate["actorSignIns"]:
            print("  No matching sign-ins supplied; identity coverage has not been assessed.")
    for skipped in report["skippedIamEvents"]:
        print(f"Not selected: {skipped['eventId']} | {skipped['reason']}")
    if not report["candidates"]:
        print("No matching grants in the supplied events; this is not an all-clear conclusion.")
    print("Approval, IP familiarity, priority, and context coverage are NOT_EVALUATED.")
    print("No report files saved. No incident or remediation decision made.")


if __name__ == "__main__":
    main()
