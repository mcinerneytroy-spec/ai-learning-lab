"""Validate analyst-supplied context and recommend a reproducible triage priority."""

import copy
import ipaddress
import json

from triage.detection import correlate_grants
from triage.parser import ParseError, parse_timestamp, require_text


POLICY_VERSION = "triage-v1"
FAILED_SIGN_IN_THRESHOLD = 3
SOURCES = ("identityEvents", "iamEvents", "changeRecords", "actorBaselines")


def validate_context(raw, dataset_id):
    """Reject a wrong envelope; disclose missing/invalid contextual evidence."""
    if not isinstance(raw, dict) or raw.get("schemaVersion") != "1.0" or raw.get("fictional") is not True:
        raise ParseError("Context requires schemaVersion 1.0 and fictional=true.")
    if raw.get("datasetId") != dataset_id:
        raise ParseError("Events and context must have the same datasetId.")
    gaps = []
    coverage = raw.get("declaredCoverage")
    coverage = coverage if isinstance(coverage, dict) else {}
    for source in SOURCES:
        if coverage.get(source) != "complete":
            gaps.append(f"{source} coverage is not declared complete.")
    window = None
    try:
        start = parse_timestamp(raw.get("eventWindow", {}).get("startInclusive"))
        end = parse_timestamp(raw.get("eventWindow", {}).get("endExclusive"))
        if start >= end:
            raise ParseError("Event window is reversed or empty.")
        window = (start, end)
    except (ParseError, AttributeError):
        gaps.append("Context event window is missing or invalid.")

    baselines = {}
    baseline_indices = {}
    rows = raw.get("actorBaselines")
    if not isinstance(rows, list):
        gaps.append("Actor baseline list is missing or invalid.")
        rows = []
    for index, row in enumerate(rows):
        actor = row.get("actor") if isinstance(row, dict) else None
        if not isinstance(actor, str) or not actor.strip():
            gaps.append(f"Baseline index {index} has no valid actor.")
            continue
        baseline_indices.setdefault(actor, []).append(index)
        try:
            cidrs = row.get("knownSourceCidrs")
            if not isinstance(cidrs, list) or not cidrs:
                raise ValueError("No baseline networks")
            networks = [ipaddress.ip_network(cidr, strict=True) for cidr in cidrs if isinstance(cidr, str)]
            if len(networks) != len(cidrs):
                raise ValueError("Invalid network type")
            baselines[actor] = networks
        except ValueError:
            baselines[actor] = None
            gaps.append(f"Baseline index {index} has missing or invalid networks.")
    for actor, indices in baseline_indices.items():
        if len(indices) > 1:
            baselines[actor] = None
            gaps.append(f"Multiple baseline records match actor {actor}.")

    approvals = []
    seen = {}
    rows = raw.get("changeRecords")
    if not isinstance(rows, list):
        gaps.append("Change-record list is missing or invalid.")
        rows = []
    for index, row in enumerate(rows):
        try:
            if not isinstance(row, dict):
                raise ParseError("Change record must be an object.")
            change_id = require_text(row, "changeId")
            fingerprint = json.dumps(row, sort_keys=True, allow_nan=False)
            if change_id in seen:
                if seen[change_id] != fingerprint:
                    raise ParseError("Conflicting change IDs.")
                continue
            seen[change_id] = fingerprint
            for field in ("actor", "recipient", "resource", "role", "approvedBy"):
                require_text(row, field)
            if row.get("status") not in ("approved", "pending", "rejected", "revoked"):
                raise ParseError("Unknown change status.")
            approved = parse_timestamp(row.get("approvedAt"))
            begin = parse_timestamp(row.get("windowStartInclusive"))
            finish = parse_timestamp(row.get("windowEndExclusive"))
            if begin >= finish:
                raise ParseError("Invalid change window.")
            approvals.append({"record": copy.deepcopy(row), "index": index,
                              "approved": approved, "start": begin, "end": finish})
        except (ParseError, TypeError, ValueError) as error:
            # A conflicting approval identifier makes the input ambiguous.
            if str(error) == "Conflicting change IDs.":
                raise ParseError("Conflicting records share a changeId.") from error
            gaps.append(f"Change record index {index} is invalid and was not used for approval matching.")
    approval_context_complete = (coverage.get("changeRecords") == "complete"
                                 and isinstance(raw.get("changeRecords"), list)
                                 and not any(gap.startswith("Change record") for gap in gaps))
    return {"coverage": coverage, "window": window, "baselines": baselines,
            "approvalContextComplete": approval_context_complete,
            "baselineIndices": baseline_indices, "approvals": approvals, "gaps": gaps}


def analyze(timeline, raw_context):
    """Return facts, uncertainties, and recommendations, never an incident verdict."""
    context = validate_context(raw_context, timeline["datasetId"])
    correlation = correlate_grants(timeline)
    global_gaps = list(context["gaps"])
    window = context["window"]
    if window and any(not window[0] <= parse_timestamp(e["occurredAtUtc"]) < window[1] for e in timeline["events"]):
        global_gaps.append("Some supplied events fall outside the declared context window.")
    cases = []
    for candidate in correlation["candidates"]:
        case = copy.deepcopy(candidate)
        grant = case["grant"]["record"]
        grant_time = parse_timestamp(case["grant"]["occurredAtUtc"])
        lookback_start = parse_timestamp(case["windowStartInclusive"])
        gaps = list(global_gaps)
        if not window or window[0] > lookback_start or grant_time >= window[1]:
            gaps.append("Declared event window does not cover the full grant lookback interval.")
        actor = grant["actor"]
        networks = context["baselines"].get(actor)
        if context["coverage"].get("actorBaselines") != "complete" or not networks:
            familiarity = "UNKNOWN"
            gaps.append("No complete, unambiguous IP baseline is available for the granting actor.")
        else:
            address = ipaddress.ip_address(case["grant"]["sourceIpNormalized"])
            familiarity = "KNOWN_IN_SUPPLIED_BASELINE" if any(address in network for network in networks) else "OUTSIDE_SUPPLIED_BASELINE"

        matched = []
        for approval in context["approvals"]:
            record = approval["record"]
            if (record["status"] == "approved" and approval["approved"] < grant_time
                    and approval["start"] <= grant_time < approval["end"]
                    and all(record[field] == grant[field] for field in ("actor", "recipient", "resource", "role"))):
                matched.append({"contextRecordIndex": approval["index"], "record": copy.deepcopy(record)})
        if matched:
            approval_status = "MATCHED"
        elif not context["approvalContextComplete"]:
            approval_status = "UNKNOWN"
        else:
            approval_status = "NOT_FOUND_IN_SUPPLIED_RECORDS"

        chains = []
        successes_before_grant = []
        for sign_in in case["actorSignIns"]:
            if not sign_in["sameSourceIpAsGrant"] or sign_in["record"]["outcome"] != "success":
                continue
            success_time = parse_timestamp(sign_in["occurredAtUtc"])
            if success_time >= grant_time:
                gaps.append("A sign-in shares the grant timestamp; preceding order is unproven.")
                continue
            successes_before_grant.append(sign_in["record"]["eventId"])
            failures = [e["record"]["eventId"] for e in case["actorSignIns"]
                        if e["sameSourceIpAsGrant"] and e["record"]["outcome"] == "failure"
                        and parse_timestamp(e["occurredAtUtc"]) < success_time]
            if len(failures) >= FAILED_SIGN_IN_THRESHOLD:
                chains.append({"failureEventIds": failures, "successEventId": sign_in["record"]["eventId"],
                               "grantEventId": grant["eventId"]})

        elevated = bool(chains) and familiarity == "OUTSIDE_SUPPLIED_BASELINE"
        if not successes_before_grant:
            gaps.append("No matching successful sign-in strictly before the grant was supplied.")
        if elevated:
            priority, recommendation = "ELEVATED", "ESCALATE_FOR_VALIDATION"
            reason = "Repeated same-actor/IP failures preceded a successful sign-in and privileged grant outside the supplied IP baseline."
        elif gaps:
            priority, recommendation = "REVIEW", "INVESTIGATE_CONTEXT_GAPS"
            reason = "Context gaps prevent a routine-review recommendation."
        elif matched and familiarity == "KNOWN_IN_SUPPLIED_BASELINE" and not chains:
            priority, recommendation = "ROUTINE", "ROUTINE_REVIEW"
            reason = "Observed sign-in and grant have supporting IP baseline and matching prior approval."
        else:
            priority, recommendation = "REVIEW", "VERIFY_CHANGE"
            reason = "Validate the privilege change and identity activity; supplied context does not support routine handling."
        case.update({
            "caseId": f"{timeline['datasetId']}:{grant['eventId']}",
            "priority": priority, "recommendation": recommendation, "priorityReason": reason,
            "approvalStatus": approval_status, "matchingApprovals": matched,
            "ipFamiliarity": familiarity, "baselineContextIndices": context["baselineIndices"].get(actor, []),
            "signalSequences": chains, "elevatedSignalObserved": elevated,
            "contextCoverage": "INCOMPLETE_OR_UNKNOWN" if gaps else "DECLARED_COMPLETE",
            "coverageGaps": sorted(set(gaps)), "incidentVerdict": "UNCONFIRMED",
            "analystDisposition": "PENDING",
            "nextActions": [
                "Preserve original event/context files and validate source coverage.",
                "Verify the change with the actor and approver through a trusted channel.",
                "Inspect identity sessions, MFA/device context, effective access, and recipient activity.",
                "Escalate suspected active abuse to the incident lead; obtain authorization for containment.",
                "For temporary access, verify expiry or removal separately; an approval does not remove access.",
            ],
        })
        cases.append(case)
    return {
        "datasetId": timeline["datasetId"], "policyVersion": POLICY_VERSION,
        "correlationRuleVersion": correlation["ruleVersion"], "lookbackMinutes": correlation["lookbackMinutes"],
        "failedSignInThreshold": FAILED_SIGN_IN_THRESHOLD, "trackedRoles": correlation["trackedRoles"],
        "resource": correlation["resource"], "cases": cases,
        "coverageGaps": sorted(set(global_gaps)), "skippedIamEvents": correlation["skippedIamEvents"],
        "timeline": copy.deepcopy(timeline),
        "limitations": [
            "Fictional normalized inputs; no provider APIs or authentic source attestations.",
            "Source coverage and approvals are supplied assumptions, not independently established facts.",
            "Priority is a reproducible review recommendation, not a compromise or authorization verdict.",
            "The named roles/project/direct-user scope does not cover every privilege or attack path.",
            "Matching IPs do not prove a shared session; equal timestamps cannot prove sequence.",
        ],
    }
