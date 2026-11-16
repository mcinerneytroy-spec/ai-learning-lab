"""Reconcile inventory and EDR observations without network or file operations."""

from datetime import datetime, timedelta


EDR_POLICY_VERSION = "edr-v1"
MAX_CHECK_IN_AGE = timedelta(hours=24)
UNHEALTHY_STATUSES = ("unhealthy", "disabled", "offline")


def parse_timestamp(value):
    """Parse a timestamp only when its timezone is explicit."""
    try:
        stamp = datetime.fromisoformat(value)
    except (TypeError, ValueError) as error:
        raise ValueError("Missing or invalid timestamp.") from error
    if stamp.utcoffset() is None:
        raise ValueError("Timestamp needs a timezone.")
    return stamp


def assess_agent(agent, observed_at):
    """Return a decision, reason, and time evidence for one matched agent."""
    age_seconds = None
    time_issue = None
    try:
        last_seen = parse_timestamp(agent.get("lastSeenAt"))
        age = observed_at - last_seen
        age_seconds = age.total_seconds()
        if age < timedelta(0):
            time_issue = "Agent check-in is later than the source observation time."
    except ValueError:
        time_issue = "Missing, invalid, or timezone-free check-in timestamp."

    agent_id = agent.get("agentId")
    status = agent.get("status")
    if not isinstance(agent_id, str) or not agent_id.strip():
        outcome, reason = "UNKNOWN", "Matched observation has no valid agent ID."
    elif status in UNHEALTHY_STATUSES:
        outcome, reason = "FAIL", f"Agent status is {status}."
        if time_issue:
            reason += f" {time_issue}"
    elif time_issue:
        outcome, reason = "UNKNOWN", time_issue
    elif age > MAX_CHECK_IN_AGE:
        outcome, reason = "FAIL", "Agent check-in is older than the 24-hour threshold."
    elif status != "healthy":
        outcome, reason = "UNKNOWN", "Missing or unrecognized agent health status."
    else:
        outcome, reason = "PASS", "Agent is healthy and reported within 24 hours."
    return outcome, reason, age_seconds


def evaluate_edr(snapshot):
    """Assess required devices from a structurally validated fictional snapshot.

    Incomplete source declarations prevent an assessment. Missing agents are a
    finding only when the EDR response is declared complete. Duplicate agent
    matches are ambiguous rather than silently choosing the healthiest record.
    """
    for source in ("devices", "edrObservations"):
        if snapshot.get("sourceStatus", {}).get(source) != "complete":
            raise ValueError(f"Cannot assess EDR: {source} is not declared complete.")
    observed_at = parse_timestamp(snapshot.get("observedAt"))
    inventory = snapshot["devices"]
    device_ids = {device["deviceId"] for device in inventory}
    if len(device_ids) != len(inventory):
        raise ValueError("Duplicate inventory device IDs prevent reliable matching.")

    agents_by_device = {}
    gaps = []
    unmatched = set()
    agent_owners = {}
    for agent in snapshot["edrObservations"]:
        device_id = agent.get("deviceId")
        if not isinstance(device_id, str) or not device_id:
            gaps.append("An EDR observation has no valid device ID.")
            continue
        if device_id not in device_ids:
            unmatched.add(device_id)
        agents_by_device.setdefault(device_id, []).append(agent)
        agent_id = agent.get("agentId")
        if isinstance(agent_id, str) and agent_id.strip():
            agent_owners.setdefault(agent_id, set()).add(device_id)
    if unmatched:
        gaps.append("Some EDR devices are absent from the inventory; reconcile inventory completeness.")

    results = []
    excluded = []
    for device in sorted(inventory, key=lambda record: record["deviceId"]):
        required = device.get("edrRequired")
        if required is False:
            excluded.append(device["deviceId"])
            continue
        matches = agents_by_device.get(device["deviceId"], [])
        age_seconds = None
        if required is not True:
            status, reason = "UNKNOWN", "EDR applicability is missing or invalid."
        elif not matches:
            status, reason = "FAIL", "Required device is absent from the complete EDR observations."
        elif len(matches) != 1:
            status, reason = "UNKNOWN", "Multiple agent observations match this inventory device."
        elif isinstance(matches[0].get("agentId"), str) and len(agent_owners.get(matches[0]["agentId"], set())) > 1:
            status, reason = "UNKNOWN", "Agent ID is shared across devices; matching is ambiguous."
        else:
            status, reason, age_seconds = assess_agent(matches[0], observed_at)

        results.append({
            "deviceId": device["deviceId"], "hostname": device.get("hostname"),
            "status": status, "reason": reason,
            "evidence": {
                "edrRequired": required, "matchedAgentCount": len(matches),
                "agentObservations": [dict(agent) for agent in matches],
                "checkInAgeSeconds": age_seconds,
            },
        })

    return {
        "controlId": "EDR_COVERAGE", "policyVersion": EDR_POLICY_VERSION,
        "snapshotId": snapshot["snapshotId"], "resource": snapshot["resource"],
        "sourceObservedAt": snapshot["observedAt"],
        "maxCheckInAgeSeconds": int(MAX_CHECK_IN_AGE.total_seconds()),
        "scope": "Inventory devices explicitly marked as requiring EDR.",
        "excludedDeviceIds": excluded, "unmatchedEdrDeviceIds": sorted(unmatched),
        "coverageGaps": sorted(set(gaps)), "results": results,
    }
