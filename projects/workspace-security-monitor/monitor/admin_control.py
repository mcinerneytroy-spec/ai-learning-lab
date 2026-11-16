"""Compare IAM observations and correlate grants with normalized audit events."""

from datetime import datetime


ADMIN_ROLES = ("roles/owner", "roles/iam.securityAdmin")
ADMIN_POLICY_VERSION = "new-admins-v1"


def parse_time(value):
    """Require a timezone-aware timestamp before making time comparisons."""
    try:
        stamp = datetime.fromisoformat(value)
    except (TypeError, ValueError) as error:
        raise ValueError("Missing or invalid administrator timestamp.") from error
    if stamp.utcoffset() is None:
        raise ValueError("Administrator timestamps require a timezone.")
    return stamp


def evaluate_new_admins(current, previous=None):
    """Assess validated snapshots; never infer an actor from an IAM assignment.

    Output is limited to direct human grants of two explicitly selected roles.
    Event records are our normalized mock schema, not raw Google audit logs.
    """
    gaps = []
    excluded = set()

    def assignments(snapshot):
        if snapshot.get("sourceStatus", {}).get("iamPolicy") != "complete":
            raise ValueError("Cannot compare an IAM source that is not declared complete.")
        found = set()
        conditional = set()
        for binding in snapshot["iamPolicy"]["bindings"]:
            if binding["role"] not in ADMIN_ROLES:
                continue
            for member in binding["members"]:
                if not member.startswith("user:"):
                    excluded.add(member)
                elif "condition" in binding:
                    conditional.add((binding["role"], member))
                else:
                    found.add((binding["role"], member))
        if conditional:
            gaps.append(f"Conditional administrator bindings not assessed in {snapshot['snapshotId']}.")
        return found - conditional

    now = parse_time(current.get("observedAt"))
    current_assignments = assignments(current)
    prior = None
    prior_assignments = set()
    if previous is not None:
        if previous["resource"] != current["resource"]:
            raise ValueError("Snapshots must describe the same project resource.")
        prior = parse_time(previous.get("observedAt"))
        if prior >= now:
            raise ValueError("Previous snapshot must be older than the current snapshot.")
        prior_assignments = assignments(previous)

    window = current["adminEventWindow"]
    start = parse_time(window.get("startExclusive"))
    end = parse_time(window.get("endInclusive"))
    if not start < end == now:
        raise ValueError("Administrator event window must end at the current observation time.")
    if prior is not None and start != prior:
        gaps.append("Event window does not exactly cover the snapshot comparison interval.")
    if current.get("sourceStatus", {}).get("adminEvents") != "complete":
        gaps.append("Administrator event source is not declared complete.")

    events_by_assignment = {}
    seen_events = {}
    for event in current["adminEvents"]:
        event_id = event.get("eventId")
        if not isinstance(event_id, str) or not event_id:
            gaps.append("An administrator event has no valid event ID.")
            continue
        if event_id in seen_events:
            if event != seen_events[event_id]:
                raise ValueError("Conflicting administrator records share an event ID.")
            continue
        seen_events[event_id] = event
        if event.get("action") not in ("ADD_BINDING", "REMOVE_BINDING"):
            gaps.append(f"Unsupported or missing action in event {event_id}.")
            continue
        if event.get("resource") != current["resource"]:
            gaps.append(f"Unexpected resource in event {event_id}.")
            continue
        try:
            event_time = parse_time(event.get("eventTime"))
        except ValueError:
            gaps.append(f"Invalid timestamp in event {event_id}.")
            continue
        if not start < event_time <= end:
            gaps.append(f"Event {event_id} falls outside its declared window.")
            continue
        if prior is not None and event_time <= prior:
            continue
        if event["action"] != "ADD_BINDING" or event.get("role") not in ADMIN_ROLES:
            continue
        member = event.get("member")
        if not isinstance(member, str) or not member.startswith("user:") or not member[5:]:
            gaps.append(f"Non-user or invalid recipient in tracked grant event {event_id}.")
            continue
        if "condition" in event:
            gaps.append(f"Conditional grant event {event_id} is outside this version's scope.")
            continue
        actor = event.get("actor")
        actor = actor if isinstance(actor, str) and actor.strip() else None
        if actor is None:
            gaps.append(f"Actor unknown for grant event {event_id}.")
        key = (event["role"], member)
        events_by_assignment.setdefault(key, []).append({
            "eventId": event_id, "eventTime": event["eventTime"], "actor": actor,
        })

    added = current_assignments - prior_assignments if previous is not None else set()
    baseline = current_assignments if previous is None else set()
    results = []
    for role, member in sorted(added | baseline | events_by_assignment.keys()):
        key = (role, member)
        events = sorted(events_by_assignment.get(key, []), key=lambda item: (parse_time(item["eventTime"]), item["eventId"]))
        if events:
            status = "REVIEW"
            reason = "Administrator grant event observed; review authorization."
        elif key in added:
            status = "REVIEW"
            reason = "New administrator assignment observed; actor and grant time are unknown."
            gaps.append(f"No matching grant event for {member} receiving {role}.")
        else:
            status = "BASELINE"
            reason = "Existing access recorded; original grant time and approval are unknown."
        results.append({
            "principal": member, "role": role, "status": status, "reason": reason,
            "presentInCurrentSnapshot": key in current_assignments,
            "newSincePreviousSnapshot": key in added if previous is not None else None,
            "grantEvents": events,
        })

    comparison = "BASELINE" if previous is None else "NO_NEW_GRANTS_OBSERVED"
    if any(row["status"] == "REVIEW" for row in results):
        comparison = "REVIEW"
    if gaps:
        comparison = "UNKNOWN"
    return {
        "controlId": "NEW_ADMINISTRATORS", "policyVersion": ADMIN_POLICY_VERSION,
        "snapshotId": current["snapshotId"], "resource": current["resource"],
        "sourceObservedAt": current["observedAt"],
        "previousSnapshotId": previous["snapshotId"] if previous is not None else None,
        "comparisonStart": previous["observedAt"] if previous is not None else None,
        "trackedRoles": list(ADMIN_ROLES),
        "scope": "Direct human-user grants of the listed roles only; inherited access is not assessed.",
        "comparisonStatus": comparison, "coverageGaps": sorted(set(gaps)),
        "excludedPrincipals": sorted(excluded), "results": results,
    }
