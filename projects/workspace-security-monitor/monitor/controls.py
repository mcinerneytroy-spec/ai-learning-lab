"""Pure control checks: accept Python data without HTTP or file operations."""


MFA_POLICY_VERSION = "mfa-v1"


def evaluate_mfa(snapshot):
    """Assess direct IAM human users in a structurally validated snapshot.

    Both enrollment and enforcement are required by this demo policy. A known
    false value establishes failure; missing or invalid evidence never passes.
    Groups, service accounts, and other principal types are explicitly excluded.
    Conditional user bindings are reported UNKNOWN until supported.
    """
    for source in ("directoryUsers", "iamPolicy"):
        if snapshot.get("sourceStatus", {}).get(source) != "complete":
            raise ValueError(f"Cannot assess MFA: {source} is not declared complete.")

    users_by_email = {}
    for user in snapshot["directoryUsers"]:
        users_by_email.setdefault(user["primaryEmail"], []).append(user)

    roles_by_member = {}
    conditional_members = set()
    excluded_members = set()
    for binding in snapshot["iamPolicy"]["bindings"]:
        for member in binding["members"]:
            if not member.startswith("user:"):
                excluded_members.add(member)
                continue
            roles_by_member.setdefault(member, set()).add(binding["role"])
            if "condition" in binding:
                conditional_members.add(member)

    results = []
    for member, roles in sorted(roles_by_member.items()):
        matches = users_by_email.get(member.removeprefix("user:"), [])
        user = matches[0] if len(matches) == 1 else None
        evidence = {
            "isEnrolledIn2Sv": user.get("isEnrolledIn2Sv") if user else None,
            "isEnforcedIn2Sv": user.get("isEnforcedIn2Sv") if user else None,
            "suspended": user.get("suspended") if user else None,
        }

        if member in conditional_members:
            status = "UNKNOWN"
            reason = "Conditional IAM access is outside this version's evaluation scope."
        elif user is None:
            status = "UNKNOWN"
            reason = "No unique directory record matches this IAM user."
        else:
            disabled = []
            invalid = []
            for field, label in (("isEnrolledIn2Sv", "enrollment"), ("isEnforcedIn2Sv", "enforcement")):
                value = evidence[field]
                if value is False:
                    disabled.append(label)
                elif type(value) is not bool:
                    invalid.append(label)

            if disabled:
                status = "FAIL"
                reason = f"MFA {' and '.join(disabled)} disabled."
                if invalid:
                    reason += f" Missing or invalid {' and '.join(invalid)} evidence."
            elif invalid:
                status = "UNKNOWN"
                reason = f"Missing or invalid MFA {' and '.join(invalid)} evidence."
            else:
                status = "PASS"
                reason = "MFA enrollment and enforcement are both enabled."

        results.append({
            "principal": member,
            "userId": user["id"] if user else None,
            "roles": sorted(roles),
            "status": status,
            "reason": reason,
            "evidence": evidence,
        })

    return {
        "controlId": "MFA_COVERAGE",
        "policyVersion": MFA_POLICY_VERSION,
        "snapshotId": snapshot["snapshotId"],
        "resource": snapshot["resource"],
        "sourceObservedAt": snapshot["observedAt"],
        "scope": "Direct human-user IAM bindings only; inherited access is not assessed.",
        "excludedPrincipals": sorted(excluded_members),
        "results": results,
    }
