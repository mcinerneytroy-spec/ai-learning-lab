# Security Alert Triage Report

Fictional local demonstration; no incident actions executed.

- Run ID: 44b12277ce0844c1a9a65e7b893dfdfd
- Status: COMPLETED
- Analyst label: demo-analyst (self-declared; not authenticated)
- Analysis started: 2026-11-20T18:51:54.479216+00:00
- Analysis finished: 2026-11-20T18:51:54.479938+00:00

Policy: triage-v1. Cases: 1.

## Dataset timeline

| Event time (UTC) | Event ID | Actor | Event | Outcome |
| --- | --- | --- | --- | --- |
| 2026-11-17T08:50:00Z | authorized-001 | casey.rivera@example.com | sign\_in | success |
| 2026-11-17T09:00:00Z | authorized-002 | casey.rivera@example.com | iam\_binding\_change | success |
| 2026-11-17T09:05:00Z | authorized-003 | casey.rivera@example.com | iam\_binding\_change | success |

## Case 1: demo-authorized:authorized-002

- Priority: ROUTINE
- Recommendation: ROUTINE\_REVIEW
- Why: Observed sign-in and grant have supporting IP baseline and matching prior approval.
- Actor: casey.rivera@example.com; recipient: user:emery.brooks@example.com
- Role: roles/iam.securityAdmin; resource: projects/demo-triage-project
- Grant time: 2026-11-17T09:00:00Z; source IP: 192.0.2.20
- IP familiarity: KNOWN\_IN\_SUPPLIED\_BASELINE
- Approval: MATCHED
- Coverage: DECLARED\_COMPLETE
- Incident verdict: UNCONFIRMED; analyst disposition: PENDING
- JSON evidence pointer: report.json#/analysis/cases/0

### Evidence and uncertainty

- Approval CHG-DEMO-001, approved by devon.patel@example.com at 2026-11-17T08:00:00Z; context index 0.

### Suggested analyst actions

- Preserve original event/context files and validate source coverage.
- Verify the change with the actor and approver through a trusted channel.
- Inspect identity sessions, MFA/device context, effective access, and recipient activity.
- Escalate suspected active abuse to the incident lead; obtain authorization for containment.
- For temporary access, verify expiry or removal separately; an approval does not remove access.

## Dataset coverage gaps

No dataset-level gaps detected in the supplied context; case-specific gaps may still apply.

## IAM events not selected by this rule

- authorized-003: Role is not in the tracked administrator-role list.

## Limitations

- Fictional normalized inputs; no provider APIs or authentic source attestations.
- Source coverage and approvals are supplied assumptions, not independently established facts.
- Priority is a reproducible review recommendation, not a compromise or authorization verdict.
- The named roles/project/direct-user scope does not cover every privilege or attack path.
- Matching IPs do not prove a shared session; equal timestamps cannot prove sequence.
- Local report files and adjacent hashes are editable, not authenticated or tamper-evident evidence.
