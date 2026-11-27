# Security Alert Triage Report

Fictional local demonstration; no incident actions executed.

- Run ID: 97f1b9517497481ebe02506aa07547fb
- Status: COMPLETED
- Analyst label: demo-analyst (self-declared; not authenticated)
- Analysis started: 2026-11-20T18:51:54.477590+00:00
- Analysis finished: 2026-11-20T18:51:54.478528+00:00

Policy: triage-v1. Cases: 1.

## Dataset timeline

| Event time (UTC) | Event ID | Actor | Event | Outcome |
| --- | --- | --- | --- | --- |
| 2026-11-17T08:40:00Z | suspicious-001 | casey.rivera@example.com | sign\_in | failure |
| 2026-11-17T08:42:00Z | suspicious-002 | casey.rivera@example.com | sign\_in | failure |
| 2026-11-17T08:44:00Z | suspicious-003 | casey.rivera@example.com | sign\_in | failure |
| 2026-11-17T08:50:00Z | suspicious-004 | casey.rivera@example.com | sign\_in | success |
| 2026-11-17T08:55:00Z | suspicious-006 | devon.patel@example.com | iam\_binding\_change | success |
| 2026-11-17T09:00:00Z | suspicious-005 | casey.rivera@example.com | iam\_binding\_change | success |

## Case 1: demo-suspicious:suspicious-005

- Priority: ELEVATED
- Recommendation: ESCALATE\_FOR\_VALIDATION
- Why: Repeated same-actor/IP failures preceded a successful sign-in and privileged grant outside the supplied IP baseline.
- Actor: casey.rivera@example.com; recipient: user:blair.chen@example.com
- Role: roles/owner; resource: projects/demo-triage-project
- Grant time: 2026-11-17T09:00:00Z; source IP: 203.0.113.42
- IP familiarity: OUTSIDE\_SUPPLIED\_BASELINE
- Approval: NOT\_FOUND\_IN\_SUPPLIED\_RECORDS
- Coverage: DECLARED\_COMPLETE
- Incident verdict: UNCONFIRMED; analyst disposition: PENDING
- JSON evidence pointer: report.json#/analysis/cases/0

### Evidence and uncertainty

- Source events: suspicious-001, suspicious-002, suspicious-003 → suspicious-004 → suspicious-005.

### Suggested analyst actions

- Preserve original event/context files and validate source coverage.
- Verify the change with the actor and approver through a trusted channel.
- Inspect identity sessions, MFA/device context, effective access, and recipient activity.
- Escalate suspected active abuse to the incident lead; obtain authorization for containment.
- For temporary access, verify expiry or removal separately; an approval does not remove access.

## Dataset coverage gaps

No dataset-level gaps detected in the supplied context; case-specific gaps may still apply.

## IAM events not selected by this rule

- suspicious-006: Role is not in the tracked administrator-role list.

## Limitations

- Fictional normalized inputs; no provider APIs or authentic source attestations.
- Source coverage and approvals are supplied assumptions, not independently established facts.
- Priority is a reproducible review recommendation, not a compromise or authorization verdict.
- The named roles/project/direct-user scope does not cover every privilege or attack path.
- Matching IPs do not prove a shared session; equal timestamps cannot prove sequence.
- Local report files and adjacent hashes are editable, not authenticated or tamper-evident evidence.
