# Investigation specification: privileged IAM grant

## Objective and scope

Produce a defensible triage recommendation for each successful ADD of
`roles/owner` or `roles/iam.securityAdmin` in the fictional project
`projects/demo-triage-project`. Start with direct human recipients only.
Group expansion, inherited/custom roles, service-account impersonation, MFA
verification, IP reputation, geolocation, and live incident actions are outside
this first version. Other events remain available as context but are not silently
interpreted as successful privileged grants.

This is a grant investigation, not proof that the account is new, the recipient
first became an administrator, or a compromise occurred.

## Common event schema

Every event needs `eventId`, `eventType`, `occurredAt`, `actor`, `sourceIp`, and
`outcome`. Types are `sign_in` and `iam_binding_change`; outcomes are `success`
or `failure`. An IAM change additionally needs `resource`, `changeAction`, `role`,
and `recipient`. Actions are ADD or REMOVE. Field values are our lab contract,
not provider-specific method names. A missing actor is a data-quality issue,
never permission to substitute the recipient.

## Proposed deterministic correlation policy: triage-v1

- Identify successful privileged ADDs under the stated project/role/recipient
  scope. Failed operations and REMOVEs do not establish a successful grant.
- Correlate sign-ins of the **granting actor**, not the recipient, from 30 minutes
  before the grant through its timestamp, inclusive. Later events must not be
  used as earlier context. Equal timestamps cannot establish precise ordering.
- Elevate priority when a successful sign-in from the grant's same source IP
  falls outside that actor's supplied known CIDRs, and at least three distinct
  failed sign-ins for that actor/IP precede that success in the lookback window.
  Deduplicate before counting. These thresholds are demo choices, not standards.
- A matching approval requires approved status, approval before the grant,
  exact actor/recipient/resource/role, and event time within the approved interval
  `[windowStartInclusive, windowEndExclusive)`. Keep approval ID and approver.
- Elevated signal remains visible even if approval matches. Matching approval
  and no elevated signal supports routine review; no matching supplied approval
  requires verification and review, not a declaration of unauthorized access.
- Missing identity data, baseline, change records, or source coverage must be
  disclosed. Unknown baseline is not a known-safe IP, and an empty partial event
  feed is not proof there were no sign-in failures. The supplied complete-source
  declarations only make the toy expectations reproducible.

Do not confuse deterministic rule output with an analyst's final disposition.
Keep priority, observed facts, approval match, missing data, and recommendations
separate. The program will not disable accounts, revoke roles, contact anyone,
or automatically close a case as benign.

## Expected suspicious-case timeline

| UTC time on Nov 17, 2026 | Source event | Observation |
| --- | --- | --- |
| 08:40 | suspicious-001 | Failed sign-in by Casey from 203.0.113.42 |
| 08:42 | suspicious-002 | Same actor/IP fails again |
| 08:44 | suspicious-003 | Third distinct failure |
| 08:50 | suspicious-004 | Same actor/IP signs in successfully |
| 08:55 | suspicious-006 | Devon grants Viewer to Alex; not a tracked admin role |
| 09:00 | suspicious-005 | Casey grants Owner to Blair from the same IP |

There are seven input records and six unique events, with one privileged grant.
Expected triage: elevated priority, approval not found in supplied records, and
escalation for prompt validation. The observed sequence is consistent with a
possible compromised granting account, but also has plausible nonmalicious
explanations. Unfamiliar IP alone does not establish a compromise or IP location.

Suggested analyst actions: preserve source events and exact queries; verify the
change with the actor and approver through a trusted channel; inspect identity
session/MFA/device context and effective permissions; review the recipient and
subsequent actions; escalate suspected active abuse to the incident lead. Any
containment decision should consider impact, confidence, and the response policy.

## Expected authorized-case result

There are three unique events and one tracked privileged grant at 09:00 UTC.
Casey's successful 08:50 sign-in uses 192.0.2.20 within the supplied baseline.
CHG-DEMO-001 was approved before the grant and matches its subject, actor, role,
resource, and approved time window. Expected recommendation: routine review with
supporting context; record uncertainty and verify the intended temporary-access
removal. This does not prove the account or change is harmless.

## Planned quality checks

Tests will cover invalid or timezone-free timestamps, exact duplicate events,
conflicting IDs, failed grants, other roles, REMOVE actions, the 30-minute
boundary, after-grant activity, recipient-only sign-ins, missing baseline,
unknown source completeness, mismatched/late approvals, and preserved input data.
Report tests will verify references back to the source IDs and distinguish event
time from actual analysis time. These tests are planned, not implemented yet.
