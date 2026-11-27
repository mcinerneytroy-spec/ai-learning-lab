# Response playbook: a successful privileged-role grant

This is an analyst exercise for fictional data. The program recommends review;
it does not declare an incident, contact anyone, or execute containment.

## 1. Establish scope and preserve evidence

Record the case/run IDs, rule versions, grant event ID, actor, recipient, role,
resource, source event time, and actual analysis time. Preserve the original event
and context files plus the generated JSON/Markdown package. Keep duplicate-source
indices. Confirm that source scope and time coverage support the investigation.
Local body hashes help compare bytes but do not provide authenticated custody.

## 2. Validate what actually happened

- Is the change a successful ADD rather than a failed request or REMOVE?
- Does it affect a tracked role and the intended project?
- Which principal performed the action, and which principal received access?
- Could the source event be duplicated, delayed, malformed, or incomplete?
- Are conditional/inherited/group/service-account paths outside this rule relevant?

## 3. Investigate the granting identity

Review actor sign-ins, failed/successful ordering, and source IP against the
supplied baseline. In a real authorized investigation, corroborate with identity
session, MFA, device, token/delegation, and network context. An IP outside a
baseline is not an attribution or reputation verdict. A shared IP is not proof
of the same session. Equal timestamps do not establish precise action ordering.

Inspect recipient history and post-grant activity separately. The current lab
correlates preceding sign-ins of the granting actor, not subsequent recipient use.

## 4. Verify approval and business context

Confirm the actor, recipient, role, resource, approval time, approved interval,
and approver match the actual change. Use a trusted channel to verify intent;
do not rely solely on the potentially affected session or account. A ticket can
be incorrect, forged, outdated, or associated with a different action. Absence
from supplied records does not prove absence of an approval elsewhere.

For temporary access, verify enforced expiry or a separate removal event. The
fixture's temporary justification does not demonstrate an expiring IAM condition.
This implementation does not evaluate approval-authority or separation-of-duties
policy; those are additional production controls.

## 5. Recommend and escalate

| Lab output | Proposed analyst handling |
| --- | --- |
| ELEVATED / ESCALATE_FOR_VALIDATION | Promptly validate the suspicious sequence and involve the incident lead according to the organization's response policy |
| REVIEW / INVESTIGATE_CONTEXT_GAPS | Obtain missing or ambiguous evidence; do not close as benign |
| REVIEW / VERIFY_CHANGE | Validate the change or unfamiliar activity before disposition |
| ROUTINE / ROUTINE_REVIEW | Record supporting context and confirm intended access expiry/removal; this is not automatic closure |

Observed positive signals can remain elevated even with incomplete sources.
Missing sources remain explicit gaps, not contrary evidence. Priority is a
demonstration policy output, not an SLA, confirmed severity, or impact assessment.

Containment, such as revoking access or sessions, requires an authorized human
decision considering confidence, impact, and policy. This lab implements none
of those actions. Execution exit status and COMPLETED run status only describe
whether analysis finished, not whether the activity was legitimate.

## 6. Record disposition and lessons

A real case record should identify the reviewer, decision time, verified facts,
remaining uncertainty, communications, approved actions, action outcomes, and
follow-up owner. The program leaves `analystDisposition: PENDING` and
`incidentVerdict: UNCONFIRMED`; it does not claim a reviewer has approved anything.
Preserve the original report rather than editing it into a false record of
an action the program never performed.

Consider a missed-detection example, a false-positive explanation, collection
gaps, and whether the threshold or baseline needs revision. Version changes
and add regression tests for any new rule behavior.

For broader operational response planning, consult
[NIST SP 800-61 Revision 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final), which
addresses incident response within cybersecurity risk management. This small
playbook is an educational implementation choice, not a claim of NIST compliance.
