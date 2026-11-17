# Security Alert Triage Lab

A local Python portfolio exercise for investigating privileged-access changes.
It will correlate fictional IAM grants, identity events, actor baselines, and
approval records, then produce an evidence-linked timeline and triage report.

This is an independent learning project, with no company data, credentials,
live API access, paid services, or automatic remediation. All records are invented.
Development will proceed incrementally, with AI-assisted mentoring and exercises
to help the learner understand and modify the implementation.

## Current lesson: define one investigation before coding

**Question:** Does this successful privileged-role grant need escalation, and
what observed facts support that decision?

Created so far: project structure, two fictional event datasets, supporting
context records, and the [investigation specification](docs/SCENARIO.md).
There is no parser, detection engine, runnable triage command, automated test
suite, or generated report yet. Expected outcomes below are design targets.

```text
security-alert-triage-lab/
├── README.md
├── .gitignore
├── data/
│   ├── suspicious/
│   │   ├── events.json
│   │   └── context.json
│   └── authorized/
│       ├── events.json
│       └── context.json
├── docs/
│   └── SCENARIO.md
├── triage/
│   └── __init__.py
├── tests/
│   └── __init__.py
└── outputs/
    └── .gitkeep
```

The package markers contain explanatory text only. `outputs` is reserved for
future generated reports and is ignored by Git except for its placeholder.

## Two comparison datasets

| Dataset | Available observations | Expected triage direction |
| --- | --- | --- |
| suspicious | Three failed sign-ins, then success from an IP outside the actor's known baseline, followed by an Owner grant; no matching supplied approval | Elevated-priority review and escalation for validation; compromise is unconfirmed |
| authorized | Successful sign-in from a known IP, a Security Admin grant, and a prior approval matching the actor, recipient, project, role, and window | Routine review supported by matching context; no automatic assertion that the account is safe |

Both datasets include a Viewer grant outside the selected administrative roles.
The suspicious dataset intentionally contains one exact duplicate grant event
and out-of-order records. A parser must deduplicate and sort rather than count
the same grant twice or trust the file's order.

The approved case is a comparison exercise, not a reason to suppress every grant
with a ticket. Familiar IPs and approval records can coexist with malicious activity.
The supplied approval describes temporary intent but does not prove that access
expires automatically or is later removed.

## Planned flow

```text
Fictional event JSON + contextual JSON
        ↓
Validate, deduplicate, and normalize timestamps
        ↓
Find successful ADDs of explicitly tracked privileged roles
        ↓
Correlate the granting actor's earlier sign-ins and matching approval records
        ↓
Timeline + observed facts + uncertainty + recommended analyst actions
```

This differs from the existing evidence monitor: the monitor evaluates controls;
this project investigates event sequences and explains a response decision.

## Data format and limitations

The fixtures use **our normalized lab schema**, not raw Google or identity-provider
API responses. A future adapter can map Cloud Audit Logs fields such as
`timestamp`, `protoPayload.authenticationInfo.principalEmail`,
`protoPayload.requestMetadata.callerIp`, and `protoPayload.resourceName` into
the common event model. See the [AuditLog reference](https://docs.cloud.google.com/logging/docs/reference/audit/auditlog/rest/Shared.Types/AuditLog)
and [role-grant examples](https://docs.cloud.google.com/iam/docs/audit-logging/examples-service-accounts).
Provider-specific policy-delta parsing is not implemented or claimed here.

`sign_in` records simulate a separate identity source, not an assertion that
Cloud Audit Logs supplies every sign-in. `context.json` holds fictional baseline,
source coverage declarations, and change records; these are analyst inputs,
not independently verified truths. No approval status is embedded in the events.

Emails use example.com. IPs use documentation ranges; they are not real device
addresses, geolocation evidence, reputation results, or an attribution claim.
All timestamps are fixed UTC values for reproducible tests.

## First exercise

Open the files or check their JSON syntax from this project's folder:

```sh
python3 -m json.tool data/suspicious/events.json
python3 -m json.tool data/authorized/context.json
```

Read the suspicious records and answer:

1. Who performed the privileged grant, and who received it?
2. Which earlier sign-ins should be correlated: the granting actor's or the
   recipient's? Why?
3. Does an unmatched source IP prove the actor is malicious?
4. What evidence would you ask for before recommending access revocation?

JSON objects become Python dictionaries; arrays become lists. `eventId` identifies
a source event, not an incident. A chronological timeline requires parsing
`occurredAt` as a timezone-aware datetime and sorting; JSON file order is not time.

## Next lessons

1. Implement the parser with tests for required fields, invalid times, exact
   duplicates, conflicting IDs, and deterministic ordering.
2. Implement privileged-grant selection and time-bounded correlation, with
   tests for actor versus recipient, failed operations, and time boundaries.
3. Match approval context without treating absent context as proof of abuse.
4. Generate JSON and Markdown case reports, retaining provenance, missing-data
   warnings, a timeline, analyst questions, and suggested escalation.
5. Add a response playbook and a reproducible GitHub walkthrough.

Python 3.11 or newer is the intended baseline. The first version will use only
the standard library. No service needs to run for the file-based exercise.
