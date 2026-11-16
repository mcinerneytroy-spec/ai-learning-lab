# Incremental learning notes

These notes preserve the earlier step-by-step lessons and milestone descriptions.
For the current combined collector, evidence output, test count, and quickstart,
use the [project README](../README.md). Statements that evidence saving is still
planned describe the earlier lessons; individual check commands still print only.

A personal Python portfolio project for daily security evidence collection.
The first version runs locally, uses fictional records, and demonstrates three
controls: MFA coverage, new Google Cloud IAM administrators, and endpoint EDR
coverage. It is intended to demonstrate engineering and GRC reasoning when
shared as a portfolio; it does not describe any company's systems or assess their compliance.

## Earlier lesson milestones

The local mock REST server, separate HTTP client, all three control checks,
fictional snapshots, and 55 automated tests are implemented. Evidence reports and
scheduling are still planned. Two fictional
daily snapshots let us demonstrate change without
waiting a day. No real Google or EDR connection exists.

```text
workspace-security-monitor/
├── README.md
├── .gitignore
├── data/
│   ├── users.json                 # Original eight-user JSON learning exercise
│   └── scenarios/
│       ├── day_1.json             # Baseline: four identities and two devices
│       └── day_2.json             # Next day's observations and one IAM grant
├── monitor/
│   ├── __init__.py                # Package marker
│   ├── mock_server.py             # Loopback-only, read-only snapshot API
│   ├── client.py                  # HTTP GET, JSON parsing, basic validation
│   ├── controls.py                # MFA policy evaluation; no network/file access
│   ├── check_mfa.py               # Retrieves data and prints MFA findings
│   ├── admin_control.py           # IAM snapshot comparison and grant correlation
│   ├── check_admins.py            # Retrieves snapshots and prints administrator findings
│   ├── edr_control.py             # Inventory/agent matching and coverage decisions
│   └── check_edr.py               # Retrieves snapshots and prints EDR findings
├── outputs/
│   └── .gitkeep                   # Placeholder; no generated evidence yet
└── tests/
    ├── __init__.py                # Package marker
    ├── test_mock_server.py        # Real HTTP tests with temporary fixture copies
    ├── test_client.py             # Retrieval, response validation, failure handling
    ├── test_mfa.py                # MFA decisions, scope, and missing evidence
    ├── test_admins.py             # Baseline, grants, attribution, gaps, and HTTP flow
    └── test_edr.py                # Agent matching, health, time boundaries, and HTTP flow
```

The folder name stays `workspace-security-monitor` so existing local commands
still work. `data/users.json` is retained for the original exercise. Its Workspace
admin flags and inactivity dates are not inputs to the revised three controls.
The new scenarios use four of those fictional identities and omit those unrelated
fields. Google Workspace admin flags do not establish Google Cloud IAM access.

## Confirmed scope

- Local mock first; source adapters can support authorized live APIs later.
- Google-managed sign-in, with MFA evidence separate from Cloud IAM permissions.
- One fictional Google Cloud project with direct human-user IAM assignments.
- Two fictional devices: `demo-gcp-vm-01` (Linux cloud VM) and
  `demo-laptop-01` (macOS employee laptop).
- Collect and evaluate observations; no account changes or remediation.
- Simulated daily observations first. Actual scheduling is a later component.

Running the collector in Google Cloud and collecting evidence about Google
Cloud are different choices. Version one runs on a Mac and simulates evidence
about cloud access and device coverage. Cloud hosting is an optional later step.

## Read the new sample data

A snapshot is a set of observations at a particular time. These are fixed
fictional source observations, not evidence of real collection runs.

| Section | Meaning |
| --- | --- |
| `snapshotId`, `observedAt` | Fictional source snapshot identifier and UTC observation time |
| `identityProvider` | This scenario assumes Google-managed sign-in |
| `resource` | Fictional Google Cloud project being assessed |
| `sourceStatus` | Declares simulated complete source collections; real collectors must establish completeness |
| `directoryUsers` | Google Directory-style user records with MFA enrollment and enforcement |
| `iamPolicy.bindings` | Role-to-member assignments for this project |
| `adminEventWindow` | Time interval covered by simulated administrator events |
| `adminEvents` | Changes with actor, recipient, role, resource, and event time |
| `devices` | Independent inventory of devices expected to have EDR |
| `edrObservations` | Vendor-neutral agent status and latest check-in observations |

User fields follow a subset of the
[Directory User resource](https://developers.google.com/workspace/admin/directory/reference/rest/v1/users).
The IAM policy uses the
[Google IAM Policy binding structure](https://docs.cloud.google.com/iam/docs/reference/rest/v1/Policy).
The outer snapshot envelope, administrator events, device records, EDR records,
and status metadata are our own normalized training schema, not exact Google or
EDR API responses. A future adapter must translate raw provider data and preserve
that raw evidence separately. Matching toy IAM users to directory users by email
is sufficient here; a real adapter must address stable identity and email changes.

JSON objects become Python dictionaries, arrays become lists, and `true`/`false`
become `True`/`False`. Times start as strings; parse them into timezone-aware
values before comparing them. `Z` indicates UTC. A role binding associates a
role with one or more principals, such as `user:alex.morgan@example.com`.

## Demonstration scenarios

| Subject | Day 1: Nov 15, 2026, 12:00 UTC | Day 2: Nov 16, 2026, 12:00 UTC |
| --- | --- | --- |
| Alex | MFA enrolled and enforced; Viewer | Unchanged |
| Blair | MFA not enrolled or enforced; Viewer | MFA enrolled and enforced; Security Admin role added |
| Casey | MFA enrolled and enforced; existing Owner | Recorded as granting Blair the Security Admin role at 09:00 UTC |
| Indigo | MFA enrolled; enforcement off; Viewer | Unchanged, illustrating enrollment versus enforcement |
| Cloud VM | Healthy EDR status; check-in 5 minutes old | Status still says healthy, but check-in is 24 hours 5 minutes old |
| Laptop | In inventory; absent from complete EDR observations | Healthy EDR agent with a check-in 10 minutes old |

There is no MFA-change actor in these snapshots. The future report must mark
that actor unknown instead of attributing the MFA change to Blair or Casey.
The administrator grant includes an explicit fictional actor. First collection
establishes a baseline; it cannot establish when Casey's existing role was granted.

## Control rules

These are demonstration policies, not universal SOC 2 requirements. MFA is
implemented as `mfa-v1`, administrator detection as `new-admins-v1`, and EDR
coverage as `edr-v1`.

1. **MFA coverage:** assess direct human users listed in the scoped IAM policy.
   Proposed PASS requires both enrollment and enforcement to be explicitly true.
   Either explicitly false means FAIL; otherwise missing/invalid required evidence
   means UNKNOWN. An IAM user missing from directory data is UNKNOWN. Service
   accounts are outside this human MFA check, not implicitly passing.
2. **New administrators:** initially track the explicit role list
   `roles/owner` and `roles/iam.securityAdmin`. This is intentionally not an
   exhaustive privilege analysis. Compare `(resource, role, member)` assignments
   with the previous successful complete snapshot. Newly observed assignments
   require REVIEW; correlate with events for who/when. Also inspect grant events
   so a grant removed between snapshots is not silently missed. First run is
   BASELINE, not a claim that existing administrators are approved. Missing event
   history means actor/time are unknown and event coverage is incomplete.
3. **EDR coverage:** for inventory devices marked `edrRequired`, require for PASS
   only when a matching agent is healthy and last reported at most 24 hours before
   the snapshot time. An absent agent in a complete EDR collection, unhealthy
   status, or stale check-in means FAIL. Missing, invalid, or future timestamps
   mean UNKNOWN unless other reliable evidence already establishes failure.
   Failed or incomplete source collection must be surfaced as a coverage gap.

Use each scenario's `observedAt` for repeatable demonstrations. Record actual
collection time separately later. A snapshot difference proves a change was
observed between collections; event data is needed for its actual time and actor.
Group access, inherited roles, custom roles, conditional bindings, external
identities, emergency-access exceptions, and effective-permission analysis are
outside this first version and must never be silently treated as fully covered.

## Planned architecture and lessons

```text
Fictional source snapshots
        ↓
Local mock REST API (127.0.0.1 only)
        ↓ HTTP GET / JSON
Python client / replaceable source adapters
        ↓
Three explicit control checks + previous successful snapshot
        ↓
Timestamped JSON evidence + CSV observations + run status
```

1. **Complete:** fictional daily snapshots and documented proposed policies.
2. **Complete:** local GET endpoints and automated tests of success,
   unknown paths, rejection of writes, unchanged files, and source-read failures.
3. **Complete:** retrieve JSON over HTTP; handle timeouts and invalid/incomplete
   responses. Keep transport logic separate from control evaluation.
4. **Complete:** MFA, administrator, and EDR checks, with tests for missing
   evidence, baseline behavior, grant correlation, device matching, health,
   check-in timing, and scope gaps.
5. **Evidence:** preserve observations and results with collector identity,
   UTC collection/evaluation times, source window, run ID, source status, policy
   version, and change actor where available. Preserve failures as failed runs.
6. **Daily operation and portfolio:** compare runs, handle review dispositions,
   add scheduling, verify end-to-end behavior, and document a GitHub demo.

Python's standard library is enough for this local version: `http.server`,
`urllib.request`, `json`, `csv`, `datetime`, and `unittest`. No package downloads
or external services are needed. The earlier single-users-endpoint server lesson
is now a reference; the revised server lesson will expose the scenario data.

## Setup and first exercise

Python 3.15.2 now runs in this workspace. Python 3.11 or newer is the project
baseline; compatibility across versions has not yet been tested.

```sh
cd "$HOME/Documents/ChatGPT/AI Training/workspace-security-monitor"
python3 --version
python3 -m json.tool data/scenarios/day_1.json
python3 -m json.tool data/scenarios/day_2.json
```

These commands read and format JSON; they do not start an API or evaluate a
control. Compare Blair's MFA fields and IAM assignments between the two files.
Then compare the two devices against `edrObservations` and `observedAt`.

Optionally create an isolated `.venv` environment:

```sh
python3 -m venv .venv
source .venv/bin/activate
```

After activation, `python` uses that environment; `deactivate` leaves it.
The current code also runs directly with `python3`; no packages need installing.

## Server lesson: run and inspect HTTP responses

From the project folder, start the server in Terminal:

```sh
python3 -m monitor.mock_server
```

`-m monitor.mock_server` tells Python to run the `mock_server` module inside
the `monitor` package. Leave that Terminal running while making requests.
Press Control+C there when finished. The server is not left running by tests.

Open either URL in a browser:

- [Day 1](http://127.0.0.1:8000/api/v1/snapshots/day-1)
- [Day 2](http://127.0.0.1:8000/api/v1/snapshots/day-2)

`127.0.0.1` means this computer; `8000` is the listening port. The endpoint is
the URL path identifying the snapshot. These are our custom training routes,
not Google API endpoints. They return entire snapshots, not control results.

In a second Terminal window, inspect a response including its headers:

```sh
curl -i http://127.0.0.1:8000/api/v1/snapshots/day-1
```

Expect `200 OK`, JSON content type, and the fictional records. The HTTP version
in the response can be `HTTP/1.0`; that is the standard handler's default.
GET requests retrieve data. Headers describe the response; the body holds the
JSON. A 200 status means retrieval succeeded, not that a security control passed.

Try an unknown path and an unsupported write method:

```sh
curl -i http://127.0.0.1:8000/not-found
curl -i -X POST http://127.0.0.1:8000/api/v1/snapshots/day-1
```

Expect 404 (not found) and 405 (method not allowed), respectively. POST, PUT,
PATCH, DELETE, HEAD, and OPTIONS are explicitly rejected. Other unimplemented
methods use the standard handler's 501 response. Query strings and trailing
slashes are not supported: use the two URLs exactly as shown. This API serves
only its two mapped JSON files; it does not expose a file browser or directory
listing. Unreadable files or invalid JSON return a generic JSON 500 error.
The server parses JSON but does not yet validate the snapshot schema.

Run the automated tests from the project folder:

```sh
python3 -m unittest discover -s tests -v
```

Expect `Ran 55 tests` and `OK`. Server tests create temporary fixture copies and actual
HTTP connections on automatically assigned loopback ports, then close them.
No external network access is needed, but the test process must be permitted to
bind localhost sockets. Verified on Python 3.15.2; other versions are untested.

If startup says the address is already in use, check whether a prior server is
still running and stop it with Control+C. If Python cannot find `monitor`, check
that Terminal is in the project folder. Browser connection errors usually mean
the server is stopped or the address/port differs from the startup message.

## Client lesson: retrieve and parse a snapshot

Keep the server running in the first Terminal. Open a second Terminal and run:

```sh
cd "$HOME/Documents/ChatGPT/AI Training/workspace-security-monitor"
python3 -m monitor.client --day 1
python3 -m monitor.client --day 2
```

Each client command finishes and returns to the prompt; the server must keep
running to respond. No browser is needed. `--day` is a command-line argument
selecting which fictional snapshot to retrieve. The server defaults to port 8000;
the client also accepts `--port` for tests or a separately configured local server.

For day 1, expect:

```text
Retrieved demo-day-1 over HTTP GET
Source observation time: 2026-11-15T12:00:00Z
Directory users: 4
IAM role bindings: 2
Administrator events: 0
Inventory devices: 2
EDR observations: 1
Basic validation passed; source completeness is declared by the mock.
No security controls evaluated. No evidence files saved.
```

Day 2 has three role bindings, one administrator event, and two EDR observations.
Both commands use `fetch_snapshot()`: send GET, read the response bytes, decode
UTF-8 text, parse JSON into a Python dictionary, and validate its basic structure.
Functions group reusable steps. Exceptions describe failures; `try`/`except`
converts those failures into a readable message and a nonzero exit status.

The client checks HTTP success, JSON content type, a 1 MB response limit, schema
version, fictional/source identifiers, timezone-aware observation and event-window
times, expected section types, basic IAM bindings, and unique user/device IDs.
All five source declarations must say complete. It ignores system proxies and
refuses redirects so retrieval remains local. It makes no file writes.

These checks do not establish that the population is truly complete or facts are
accurate. The client does not require exactly four users or two devices: sample
counts are not evidence of completeness. The separate MFA check now interprets
MFA fields and matches direct IAM users to directory records. Administrator
events are interpreted by the separate new-admin check. EDR evaluation uses its
own control module and command.
Raw-response retention and actual collection timestamps are also still planned.

If the server is stopped, expect `Collection failed: Could not retrieve snapshot`.
Start it again in the first Terminal and rerun the client in the second. Automated
tests simulate connection failures, timeouts, HTTP errors, bad JSON, wrong response
types, incomplete declarations, missing sections, invalid times, duplicate IDs,
wrong snapshots, and redirects. An integration test retrieves both real local
responses and checks that the original source files are unchanged.

## MFA lesson: turn source observations into control results

If the server is stopped, restart it in the first Terminal from the project
folder with `python3 -m monitor.mock_server`. Leave it running. In the second
Terminal, run these commands from the project folder:

```sh
python3 -m monitor.check_mfa --day 1
python3 -m monitor.check_mfa --day 2
```

The command retrieves data through the existing HTTP client, then calls
`evaluate_mfa(snapshot)`. The control function has no HTTP or file operations:
it accepts a Python dictionary and returns a report dictionary. Keeping these
responsibilities separate makes a future data-source replacement easier.

The check starts with direct `user:` members in IAM, then finds each user's
directory record by email. It does not start with the directory alone, because
that could silently omit an IAM user whose directory record is missing. Multiple
roles still produce one result per user. Suspension does not automatically
exempt an account. Results include the principal, user ID, roles, raw MFA values,
status, and reason; the report identifies the snapshot, resource, source time,
policy version, scope, and excluded principal types. Actor information is not
inferred from these MFA observations.

| User | Day 1 | Day 2 |
| --- | --- | --- |
| Alex | PASS | PASS |
| Blair | FAIL | PASS |
| Casey | PASS | PASS |
| Indigo | FAIL | FAIL |

Expect `Summary: PASS=2 FAIL=2 UNKNOWN=0` for day 1 and
`Summary: PASS=3 FAIL=1 UNKNOWN=0` for day 2. Indigo is enrolled but enforcement
is off. This demo policy requires both to be explicitly true. A known false
value means FAIL even if the other value is missing. Otherwise missing or invalid
values mean UNKNOWN. Python distinguishes the boolean `True` from the string
`"true"` and from the number `1`; the check requires actual booleans.

In `controls.py`, a dictionary maps user emails to directory records. A set
keeps each IAM role once per user. `if`/`elif`/`else` chooses an outcome based
on the evidence. A function returns structured results so future JSON and CSV
reporting can use them without parsing terminal text.

Non-user principals such as groups and service accounts are listed outside
the direct-user scope. Group members and inherited access are not expanded.
Any user with a conditional binding receives UNKNOWN in this conservative
first version, even if they also have an unconditional binding. Missing or
ambiguous directory matches also produce UNKNOWN. Empty scope is explicitly
reported, not described as an overall PASS. Complete-source declarations remain
mock assumptions; neither these results nor their counts prove full coverage.

The CLI exits with status 1 for collection/input failure, and 0 when an assessment
finishes even if findings FAIL or UNKNOWN. This separates a failed execution
from a successfully executed check that found a policy problem. Evidence saving
and actual collection timestamps are still planned. EDR and administrator checks
are available as separate commands below.
The earlier `monitor.client` command continues to print collection counts only.

## New-administrator lesson: compare snapshots and correlate events

Keep the mock server running in the first Terminal. In the second Terminal,
from the project folder, run:

```sh
python3 -m monitor.check_admins --day 1
python3 -m monitor.check_admins --day 2
```

Day 1 records Casey's existing Owner assignment as BASELINE. It does not claim
that the assignment is new or approved. Original grant time and actor are UNKNOWN.
Day 2 retrieves both days through HTTP and reports one grant for REVIEW:

```text
Comparison status: REVIEW
REVIEW   user:blair.chen@example.com | roles/iam.securityAdmin
  Administrator grant event observed; review authorization.
  Actor: user:casey.rivera@example.com
  Grant time: 2026-11-16T09:00:00Z | Event: fictional-event-001
  Present in current snapshot: True
```

This is a new tracked role assignment, not necessarily a newly created account
or the person's first administrative role. REVIEW is not an unauthorized-access
verdict. The program does not record approval or close findings yet.

`admin_control.py` has no network or file operations. It accepts structurally
validated snapshots and compares sets of `(role, member)` pairs within the same
project resource. Python set subtraction identifies assignments present now but
absent before. Only direct human assignments of `roles/owner` and
`roles/iam.securityAdmin` are tracked in this small demonstration.

The function also reads ADD_BINDING events within the declared time window,
using `(resource, role, member)` to match events to assignments. This catches
grants that disappear before the next snapshot, and re-grants of existing roles.
Multiple grant events for an assignment remain separate evidence entries.
Exact duplicate events are deduplicated by ID; conflicting IDs stop assessment.
REMOVE_BINDING events are accepted but do not create new-grant findings.

A source snapshot time indicates when access was observed. Event time indicates
when a recorded grant occurred. A difference without a matching event still
requires REVIEW, with unknown actor/time and a visible attribution gap. No actor
is inferred from the recipient or current Owner. Missing actors, malformed events,
incomplete event sources, nonmatching windows, and conditional administrator
bindings create coverage gaps and an overall UNKNOWN comparison status, while
known grant findings remain visible. Different projects or reversed snapshot
order stop assessment. Nonhuman principals are disclosed outside scope.

An unchanged comparison with no grants says NO_NEW_GRANTS_OBSERVED, not PASS
for all administrative access. This is limited to the named roles, direct user
bindings, and available events; group membership changes and inherited/custom
privileges are not evaluated. The client currently rejects any source marked
incomplete before control evaluation; the pure control function additionally
defends against incomplete inputs when called directly.

The CLI returns 0 when the assessment completes, including REVIEW/UNKNOWN,
and 1 when collection or input validation prevents execution. Source declarations
remain fictional assumptions. Reports, actual collection timestamps, persistent
baseline management, and review dispositions have not been implemented. Day 2
explicitly re-fetches the Day 1 fixture rather than loading a saved baseline.

## EDR lesson: reconcile devices with agent observations

Keep the mock server running in the first Terminal. In the second Terminal,
from the project folder, run:

```sh
python3 -m monitor.check_edr --day 1
python3 -m monitor.check_edr --day 2
```

| Device | Day 1 | Day 2 |
| --- | --- | --- |
| `demo-gcp-vm-01` | PASS: healthy; check-in 5 minutes old | FAIL: check-in 24 hours 5 minutes old |
| `demo-laptop-01` | FAIL: missing from complete EDR observations | PASS: healthy; check-in 10 minutes old |

Both days have `Summary: PASS=1 FAIL=1 UNKNOWN=0`, but the failing device differs.
Read the per-device reasons rather than relying only on summary counts.
Day 2's VM still has a `healthy` status string, but its check-in is stale.

`evaluate_edr(snapshot)` begins with the independent inventory, groups agent
records by device ID, and matches each expected device. This detects devices
that never appeared in EDR. It does not infer coverage from the EDR list alone
or install agents. Device and agent IDs are fictional normalized identifiers.
A real adapter must establish stable, reliable cross-source matching.

The policy uses full elapsed time relative to the snapshot's `observedAt`, not
the computer clock: exactly 24 hours is allowed; even a fraction beyond 24 hours
is stale. Timezone offsets are honored. The 24-hour limit is a demonstration
policy choice, not a universal compliance requirement. The snapshot time remains
separate from the future actual collection timestamp.

PASS requires EDR applicability explicitly true, one unambiguous agent with a
valid ID, normalized status `healthy`, and a valid check-in no more than 24 hours
old. Recognized statuses `unhealthy`, `disabled`, and `offline` fail even if time
evidence is missing; the reason discloses that time gap. A stale valid check-in
also fails even if the health status is unrecognized. Missing/invalid/timezone-free
or future check-ins otherwise mean UNKNOWN. Missing agent IDs, multiple matches,
and agent IDs shared across devices mean UNKNOWN rather than silently selecting
a passing record. A real EDR adapter must translate its vendor's status values.

Devices explicitly marked `edrRequired: false` are listed as excluded; this
does not prove an approved exception. Missing or invalid applicability produces
UNKNOWN. EDR records with invalid device IDs or devices absent from inventory
produce visible coverage gaps. The report lists orphan device IDs for inventory
reconciliation. Counts describe assessed inventory devices, not these extra records.

Incomplete inventory or EDR source declarations stop assessment. In particular,
absence from an incomplete EDR response is not treated as a missing-agent finding.
Empty scope is explicitly reported, not called an overall PASS. Snapshot field
validation and source declarations do not independently establish completeness.

Python dictionaries group records by device ID. Datetime subtraction produces
a `timedelta`, an elapsed duration, which is compared with the 24-hour threshold.
The function returns structured results and matching source observations; the
CLI prints them. It has no remediation behavior and saves no evidence yet.
Source snapshots remain unchanged. The CLI returns 0 for a completed check,
including FAIL/UNKNOWN findings, and 1 when collection/input prevents execution.

Next we will combine the three checks into one collection run and preserve
timestamped JSON evidence and a CSV control report, including failed-run records.

## Evidence and security limitations

All names, project IDs, device IDs, events, and observations are invented. No
credentials, confidential company information, or production data belong in this repository.
A local API bound to loopback is a training service, not production hosting.
Source records remain read-only; saving local reports is intentional.

A future daily schedule provides recurring observations, not real-time coverage.
The report must disclose collection failures, missing sources, and coverage
limits. Git-ignored output is not protected storage. Tamper resistance, retention,
access controls, and a reviewer history need explicit implementation before we
claim a production audit trail. Local snapshots alone prove no such guarantees.

These three technical controls can support a SOC 2 evidence strategy. Criterion
mapping and acceptance of evidence depend on the actual control design, scope,
and audit requirements; this project provides no compliance opinion.
