# Detection lesson: select a grant and gather the actor's context

This preserves the second lesson. Context evaluation and saved reports are now
available through `triage.analyze`; see the [finished-project guide](FINISHED_PROJECT_GUIDE.md).
The detection-only command still intentionally stops at correlation.

The parser lesson prepared a timeline. This lesson adds a narrowly scoped rule
in `triage/detection.py`. It does not yet read `context.json`, decide severity,
match approvals, generate reports, or take incident actions.

## 1. Run the rule

From Terminal:

```sh
cd "$HOME/Documents/ChatGPT/AI Training/security-alert-triage-lab"
python3 -m triage.detection --scenario suspicious
```

Expect one candidate for REVIEW. The grant is Casey granting Owner to Blair at
09:00 UTC. Its correlation window is 08:30 through 09:00 UTC, inclusive. Four
sign-ins match Casey in that window: three failures and one success. The Viewer
grant is explicitly listed as not selected by this administrator-role rule.

Compare:

```sh
python3 -m triage.detection --scenario authorized
```

Expect one candidate and one successful sign-in. Its name is only a dataset
label, not a decision the program trusts. It is still REVIEW because approval
matching has not been implemented. Both commands keep source data unchanged.

## 2. Follow the existing call chain

```text
main() in detection.py
  → load_events(path) from parser.py
      → validate, deduplicate, normalize, sort
  → correlate_grants(parsed_timeline)
      → group sign-ins by actor
      → select supported grant candidates
      → match actor and time window
      → return structured evidence
  → print results
```

The detection function receives parsed Python data. It has no file or network
operations. Validation remains the parser's responsibility, keeping the rule
small and independently testable. Call it with parser output, not raw JSON text.

## 3. Read the scope settings

```python
RULE_VERSION = "privileged-grant-correlation-v1"
TARGET_RESOURCE = "projects/demo-triage-project"
TRACKED_ROLES = ("roles/owner", "roles/iam.securityAdmin")
LOOKBACK_MINUTES = 30
```

These make the rule's boundary explicit. The parenthesized role collection is
a tuple. The `in` operator checks whether a value belongs to it. This is a
selected-role exercise, not a complete analysis of every administrative permission.
The lookback is a demonstration choice. Later versions should deliberately
version rule changes and test the resulting behavior.

## 4. Understand grant selection

`grant_exclusion_reason(event)` is called for each IAM event. It returns a text
reason when the event is not a supported candidate, and None otherwise.

A selected event must be a successful ADD of one tracked role in the named
project to a direct `user:` recipient, without a conditional-grant field.
Failed operations, removals, Viewer grants, other projects, and group/service
account recipients are not selected. Their IAM event IDs and reasons are retained
under `skippedIamEvents`; they are not silently erased from the source timeline.
They can still have security significance beyond this rule.

The main loop uses `continue` to move to the next item when it is not an IAM
change or is excluded. The condition `reason is not None` distinguishes an actual
exclusion from a supported candidate. The helper assumes a parser-validated IAM
event; it is not a second generic input validator.

## 5. Group sign-ins by the actor

```python
sign_ins_by_actor.setdefault(event["actor"], []).append(item)
```

This builds a dictionary mapping each actor to their sign-in wrappers.
`setdefault(actor, [])` creates an empty list if the actor isn't present yet;
otherwise it returns the existing list. `.append(item)` puts the sign-in into it.

Conceptually:

```text
casey.rivera@example.com → Casey's sign-ins
another.person@example.com → that person's sign-ins
```

For the Casey-to-Blair grant, the rule looks up Casey. It does not substitute
Blair, the recipient. Investigating Blair's subsequent use of the permission
would be a separate investigation step.

## 6. Build a window using datetime arithmetic

```python
grant_time = parse_timestamp(item["occurredAtUtc"])
window_start = grant_time - timedelta(minutes=LOOKBACK_MINUTES)
```

`timedelta` represents elapsed time. Subtracting 30 minutes from 09:00 gives
08:30. The existing timestamp parser supplies timezone-aware UTC datetimes.
For each sign-in of the actor:

```python
if window_start <= sign_in_time <= grant_time:
```

This is a chained comparison: both conditions must hold. Exactly 08:30 and
exactly 09:00 are included. 08:29:59.999999 and 09:00:00.000001 are excluded.
This prevents post-grant activity from being described as earlier evidence.
Each grant gets its own actor and window, even if one dataset contains several.

At equal timestamps, a sign-in is included but marked `sameTimeAsGrant: true`.
We cannot claim it occurred before the grant merely because it prints first.

## 7. Preserve evidence and annotate IP matches

The matched wrapper is deep-copied and annotated:

```python
evidence["sameSourceIpAsGrant"] = (
    sign_in["sourceIpNormalized"] == item["sourceIpNormalized"]
)
```

`==` compares values and returns a boolean. Single `=` assigns a value instead.
Normalized addresses allow equivalent IPv6 spellings to match. Sign-ins from
other IPs remain in the actor's window with this annotation false; they are not
discarded. Matching IP does not prove a shared session or identify a human.
IP familiarity/reputation is not evaluated by this step.

## 8. Count without deciding severity

```python
sum(sign_in["record"]["outcome"] == "failure" for sign_in in matched)
```

The comparison produces True or False for each matched sign-in. `sum` adds them,
using True as 1 and False as 0, to count failures. The expression inside sum is
a generator: it supplies one comparison result at a time.

The parser has already deduplicated records, so repeated delivery of the same
failure event does not increase the count. These are actor-wide window counts,
not necessarily a three-failures-before-success sequence from one IP. The next
context/risk lesson must apply ordering and same-IP conditions explicitly.

## 9. Inspect the structured output

At a Python prompt (`python3` from the project folder), enter:

```python
from triage.parser import load_events
from triage.detection import correlate_grants

timeline = load_events("data/suspicious/events.json")
report = correlate_grants(timeline)
candidate = report["candidates"][0]

candidate["grant"]["record"]["actor"]
candidate["grant"]["record"]["recipient"]
candidate["windowStartInclusive"]
candidate["failedSignInCount"]
candidate["successfulSignInCount"]
candidate["approvalStatus"]
```

Expect Casey, user:blair.chen@example.com, 2026-11-17T08:30:00Z, 3, 1, and
NOT_EVALUATED. Every candidate retains its grant and matching sign-in wrappers,
including original fields and source record positions. This lets future reports
explain which events support each statement.

The status is REVIEW, not confirmed abuse. `priority`, `approvalStatus`, and
`contextCoverage` are explicitly NOT_EVALUATED. No matching sign-ins means no
matching records were supplied; it does not establish complete identity coverage.
No candidates likewise is not an all-clear conclusion.

Use `exit()` to return to Terminal before entering shell commands.

## 10. Read the tests

```sh
python3 -m unittest discover -s tests -v
```

The detection milestone had 30 tests: 17 parser and 13 detection tests. The full
suite now includes later lessons; see the README for its current count. Detection tests verify
both fixture results, duplicate handling, exact time boundaries, after-grant
exclusion, recipient-versus-actor matching, different-IP context, normalized IPv6,
several grants, source preservation, CLI output, and read errors. Invalid/failed,
unsupported, or conditional grants must not be mislabeled as supported candidates.

For example, the recipient test rewrites sign-in actors to Blair in a copied
dataset, then expects no correlated sign-ins for Casey's grant. It is a negative
test: it verifies that a plausible but incorrect identity join does not happen.
The boundary test uses microseconds to prove the window does not round times.

## 11. Your coding exercise

After inspecting the output at a Python prompt, write a function that returns
the event IDs of only failed sign-ins within a candidate's already matched list.
Start with an empty list, loop over `candidate["actorSignIns"]`, check each
original record's outcome, append matching IDs, and return the list.

Expect suspicious-001, suspicious-002, suspicious-003. Do not change the production
rule or add new severity logic yet. Check your answer against the source IDs.

<details>
<summary>Compare your solution after trying it</summary>

```python
def failed_sign_in_ids(candidate):
    ids = []
    for item in candidate["actorSignIns"]:
        event = item["record"]
        if event["outcome"] == "failure":
            ids.append(event["eventId"])
    return ids
```

</details>

Next we will load baseline and approval context, disclose coverage gaps, and
explain a priority recommendation. No reports or remediation are implemented yet.
