# Run and explain the finished local lab

No API server, cloud account, credentials, paid service, or package installation
is required. All inputs are fictional. Use Terminal, not the Python >>> prompt,
for the commands in the first four steps. If you are at >>>, enter `exit()` first.

## 1. Enter the working folder

```sh
cd "$HOME/Documents/ChatGPT/AI Training/security-alert-triage-lab"
```

Use this original working folder, not the `github-upload` snapshot. `$HOME` means
your home folder. If you cloned the project elsewhere, use its actual location.

## 2. Run a complete investigation

```sh
python3 -m triage.analyze --scenario suspicious
```

Expect COMPLETED, report paths, and an ELEVATED recommendation. The program
selects Casey's Owner grant, correlates the actor's three distinct failures and
later successful sign-in at the same IP, compares that IP to the supplied baseline,
and searches for matching prior approval. It recommends escalation for validation.
It does not assert that Casey or Blair is malicious or execute any incident action.

## 3. Compare the context-supported scenario

```sh
python3 -m triage.analyze --scenario authorized
```

Expect ROUTINE review and MATCHED approval. The prior approval, actor, recipient,
role, project, and approved interval must match. This does not automatically
close the case, authenticate the approver, or prove the account is safe.

## 4. Open the generated reports

Each command prints absolute file paths. In Finder, press Command+Shift+G and
paste the containing folder path (omit the final report filename). Open:

- `report.md`: readable timeline, case facts, evidence IDs, priorities, approval
  context, coverage gaps, and next investigative actions.
- `report.json`: full structured record, including source bodies, parsed inputs,
  original event wrappers and indices, rule versions, and analysis metadata.

Every run creates a unique folder under `outputs/`. These runs are ignored by
Git. Curated examples under `examples/` are intended for portfolio review.

`analysisStartedAt` and `analysisCompletedAt` are actual UTC execution times.
Event and approval times are fixed fictional dates. An `analystLabel` is a
self-declared demonstration identifier, not an authenticated identity. You can
set it explicitly with `--analyst-label demo-reviewer`.

## 5. Understand the program's layers

```text
analyze.py: run coordinator and source capture
  → parser.py: validate and deduplicate events; produce a UTC timeline
  → context.py: validate context and apply the triage policy
      → detection.py: select grants and correlate actor sign-ins
  → reporting.py: save JSON and escaped Markdown
```

`triage.context.analyze()` is the pure analysis function: Python data goes in and
Python data comes out, without reading/writing files or making network calls.
`triage.analyze.run_analysis()` is the coordinator that performs file operations.
The same function name in different modules is allowed; their namespaces keep
the responsibilities separate.

## 6. Read context validation

`validate_context(raw, dataset_id)` first requires the fictional schema envelope
and matching dataset ID. A context file for a different dataset rejects the run.
It then checks coverage declarations, event window, actor baseline records and
CIDRs, and change records. Missing or malformed contextual evidence creates
explicit gaps. An ambiguous baseline is not selected arbitrarily. Conflicting
records sharing a change ID reject analysis rather than choosing an approval.

The context's intermediate validated form can contain datetime and network
objects. Those are useful for comparison. The returned report uses serializable
strings, original source records, and indices rather than inserting those objects
directly into JSON.

## 7. Understand IP baseline comparison

The key expression is:

```python
any(address in network for network in networks)
```

`ipaddress.ip_address` parses the grant source address. `ip_network` parses CIDRs.
The expression asks whether the address belongs to at least one supplied network.
An address inside the supplied list becomes KNOWN_IN_SUPPLIED_BASELINE; outside
becomes OUTSIDE_SUPPLIED_BASELINE only when a valid, unambiguous baseline is
available and declared complete. Otherwise the result is UNKNOWN.

This is a comparison to supplied data, not IP reputation, geolocation, proof of
ownership, or a real identity verification service.

## 8. Understand the failure/success/grant sequence

The detector gathers a 30-minute actor window. The context policy then considers
successful sign-ins from the grant's same normalized IP, strictly before the
grant. For each success it gathers distinct same-actor/IP failures strictly before
that success inside the lookback window. At least three failures plus an IP
outside the supplied baseline create an elevated signal.

The threshold is a demonstration choice. Three failures anywhere in the dataset
are insufficient. Different actors, different IPs, duplicates, later failures,
and equal-time success/grant pairs do not establish the required sequence.
Source event IDs supporting each chain are retained under `signalSequences`.

## 9. Understand approval matching

One part uses:

```python
all(record[field] == grant[field]
    for field in ("actor", "recipient", "resource", "role"))
```

`all` requires every comparison to be true. An approved ticket must also have
approval strictly before the grant and a window satisfying:

```python
approval_start <= grant_time < approval_end
```

The start is included and the end excluded. Approval at exactly the event time
does not prove prior approval. Matching records retain the original approval,
change ID, approver, and context-list index.

A missing match is NOT_FOUND_IN_SUPPLIED_RECORDS when the supplied approval
context is complete and valid. It is UNKNOWN when that context is missing,
incomplete, or invalid. Neither means proven unauthorized access.

## 10. Understand priority decisions

| Situation | Output |
| --- | --- |
| Observed failure/success/grant sequence plus outside-baseline IP | ELEVATED, even if approval also matches or another source has a gap |
| No elevated signal, but context gaps exist | REVIEW: investigate gaps |
| Matching prior approval, known baseline IP, observed successful sign-in, no failure chain, no gaps | ROUTINE review |
| Other supported privileged grants | REVIEW: verify change |

The program can preserve a positive suspicious signal without claiming complete
coverage. It cannot use a gap to infer benign activity. An event window that
does not cover the full lookback interval is a gap. Completeness is still a
fictional declaration; a real integration must establish it independently.

## 11. Understand source retention and writes

`run_analysis()` creates a unique directory and RUNNING JSON before reading input.
Each source retains its filename (not a personal absolute path), actual read
times, exact bytes encoded as Base64, SHA-256, and decoded input where possible.
Base64 is encoding, not encryption. The adjacent hash is a comparison fingerprint,
not proof of authenticity or tamper resistance.

The coordinator reads the files only once for source capture and parses that
captured content, avoiding a second file read that could see different data.
Normal input failures produce a FAILED JSON and Markdown report with no completed
analysis. Original bad bytes are retained when readable. Output-write errors
return failure and may prevent a complete package. Each file is replaced
atomically, but the JSON/Markdown pair is not one atomic transaction. An abrupt
interruption or unhandled programming error can leave RUNNING/partial artifacts;
investigate those rather than treating them as clean results.

Markdown display text escapes HTML and link/table syntax; original values remain
in JSON. Example reports contain only fictional data.

## 12. Run and interpret the tests

```sh
python3 -m unittest discover -s tests -v
```

The suite covers parser behavior, correlation, approval boundaries, context gaps,
duplicate conflicts, signal ordering, missing sources, reporting, and the actual
file-to-report path. It uses temporary directories so test outputs do not pollute
the source fixtures or portfolio examples. A passing suite verifies the exercised
behavior; it is not proof of source truth or complete detection coverage.

## 13. A safe learning experiment

At a Python prompt from this project folder:

```python
import copy
import json
from pathlib import Path
from triage.parser import load_events
from triage.context import analyze

timeline = load_events("data/authorized/events.json")
context = json.loads(Path("data/authorized/context.json").read_text())
analyze(timeline, context)["cases"][0]["priority"]

incomplete = copy.deepcopy(context)
incomplete["declaredCoverage"]["identityEvents"] = "incomplete"
case = analyze(timeline, incomplete)["cases"][0]
case["priority"]
case["coverageGaps"]
```

Predict ROUTINE for the complete comparison case and REVIEW after declaring
identity coverage incomplete. No source file changes: the experiment modifies
an independent in-memory copy. Use `exit()` to return to Terminal.

## 14. Demonstrate and publish

Follow the [response playbook](RESPONSE_PLAYBOOK.md) to explain the human review
step. Then follow the [GitHub update instructions](GITHUB_UPDATE.md) to replace
the old project snapshot in your learning repository. The code and prepared
upload folder do not synchronize with GitHub automatically. Publishing is a
separate user action; the analysis commands never upload anything.
