# Understand the evidence package

Run `python3 -m monitor.collect --day 2` while the local mock server is running.
The command prints the absolute locations of two files inside a unique folder:

```text
outputs/<UTC-timestamp>_<unique-run-id>/
├── evidence.json
└── controls.csv
```

## JSON: full run record

| Field | Purpose |
| --- | --- |
| `runId`, `runStatus`, `error` | Identify a run and distinguish completion from execution failure |
| `collectorId` | Self-declared demo collector label; not proof of authenticated identity |
| `collectionStartedAt`, `collectionCompletedAt` | Actual run times in UTC |
| `sources` | Each attempted HTTP request, collection times, validation outcome, retained response body, and parsed snapshot if validation succeeded |
| `controls` | Policy versions, scope, observations, reasons, exclusions, and coverage gaps |
| `limitations` | What the evidence does not establish |

Each source has its own URL, GET method, collection start/completion, and response
receipt time when a response is received. `sourceObservedAt` in a control comes
from the fixed fictional source snapshot. Administrator `eventTime` comes from
the event record. These timestamps must not be substituted for one another.
The fixture's dates may be earlier or later than the actual collection date;
this is explicitly a simulation evaluated at the fixture observation time.

`rawBodyBase64` encodes the retained response bytes as JSON-safe text. Base64 is
encoding, not encryption. `rawBodySha256` fingerprints those same bytes; matching
hashes do not prove source authenticity or tamper resistance when both data and
hash are stored in editable local files. The parsed `snapshot` is convenient
for inspection; the raw body retains the original HTTP body formatting.

The client caps reads at 1,000,001 bytes and rejects responses over its 1 MB demo
limit. Oversized retained bodies are marked truncated. Content type, HTTP status,
JSON validity, declared content length when present, and basic schema are checked.
No response body exists for some connection failures. Those attempts still have
a failure record. Transport metadata is not an authenticated source attestation.

Validation before control execution does not establish real-world population
completeness. A provider can omit data while returning syntactically valid JSON.
Real integration requires pagination handling and independent scope reconciliation.

## CSV: readable observations with traceability

Open `controls.csv` in a text editor or spreadsheet program. It contains:

- One CONTROL_SUMMARY per control, including controls that were NOT_EVALUATED.
- OBSERVATION rows for each assessed user, administrator assignment/event,
  or device. Multiple grant events retain separate CSV rows.
- COVERAGE_GAP, EXCLUSION, and UNMATCHED rows where relevant.
- Run ID, collector label, UTC collection times, source observation time,
  policy version, subject, status, reason, and a JSON evidence pointer.
- Change actor, event time, and event ID for administrator events. Other
  observations explicitly use UNKNOWN where change attribution is unavailable.

An `evidencePointer` such as `evidence.json#/controls/0/results/1` identifies
the result inside the adjacent JSON file: index 0 is the first control, and
index 1 is its second result. Keep the two files together.
Formula-like CSV values are prefixed with an apostrophe for spreadsheet safety;
original values remain in JSON. CSV quoting preserves commas and line breaks.

Summary PASS_IN_SCOPE describes only assessed subjects under the stated policy.
It is not an overall compliance verdict. Findings, gaps, exclusions, and partial
runs must be reviewed together. runStatus COMPLETED means execution finished,
even when a control fails or needs review.

## Failures and durability

The collector writes RUNNING evidence before fetching data and checkpoints after
each source and control. Normal collection or validation failures leave FAILED
evidence and NOT_EVALUATED summaries for checks that did not run. Earlier responses
and completed checks are retained. An interrupted process can leave RUNNING or
partially completed artifacts; investigate these as monitoring gaps.

Each file is replaced atomically, but the two files are not one atomic transaction.
Disk/permission failures can prevent any durable record or leave only one file.
The CLI reports failure if output cannot be written. This is a local prototype,
not a production durable evidence store. There is no signing, append-only log,
retention lock, automatic schedule, authenticated collector, or reviewer workflow.
The CLI returns 0 on completed execution with findings and 1 on execution/output
failure. Source fixtures are never modified by a collection.
