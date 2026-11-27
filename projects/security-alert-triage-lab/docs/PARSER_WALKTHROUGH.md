# Parser lesson: understand the code before adding detection

This guide preserves the initial parser lesson. The complete pipeline is now
available; see the [finished-project guide](FINISHED_PROJECT_GUIDE.md). Earlier
stage limitations below describe the parser command, not the full analyzer.

This guide explains the existing `triage/parser.py` and `tests/test_parser.py`.
It adds no application behavior. Work through one section at a time. You do not
need a server or cloud account. All exercises use fictional data locally.

## 1. What problem are we solving?

Before asking whether an administrator grant is suspicious, we need trustworthy
handling of the supplied records. The input contains seven records, including
one duplicate, and the records are not chronological. Counting every record as
a distinct action would exaggerate the activity. Reading in file order would
produce the wrong sequence.

The parser prepares six validated unique events in time order. It does not
establish that the source is truthful or complete. It does not investigate the
actor, match approvals, decide severity, or perform remediation yet.

```text
events.json on disk
    ↓ read UTF-8 text
JSON text held in a Python string
    ↓ json.loads
Python dictionary containing a list of event dictionaries
    ↓ field validation and duplicate handling
Unique event wrappers retaining their source positions
    ↓ timestamp sorting
Timeline dictionary
    ↓ print
Terminal output
```

`context.json` is not used in this lesson. It is reserved for later correlation.

## 2. Run the existing program once

In Terminal, enter:

```sh
cd "$HOME/Documents/ChatGPT/AI Training/security-alert-triage-lab"
python3 -m triage.parser --scenario suspicious
```

`cd` changes the working folder. `$HOME` expands to your home directory without
hard-coding a personal username. Quotes keep spaces in the path together.
`python3` launches the interpreter. `-m` runs a Python module, `triage.parser`,
from the `triage` package. `--scenario suspicious` selects the fictional dataset.

Expected counts are 7 input records, 6 unique events, and 1 duplicate. Six timeline
lines follow, starting at 08:40 UTC and ending at 09:00 UTC. These are source
event times, not the time you ran the program. Nothing is saved or changed.

## 3. Recognize the Python data structures

An abbreviated source record looks like:

```json
{
  "eventId": "suspicious-005",
  "actor": "casey.rivera@example.com",
  "outcome": "success"
}
```

After parsing, that object becomes a Python dictionary: a collection of keys
and values. `record["actor"]` retrieves the value under the actor key. The full
dataset's `events` array becomes a Python list. Lists have positions starting
at zero: `records[0]` is the first record, while `records[-1]` is the last.

Useful distinctions:

| Expression | Meaning |
| --- | --- |
| `record["actor"]` | Retrieve a required key; missing keys raise KeyError |
| `record.get("actor")` | Retrieve the value, or None if the key is absent |
| `None` | A Python value representing no supplied value |
| `"success"` | Text, called a string |
| `True` / `False` | Python boolean values; JSON spells them true / false |
| `len(records)` | Number of items in the list |
| `{}` | An empty dictionary |
| `[]` | An empty list |

The program's `record` variable is one event, not the entire file.

## 4. Imports provide existing tools

The opening triple-quoted text is a module docstring, describing the file.
Imports make tools available without copying their implementation into our code.
All imports here come from Python's standard library.

| Import | Why it is used |
| --- | --- |
| `argparse` | Reads command-line choices such as --scenario |
| `copy` | Creates an independent copy of nested event data |
| `ipaddress` | Validates and normalizes IPv4/IPv6 addresses |
| `json` | Converts between JSON text and Python values |
| `re` | Checks a timestamp's text pattern |
| `datetime`, `timezone` | Parses real dates, compares instants, converts to UTC |
| `Path` | Builds paths and reads files |

Imports and function definitions are processed before the command starts reading
events. Defining a function does not run its body; a later function call does.

## 5. Constants establish location and input format

```python
DATA_DIRECTORY = Path(__file__).resolve().parent.parent / "data"
```

`__file__` identifies this Python file. `resolve()` obtains its resolved absolute
path. One `.parent` reaches the `triage` folder; the next reaches the project
folder. `/ "data"` joins a child path; with Path objects this is not division.
This locates bundled data relative to the code rather than an arbitrary working
directory. Uppercase names are a convention for settings, not enforced immutability.

`TIMESTAMP_PATTERN` is a compiled regular expression, a text-format rule:

```python
r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$"
```

Read it in pieces: four year digits, two month digits, two day digits, a literal T,
hours/minutes/seconds, optional fractional seconds, then Z or a signed timezone
offset. `\d` means a digit; `{4}` means exactly four; `?` makes a part optional;
`|` means an alternative. `(?:...)` groups without capturing a separate result.
The initial `r` creates a raw string so Python preserves the backslashes for the
regular-expression engine. The pattern checks the shape of the whole value;
it cannot determine whether February has 30 days. Calendar validation comes next.

## 6. Functions accept inputs and return outputs

```python
def parse_timestamp(value):
```

`def` defines a function; `value` is a parameter receiving an argument at a call.
The colon starts its body, and indented lines belong to that function.
`return` sends a result to the caller and ends that function call.

`parse_timestamp()` first requires a string matching the timestamp pattern:

```python
if not isinstance(value, str) or not TIMESTAMP_PATTERN.fullmatch(value):
    raise ParseError(...)
```

`isinstance(value, str)` asks whether the value is text. `not` reverses a boolean.
`or` means either rejection condition is sufficient. Python short-circuits:
if the value is not text, it does not attempt the string pattern check.

Then:

```python
return datetime.fromisoformat(value).astimezone(timezone.utc)
```

This parses an actual datetime and converts the same instant to UTC. For example,
02:00 at offset -07:00 is 09:00 UTC. It does not add seven hours of real elapsed
time; it expresses one instant with a different timezone label.

## 7. Errors make rejected evidence visible

```python
class ParseError(ValueError):
    """The input does not meet the lab's event contract."""
```

This defines a named exception for parser failures. It inherits from ValueError,
a built-in error type. For now, think of it as a recognizable failure category.

`raise ParseError(...)` stops the current normal flow. `try` runs code that may
fail, and `except` handles a specified failure. `raise ... from error` retains the
underlying cause for debugging. We do not simply catch a bad event and continue:
that could hide important missing evidence while implying a complete timeline.

`require_text(record, field)` is a reusable helper. It uses `.get`, checks the
value is nonblank text without surrounding whitespace, and rejects ASCII control
characters such as embedded newlines. `.strip()` returns a trimmed string; the
helper compares it with the original rather than silently rewriting the input.
`any(...)` checks whether at least one character is disallowed; `ord` gives its
numeric Unicode code point. The code explicitly rejects values below 32 and 127,
not every possible Unicode formatting character.

The `f` in `f"{field} must be ..."` creates an f-string: values inside braces are
inserted into readable text. That helps errors name the offending field.

## 8. Validate the dataset and each event

`parse_dataset(dataset)` checks the outer object before looping over events:

- A dictionary is required at the top level.
- The supported schema version is 1.0.
- `fictional` must be the actual boolean True, not the string "true" or number 1.
- `datasetId` must be nonblank text and `events` must be a list.

Then it creates two empty dictionaries:

```python
unique = {}
fingerprints = {}
```

And examines the list:

```python
for index, record in enumerate(records):
```

`for` repeats the indented body for each item. `enumerate` supplies both the
zero-based position and the record. Keeping this position lets us trace a returned
event to its original occurrence(s). The first grant is at index 0 and its exact
duplicate is at index 5 in the suspicious input.

Each event must have a valid ID, recognized type, success/failure outcome, actor,
timestamp, and IP address. `ipaddress.ip_address` checks address syntax without
contacting the Internet. It does not determine reputation or the actor's location.
An IAM change also needs resource, role, recipient, and ADD/REMOVE action. A
sign-in does not need those IAM-only fields, hence the event-type-specific `if`.

The parser retains failed operations, Viewer grants, and REMOVE events when they
meet the schema. Selecting meaningful privileged grants is a later detector's job.

## 9. Deduplicate by ID without hiding conflicts

```python
fingerprint = json.dumps(record, sort_keys=True, allow_nan=False)
```

`dumps` converts a Python value into JSON text; `loads` goes the opposite way.
Sorting dictionary keys makes content comparable even if the object keys were
written in different orders. `allow_nan=False` rejects values outside the JSON
contract. This fingerprint is a stable comparison string, not a cryptographic
hash, source signature, or evidence-authentication mechanism.

Three possible outcomes follow:

| Situation | Action |
| --- | --- |
| New event ID | Save the record and its comparison string |
| Existing ID, identical content | Retain the additional source position and skip another timeline entry |
| Existing ID, different content | Raise ParseError; do not choose a record silently |

For an exact duplicate:

```python
unique[event_id]["sourceRecordIndices"].append(index)
continue
```

`.append(index)` adds the duplicate's position to a list. `continue` moves to the
next loop iteration. It does not end the whole function.

Distinct IDs remain distinct events even if other fields match. Equivalent
timestamp/IP spellings under the same ID are still differing source content;
normalization is not used to silently erase that difference. Deduplication is
limited to this dataset, not to every possible source system.

## 10. Preserve originals inside a wrapper

For a new ID, we build a wrapper:

```python
unique[event_id] = {
    "record": copy.deepcopy(record),
    "occurredAtUtc": stamp.isoformat().replace("+00:00", "Z"),
    "sourceIpNormalized": source_ip,
    "sourceRecordIndices": [index],
}
```

`record` keeps the original field values. Separate fields hold normalized values
and provenance. A deep copy recursively copies nested dictionaries and lists,
so changing a returned record later does not change the original input object.
It does not make either object immutable, and the program still makes no writes
to the source file.

`stamp.isoformat()` converts the datetime into ISO text. Replacing the UTC suffix
`+00:00` with Z gives a familiar UTC display. The original occurredAt stays under
`record`, including its original offset.

The surrounding `except ParseError` adds the record index to an error message,
so a user can locate the bad input. It then raises again instead of discarding it.

## 11. Sort by actual instant and return a result

```python
ordered = sorted(unique.values(), key=lambda item: (
    parse_timestamp(item["occurredAtUtc"]), item["record"]["eventId"]
))
```

`unique.values()` supplies saved wrappers. `sorted` produces a new list. `key`
tells it what to compare, and `lambda` defines a small unnamed function used to
compute that key. The tuple inside parentheses sorts first by datetime, then by
event ID when times are equal. The ID tiebreak is repeatable display order, not
evidence of the true ordering of simultaneous actions.

The function returns a dictionary containing the dataset ID, counts, and ordered
wrappers. The duplicate count is input count minus unique count: 7 - 6 = 1.
Suspicious-006 appears before suspicious-005 because its event time is earlier;
the numeric-looking ID is not a timestamp.

## 12. Read JSON without ambiguous interpretation

`load_events(path)` reads text with:

```python
text = Path(path).read_text(encoding="utf-8")
```

The variable `text` is still a string. `json.loads` turns it into Python data:

```python
dataset = json.loads(
    text,
    object_pairs_hook=reject_duplicate_keys,
    parse_constant=reject_non_json_constant,
)
```

The hook is a function Python's JSON decoder calls for each object. It rejects
duplicate keys like `{"outcome": "failure", "outcome": "success"}` rather than
silently keeping one. These are duplicate keys inside one object, different
from duplicate event records in the list. The second callback rejects nonstandard
constants such as NaN. The decoded dataset then goes through parse_dataset.

Unreadable files, invalid UTF-8, and malformed JSON produce readable errors.
This file-based loader is not a production high-volume ingestion service.

## 13. Understand the entry point and CLI

At the end:

```python
if __name__ == "__main__":
    main()
```

When we run this module with -m, this condition calls main. When a test imports
parse_dataset from the module, main is not automatically called. That is why
we can test functions without launching the command-line interface.

Within main, argparse accepts either --scenario or --file, not both. The default
is the suspicious scenario. A conditional expression chooses a custom file when
provided; otherwise the code joins the selected bundled data path. The command
calls load_events, receives the timeline dictionary, and prints counts and rows.
The printing loop retrieves each original record from its wrapper and adds IAM
details only for IAM events. The printed arrow means actor action toward a
recipient; it is not another Python operator in this output string.

CLI exit status 1 means parsing failed. Successful parsing normally ends with
status 0. Status 0 does not mean an environment is secure. An empty list is allowed
but printed as no supplied events, never interpreted as no activity.

Actual call order is:

```text
main()
  → load_events(path)
      → JSON decoding callbacks
      → parse_dataset(dataset)
          → require_text(...), parse_timestamp(...), IP validation
          → duplicate comparison and sorting
      ← timeline dictionary
  → print timeline
```

## 14. Inspect results yourself in Python

From the project folder, start the interactive interpreter:

```sh
python3
```

You will see a `>>>` prompt. Enter the Python below; do not type the prompt itself.

```python
from triage.parser import load_events

timeline = load_events("data/suspicious/events.json")
type(timeline)
timeline["inputRecordCount"]
timeline["uniqueEventCount"]

first = timeline["events"][0]
first["record"]["eventId"]
first["record"]["actor"]
first["occurredAtUtc"]

grant = timeline["events"][-1]
grant["record"]["recipient"]
grant["sourceRecordIndices"]
```

Expected selected results are dict, 7, 6, suspicious-001,
casey.rivera@example.com, 2026-11-17T08:40:00Z, user:blair.chen@example.com,
and [0, 5]. Assignments do not print a result; entering an expression alone does.

Leave with `exit()` before entering shell commands again. Terminal commands such
as `cd` are not Python statements and should not be entered at the >>> prompt.

## 15. Experiment without changing the fictional source files

At a Python prompt in this project folder, enter:

```python
import copy
import json
from pathlib import Path
from triage.parser import ParseError, parse_dataset

original = json.loads(Path("data/suspicious/events.json").read_text())
extra = copy.deepcopy(original)
extra["events"].append(copy.deepcopy(extra["events"][0]))
result = parse_dataset(extra)
print(result["inputRecordCount"], result["uniqueEventCount"], result["duplicateRecordCount"])
```

Predict before running: output is `8 6 2`. We added a repeated record, not a new
distinct event. No file changed; extra is an independent in-memory object.

Next try:

```python
conflict = copy.deepcopy(original)
conflict["events"][5]["recipient"] = "user:alex.morgan@example.com"
try:
    parse_dataset(conflict)
except ParseError as error:
    print(error)
```

When entering the try/except block interactively, press Return on a blank line
after its final indented line. Expected: a record-index-5 error identifying
conflicting records sharing suspicious-005. That failure is intended. The code
must not choose which recipient to believe without more evidence.

## 16. Understand and run the tests

Leave the interactive interpreter with exit(), then run in Terminal:

```sh
python3 -m unittest discover -s tests -v
```

`unittest` is Python's test framework. `discover` finds test files, `-s tests`
selects the tests folder, and `-v` prints each test name. The parser initially
had 17 test methods; the full suite now includes later lessons. See the README
for the current test count. Several methods exercise multiple values through subtests.

In tests/test_parser.py:

- `class ParserTests(unittest.TestCase)` groups the checks.
- `setUp()` loads a fresh fixture before each test method so changes in one
  method do not leak into another.
- `self.assertEqual(actual, expected)` fails if behavior differs from the target.
- `assertRaisesRegex(ParseError, "Conflicting")` requires both a failure of the
  right type and a matching message. Expecting an error can be a passing test.
- `subTest` runs related inputs while identifying which specific value failed.
- `TemporaryDirectory` keeps malformed-file experiments outside source fixtures
  and removes them when the block ends.
- `patch("sys.argv", ...)` supplies pretend command-line arguments.
- `StringIO` and `redirect_stdout` capture printed output for assertions instead
  of requiring someone to visually inspect every command.

The first test checks 7 records become 6 unique events, validates chronological
event IDs, and checks source indices [0, 5] for the duplicate. Other tests check
invalid dates, missing fields, conflicting IDs, equal-time ordering, and preserved
inputs. Passing tests establish these exercised behaviors, not bug-free software
or accurate production security conclusions.

## 17. Your own short coding exercise

At the Python prompt, write a function named `is_successful(event)` that takes
one original event dictionary and returns True only when outcome equals success.
Call it with the first and last original events in the parsed timeline. Expect
False for the first event and True for the last. It should return booleans,
not print a conclusion, change data, or filter the timeline.

<details>
<summary>Compare your answer after trying it</summary>

```python
def is_successful(event):
    return event.get("outcome") == "success"
```

This only checks one field; it does not identify privileged grants or determine
whether an action is malicious. A successful sign-in also returns True.

</details>

## 18. Stop at this milestone

You should now be able to explain where the records come from, how JSON becomes
Python data, why we validate before analysis, how duplicate handling works,
how timestamps are sorted, and what the tests establish. Next we will implement
privileged-grant selection and actor-centered time-window correlation.

The original working folder, clean upload copy, and GitHub are separate copies.
Only the local documentation is updated automatically in this lesson. A prepared
upload copy may be refreshed separately; nothing is uploaded to GitHub by these
commands. No new detection behavior is introduced by this guide.
