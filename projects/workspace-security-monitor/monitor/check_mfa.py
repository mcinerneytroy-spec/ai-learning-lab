"""Retrieve one local snapshot and print MFA observations without saving files."""

import argparse
from collections import Counter

from monitor.client import CollectionError, fetch_snapshot
from monitor.controls import evaluate_mfa


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--day", type=int, choices=(1, 2), default=1)
    parser.add_argument("--port", type=int, default=8000)
    arguments = parser.parse_args()
    try:
        snapshot = fetch_snapshot(day=arguments.day, port=arguments.port)
        report = evaluate_mfa(snapshot)
    except (CollectionError, ValueError) as error:
        parser.exit(1, f"MFA assessment could not run: {error}\n")

    print(f"MFA coverage: {report['snapshotId']} | policy {report['policyVersion']}")
    print(f"Source observation time: {report['sourceObservedAt']}")
    print(f"Scope: {report['scope']}")
    for result in report["results"]:
        email = result["principal"].removeprefix("user:")
        print(f"{result['status']:7} {email}: {result['reason']}")

    counts = Counter(result["status"] for result in report["results"])
    print(f"Summary: PASS={counts['PASS']} FAIL={counts['FAIL']} UNKNOWN={counts['UNKNOWN']}")
    if not report["results"]:
        print("No direct human users found; this is not an overall PASS.")
    for principal in report["excludedPrincipals"]:
        print(f"Outside direct-user scope: {principal}")
    print("Mock source completeness is declared, not independently established.")
    print("No evidence files saved. This command evaluates MFA only.")


if __name__ == "__main__":
    main()
