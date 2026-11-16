"""Retrieve one local snapshot and print device EDR coverage observations."""

import argparse
from collections import Counter

from monitor.client import CollectionError, fetch_snapshot
from monitor.edr_control import evaluate_edr


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--day", type=int, choices=(1, 2), default=1)
    parser.add_argument("--port", type=int, default=8000)
    arguments = parser.parse_args()
    try:
        snapshot = fetch_snapshot(day=arguments.day, port=arguments.port)
        report = evaluate_edr(snapshot)
    except (CollectionError, ValueError) as error:
        parser.exit(1, f"EDR assessment could not run: {error}\n")

    print(f"EDR coverage: {report['snapshotId']} | policy {report['policyVersion']}")
    print(f"Source observation time: {report['sourceObservedAt']}")
    print(f"Scope: {report['scope']}")
    for row in report["results"]:
        print(f"{row['status']:7} {row['hostname'] or row['deviceId']}: {row['reason']}")
    counts = Counter(row["status"] for row in report["results"])
    print(f"Summary: PASS={counts['PASS']} FAIL={counts['FAIL']} UNKNOWN={counts['UNKNOWN']}")
    if not report["results"]:
        print("No devices assessed; this is not an overall PASS.")
    for device_id in report["excludedDeviceIds"]:
        print(f"EDR not required by inventory: {device_id}")
    for gap in report["coverageGaps"]:
        print(f"Coverage gap: {gap}")
    for device_id in report["unmatchedEdrDeviceIds"]:
        print(f"EDR device missing from inventory: {device_id}")
    print("Mock source completeness is declared, not independently established.")
    print("No evidence files saved. This command evaluates EDR coverage only.")


if __name__ == "__main__":
    main()
