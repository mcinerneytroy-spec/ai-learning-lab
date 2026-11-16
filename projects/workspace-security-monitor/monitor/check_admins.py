"""Retrieve local snapshots and print new-administrator observations."""

import argparse

from monitor.admin_control import evaluate_new_admins
from monitor.client import CollectionError, fetch_snapshot


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--day", type=int, choices=(1, 2), default=2)
    parser.add_argument("--port", type=int, default=8000)
    arguments = parser.parse_args()
    try:
        current = fetch_snapshot(day=arguments.day, port=arguments.port)
        previous = fetch_snapshot(day=1, port=arguments.port) if arguments.day == 2 else None
        report = evaluate_new_admins(current, previous)
    except (CollectionError, ValueError) as error:
        parser.exit(1, f"Administrator assessment could not run: {error}\n")

    print(f"New administrators: {report['snapshotId']} | policy {report['policyVersion']}")
    print(f"Scope: {report['scope']}")
    print(f"Comparison status: {report['comparisonStatus']}")
    for row in report["results"]:
        print(f"{row['status']:8} {row['principal']} | {row['role']}")
        print(f"  {row['reason']}")
        if row["grantEvents"]:
            for event in row["grantEvents"]:
                print(f"  Actor: {event['actor'] or 'UNKNOWN'}")
                print(f"  Grant time: {event['eventTime']} | Event: {event['eventId']}")
        else:
            print("  Actor: UNKNOWN | Grant time: UNKNOWN")
        print(f"  Present in current snapshot: {row['presentInCurrentSnapshot']}")
    for gap in report["coverageGaps"]:
        print(f"Coverage gap: {gap}")
    for principal in report["excludedPrincipals"]:
        print(f"Outside direct-user scope: {principal}")
    print("Mock source completeness is declared, not independently established.")
    print("REVIEW does not mean access was unauthorized. No approval is inferred.")
    print("No evidence files saved. This command evaluates administrator grants only.")


if __name__ == "__main__":
    main()
