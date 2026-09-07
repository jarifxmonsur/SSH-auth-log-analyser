"""
This is an SSH auth log analyser.

It reads an authentication log and reports likely attacks such as:
1. Brute force: Mny failed logins from the same IP in a short time-span.
2. User enumeration: Uses the same IP but several different usernames.

Usage:
    python project.py sample_auth.log

"""

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from tabulate import tabulate

# A failed log line can have 2 formats
FAILED = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
    r"\S+ sshd\[\d+\]: Failed password for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\S+) port \d+"
)

# An accepted log line has a single format
ACCEPTED = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
    r"\S+ sshd\[\d+\]: Accepted password for (?P<user>\S+) "
    r"from (?P<ip>\S+) port \d+ ssh2"
)

# This function parses each line and checks if it follows the failed format or passed format and returns the data associated with it


def parse_line(line, year=None):

    if year is None:
        year = datetime.now().year

    match = FAILED.search(line)
    success = False

    if match:
        success = False
    else:
        match = ACCEPTED.search(line)
        if not match:
            return None
        success = True

    if not match:
        return None

    data = match.groupdict()
    time_str = f"{data['month']} {data['day']} {data['time']} {year}"
    timestamp = datetime.strptime(time_str, "%b %d %H:%M:%S %Y")

    return {
        "timestamp": timestamp,
        "ip": data["ip"],
        "user": data["user"],
        "success": success,
    }

# This functions opens the sample_auth.log and reads each line and sends it to parse_line func and then appends to events


def read_log(path, year=None):
    events = []
    with open(path) as f:
        for line in f:
            event = parse_line(line, year)
            if event is not None:
                events.append(event)

    return events

# This basically groups the events by its ip number


def group_by_ip(events):
    grouped = defaultdict(list)

    for event in events:
        grouped[event["ip"]].append(event)

    return grouped


def detect_bruteforce(events, threshold=5, window=timedelta(minutes=1)):
    """
    This functions checks if there are "threshold" failures in <= "window" time.
    Lets say by default. the threshold is 5 failures and the time window is 60s.
    The function first creates a list and then checks the ip_map for failures and
    appens them to the list. Then it checks for the failure timestamps and determines
    whether there are too many failures from that specific IP in window time period
    and appends it to the "findings" list and returns it.
    """

    findings = []
    ip_map = group_by_ip(events)

    for ip, ip_events in ip_map.items():
        failures = sorted([i["timestamp"] for i in ip_events if not i["success"]])

        if len(failures) < threshold:
            continue

        left = 0
        for right in range(len(failures)):
            while failures[right] - failures[left] > window:
                left += 1

            if right - left + 1 >= threshold:
                findings.append({
                    "ip": ip,
                    "count": right - left + 1,
                    "start": failures[left],
                    "end": failures[right],
                })
                break

    return findings


def detect_enumeration(events, threshold=10):
    """
    This function aims to detect a different kind of intrusion than brute force.
    What it does it looks at all of the attempts and adds it to the
    "findings" list if the number of failed attempts from the same IP regardless
    of the username exceeds the specified threshold. This one doesnt look at the
    time window, it looks at the total picture instead. It then returns the list
    that it created.
    """

    findings = []
    ip_map = group_by_ip(events)

    for ip, ip_events in ip_map.items():
        failed_users = {e["user"] for e in ip_events if not e["success"]}

        if len(failed_users) >= threshold:
            findings.append({
                "ip": ip,
                "count": len(failed_users),
                "users": sorted(list(failed_users)),
            })

    return findings


def summarise(events, bruteforce, enumeration):
    """
    This function builds the report as a string.
    """

    lines = []

    total_events = len(events)
    successes = sum(1 for i in events if i["success"])
    failures = total_events - successes

    lines.append("")

    lines.append("=== Summary ===")
    lines.append(f"Total events: {total_events}")
    lines.append(f"Successes: {successes}")
    lines.append(f"Failures: {failures}\n")

    lines.append("=== Brute Force Findings ===")
    lines.append("")
    if bruteforce:
        bf_data = [[f["ip"], f["count"], f["start"], f["end"]] for f in bruteforce]
        lines.append(tabulate(bf_data, headers=["IP", "Count", "Start", "End"]))
    else:
        lines.append("No brute force attacks detected.")
        lines.append("")

    lines.append("")
    lines.append("")
    lines.append("=== User Enumeration Findings ===")
    lines.append("")
    if enumeration:
        enum_data = [[f["ip"], f["count"], ", ".join(
            f["users"][:5]) + ("..." if len(f["users"]) > 5 else "")] for f in enumeration]
        lines.append(tabulate(enum_data, headers=["IP", "Distinct Users", "Sample Users"]))
    else:
        lines.append("No user enumeration attacks detected.")

    lines.append("")
    lines.append("")
    lines.append("=== Top 5 Targeted Usernames ===")
    lines.append("")
    top_users = Counter(e["user"] for e in events).most_common(5)
    if top_users:
        top_data = [[user, count] for user, count in top_users]
        lines.append(tabulate(top_data, headers=["Username", "Attempts"]))
    else:
        lines.append("No username data is available.")

    return "\n".join(lines)


def main():

    parser = argparse.ArgumentParser(
        description="Detect brute-force and user-enumeration attacks in an SSH auth log"
    )
    parser.add_argument("logfile", help="path to the auth log")
    parser.add_argument(
        "--threshold", type=int, default=5,
        help="failed logins needed to flag brute force (default: 5)"
    )

    parser.add_argument(
        "--window", type=int, default=60,
        help="brute-force window in seconds (default: 60)"
    )

    parser.add_argument(
        "--users", type=int, default=10,
        help="distinct usernames needed to flag enumeration (default: 10)"
    )

    parser.add_argument(
        "--year", type=int,
        help="year to assume for timestamps (syslog omits it)"
    )

    parser.add_argument(
        "--json", action="store_true",
        help="output findings as JSON instead of a table"
    )
    args = parser.parse_args()

    try:
        events = read_log(args.logfile, args.year)
    except FileNotFoundError:
        sys.exit(f"No such file: {args.logfile}")

    if not events:
        sys.exit(f"No SSH authentication events found in {args.logfile}")

    bruteforce = detect_bruteforce(events, threshold=args.threshold,
                                   window=timedelta(seconds=args.window))
    enumeration = detect_enumeration(events, threshold=args.users)

    if args.json:
        print(json.dumps(
            {"bruteforce": bruteforce, "enumeration": enumeration},
            indent=2,
            default=str,
        ))
    else:
        print(summarise(events, bruteforce, enumeration))


if __name__ == "__main__":
    main()

