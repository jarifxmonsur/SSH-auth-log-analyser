"""
This file generates a pseudo SSH auth log for test the main program.
"""

import argparse
import random
from datetime import datetime, timedelta

# List of genuine users and IPs they log in from
REAL_USERS = ["zarif", "admin", "deploy", "backup"]
INTERNAL_IPS = ["10.0.0.5", "10.0.0.12", "10.0.0.31", "192.168.1.100"]

# Usernames that attackers try quite often(taken from a single online search)
COMMON_TARGETS = [
    "root", "admin", "test", "user", "ubuntu", "oracle", "postgres",
    "mysql", "ftp", "guest", "nagios", "jenkins", "git", "pi",
    "ansible", "vagrant", "docker", "elastic", "tomcat", "www-data",
]

# "Noise" that is commonly found in real logs and should be ignored.
NOISE = [
    "server CRON[{pid}]: pam_unix(cron:session): session opened for user root",
    "server systemd[1]: Started Session {pid} of user zarif.",
    "server sudo: zarif : TTY=pts/0 ; PWD=/home/zarif ; USER=root ; COMMAND=/usr/bin/apt update",
    "server sshd[{pid}]: Received disconnect from 10.0.0.5 port 54321:11: disconnected by user",
]

def timestamp(when):
    """Format a datetime the way a syslog does.

    Syslog space-pads the day to two characters ("Jan  5", "Jan 15") and
    zero-pads the time. There is no year, which is why the parser has to
    supply one.
    """
    return f"{when.strftime('%b')} {when.day:>2} {when.strftime('%H:%M:%S')}"

def failed(when, user, ip, invalid=False):
    prefix = "invalid user " if invalid else ""
    return(
        f"{timestamp(when)} server sshd[{random.randint(1000, 9999)}]: "
        f"Failed password for {prefix}{user} from {ip} "
        f"port {random.randint(30000, 60000)} ssh2"
    )

def accepted(when, user, ip):
    return (
        f"{timestamp(when)} server sshd[{random.randint(1000, 9999)}]: "
        f"Accepted password for {user} from {ip} "
        f"port {random.randint(30000, 60000)} ssh2"
    )

def noise(when):
    template = random.choice(NOISE)
    return f"{timestamp(when)} {template.format(pid=random.randint(1000, 9999))}"

def normal_traffic(start, hours=8):
    """Ordinary logins and the mistyped password cases"""
    entries = []
    when = start

    for _ in range(hours * 6):
        when += timedelta(seconds=random.randint(60,900))
        user = random.choice(REAL_USERS)
        ip = random.choice(INTERNAL_IPS)

        if random.random() < 0.15:
            entries.append((when, failed(when, user, ip)))
            when += timedelta(seconds=random.randint(3, 20))

        entries.append((when, accepted(when, user, ip)))

        if random.random() < 0.3:
            when += timedelta(seconds=random.randint(5, 60))
            entries.append((when, noise(when)))

    return entries

def bruteforce_burst(start, ip, attempts=25, seconds=30):
    """Many failures for the same account in a very short time window"""
    entries = []
    when = start
    step = seconds / attempts

    for _ in range(attempts):
        when += timedelta(seconds=step + random.uniform(-0.3, 0.3))
        entries.append((when, failed(when, "root", ip)))

    return entries

def enumeration_scan(start, ip, count=40):
    """This is the case where the same IP tries many different account name"""
    entries = []
    when = start
    users = random.sample(COMMON_TARGETS, min(count, len(COMMON_TARGETS)))

    while len(users) < count:
        users.append(f"user{random.randint(1, 999)}")

    for user in users:
        when += timedelta(seconds=random.uniform(0.5, 3))
        entries.append((when, failed(when, user, ip, invalid=True)))

    return entries

def successful_breach(start, ip, attempts=15):
    """Multiple failures followed by a success meaning the intruder succeeded"""
    entries = []
    when = start

    for _ in range(attempts):
        when += timedelta(seconds=random.uniform(1, 4))
        entries.append((when, failed(when, "admin", ip)))

    when += timedelta(seconds=random.uniform(1, 4))
    entries.append((when, accepted(when, "admin", ip)))

    return entries

def main():
    parser = argparse.ArgumentParser(description="Generate a sample SSH auth log")
    parser.add_argument("--output", default="sample_auth.log")
    parser.add_argument("--seed", type=int, help="fix the seed for reproducible output")
    args = parser.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    start = datetime(2026, 1, 15, 6, 0, 0)

    entries = []
    entries += normal_traffic(start)

    entries += bruteforce_burst(start + timedelta(hours=2, minutes=17), "203.0.113.45")
    entries += enumeration_scan(start + timedelta(hours=4, minutes=3), "198.51.100.22")
    entries += successful_breach(start + timedelta(hours=6, minutes=41), "203.0.113.99")

    entries.sort(key=lambda pair: pair[0])

    with open(args.output, "w") as f:
        for _, line in entries:
            f.write(line + "\n")

    print(f"Wrote {len(entries)} lines to {args.output}")
    print()
    print("Planted attacks:")
    print("  203.0.113.45  — 25 failures in 30s (brute force)")
    print("  198.51.100.22 — 40 distinct usernames (enumeration)")
    print("  203.0.113.99  — 15 failures then a success (breach)")


if __name__ == "__main__":
    main()

