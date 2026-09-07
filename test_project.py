"""
Tests for project.py
"""

from datetime import datetime, timedelta
from project import parse_line, detect_bruteforce, summarise

def test_parse_line():

    year = 2026

    line_failed_exist = "Jan 15 08:23:41 webserver sshd[12345]: Failed password for root from 192.168.1.50 port 49152 ssh2"
    line1 = parse_line(line_failed_exist, year=year)
    assert line1 == {
        "timestamp": datetime(2026, 1, 15, 8, 23, 41),
        "ip": "192.168.1.50",
        "user": "root",
        "success": False
    }

    line_failed_invalid = "Jan 15 08:24:00 webserver sshd[12345]: Failed password for invalid user admin from 192.168.1.51 port 49153 ssh2"
    line2 = parse_line(line_failed_invalid, year=year)
    assert line2 == {
        "timestamp": datetime(2026, 1, 15, 8, 24, 0),
        "ip": "192.168.1.51",
        "user": "admin",
        "success": False
    }

    line_accepted = "Jan 15 08:25:12 webserver sshd[12345]: Accepted password for deploy from 192.168.1.52 port 49154 ssh2"
    line3 = parse_line(line_accepted, year=year)
    assert line3 == {
        "timestamp": datetime(2026, 1, 15, 8, 25, 12),
        "ip": "192.168.1.52",
        "user": "deploy",
        "success": True
    }

    line_cron = "Jan 15 08:26:01 webserver CRON[12346]: (root) CMD (test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; })"
    line4 = parse_line(line_cron, year=year)
    assert line4 is None

# Making a helper function to test the bruteforce detection function.
def make_event(ip, seconds_offset, success=False, user="root"):
    return {
            "ip": ip,
            "user": user,
            "success": success,
            "timestamp": datetime(2026, 1, 1, 0, 0, 0) + timedelta(seconds=seconds_offset),
        }

def test_detect_bruteforce():

    threshold = 3
    window = timedelta(seconds=10)

    burst_events = [
        make_event("203.0.113.5", 0),
        make_event("203.0.113.5", 4),
        make_event("203.0.113.5", 8),
    ]

    findings1 = detect_bruteforce(burst_events, threshold=threshold, window=window)
    assert len(findings1) == 1
    assert findings1[0]["ip"] == "203.0.113.5"
    assert findings1[0]["count"] == 3


    spread_events = [
        make_event("203.0.113.6", 0),
        make_event("203.0.113.6", 15),
        make_event("203.0.113.6", 30),
    ]
    findings2 = detect_bruteforce(spread_events, threshold=threshold, window=window)
    assert len(findings2) == 0


    boundary_events = [
        make_event("203.0.113.7", 0),
        make_event("203.0.113.7", 2),
    ]
    findings3 = detect_bruteforce(boundary_events, threshold=threshold, window=window)
    assert len(findings3) == 0


    mix_events = [
        make_event("203.0.113.8", 0, success=False),
        make_event("203.0.113.8", 2, success=True), # Success
        make_event("203.0.113.8", 4, success=False),
    ]
    findings4 = detect_bruteforce(mix_events, threshold=threshold, window=window)
    assert len(findings4) == 0

def test_summarise():
    base_time = datetime(2026, 1, 1, 12, 0, 0)

    sample_events = [
        {"timestamp": base_time, "ip": "1.1.1.1", "user": "root", "success": False},
        {"timestamp": base_time, "ip": "1.1.1.1", "user": "admin", "success": False},
        {"timestamp": base_time, "ip": "2.2.2.2", "user": "root", "success": True},

    ]

    fake_bruteforce = [
        {"ip": "1.1.1.1", "count": 5, "start": base_time, "end": base_time + timedelta(seconds=10)}
    ]

    fake_enumeration = [
        {"ip": "1.1.1.1", "count": 2, "users": ["admin", "root"]}
    ]

    report = summarise(sample_events, fake_bruteforce, fake_enumeration)
    assert "Total events: 3" in report
    assert "Successes: 1" in report
    assert "Failures: 2" in report
    assert "1.1.1.1" in report
    assert "root" in report

    empty_report = summarise(sample_events, [], [])
    assert "No brute force attacks detected." in empty_report
    assert "No user enumeration attacks detected." in empty_report

