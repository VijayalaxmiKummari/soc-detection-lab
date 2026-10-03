"""
rules.py - the detection rules.

Each rule is a small function that takes a list of events (see parsers.py) and
returns a list of alerts. The rules only look at plain Python data, so every
one of them can be tested without a real log file.

Every rule is mapped to a MITRE ATT&CK technique so an analyst can see at a
glance what the activity means and where it sits in an attack.
"""

import re
from collections import defaultdict
from datetime import timedelta

# Thresholds (change these to make the rules stricter or looser)
BRUTE_FORCE_FAILURES = 5          # failed logins for one account from one IP ...
BRUTE_FORCE_WINDOW = 120          # ... within this many seconds
SPRAY_USERS = 5                   # different usernames tried from one IP ...
SPRAY_WINDOW = 600                # ... within this many seconds
COMPROMISE_FAILURES = 5           # failures before a successful login ...
COMPROMISE_WINDOW = 600           # ... within this many seconds
ENUMERATION_404S = 20             # "not found" replies to one IP ...
ENUMERATION_WINDOW = 60           # ... within this many seconds
MAX_EVIDENCE = 5                  # raw log lines kept with each alert

RULES = {
    "DL-001": {"name": "SSH brute force against one account", "severity": "high",
               "technique": "T1110.001", "technique_name": "Brute Force: Password Guessing",
               "tactic": "Credential Access"},
    "DL-002": {"name": "SSH password spraying", "severity": "high",
               "technique": "T1110.003", "technique_name": "Brute Force: Password Spraying",
               "tactic": "Credential Access"},
    "DL-003": {"name": "Successful SSH login after repeated failures", "severity": "critical",
               "technique": "T1078", "technique_name": "Valid Accounts",
               "tactic": "Initial Access"},
    "DL-004": {"name": "Sudo attempt by a user who is not allowed", "severity": "medium",
               "technique": "T1548.003", "technique_name": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
               "tactic": "Privilege Escalation"},
    "DL-005": {"name": "New local account created", "severity": "medium",
               "technique": "T1136.001", "technique_name": "Create Account: Local Account",
               "tactic": "Persistence"},
    "DL-006": {"name": "SQL injection attempt", "severity": "high",
               "technique": "T1190", "technique_name": "Exploit Public-Facing Application",
               "tactic": "Initial Access"},
    "DL-007": {"name": "Path traversal attempt", "severity": "high",
               "technique": "T1190", "technique_name": "Exploit Public-Facing Application",
               "tactic": "Initial Access"},
    "DL-008": {"name": "Known scanning tool user agent", "severity": "medium",
               "technique": "T1595.002", "technique_name": "Active Scanning: Vulnerability Scanning",
               "tactic": "Reconnaissance"},
    "DL-009": {"name": "Web directory enumeration", "severity": "medium",
               "technique": "T1595.003", "technique_name": "Active Scanning: Wordlist Scanning",
               "tactic": "Reconnaissance"},
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

SQLI_PATTERNS = re.compile(
    r"union\s+(all\s+)?select"            # UNION SELECT
    r"|'\s*or\s+'?\d+'?\s*=\s*'?\d+"      # ' OR '1'='1
    r"|information_schema"
    r"|sleep\s*\(\s*\d+\s*\)"             # time-based blind injection
    r"|benchmark\s*\("
    r"|;\s*drop\s+table")

TRAVERSAL_PATTERNS = re.compile(r"\.\./|\.\.\\|/etc/passwd|/etc/shadow|boot\.ini|win\.ini")

SCANNER_AGENTS = re.compile(r"sqlmap|nikto|nmap|gobuster|dirbuster|wpscan|masscan|nuclei|ffuf|zgrab", re.IGNORECASE)


def _alert(rule_id, events, summary, source_ip=None, user=None):
    """Build one alert. 'events' are the log events that triggered it."""
    rule = RULES[rule_id]
    return {
        "rule_id": rule_id,
        "rule": rule["name"],
        "severity": rule["severity"],
        "technique": rule["technique"],
        "technique_name": rule["technique_name"],
        "tactic": rule["tactic"],
        "time": events[0]["time"],
        "source_ip": source_ip,
        "user": user,
        "summary": summary,
        "event_count": len(events),
        "evidence": [event["raw"] for event in events[:MAX_EVIDENCE]],
    }


def _of_type(events, kind):
    return sorted((e for e in events if e.get("type") == kind), key=lambda e: e["time"])


def _first_burst(events, threshold, window_seconds):
    """Return the first run of 'threshold' events that fits inside the time window, or None.

    'events' must already be sorted by time.
    """
    window = timedelta(seconds=window_seconds)
    start = 0
    for end, event in enumerate(events):
        while event["time"] - events[start]["time"] > window:
            start += 1
        if end - start + 1 >= threshold:
            return events[start:end + 1]
    return None


def detect_brute_force(events):
    """DL-001: many failed SSH logins for the same account from the same IP in a short time."""
    attempts = defaultdict(list)
    for event in _of_type(events, "ssh_failed"):
        attempts[(event["ip"], event["user"])].append(event)

    alerts = []
    for (ip, user), failures in attempts.items():
        if _first_burst(failures, BRUTE_FORCE_FAILURES, BRUTE_FORCE_WINDOW):
            alerts.append(_alert(
                "DL-001", failures,
                "{} failed SSH logins for '{}' from {}.".format(len(failures), user, ip),
                source_ip=ip, user=user))
    return alerts


def detect_password_spray(events):
    """DL-002: one IP trying many different usernames in a short time."""
    by_ip = defaultdict(list)
    for event in _of_type(events, "ssh_failed"):
        by_ip[event["ip"]].append(event)

    alerts = []
    window = timedelta(seconds=SPRAY_WINDOW)
    for ip, failures in by_ip.items():
        start = 0
        for end, event in enumerate(failures):
            while event["time"] - failures[start]["time"] > window:
                start += 1
            users = {f["user"] for f in failures[start:end + 1]}
            if len(users) >= SPRAY_USERS:
                all_users = sorted({f["user"] for f in failures})
                alerts.append(_alert(
                    "DL-002", failures,
                    "{} tried {} different usernames over SSH ({}).".format(
                        ip, len(all_users), ", ".join(all_users)),
                    source_ip=ip))
                break
    return alerts


def detect_login_after_failures(events):
    """DL-003: a login that succeeds straight after a run of failures from the same IP.

    This is the pattern that suggests a password was actually guessed.
    """
    failures_by_ip = defaultdict(list)
    for event in _of_type(events, "ssh_failed"):
        failures_by_ip[event["ip"]].append(event)

    alerts = []
    window = timedelta(seconds=COMPROMISE_WINDOW)
    for login in _of_type(events, "ssh_accepted"):
        earlier = [f for f in failures_by_ip.get(login["ip"], [])
                   if timedelta(0) <= login["time"] - f["time"] <= window]
        if len(earlier) >= COMPROMISE_FAILURES:
            alerts.append(_alert(
                "DL-003", [login] + earlier,
                "'{}' logged in from {} after {} failed attempts from the same address.".format(
                    login["user"], login["ip"], len(earlier)),
                source_ip=login["ip"], user=login["user"]))
    return alerts


def detect_sudo_denied(events):
    """DL-004: a user who is not in the sudoers file tried to run a command as root."""
    return [_alert("DL-004", [event],
                   "'{}' is not in sudoers but tried to run: {}".format(event["user"], event["command"]),
                   user=event["user"])
            for event in _of_type(events, "sudo_denied")]


def detect_account_created(events):
    """DL-005: a new local account appeared. Often legitimate, so it needs checking against change records."""
    return [_alert("DL-005", [event],
                   "New local account '{}' was created on {}.".format(event["user"], event["host"]),
                   user=event["user"])
            for event in _of_type(events, "user_created")]


def _web_matches_by_ip(events, test):
    """Group the web requests that pass 'test' by the IP that sent them."""
    by_ip = defaultdict(list)
    for event in _of_type(events, "http_request"):
        if test(event):
            by_ip[event["ip"]].append(event)
    return by_ip


def detect_sql_injection(events):
    """DL-006: SQL injection payloads in the requested URL."""
    matches = _web_matches_by_ip(events, lambda e: SQLI_PATTERNS.search(e["decoded_path"]))
    return [_alert("DL-006", hits,
                   "{} request(s) from {} contain SQL injection payloads.".format(len(hits), ip),
                   source_ip=ip)
            for ip, hits in matches.items()]


def detect_path_traversal(events):
    """DL-007: attempts to climb out of the web root or read system files."""
    matches = _web_matches_by_ip(events, lambda e: TRAVERSAL_PATTERNS.search(e["decoded_path"]))
    return [_alert("DL-007", hits,
                   "{} request(s) from {} try to read files outside the web root.".format(len(hits), ip),
                   source_ip=ip)
            for ip, hits in matches.items()]


def detect_scanner_agents(events):
    """DL-008: requests whose user agent names a well-known scanning tool."""
    matches = _web_matches_by_ip(events, lambda e: SCANNER_AGENTS.search(e["agent"]))
    alerts = []
    for ip, hits in matches.items():
        tool = SCANNER_AGENTS.search(hits[0]["agent"]).group(0).lower()
        alerts.append(_alert("DL-008", hits,
                             "{} request(s) from {} identify themselves as '{}'.".format(len(hits), ip, tool),
                             source_ip=ip))
    return alerts


def detect_directory_enumeration(events):
    """DL-009: a burst of 'not found' replies to one IP, as a wordlist scanner would cause."""
    matches = _web_matches_by_ip(events, lambda e: e["status"] == 404)
    return [_alert("DL-009", hits,
                   "{} requests from {} returned 404, with at least {} inside {} seconds.".format(
                       len(hits), ip, ENUMERATION_404S, ENUMERATION_WINDOW),
                   source_ip=ip)
            for ip, hits in matches.items()
            if _first_burst(hits, ENUMERATION_404S, ENUMERATION_WINDOW)]


ALL_DETECTIONS = (detect_brute_force, detect_password_spray, detect_login_after_failures,
                  detect_sudo_denied, detect_account_created, detect_sql_injection,
                  detect_path_traversal, detect_scanner_agents, detect_directory_enumeration)


def run_detections(events):
    """Run every rule and return all alerts in time order."""
    alerts = []
    for detection in ALL_DETECTIONS:
        alerts.extend(detection(events))
    return sorted(alerts, key=lambda a: (a["time"], a["rule_id"]))
