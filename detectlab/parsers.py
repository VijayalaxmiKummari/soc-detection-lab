"""
parsers.py - turn raw log lines into plain Python dictionaries ("events").

Two log formats are supported:

  * Linux auth.log / secure  (SSH logins, sudo, new accounts)
  * Apache / Nginx access log in the "combined" format

Lines that carry nothing the detection rules care about (cron jobs, session
open/close messages and so on) are skipped, and so are lines that cannot be
read. A bad line never stops the run.
"""

import re
from datetime import datetime, timezone
from urllib.parse import unquote_plus

MONTHS = {name: number for number, name in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}

# Oct  3 09:12:05 web01 sshd[2211]: Failed password for root from 203.0.113.50 port 40112 ssh2
SYSLOG_LINE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2}) (?P<clock>\d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) (?P<process>[\w\-./]+)(?:\[\d+\])?: (?P<message>.*)$")

SSH_FAILED = re.compile(r"Failed password for (?P<invalid>invalid user )?(?P<user>\S+) from (?P<ip>\S+) port \d+")
SSH_ACCEPTED = re.compile(r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port \d+")
SUDO_DENIED = re.compile(r"^\s*(?P<user>\S+) : user NOT in sudoers ; .*COMMAND=(?P<command>.*)$")
USER_CREATED = re.compile(r"new user: name=(?P<user>[^,\s]+)")

# 203.0.113.77 - - [03/Oct/2026:09:30:02 +0000] "GET /x?id=1 HTTP/1.1" 200 512 "-" "sqlmap/1.7"
ACCESS_LINE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<request>[^"]*)" '
    r'(?P<status>\d{3}) (?P<size>\S+)(?: "(?P<referrer>[^"]*)" "(?P<agent>[^"]*)")?')


def parse_auth_line(line, year, line_number=None):
    """Read one auth.log line. Returns an event, or None if the line is not of interest.

    auth.log does not record the year, so the caller has to supply it.
    """
    match = SYSLOG_LINE.match(line.rstrip("\n"))
    if not match or match["month"] not in MONTHS:
        return None
    try:
        hour, minute, second = (int(part) for part in match["clock"].split(":"))
        when = datetime(year, MONTHS[match["month"]], int(match["day"]), hour, minute, second)
    except ValueError:
        return None

    event = {"source": "auth", "time": when, "host": match["host"],
             "raw": line.strip(), "line": line_number}
    process, message = match["process"], match["message"]

    if process == "sshd":
        failed = SSH_FAILED.search(message)
        if failed:
            event.update(type="ssh_failed", user=failed["user"], ip=failed["ip"],
                         invalid_user=bool(failed["invalid"]))
            return event
        accepted = SSH_ACCEPTED.search(message)
        if accepted:
            event.update(type="ssh_accepted", user=accepted["user"], ip=accepted["ip"],
                         method=accepted["method"])
            return event
    elif process == "sudo":
        denied = SUDO_DENIED.search(message)
        if denied:
            event.update(type="sudo_denied", user=denied["user"], command=denied["command"].strip())
            return event
    elif process == "useradd":
        created = USER_CREATED.search(message)
        if created:
            event.update(type="user_created", user=created["user"])
            return event
    return None


def decode_path(path):
    """Undo URL encoding (twice, to catch double-encoded payloads) and lower-case the result."""
    return unquote_plus(unquote_plus(path)).lower()


def parse_access_line(line, line_number=None):
    """Read one web access log line. Returns an event, or None if the line cannot be read."""
    match = ACCESS_LINE.match(line.rstrip("\n"))
    if not match:
        return None
    try:
        when = datetime.strptime(match["time"], "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return None
    # Store every time as plain UTC so auth and web events can be sorted together.
    when = when.astimezone(timezone.utc).replace(tzinfo=None)

    parts = match["request"].split(" ")
    method = parts[0] if parts else ""
    if len(parts) >= 3 and parts[-1].startswith("HTTP/"):
        path = " ".join(parts[1:-1])
    else:
        path = " ".join(parts[1:])

    return {"source": "web", "type": "http_request", "time": when, "ip": match["ip"],
            "method": method, "path": path, "decoded_path": decode_path(path),
            "status": int(match["status"]), "agent": match["agent"] or "",
            "raw": line.strip(), "line": line_number}


def parse_auth_lines(lines, year):
    events = (parse_auth_line(line, year, number) for number, line in enumerate(lines, start=1))
    return [event for event in events if event]


def parse_access_lines(lines):
    events = (parse_access_line(line, number) for number, line in enumerate(lines, start=1))
    return [event for event in events if event]


def read_auth_log(path, year):
    with open(path, encoding="utf-8", errors="replace") as handle:
        return parse_auth_lines(handle, year)


def read_access_log(path):
    with open(path, encoding="utf-8", errors="replace") as handle:
        return parse_access_lines(handle)
