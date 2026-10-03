"""Tests for the log parsers. Run with:  python3 -m unittest discover tests -v"""

import os
import sys
import unittest
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from detectlab import parsers  # noqa: E402


class AuthLogTests(unittest.TestCase):
    def test_failed_password(self):
        event = parsers.parse_auth_line(
            "Oct  3 09:12:05 web01 sshd[2211]: Failed password for root from 203.0.113.50 port 40112 ssh2", 2026)
        self.assertEqual(event["type"], "ssh_failed")
        self.assertEqual(event["user"], "root")
        self.assertEqual(event["ip"], "203.0.113.50")
        self.assertFalse(event["invalid_user"])
        self.assertEqual(event["time"], datetime(2026, 10, 3, 9, 12, 5))

    def test_failed_password_for_unknown_user(self):
        event = parsers.parse_auth_line(
            "Oct 13 10:30:00 web01 sshd[2540]: Failed password for invalid user admin from 203.0.113.61 port 38800 ssh2", 2026)
        self.assertEqual(event["user"], "admin")
        self.assertTrue(event["invalid_user"])

    def test_accepted_login(self):
        event = parsers.parse_auth_line(
            "Oct  3 07:58:12 web01 sshd[1840]: Accepted publickey for alice from 10.0.0.21 port 50212 ssh2", 2026)
        self.assertEqual(event["type"], "ssh_accepted")
        self.assertEqual(event["method"], "publickey")
        self.assertEqual(event["user"], "alice")

    def test_sudo_denied(self):
        event = parsers.parse_auth_line(
            "Oct  3 11:05:44 web01 sudo:   deploy : user NOT in sudoers ; TTY=pts/1 ; "
            "PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow", 2026)
        self.assertEqual(event["type"], "sudo_denied")
        self.assertEqual(event["user"], "deploy")
        self.assertEqual(event["command"], "/usr/bin/cat /etc/shadow")

    def test_allowed_sudo_is_not_an_event(self):
        line = ("Oct  3 08:04:40 web01 sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; "
                "USER=root ; COMMAND=/usr/bin/systemctl restart nginx")
        self.assertIsNone(parsers.parse_auth_line(line, 2026))

    def test_new_account(self):
        event = parsers.parse_auth_line(
            "Oct  3 14:40:03 web01 useradd[3120]: new user: name=sysbackup, UID=1004, GID=1004, "
            "home=/home/sysbackup, shell=/bin/sh, from=/dev/pts/0", 2026)
        self.assertEqual(event["type"], "user_created")
        self.assertEqual(event["user"], "sysbackup")

    def test_uninteresting_and_broken_lines_are_skipped(self):
        lines = [
            "Oct  3 08:17:01 web01 CRON[2008]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)",
            "this is not a log line",
            "",
            "Xyz  3 08:17:01 web01 sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2",
            "Feb 31 08:17:01 web01 sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2",
        ]
        self.assertEqual(parsers.parse_auth_lines(lines, 2026), [])

    def test_line_numbers_are_kept(self):
        lines = ["junk", "Oct  3 09:12:05 web01 sshd[1]: Failed password for root from 203.0.113.50 port 1 ssh2"]
        self.assertEqual(parsers.parse_auth_lines(lines, 2026)[0]["line"], 2)


class AccessLogTests(unittest.TestCase):
    LINE = ('203.0.113.77 - - [03/Oct/2026:09:30:02 +0000] '
            '"GET /products.php?id=1%27%20OR%20%271%27%3D%271 HTTP/1.1" 500 512 "-" "sqlmap/1.7.11"')

    def test_fields_are_read(self):
        event = parsers.parse_access_line(self.LINE)
        self.assertEqual(event["ip"], "203.0.113.77")
        self.assertEqual(event["method"], "GET")
        self.assertEqual(event["status"], 500)
        self.assertEqual(event["agent"], "sqlmap/1.7.11")
        self.assertEqual(event["time"], datetime(2026, 10, 3, 9, 30, 2))

    def test_path_is_url_decoded(self):
        event = parsers.parse_access_line(self.LINE)
        self.assertEqual(event["decoded_path"], "/products.php?id=1' or '1'='1")

    def test_double_encoding_is_undone(self):
        self.assertEqual(parsers.decode_path("/a?f=..%252f..%252fetc"), "/a?f=../../etc")

    def test_time_is_converted_to_utc(self):
        line = '198.51.100.14 - - [03/Oct/2026:10:00:00 +0100] "GET / HTTP/1.1" 200 5120 "-" "Mozilla/5.0"'
        self.assertEqual(parsers.parse_access_line(line)["time"], datetime(2026, 10, 3, 9, 0, 0))

    def test_common_format_without_user_agent(self):
        event = parsers.parse_access_line('198.51.100.14 - - [03/Oct/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 5120')
        self.assertEqual(event["agent"], "")
        self.assertEqual(event["path"], "/")

    def test_broken_lines_are_skipped(self):
        self.assertEqual(parsers.parse_access_lines(["nonsense", "", '1.2.3.4 - - [bad time] "GET / HTTP/1.1" 200 1']), [])


if __name__ == "__main__":
    unittest.main()
