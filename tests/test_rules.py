"""Tests for the detection rules. Every rule is checked for a hit and for a case it must ignore."""

import os
import sys
import unittest
from collections import Counter
from datetime import datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from detectlab import parsers, rules  # noqa: E402

START = datetime(2026, 10, 3, 9, 0, 0)
ROOT = os.path.join(os.path.dirname(__file__), "..")


def failed(seconds, ip="203.0.113.50", user="root"):
    return {"source": "auth", "type": "ssh_failed", "time": START + timedelta(seconds=seconds),
            "ip": ip, "user": user, "host": "web01", "raw": "failed {} {}".format(user, ip)}


def accepted(seconds, ip="203.0.113.50", user="root"):
    return {"source": "auth", "type": "ssh_accepted", "time": START + timedelta(seconds=seconds),
            "ip": ip, "user": user, "host": "web01", "raw": "accepted {} {}".format(user, ip)}


def request(seconds, path="/", status=200, ip="203.0.113.77", agent="Mozilla/5.0"):
    return {"source": "web", "type": "http_request", "time": START + timedelta(seconds=seconds),
            "ip": ip, "method": "GET", "path": path, "decoded_path": parsers.decode_path(path),
            "status": status, "agent": agent, "raw": "GET {}".format(path)}


class BruteForceTests(unittest.TestCase):
    def test_five_quick_failures_raise_an_alert(self):
        alerts = rules.detect_brute_force([failed(i * 5) for i in range(5)])
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["rule_id"], "DL-001")
        self.assertEqual(alerts[0]["technique"], "T1110.001")
        self.assertEqual(alerts[0]["source_ip"], "203.0.113.50")

    def test_four_failures_are_ignored(self):
        self.assertEqual(rules.detect_brute_force([failed(i * 5) for i in range(4)]), [])

    def test_slow_failures_are_ignored(self):
        # Five failures, but ten minutes apart: a forgetful user, not an attack.
        self.assertEqual(rules.detect_brute_force([failed(i * 600) for i in range(5)]), [])

    def test_failures_spread_over_many_accounts_are_not_brute_force(self):
        events = [failed(i * 5, user="user{}".format(i)) for i in range(8)]
        self.assertEqual(rules.detect_brute_force(events), [])


class PasswordSprayTests(unittest.TestCase):
    def test_many_usernames_from_one_ip(self):
        events = [failed(i * 20, user="user{}".format(i)) for i in range(5)]
        alerts = rules.detect_password_spray(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["technique"], "T1110.003")

    def test_one_username_many_times_is_not_spraying(self):
        self.assertEqual(rules.detect_password_spray([failed(i * 5) for i in range(20)]), [])

    def test_usernames_from_different_ips_are_not_spraying(self):
        events = [failed(i * 20, ip="203.0.113.{}".format(i), user="user{}".format(i)) for i in range(8)]
        self.assertEqual(rules.detect_password_spray(events), [])

    def test_only_one_alert_per_ip(self):
        events = [failed(i * 5, user="user{}".format(i)) for i in range(12)]
        self.assertEqual(len(rules.detect_password_spray(events)), 1)


class LoginAfterFailuresTests(unittest.TestCase):
    def test_success_after_failures_is_critical(self):
        events = [failed(i * 5) for i in range(6)] + [accepted(60)]
        alerts = rules.detect_login_after_failures(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["severity"], "critical")
        self.assertEqual(alerts[0]["user"], "root")

    def test_a_couple_of_typos_then_success_is_normal(self):
        events = [failed(0), failed(5), accepted(15)]
        self.assertEqual(rules.detect_login_after_failures(events), [])

    def test_success_from_a_different_ip_is_not_linked(self):
        events = [failed(i * 5) for i in range(6)] + [accepted(60, ip="10.0.0.21")]
        self.assertEqual(rules.detect_login_after_failures(events), [])

    def test_old_failures_do_not_count(self):
        events = [failed(i * 5) for i in range(6)] + [accepted(3600)]
        self.assertEqual(rules.detect_login_after_failures(events), [])

    def test_failures_after_the_login_do_not_count(self):
        events = [accepted(0)] + [failed(10 + i * 5) for i in range(6)]
        self.assertEqual(rules.detect_login_after_failures(events), [])


class AccountTests(unittest.TestCase):
    def test_sudo_denied(self):
        event = {"type": "sudo_denied", "time": START, "user": "deploy", "command": "/usr/bin/cat /etc/shadow",
                 "host": "web01", "raw": "sudo denied"}
        alerts = rules.detect_sudo_denied([event])
        self.assertEqual(alerts[0]["technique"], "T1548.003")
        self.assertIn("/etc/shadow", alerts[0]["summary"])

    def test_account_created(self):
        event = {"type": "user_created", "time": START, "user": "sysbackup", "host": "web01", "raw": "useradd"}
        alerts = rules.detect_account_created([event])
        self.assertEqual(alerts[0]["technique"], "T1136.001")
        self.assertEqual(alerts[0]["user"], "sysbackup")


class WebTests(unittest.TestCase):
    def test_sql_injection_payloads(self):
        for path in ["/p?id=1%27%20OR%20%271%27%3D%271",
                     "/p?id=1 UNION SELECT username,password FROM users",
                     "/p?id=1+UNION+ALL+SELECT+NULL",
                     "/p?id=1 AND SLEEP(5)",
                     "/p?q=x FROM information_schema.tables"]:
            self.assertEqual(len(rules.detect_sql_injection([request(0, path)])), 1, path)

    def test_ordinary_urls_are_not_sql_injection(self):
        events = [request(0, "/products?id=12"), request(1, "/search?q=trade+union+news"),
                  request(2, "/blog/how-to-select-a-laptop"), request(3, "/sleep-tips")]
        self.assertEqual(rules.detect_sql_injection(events), [])

    def test_sql_injection_is_grouped_by_ip(self):
        events = [request(i, "/p?id=1 UNION SELECT {}".format(i)) for i in range(4)]
        alerts = rules.detect_sql_injection(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["event_count"], 4)
        self.assertEqual(len(alerts[0]["evidence"]), 4)

    def test_path_traversal_plain_and_encoded(self):
        for path in ["/download?file=../../etc/passwd",
                     "/download?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                     "/download?file=..%252f..%252fetc%252fshadow"]:
            self.assertEqual(len(rules.detect_path_traversal([request(0, path)])), 1, path)

    def test_ordinary_paths_are_not_traversal(self):
        self.assertEqual(rules.detect_path_traversal([request(0, "/docs/v1.2/guide..html")]), [])

    def test_scanner_user_agents(self):
        alerts = rules.detect_scanner_agents([request(0, agent="sqlmap/1.7.11#stable"),
                                              request(1, agent="Mozilla/5.00 (Nikto/2.5.0)", ip="203.0.113.140")])
        self.assertEqual(sorted(a["source_ip"] for a in alerts), ["203.0.113.140", "203.0.113.77"])
        self.assertTrue(all(a["technique"] == "T1595.002" for a in alerts))

    def test_browsers_are_not_scanners(self):
        self.assertEqual(rules.detect_scanner_agents([request(0, agent="Mozilla/5.0 Safari/605.1.15")]), [])

    def test_burst_of_404s_is_enumeration(self):
        events = [request(i, "/guess{}".format(i), status=404) for i in range(25)]
        alerts = rules.detect_directory_enumeration(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["technique"], "T1595.003")

    def test_occasional_404s_are_normal(self):
        # 25 missing pages, but spread over more than four hours.
        events = [request(i * 600, "/favicon.ico", status=404) for i in range(25)]
        self.assertEqual(rules.detect_directory_enumeration(events), [])

    def test_successful_requests_are_not_enumeration(self):
        self.assertEqual(rules.detect_directory_enumeration([request(i) for i in range(50)]), [])


class EvidenceTests(unittest.TestCase):
    def test_evidence_is_capped(self):
        alert = rules.detect_brute_force([failed(i) for i in range(40)])[0]
        self.assertEqual(alert["event_count"], 40)
        self.assertEqual(len(alert["evidence"]), rules.MAX_EVIDENCE)

    def test_alerts_come_back_in_time_order(self):
        events = [request(500, "/p?id=1 UNION SELECT 1")] + [failed(i * 5) for i in range(5)]
        alerts = rules.run_detections(events)
        self.assertEqual([a["rule_id"] for a in alerts], ["DL-001", "DL-006"])

    def test_every_rule_has_a_mitre_mapping(self):
        for rule_id, rule in rules.RULES.items():
            self.assertRegex(rule["technique"], r"^T\d{4}(\.\d{3})?$", rule_id)
            self.assertIn(rule["severity"], rules.SEVERITY_ORDER, rule_id)


class SampleLogTests(unittest.TestCase):
    """End-to-end check: the sample logs must raise exactly the alerts the README describes."""

    def setUp(self):
        events = parsers.read_auth_log(os.path.join(ROOT, "sample_logs", "auth.log"), 2026)
        events += parsers.read_access_log(os.path.join(ROOT, "sample_logs", "access.log"))
        self.alerts = rules.run_detections(events)

    def test_expected_alerts(self):
        self.assertEqual(Counter(a["rule_id"] for a in self.alerts), {
            "DL-001": 2, "DL-002": 1, "DL-003": 1, "DL-004": 1, "DL-005": 1,
            "DL-006": 1, "DL-007": 1, "DL-008": 2, "DL-009": 1})

    def test_ordinary_users_are_never_flagged(self):
        flagged = {a["source_ip"] for a in self.alerts if a["source_ip"]}
        self.assertTrue(all(ip.startswith("203.0.113.") for ip in flagged), flagged)


if __name__ == "__main__":
    unittest.main()
