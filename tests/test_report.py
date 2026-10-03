"""Tests for the JSON and HTML output."""

import json
import os
import sys
import tempfile
import unittest
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from detectlab import report  # noqa: E402

ALERT = {
    "rule_id": "DL-006", "rule": "SQL injection attempt", "severity": "high",
    "technique": "T1190", "technique_name": "Exploit Public-Facing Application", "tactic": "Initial Access",
    "time": datetime(2026, 10, 3, 9, 30, 2), "source_ip": "203.0.113.77", "user": None,
    "summary": "1 request(s) from 203.0.113.77 contain SQL injection payloads.",
    "event_count": 1, "evidence": ['GET /p?id=<script>alert(1)</script> HTTP/1.1'],
}


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)

    def path(self, name):
        return os.path.join(self.folder.name, name)

    def test_technique_links(self):
        self.assertEqual(report.technique_url("T1190"), "https://attack.mitre.org/techniques/T1190/")
        self.assertEqual(report.technique_url("T1110.001"), "https://attack.mitre.org/techniques/T1110/001/")

    def test_json_can_be_read_back(self):
        report.write_json([ALERT], self.path("alerts.json"))
        with open(self.path("alerts.json"), encoding="utf-8") as handle:
            rows = json.load(handle)
        self.assertEqual(rows[0]["rule_id"], "DL-006")
        self.assertEqual(rows[0]["time"], "2026-10-03T09:30:02Z")

    def test_html_escapes_log_content(self):
        # Log lines are attacker-controlled, so they must never be written as live HTML.
        report.write_html([ALERT], self.path("report.html"), event_count=10)
        with open(self.path("report.html"), encoding="utf-8") as handle:
            page = handle.read()
        self.assertNotIn("<script>alert(1)</script>", page)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", page)
        self.assertIn("https://attack.mitre.org/techniques/T1190/", page)

    def test_html_with_no_alerts(self):
        report.write_html([], self.path("report.html"))
        with open(self.path("report.html"), encoding="utf-8") as handle:
            self.assertIn("No alerts", handle.read())

    def test_severity_counts(self):
        counts = report.severity_counts([ALERT, ALERT])
        self.assertEqual(counts["high"], 2)
        self.assertEqual(counts["critical"], 0)


if __name__ == "__main__":
    unittest.main()
