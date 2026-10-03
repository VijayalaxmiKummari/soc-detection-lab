"""
SOC Detection Lab - read SSH and web server logs, run detection rules mapped to
MITRE ATT&CK, and report what was found.

Usage:
    python3 detect.py                                   (analyse the sample logs)
    python3 detect.py --auth /var/log/auth.log --access /var/log/nginx/access.log
    python3 detect.py --html report.html --json alerts.json
"""

import argparse
import os
from datetime import date

from detectlab import parsers, report, rules

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLE_AUTH = os.path.join(HERE, "sample_logs", "auth.log")
SAMPLE_ACCESS = os.path.join(HERE, "sample_logs", "access.log")


def main():
    parser = argparse.ArgumentParser(description="Run detection rules over SSH and web server logs.")
    parser.add_argument("--auth", help="path to a Linux auth.log / secure file")
    parser.add_argument("--access", help="path to an Apache or Nginx access log (combined format)")
    parser.add_argument("--year", type=int, default=date.today().year,
                        help="year of the auth.log entries, which do not record it (default: this year)")
    parser.add_argument("--html", default="report.html", help="HTML report to write (default report.html)")
    parser.add_argument("--json", default="alerts.json", help="JSON alert file to write (default alerts.json)")
    args = parser.parse_args()

    # With no log files given, fall back to the sample logs shipped with the project.
    if not args.auth and not args.access:
        print("[*] No log files given, analysing the sample logs in sample_logs/\n")
        args.auth, args.access = SAMPLE_AUTH, SAMPLE_ACCESS

    events = []
    if args.auth:
        auth_events = parsers.read_auth_log(args.auth, args.year)
        print("[*] {}: {} security events".format(args.auth, len(auth_events)))
        events.extend(auth_events)
    if args.access:
        web_events = parsers.read_access_log(args.access)
        print("[*] {}: {} web requests".format(args.access, len(web_events)))
        events.extend(web_events)

    alerts = rules.run_detections(events)
    report.print_alerts(alerts)

    report.write_json(alerts, args.json)
    report.write_html(alerts, args.html, event_count=len(events))
    print("\n[✓] Alerts saved to:  {}".format(os.path.abspath(args.json)))
    print("[✓] Report saved to:  {}".format(os.path.abspath(args.html)))


if __name__ == "__main__":
    main()
