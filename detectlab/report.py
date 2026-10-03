"""
report.py - show the alerts on screen and save them as JSON and as an HTML report.
"""

import html
import json

from .rules import SEVERITY_ORDER

SEVERITY_COLOURS = {"critical": "#B42318", "high": "#C4580A", "medium": "#8A6A00", "low": "#3B6E8F"}


def technique_url(technique):
    """T1110.001 -> https://attack.mitre.org/techniques/T1110/001/"""
    return "https://attack.mitre.org/techniques/{}/".format(technique.replace(".", "/"))


def severity_counts(alerts):
    counts = {name: 0 for name in SEVERITY_ORDER}
    for alert in alerts:
        counts[alert["severity"]] += 1
    return counts


def print_alerts(alerts):
    if not alerts:
        print("[*] No alerts. Nothing in these logs matched a detection rule.")
        return
    counts = severity_counts(alerts)
    print("[*] {} alert(s): ".format(len(alerts)) +
          ", ".join("{} {}".format(counts[s], s) for s in SEVERITY_ORDER if counts[s]))
    for alert in alerts:
        print("\n[{}] {}  {}".format(alert["severity"].upper(), alert["rule_id"], alert["rule"]))
        print("    Time:    {}".format(alert["time"].strftime("%Y-%m-%d %H:%M:%S")))
        if alert["source_ip"]:
            print("    Source:  {}".format(alert["source_ip"]))
        print("    MITRE:   {} {} ({})".format(alert["technique"], alert["technique_name"], alert["tactic"]))
        print("    Detail:  {}".format(alert["summary"]))


def write_json(alerts, path):
    """Save the alerts as JSON, the format a SIEM or ticketing system would take in."""
    rows = [dict(alert, time=alert["time"].strftime("%Y-%m-%dT%H:%M:%SZ")) for alert in alerts]
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(rows, handle, indent=2)
        handle.write("\n")


PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Detection report</title>
<style>
  body {{ font-family: -apple-system, "Segoe UI", Roboto, Arial, sans-serif; margin: 0;
         background: #F5F6F8; color: #1B1F24; }}
  main {{ max-width: 1080px; margin: 0 auto; padding: 32px 20px 48px; }}
  h1 {{ font-size: 24px; margin: 0 0 4px; }}
  .meta {{ color: #5B6470; font-size: 14px; margin-bottom: 24px; }}
  .cards {{ display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 24px; }}
  .card {{ background: #fff; border: 1px solid #DDE1E6; border-top: 4px solid; border-radius: 6px;
          padding: 12px 18px; min-width: 120px; }}
  .card b {{ display: block; font-size: 28px; }}
  .card span {{ font-size: 12px; text-transform: uppercase; letter-spacing: .05em; color: #5B6470; }}
  table {{ width: 100%; border-collapse: collapse; background: #fff; border: 1px solid #DDE1E6;
          border-radius: 6px; font-size: 14px; }}
  th, td {{ text-align: left; padding: 10px 12px; border-bottom: 1px solid #E9ECEF; vertical-align: top; }}
  th {{ background: #EEF0F3; font-size: 12px; text-transform: uppercase; letter-spacing: .05em; }}
  .badge {{ color: #fff; border-radius: 3px; padding: 2px 8px; font-size: 12px; font-weight: 600;
           text-transform: uppercase; white-space: nowrap; }}
  .nowrap {{ white-space: nowrap; }}
  a {{ color: #0B5CAD; }}
  details {{ margin-top: 6px; }}
  summary {{ cursor: pointer; color: #5B6470; font-size: 13px; }}
  pre {{ background: #F5F6F8; padding: 8px; border-radius: 4px; font-size: 12px;
        white-space: pre-wrap; word-break: break-all; margin: 6px 0 0; }}
</style>
</head>
<body>
<main>
<h1>Detection report</h1>
<div class="meta">{event_count} log events analysed &middot; {alert_count} alert(s) raised</div>
<div class="cards">{cards}</div>
<table>
<thead><tr><th>Severity</th><th>Time (UTC)</th><th>Rule</th><th>Source</th><th>MITRE ATT&amp;CK</th><th>What happened</th></tr></thead>
<tbody>
{rows}
</tbody>
</table>
</main>
</body>
</html>
"""


def write_html(alerts, path, event_count=0):
    """Save a self-contained HTML report that opens in any browser."""
    esc = html.escape
    counts = severity_counts(alerts)
    cards = "".join(
        '<div class="card" style="border-top-color:{}"><b>{}</b><span>{}</span></div>'.format(
            SEVERITY_COLOURS[name], counts[name], name)
        for name in SEVERITY_ORDER)

    rows = []
    for alert in alerts:
        evidence = "\n".join(esc(line) for line in alert["evidence"])
        hidden = alert["event_count"] - len(alert["evidence"])
        label = "Show log evidence ({} line(s){})".format(
            len(alert["evidence"]), ", {} more not shown".format(hidden) if hidden > 0 else "")
        rows.append(
            '<tr><td><span class="badge" style="background:{colour}">{severity}</span></td>'
            '<td class="nowrap">{time}</td>'
            '<td><b>{rule_id}</b><br>{rule}</td>'
            '<td class="nowrap">{source}</td>'
            '<td><a href="{url}">{technique}</a><br>{technique_name}<br><i>{tactic}</i></td>'
            '<td>{summary}<details><summary>{label}</summary><pre>{evidence}</pre></details></td></tr>'.format(
                colour=SEVERITY_COLOURS[alert["severity"]], severity=esc(alert["severity"]),
                time=alert["time"].strftime("%Y-%m-%d %H:%M:%S"),
                rule_id=esc(alert["rule_id"]), rule=esc(alert["rule"]),
                source=esc(alert["source_ip"] or alert["user"] or "-"),
                url=esc(technique_url(alert["technique"])), technique=esc(alert["technique"]),
                technique_name=esc(alert["technique_name"]), tactic=esc(alert["tactic"]),
                summary=esc(alert["summary"]), label=esc(label), evidence=evidence))
    if not rows:
        rows.append('<tr><td colspan="6">No alerts. Nothing in these logs matched a detection rule.</td></tr>')

    with open(path, "w", encoding="utf-8") as handle:
        handle.write(PAGE.format(event_count=event_count, alert_count=len(alerts),
                                 cards=cards, rows="\n".join(rows)))
