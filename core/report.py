"""
report.py - Daily Security Report Generator
Exports a human-readable .txt summary and a machine-readable .csv.
"""

import csv
import datetime
from collections import Counter, defaultdict
from pathlib import Path
from core.detector import severity_order


# ──────────────────────────────────────────────
# REPORT DATA BUILDER
# ──────────────────────────────────────────────

def build_report_data(events: list[dict], alerts: list[dict]) -> dict:
    """
    Aggregate events and alerts into a statistics dictionary.
    """
    now = datetime.datetime.now()

    total_events       = len(events)
    failed_logins      = sum(1 for e in events if e["status"] == "FAILED")
    successful_logins  = sum(1 for e in events if e["status"] == "SUCCESS")
    priv_escalations   = sum(1 for e in events if e["event_type"] == "PRIVILEGE_ESCALATION")

    # Top suspicious IPs (most failed-login appearances)
    ip_fail_counts = Counter(
        e["source_ip"] for e in events
        if e["status"] == "FAILED" and e["source_ip"]
    )
    top_ips = ip_fail_counts.most_common(10)

    # Top targeted users
    user_fail_counts = Counter(
        e["user"] for e in events
        if e["status"] == "FAILED" and e["user"]
    )
    top_users = user_fail_counts.most_common(10)

    # Alert breakdown by severity
    alert_by_severity = Counter(a["severity"] for a in alerts)
    total_risk = sum(e["risk_score"] for e in events)

    # High-risk events (individual score >= 7)
    high_risk_events = [e for e in events if e["risk_score"] >= 7]

    # Hourly activity (failed + successful logins)
    hourly = defaultdict(int)
    for e in events:
        hour_key = e["timestamp"].strftime("%Y-%m-%d %H:00")
        hourly[hour_key] += 1

    return {
        "generated_at":      now.isoformat(),
        "period":            "Last 24 hours",
        "total_events":      total_events,
        "failed_logins":     failed_logins,
        "successful_logins": successful_logins,
        "priv_escalations":  priv_escalations,
        "total_risk_score":  total_risk,
        "high_risk_events":  len(high_risk_events),
        "total_alerts":      len(alerts),
        "alerts_critical":   alert_by_severity.get("CRITICAL", 0),
        "alerts_high":       alert_by_severity.get("HIGH", 0),
        "alerts_medium":     alert_by_severity.get("MEDIUM", 0),
        "alerts_low":        alert_by_severity.get("LOW", 0),
        "top_suspicious_ips":   top_ips,
        "top_targeted_users":   top_users,
        "hourly_activity":      dict(sorted(hourly.items())),
        "alerts":               alerts,
        "events":               events,
    }


# ──────────────────────────────────────────────
# TXT REPORT
# ──────────────────────────────────────────────

def generate_txt_report(data: dict, path: Path = Path("security_report.txt")) -> Path:
    """Write a human-readable security report to a .txt file."""
    lines = []
    _h  = lambda t: lines.append(f"\n{'─'*60}\n  {t}\n{'─'*60}")
    _ln = lambda s="": lines.append(s)

    _ln("╔══════════════════════════════════════════════════════════╗")
    _ln("║          MINI SIEM — DAILY SECURITY REPORT              ║")
    _ln("╚══════════════════════════════════════════════════════════╝")
    _ln(f"  Generated : {data['generated_at']}")
    _ln(f"  Period    : {data['period']}")

    _h("EXECUTIVE SUMMARY")
    _ln(f"  Total Events Collected  : {data['total_events']}")
    _ln(f"  Failed Login Attempts   : {data['failed_logins']}")
    _ln(f"  Successful Logins       : {data['successful_logins']}")
    _ln(f"  Privilege Escalations   : {data['priv_escalations']}")
    _ln(f"  High-Risk Individual Evts: {data['high_risk_events']}")
    _ln(f"  Total System Risk Score : {data['total_risk_score']}")

    _h("ALERTS GENERATED")
    _ln(f"  Total Alerts  : {data['total_alerts']}")
    _ln(f"  ├─ CRITICAL   : {data['alerts_critical']}")
    _ln(f"  ├─ HIGH       : {data['alerts_high']}")
    _ln(f"  ├─ MEDIUM     : {data['alerts_medium']}")
    _ln(f"  └─ LOW        : {data['alerts_low']}")

    _h("TOP SUSPICIOUS IPs")
    if data["top_suspicious_ips"]:
        for ip, cnt in data["top_suspicious_ips"]:
            _ln(f"  {ip:<20}  {cnt} failed attempt(s)")
    else:
        _ln("  None detected.")

    _h("TOP TARGETED USERS")
    if data["top_targeted_users"]:
        for user, cnt in data["top_targeted_users"]:
            _ln(f"  {user:<20}  {cnt} failed attempt(s)")
    else:
        _ln("  None detected.")

    _h("ALERT DETAILS")
    sorted_alerts = sorted(
        data["alerts"],
        key=lambda a: (-severity_order(a["severity"]), a["timestamp"])
    )
    if sorted_alerts:
        for alert in sorted_alerts:
            ts = alert["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
            _ln(f"\n  [{alert['severity']}] {alert['rule']}  |  {ts}  |  Score: {alert['risk_score']}")
            _ln(f"  → {alert['description']}")
    else:
        _ln("  No alerts.")

    _h("HOURLY ACTIVITY")
    for hour, count in sorted(data["hourly_activity"].items()):
        bar = "█" * min(count, 40)
        _ln(f"  {hour}  {bar} {count}")

    _ln()
    _ln("═" * 60)
    _ln("  END OF REPORT")
    _ln("═" * 60)

    path.write_text("\n".join(lines), encoding="utf-8")
    print(f"[*] TXT report saved to {path}")
    return path


# ──────────────────────────────────────────────
# CSV REPORT (events)
# ──────────────────────────────────────────────

def generate_csv_report(data: dict, path: Path = Path("security_events.csv")) -> Path:
    """Export all events to a CSV file for further analysis."""
    fieldnames = ["timestamp", "event_type", "user", "source_ip", "status", "risk_score", "raw_source"]

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for ev in sorted(data["events"], key=lambda e: e["timestamp"]):
            row = {k: (v.isoformat() if isinstance(v, __import__("datetime").datetime) else v)
                   for k, v in ev.items() if k in fieldnames}
            writer.writerow(row)

    print(f"[*] CSV events saved to {path}")
    return path


def generate_alerts_csv(data: dict, path: Path = Path("security_alerts.csv")) -> Path:
    """Export alert summary to CSV."""
    fieldnames = ["timestamp", "severity", "rule", "risk_score", "description", "entity"]

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for alert in sorted(data["alerts"], key=lambda a: a["timestamp"]):
            writer.writerow({
                "timestamp":   alert["timestamp"].isoformat(),
                "severity":    alert["severity"],
                "rule":        alert["rule"],
                "risk_score":  alert["risk_score"],
                "description": alert["description"],
                "entity":      alert.get("entity", ""),
            })

    print(f"[*] CSV alerts saved to {path}")
    return path