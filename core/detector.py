"""
detector.py - Rule-Based Detection Engine & Risk Scoring
Analyses parsed events and emits structured alerts.
"""

import datetime
from collections import defaultdict
from core.parser import is_internal_ip

# ──────────────────────────────────────────────
# RISK SCORES (points per event type)
# ──────────────────────────────────────────────
RISK_WEIGHTS = {
    "FAILED_LOGIN":         2,
    "PRIVILEGE_ESCALATION": 5,
    "ACCOUNT_LOCKOUT":      4,
    "EXPLICIT_CRED_LOGIN":  3,
    "SUCCESSFUL_LOGIN":     0,
    "UNKNOWN":              1,
}

# Extra risk for additional conditions
RISK_UNKNOWN_IP     = 3   # source IP not in internal ranges
RISK_BRUTE_FORCE    = 8   # triggered when brute-force rule fires
RISK_ERROR_SPIKE    = 6   # triggered when sudden error spike fires
CRITICAL_THRESHOLD  = 20  # total accumulated score → CRITICAL alert


# ──────────────────────────────────────────────
# DETECTION RULES CONFIG
# ──────────────────────────────────────────────
BRUTE_FORCE_LIMIT   = 5   # failed attempts
BRUTE_FORCE_WINDOW  = 120 # seconds
ERROR_SPIKE_LIMIT   = 10  # errors in window
ERROR_SPIKE_WINDOW  = 60  # seconds


# ──────────────────────────────────────────────
# ALERT SCHEMA
# ──────────────────────────────────────────────
# {
#   "rule":        str,
#   "severity":    "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
#   "timestamp":   datetime,
#   "description": str,
#   "events":      list[dict],   # contributing events
#   "risk_score":  int,
# }


def detect(events: list[dict], known_ips: set[str] | None = None, use_threat_intel: bool = True) -> tuple[list[dict], list[dict]]:
    """
    Run all detection rules over a list of parsed events.

    Args:
        events:    Parsed events from parser.py (sorted chronologically).
        known_ips: Set of IPs previously seen (for new-IP detection).
                   Pass None to auto-build from the event set itself.

    Returns:
        (annotated_events, alerts)
        - annotated_events: Same list but with risk_score populated.
        - alerts:           List of alert dicts.
    """
    if known_ips is None:
        known_ips = _build_known_ips(events)

    alerts = []

    # Per-event risk scoring
    for ev in events:
        score = RISK_WEIGHTS.get(ev["event_type"], 1)
        if ev["source_ip"] and not is_internal_ip(ev["source_ip"]) and ev["source_ip"] not in known_ips:
            score += RISK_UNKNOWN_IP
        ev["risk_score"] = score

    # ── Rule 1: Brute-Force (multiple failed logins) ──
    alerts.extend(_rule_brute_force(events))

    # ── Rule 2: Login from new / unknown IP ──
    alerts.extend(_rule_new_ip(events, known_ips))

    # ── Rule 3: Privilege Escalation Attempt ──
    alerts.extend(_rule_privilege_escalation(events))

    # ── Rule 4: Sudden Error Spike ──
    alerts.extend(_rule_error_spike(events))

    # ── Rule 5: Threat Intelligence Match ──
    try:
        from core.threat_intel import check_events_against_intel
        alerts.extend(check_events_against_intel(events))
    except Exception:
        pass  # threat intel is optional — never crash the pipeline

    # ── Rule 6: Critical aggregate risk score ──
    alerts.extend(_rule_critical_risk(events))

    # Deduplicate (same rule + same entity within 5 min)
    alerts = _deduplicate_alerts(alerts)

    # Sort alerts by timestamp
    alerts.sort(key=lambda a: a["timestamp"])

    severity_counts = defaultdict(int)
    for a in alerts:
        severity_counts[a["severity"]] += 1
    print(f"[*] Detector: {len(alerts)} alerts — " +
          ", ".join(f"{sev}={cnt}" for sev, cnt in severity_counts.items()))

    return events, alerts


# ──────────────────────────────────────────────
# RULES
# ──────────────────────────────────────────────

def _rule_brute_force(events: list[dict]) -> list[dict]:
    """Fire when any IP/user combo has >LIMIT failures in WINDOW seconds."""
    alerts = []
    failed = [e for e in events if e["status"] == "FAILED"]

    # Group by source_ip (or user if no IP)
    groups = defaultdict(list)
    for ev in failed:
        key = ev["source_ip"] or ev["user"] or "unknown"
        groups[key].append(ev)

    for key, entries in groups.items():
        entries.sort(key=lambda x: x["timestamp"])
        # Sliding window
        for i, start_ev in enumerate(entries):
            window = [start_ev]
            for j in range(i + 1, len(entries)):
                delta = (entries[j]["timestamp"] - start_ev["timestamp"]).total_seconds()
                if delta <= BRUTE_FORCE_WINDOW:
                    window.append(entries[j])
                else:
                    break
            if len(window) >= BRUTE_FORCE_LIMIT:
                # Boost risk scores for events in the window
                for ev in window:
                    ev["risk_score"] += RISK_BRUTE_FORCE
                alerts.append({
                    "rule":        "BRUTE_FORCE",
                    "severity":    "HIGH",
                    "timestamp":   window[0]["timestamp"],
                    "description": (
                        f"{len(window)} failed login attempts in "
                        f"{BRUTE_FORCE_WINDOW}s from '{key}'"
                    ),
                    "events":      window[:],
                    "risk_score":  sum(e["risk_score"] for e in window),
                    "entity":      key,
                })
                break  # one alert per key per run

    return alerts


def _rule_new_ip(events: list[dict], known_ips: set[str]) -> list[dict]:
    """Fire on successful login from an IP not in known_ips."""
    alerts = []
    seen_this_run: set[str] = set()

    for ev in events:
        ip = ev["source_ip"]
        if (
            ev["event_type"] == "SUCCESSFUL_LOGIN"
            and ip
            and ip not in known_ips
            and ip not in seen_this_run
        ):
            seen_this_run.add(ip)
            ev["risk_score"] += RISK_UNKNOWN_IP
            alerts.append({
                "rule":        "NEW_IP_LOGIN",
                "severity":    "MEDIUM",
                "timestamp":   ev["timestamp"],
                "description": f"Successful login from previously unseen IP: {ip} (user: {ev['user'] or '?'})",
                "events":      [ev],
                "risk_score":  ev["risk_score"],
                "entity":      ip,
            })

    return alerts


def _rule_privilege_escalation(events: list[dict]) -> list[dict]:
    """Fire on any privilege escalation event."""
    alerts = []
    for ev in events:
        if ev["event_type"] in ("PRIVILEGE_ESCALATION", "EXPLICIT_CRED_LOGIN"):
            alerts.append({
                "rule":        "PRIVILEGE_ESCALATION",
                "severity":    "HIGH",
                "timestamp":   ev["timestamp"],
                "description": (
                    f"Privilege escalation detected — user: {ev['user'] or '?'}, "
                    f"ip: {ev['source_ip'] or 'N/A'}, status: {ev['status']}"
                ),
                "events":      [ev],
                "risk_score":  ev["risk_score"],
                "entity":      ev["user"] or ev["source_ip"] or "unknown",
            })
    return alerts


def _rule_error_spike(events: list[dict]) -> list[dict]:
    """Fire when error count exceeds LIMIT within WINDOW seconds."""
    alerts = []
    errors = [e for e in events if e["status"] in ("FAILED", "UNKNOWN")]
    errors.sort(key=lambda x: x["timestamp"])

    for i, start_ev in enumerate(errors):
        window = [start_ev]
        for j in range(i + 1, len(errors)):
            delta = (errors[j]["timestamp"] - start_ev["timestamp"]).total_seconds()
            if delta <= ERROR_SPIKE_WINDOW:
                window.append(errors[j])
            else:
                break
        if len(window) >= ERROR_SPIKE_LIMIT:
            for ev in window:
                ev["risk_score"] += RISK_ERROR_SPIKE
            alerts.append({
                "rule":        "ERROR_SPIKE",
                "severity":    "MEDIUM",
                "timestamp":   window[0]["timestamp"],
                "description": f"{len(window)} errors/failures detected in {ERROR_SPIKE_WINDOW}s",
                "events":      window[:],
                "risk_score":  sum(e["risk_score"] for e in window),
                "entity":      "global",
            })
            break  # one spike alert per analysis run

    return alerts


def _rule_critical_risk(events: list[dict]) -> list[dict]:
    """
    Fire CRITICAL only when genuine threat risk exceeds threshold.
    Excludes events that came from whitelisted/local sudo activity
    (those have status=INFO and no source IP).
    """
    # Only count events that look like real external threats
    genuine_events = [
        e for e in events
        if not (
            e.get("status") == "INFO"
            and not e.get("source_ip")
            and e.get("event_type") == "PRIVILEGE_ESCALATION"
        )
    ]

    total = sum(e["risk_score"] for e in genuine_events)

    if total >= CRITICAL_THRESHOLD:
        return [{
            "rule":        "CRITICAL_RISK_THRESHOLD",
            "severity":    "CRITICAL",
            "timestamp":   events[-1]["timestamp"] if events else datetime.datetime.now(),
            "description": (
                f"Genuine threat risk score {total} exceeds critical threshold "
                f"{CRITICAL_THRESHOLD}. Immediate investigation recommended."
            ),
            "events":      genuine_events,
            "risk_score":  total,
            "entity":      "system",
        }]
    return []


# ──────────────────────────────────────────────
# HELPERS
# ──────────────────────────────────────────────

def _build_known_ips(events: list[dict]) -> set[str]:
    """
    Derive 'known' IPs from the data itself:
    IPs that appear in SUCCESSFUL_LOGIN events more than once are treated as known.
    In production you'd load this from a persistent whitelist file.
    """
    from collections import Counter
    ip_counts = Counter(
        e["source_ip"] for e in events
        if e["event_type"] == "SUCCESSFUL_LOGIN" and e["source_ip"]
    )
    return {ip for ip, cnt in ip_counts.items() if cnt >= 2}


def _deduplicate_alerts(alerts: list[dict]) -> list[dict]:
    """Remove duplicate alerts of the same rule+entity within 5 minutes."""
    seen: dict[tuple, datetime.datetime] = {}
    deduped = []
    for alert in sorted(alerts, key=lambda a: a["timestamp"]):
        key = (alert["rule"], alert.get("entity", ""))
        last_ts = seen.get(key)
        if last_ts is None or (alert["timestamp"] - last_ts).total_seconds() > 300:
            deduped.append(alert)
            seen[key] = alert["timestamp"]
    return deduped


def severity_order(severity: str) -> int:
    return {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}.get(severity, -1)