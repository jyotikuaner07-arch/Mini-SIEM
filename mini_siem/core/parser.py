"""
parser.py - Log Parsing & Normalization Layer
Converts raw log dicts into a clean, uniform schema for the detection engine.
"""

import re
import datetime
from typing import Optional


# ──────────────────────────────────────────────
# CANONICAL EVENT SCHEMA
# ──────────────────────────────────────────────
# Every parsed event will match this shape:
#
# {
#   "timestamp":   datetime object,
#   "event_type":  str  (FAILED_LOGIN | SUCCESSFUL_LOGIN | PRIVILEGE_ESCALATION |
#                        ACCOUNT_LOCKOUT | EXPLICIT_CRED_LOGIN | UNKNOWN),
#   "user":        str,
#   "source_ip":   str,
#   "status":      str  (FAILED | SUCCESS | INFO | UNKNOWN),
#   "risk_score":  int  (set by detector, 0 at parse time),
#   "raw_source":  str,
#   "raw_message": str,
# }


KNOWN_INTERNAL_RANGES = [
    re.compile(r"^10\."),
    re.compile(r"^192\.168\."),
    re.compile(r"^172\.(1[6-9]|2\d|3[01])\."),
    re.compile(r"^127\."),
]

VALID_EVENT_TYPES = {
    "FAILED_LOGIN",
    "SUCCESSFUL_LOGIN",
    "PRIVILEGE_ESCALATION",
    "ACCOUNT_LOCKOUT",
    "EXPLICIT_CRED_LOGIN",
    "UNKNOWN",
}

VALID_STATUSES = {"FAILED", "SUCCESS", "INFO", "UNKNOWN"}


def parse_log_entry(raw: dict) -> Optional[dict]:
    """
    Normalize a raw log dict (from collector.py) into the canonical schema.
    Returns None if the entry is malformed / unrecognisable.
    """
    if not isinstance(raw, dict):
        return None

    # ── Timestamp ──
    ts = _parse_timestamp(raw.get("timestamp", ""))
    if ts is None:
        return None

    # ── Event type ──
    event_type = str(raw.get("event_type", "UNKNOWN")).upper()
    if event_type not in VALID_EVENT_TYPES:
        event_type = "UNKNOWN"

    # ── Status ──
    status = str(raw.get("status", "UNKNOWN")).upper()
    if status not in VALID_STATUSES:
        status = "UNKNOWN"

    # ── User ──
    user = _sanitize_string(raw.get("user", ""))

    # ── Source IP ──
    source_ip = _validate_ip(raw.get("source_ip", ""))

    return {
        "timestamp":   ts,
        "event_type":  event_type,
        "user":        user,
        "source_ip":   source_ip,
        "status":      status,
        "risk_score":  0,                       # filled by detector
        "raw_source":  raw.get("_raw_source", "unknown"),
        "raw_message": raw.get("raw_message", ""),
    }


def parse_all(raw_logs: list[dict]) -> list[dict]:
    """
    Parse a list of raw log dicts. Skips invalid entries.
    Returns a list sorted chronologically.
    """
    parsed = []
    skipped = 0
    for entry in raw_logs:
        result = parse_log_entry(entry)
        if result:
            parsed.append(result)
        else:
            skipped += 1

    if skipped:
        print(f"[~] Parser skipped {skipped} malformed entries.")

    parsed.sort(key=lambda x: x["timestamp"])
    print(f"[*] Parser: {len(parsed)} events normalised.")
    return parsed


# ──────────────────────────────────────────────
# HELPERS
# ──────────────────────────────────────────────

def _parse_timestamp(value) -> Optional[datetime.datetime]:
    """Try several common timestamp formats."""
    if isinstance(value, datetime.datetime):
        return value

    if not isinstance(value, str) or not value.strip():
        return None

    formats = [
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%b %d %H:%M:%S",   # syslog-style (no year)
    ]
    for fmt in formats:
        try:
            ts = datetime.datetime.strptime(value.strip(), fmt)
            # If the format has no year, attach the current year
            if ts.year == 1900:
                ts = ts.replace(year=datetime.datetime.now().year)
            return ts
        except ValueError:
            continue
    return None


def _sanitize_string(value) -> str:
    if not isinstance(value, str):
        return ""
    # strip any control characters, limit length
    cleaned = re.sub(r"[\x00-\x1f\x7f]", "", value).strip()
    return cleaned[:128]


import ipaddress

def _validate_ip(ip: str) -> str:
    if not isinstance(ip, str):
        return ""
    try:
        ipaddress.ip_address(ip)
        return ip
    except ValueError:
        return ""


def is_internal_ip(ip: str) -> bool:
    """Return True if IP belongs to a private/loopback range."""
    if not ip:
        return False
    return any(pattern.match(ip) for pattern in KNOWN_INTERNAL_RANGES)


def format_event_for_display(event: dict) -> str:
    """Human-readable one-liner for console output."""
    ts = event["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
    return (
        f"[{ts}] {event['event_type']:<25} "
        f"user={event['user'] or '?':<15} "
        f"ip={event['source_ip'] or '?':<16} "
        f"status={event['status']:<8} "
        f"risk={event['risk_score']}"
    )