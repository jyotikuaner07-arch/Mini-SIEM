"""
whitelist.py - Trusted Entity Whitelist
Prevents legitimate admin activity from triggering false alerts.

This is exactly how real SIEMs like Splunk handle this problem.
Trusted users/IPs are downgraded from HIGH alerts to INFO-level logs.
"""

import json
from pathlib import Path

WHITELIST_FILE = Path(__file__).parent.parent / "whitelist.json"

_whitelist = None


def load_whitelist() -> dict:
    """Load whitelist from JSON file. Creates default if missing."""
    global _whitelist

    if not WHITELIST_FILE.exists():
        _create_default_whitelist()

    with open(WHITELIST_FILE, "r") as f:
        _whitelist = json.load(f)

    trusted_users = len(_whitelist.get("trusted_users", []))
    trusted_ips   = len(_whitelist.get("trusted_ips", []))
    print(f"[WL] Whitelist loaded: {trusted_users} trusted users, {trusted_ips} trusted IPs")
    return _whitelist


def is_trusted_user(username: str) -> bool:
    """Return True if this user is on the trusted list."""
    if not username or _whitelist is None:
        return False
    return username.lower() in [u.lower() for u in _whitelist.get("trusted_users", [])]


def is_trusted_ip(ip: str) -> bool:
    """Return True if this IP is on the trusted list."""
    if not ip or _whitelist is None:
        return False
    return ip in _whitelist.get("trusted_ips", [])


def is_whitelisted(event: dict) -> bool:
    """
    Return True if this event should be downgraded.

    An event is trusted if:
    - The user is in trusted_users
    - The IP is in trusted_ips
    - The username is empty AND it's a local event (no external IP)
      because on macOS, sudo events from your own machine
      often don't expose the username in logs
    """
    if _whitelist is None:
        load_whitelist()

    user      = event.get("user", "").strip()
    ip        = event.get("source_ip", "").strip()
    status    = event.get("status", "")
    raw       = event.get("raw_message", "").lower()

    # Explicit trust — user or IP is on the list
    if is_trusted_user(user):
        return True
    if is_trusted_ip(ip):
        return True

    # macOS local sudo events — username often not extractable
    # If there's no external IP, it's happening on YOUR machine
    # by definition only you (or another local user) can run sudo
    if (
        not ip                          # no source IP = local event
        and status == "INFO"            # already downgraded by status
        and event.get("event_type") == "PRIVILEGE_ESCALATION"
    ):
        return True

    # If raw message contains your username anywhere
    trusted_users = _whitelist.get("trusted_users", [])
    for trusted_user in trusted_users:
        if trusted_user.lower() in raw:
            return True

    return False


def filter_alert(alert: dict) -> dict:
    """
    Check if an alert involves only trusted entities.
    If yes — downgrade severity to INFO and mark as whitelisted.
    If no  — return unchanged.

    This means the event is STILL recorded (you still have a full audit trail)
    but it won't scream at you as a HIGH/CRITICAL threat.
    """
    if _whitelist is None:
        load_whitelist()

    # Check all events that contributed to this alert
    contributing_events = alert.get("events", [])

    all_trusted = all(is_whitelisted(ev) for ev in contributing_events) if contributing_events else False

    # Also check the entity field directly (IP or username stored on the alert)
    entity = alert.get("entity", "")
    entity_trusted = (
        is_trusted_user(entity)
        or is_trusted_ip(entity)
        or entity in _whitelist.get("trusted_processes", [])
    )

    if all_trusted or entity_trusted:
        # Downgrade — still record it, just not as a scary alert
        downgraded = alert.copy()
        downgraded["severity"]    = "INFO"
        downgraded["whitelisted"] = True
        downgraded["description"] = (
            "[WHITELISTED] " + alert["description"] +
            " — trusted user/IP, downgraded from " + alert["severity"]
        )
        return downgraded

    return alert


def filter_all_alerts(alerts: list[dict]) -> tuple[list[dict], list[dict]]:
    """
    Filter a list of alerts through the whitelist.

    Returns:
        (real_alerts, whitelisted_alerts)
        real_alerts        — genuine threats, show these loudly
        whitelisted_alerts — your own legit activity, logged quietly
    """
    if _whitelist is None:
        load_whitelist()

    real_alerts        = []
    whitelisted_alerts = []

    for alert in alerts:
        filtered = filter_alert(alert)
        if filtered.get("whitelisted"):
            whitelisted_alerts.append(filtered)
        else:
            real_alerts.append(filtered)

    if whitelisted_alerts:
        print(f"[WL] {len(whitelisted_alerts)} alert(s) downgraded — matched whitelist")

    return real_alerts, whitelisted_alerts


def add_trusted_user(username: str) -> bool:
    """Add a username to the whitelist file at runtime."""
    _ensure_loaded()
    if username not in _whitelist["trusted_users"]:
        _whitelist["trusted_users"].append(username)
        _save_whitelist()
        print(f"[WL] Added trusted user: {username}")
        return True
    return False


def add_trusted_ip(ip: str) -> bool:
    """Add an IP to the whitelist file at runtime."""
    _ensure_loaded()
    if ip not in _whitelist["trusted_ips"]:
        _whitelist["trusted_ips"].append(ip)
        _save_whitelist()
        print(f"[WL] Added trusted IP: {ip}")
        return True
    return False


def get_whitelist_summary() -> dict:
    """Return what's currently whitelisted."""
    _ensure_loaded()
    return {
        "trusted_users":     _whitelist.get("trusted_users", []),
        "trusted_ips":       _whitelist.get("trusted_ips", []),
        "trusted_processes": _whitelist.get("trusted_processes", []),
    }


# ── Private helpers ──

def _ensure_loaded():
    global _whitelist
    if _whitelist is None:
        load_whitelist()


def _save_whitelist():
    with open(WHITELIST_FILE, "w") as f:
        json.dump(_whitelist, f, indent=2)


def _create_default_whitelist():
    """Create a starter whitelist file."""
    import subprocess
    # Automatically detect current username
    try:
        current_user = subprocess.check_output(["whoami"], text=True).strip()
    except Exception:
        current_user = "yourusername"

    default = {
        "trusted_users": [current_user, "root"],
        "trusted_ips":   ["127.0.0.1", "::1"],
        "trusted_processes": ["sudo", "python", "python3", "venv"],
        "notes": (
            f"Auto-generated. Current user '{current_user}' added automatically. "
            "Edit this file to add more trusted users or IPs."
        )
    }
    with open(WHITELIST_FILE, "w") as f:
        json.dump(default, f, indent=2)
    print(f"[WL] Created default whitelist at {WHITELIST_FILE}")
    print(f"[WL] Auto-added current user: {current_user}")