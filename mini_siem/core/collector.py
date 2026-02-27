from typing import List, Dict, Optional, Tuple
"""
collector.py - Cross-Platform Log Collection Layer
Supports Windows (Event Logs via pywin32) and macOS (log show / system.log)
"""

import platform
import subprocess
import datetime
import re
import sys
from pathlib import Path

SYSTEM = platform.system()  # 'Windows', 'Darwin', 'Linux'


# ──────────────────────────────────────────────
# WINDOWS COLLECTION
# ──────────────────────────────────────────────

def collect_windows_logs(hours_back: int = 24) -> list[dict]:
    """
    Collect real logs from Windows Event Log.
    Requires: pip install pywin32
    Run as Administrator for full access.
    
    Event IDs:
        4625 = Failed login
        4624 = Successful login  
        4740 = Account lockout
        4672 = Privilege escalation
    """
    try:
        import win32evtlog      # type: ignore
        import win32evtlogutil  # type: ignore
        import win32con         # type: ignore
    except ImportError:
        print("[!] pywin32 not installed. Run: pip install pywin32")
        return []

    events      = []
    cutoff      = datetime.datetime.now() - datetime.timedelta(hours=hours_back)
    event_ids   = {4625, 4624, 4740, 4672}
    server      = "localhost"
    log_type    = "Security"

    EVENT_TYPE_MAP = {
        4625: ("FAILED_LOGIN",         "FAILED"),
        4624: ("SUCCESSFUL_LOGIN",     "SUCCESS"),
        4740: ("ACCOUNT_LOCKOUT",      "FAILED"),
        4672: ("PRIVILEGE_ESCALATION", "INFO"),
    }

    try:
        hand = win32evtlog.OpenEventLog(server, log_type)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

        while True:
            records = win32evtlog.ReadEventLog(hand, flags, 0)
            if not records:
                break
            for rec in records:
                if rec.EventID not in event_ids:
                    continue
                ts = rec.TimeGenerated
                if isinstance(ts, str):
                    try:
                        ts = datetime.datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
                    except Exception:
                        continue
                if ts < cutoff:
                    return events  # records are newest first
                event_type, status = EVENT_TYPE_MAP.get(
                    rec.EventID, ("UNKNOWN", "UNKNOWN")
                )
                try:
                    strings = rec.StringInserts or []
                    user    = strings[5] if len(strings) > 5 else ""
                    ip      = strings[18] if len(strings) > 18 else ""
                    if ip in ("-", "", None):
                        ip = ""
                except Exception:
                    user, ip = "", ""

                events.append({
                    "_raw_source": "windows_event_log",
                    "timestamp":   ts.isoformat(),
                    "event_id":    rec.EventID,
                    "event_type":  event_type,
                    "user":        user.strip() if user else "",
                    "source_ip":   ip.strip()   if ip   else "",
                    "status":      status,
                    "raw_message": f"EventID={rec.EventID} User={user} IP={ip}",
                })

        win32evtlog.CloseEventLog(hand)

    except Exception as exc:
        print(f"[!] Windows Event Log error: {exc}")
        print("[!] Try running as Administrator.")

    return events

# ──────────────────────────────────────────────
# Linux COLLECTION
# ──────────────────────────────────────────────

def collect_linux_logs(hours_back: int = 24) -> list[dict]:
    """
    Collect logs from Linux systems.
    Reads from /var/log/auth.log (Ubuntu/Debian/Kali)
    or /var/log/secure (CentOS/RHEL/Fedora)
    """
    events   = []
    cutoff   = datetime.datetime.now() - datetime.timedelta(hours=hours_back)
    year     = datetime.datetime.now().year

    # Different distros store auth logs in different places
    for log_path in [
        Path("/var/log/auth.log"),   # Ubuntu, Debian, Kali
        Path("/var/log/secure"),     # CentOS, RHEL, Fedora
        Path("/var/log/messages"),   # older systems
    ]:
        if log_path.exists():
            break
    else:
        print("[!] No Linux auth log found. Try running with sudo.")
        return []

    try:
        with open(log_path, "r", errors="replace") as f:
            for line in f:
                m = re.match(r"^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})", line)
                if not m:
                    continue
                try:
                    ts = datetime.datetime.strptime(
                        f"{year} {m.group(1)}", "%Y %b %d %H:%M:%S"
                    )
                except ValueError:
                    continue
                if ts < cutoff:
                    continue

                line_lower    = line.lower()
                event_type, status = _classify_macos_line(line_lower)
                if not event_type:
                    continue

                events.append({
                    "_raw_source": f"linux_{log_path.name}",
                    "timestamp":   ts.isoformat(),
                    "event_id":    None,
                    "event_type":  event_type,
                    "user":        _extract_user_macos(line),
                    "source_ip":   _extract_ip(line),
                    "status":      status,
                    "raw_message": line.strip(),
                })

    except PermissionError:
        print(f"[!] Permission denied reading {log_path}. Run with sudo.")

    return events

# ──────────────────────────────────────────────
# macOS COLLECTION
# ──────────────────────────────────────────────

def collect_macos_logs(hours_back: int = 24) -> List[Dict]:
    """
    Collect logs from macOS using the `log show` command.
    Targets authentication/sudo/ssh messages.
    """
    events = []
    start_time = (datetime.datetime.now() - datetime.timedelta(hours=hours_back)).strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    predicates = [
        'eventMessage CONTAINS "authentication failed"',
        'eventMessage CONTAINS "Failed password"',
        'eventMessage CONTAINS "sudo"',
        'eventMessage CONTAINS "su:"',
        'eventMessage CONTAINS "FAILED"',
        'eventMessage CONTAINS "Invalid user"',
        'eventMessage CONTAINS "session opened for user root"',
    ]
    predicate = " OR ".join(predicates)

    cmd = [
        "log", "show",
        "--start", start_time,
        "--predicate", predicate,
        "--style", "syslog",
        "--info",
    ]

    try:
        with subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True) as proc:
            for line in proc.stdout:
                parsed = _parse_macos_log_line(line)
                if parsed:
                    events.append(parsed)
    except FileNotFoundError:
        print("[!] 'log' command not found. Are you on macOS?")
    except subprocess.TimeoutExpired:
        print("[!] macOS log collection timed out.")

    # Also try /var/log/system.log (older/fallback)
    system_log = Path("/var/log/system.log")
    if system_log.exists():
        events.extend(_parse_system_log(system_log, hours_back))

    return events


def _parse_macos_log_line(line: str) -> Optional[Dict]:
    """Parse a syslog-style line from macOS `log show`."""
    # Example: 2024-01-15 10:23:45.123456+0000 hostname sshd[1234]: Failed password for root
    pattern = r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"
    m = re.match(pattern, line)
    if not m:
        return None

    ts_str = m.group(1)
    try:
        ts = datetime.datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None

    line_lower = line.lower()
    event_type, status = _classify_macos_line(line_lower)
    if not event_type:
        return None

    user = _extract_user_macos(line)
    source_ip = _extract_ip(line)

    return {
        "_raw_source": "macos_log_show",
        "timestamp": ts.isoformat(),
        "event_id": None,
        "event_type": event_type,
        "user": user,
        "source_ip": source_ip,
        "status": status,
        "raw_message": line.strip(),
    }


def _parse_system_log(path: Path, hours_back: int) -> list[dict]:
    """Parse /var/log/system.log for auth-related entries."""
    events = []
    cutoff = datetime.datetime.now() - datetime.timedelta(hours=hours_back)
    current_year = datetime.datetime.now().year

    try:
        with open(path, "r", errors="replace") as f:
            for line in f:
                # Format: Jan 15 10:23:45 hostname sshd[...]: message
                m = re.match(r"^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})", line)
                if not m:
                    continue
                try:
                    ts = datetime.datetime.strptime(
                        f"{current_year} {m.group(1)}", "%Y %b %d %H:%M:%S"
                    )
                except ValueError:
                    continue
                if ts < cutoff:
                    continue

                line_lower = line.lower()
                event_type, status = _classify_macos_line(line_lower)
                if not event_type:
                    continue

                events.append({
                    "_raw_source": "system_log",
                    "timestamp": ts.isoformat(),
                    "event_id": None,
                    "event_type": event_type,
                    "user": _extract_user_macos(line),
                    "source_ip": _extract_ip(line),
                    "status": status,
                    "raw_message": line.strip(),
                })
    except PermissionError:
        print(f"[!] Permission denied reading {path}. Try running with sudo.")

    return events


def _classify_macos_line(line_lower: str) -> Tuple[Optional[str], Optional[str]]:
    if "failed password" in line_lower or "authentication failed" in line_lower:
        return "FAILED_LOGIN", "FAILED"
    if "invalid user" in line_lower:
        return "FAILED_LOGIN", "FAILED"
    if "sudo" in line_lower and ("incorrect password" in line_lower or "not allowed" in line_lower):
        return "PRIVILEGE_ESCALATION", "FAILED"
    if "sudo" in line_lower and "session opened for user root" in line_lower:
        return "PRIVILEGE_ESCALATION", "SUCCESS"
    if "su:" in line_lower:
        return "PRIVILEGE_ESCALATION", "INFO"
    if "accepted password" in line_lower or "accepted publickey" in line_lower:
        return "SUCCESSFUL_LOGIN", "SUCCESS"
    if "connection closed" in line_lower or "disconnected" in line_lower:
        return None, None
    return None, None


def _extract_user_macos(line: str) -> str:
    """
    Extract username from macOS log lines.
    Handles many different formats that macOS uses.
    """
    patterns = [
        # SSH: "Failed password for root from 1.2.3.4"
        # SSH: "Failed password for invalid user bob from 1.2.3.4"
        r"for (?:invalid user )?(\S+) from",

        # sudo: "sudo:     jyoti : TTY=ttys001 ; USER=root"
        r"sudo:\s+(\S+)\s+:",

        # su: "su: alice to root"
        r"su:\s+(\S+)\s+to",

        # PAM: "pam_unix(sudo:session): session opened for user root by jyoti"
        r"session opened for user \S+ by (\S+)",

        # PAM: "pam_unix(sshd:auth): authentication failure; user=bob"
        r"user=(\S+)",

        # Generic: "for user alice"
        r"for user (\S+)",

        # macOS unified log: "USER=root ; COMMAND=/usr/bin/python3"
        r"USER=(\S+)",

        # macOS: "authenticating as user jyoti"
        r"authenticating as (?:user )?(\S+)",

        # macOS: "jyoti : command not allowed"
        r"^[\w.]+\s+[\d:]+\s+\S+\s+sudo\[[\d]+\]:\s+(\S+)\s+:",
    ]

    for pattern in patterns:
        m = re.search(pattern, line, re.IGNORECASE)
        if m:
            username = m.group(1).strip()
            # Filter out non-usernames that sometimes get caught
            if username and username not in (
                "TTY", "PWD", "USER", "COMMAND", "root", "NULL",
                "failure", "error", "unknown", "none"
            ):
                return username
            elif username == "root":
                return "root"

    return ""


def _extract_ip(line: str) -> str:
    m = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", line)
    return m.group(1) if m else ""


# ──────────────────────────────────────────────
# DEMO / SIMULATION MODE
# ──────────────────────────────────────────────

def generate_demo_logs() -> list[dict]:
    """
    Generate realistic simulated log entries for testing the pipeline
    on any OS without needing real system access.
    """
    import random
    now = datetime.datetime.now()

    users = ["alice", "bob", "root", "admin", "jdoe", "unknownuser"]
    ips = ["192.168.1.10", "10.0.0.5", "203.0.113.42", "198.51.100.7", "192.168.1.10"]

    logs = []
    # Simulate brute-force: 8 failed logins within 90 seconds
    brute_start = now - datetime.timedelta(minutes=3)
    for i in range(8):
        logs.append({
            "_raw_source": "demo",
            "timestamp": (brute_start + datetime.timedelta(seconds=i * 11)).isoformat(),
            "event_id": 4625,
            "event_type": "FAILED_LOGIN",
            "user": "admin",
            "source_ip": "203.0.113.42",
            "status": "FAILED",
            "raw_message": f"Demo: failed login attempt {i+1} for admin",
        })

    # A few normal entries
    for _ in range(5):
        offset = random.randint(10, 1440)
        logs.append({
            "_raw_source": "demo",
            "timestamp": (now - datetime.timedelta(minutes=offset)).isoformat(),
            "event_id": 4624,
            "event_type": "SUCCESSFUL_LOGIN",
            "user": random.choice(users[:3]),
            "source_ip": random.choice(ips[:3]),
            "status": "SUCCESS",
            "raw_message": "Demo: successful login",
        })

    # Privilege escalation
    logs.append({
        "_raw_source": "demo",
        "timestamp": (now - datetime.timedelta(minutes=15)).isoformat(),
        "event_id": 4672,
        "event_type": "PRIVILEGE_ESCALATION",
        "user": "jdoe",
        "source_ip": "10.0.0.5",
        "status": "SUCCESS",
        "raw_message": "Demo: sudo session opened for root by jdoe",
    })

    # Login from new/unknown IP
    logs.append({
        "_raw_source": "demo",
        "timestamp": (now - datetime.timedelta(minutes=5)).isoformat(),
        "event_id": 4624,
        "event_type": "SUCCESSFUL_LOGIN",
        "user": "alice",
        "source_ip": "198.51.100.7",  # unusual IP
        "status": "SUCCESS",
        "raw_message": "Demo: login from unfamiliar IP",
    })

    # Error spike
    for i in range(12):
        logs.append({
            "_raw_source": "demo",
            "timestamp": (now - datetime.timedelta(seconds=i * 5)).isoformat(),
            "event_id": 4625,
            "event_type": "FAILED_LOGIN",
            "user": random.choice(users),
            "source_ip": random.choice(ips),
            "status": "FAILED",
            "raw_message": f"Demo: error spike entry {i+1}",
        })

    return sorted(logs, key=lambda x: x["timestamp"])


# ──────────────────────────────────────────────
# PUBLIC API
# ──────────────────────────────────────────────

def collect_logs(hours_back: int = 24, demo_mode: bool = False) -> list[dict]:
    if demo_mode:
        return generate_demo_logs()

    if SYSTEM == "Darwin":
        return collect_macos_logs(hours_back)
    elif SYSTEM == "Windows":
        return collect_windows_logs(hours_back)
    elif SYSTEM == "Linux":
        return collect_linux_logs(hours_back)
    else:
        print(f"[!] Unknown OS '{SYSTEM}' — using demo mode.")
        return generate_demo_logs()