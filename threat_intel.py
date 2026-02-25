"""
threat_intel.py - Threat Intelligence Engine
Compares event IPs against a list of known malicious addresses.

Real SIEMs do this against feeds like:
  - AbuseIPDB
  - Shodan
  - MISP (Malware Information Sharing Platform)

We use a local file: data/threat_intel.txt
"""

import re
from pathlib import Path

# ── Where the threat intel file lives ──
INTEL_FILE = Path(__file__).parent / "data" / "threat_intel.txt"

# ── In-memory set — loaded once, used for all lookups ──
_MALICIOUS_IPS:  set[str] = set()
_MALICIOUS_CIDR: list     = []   # for /24 subnet blocks
_loaded = False


# ════════════════════════════════════════════════════════
# LOAD
# ════════════════════════════════════════════════════════

def load_threat_intel() -> int:
    """
    Load malicious IPs from the threat_intel.txt file into memory.
    
    File format (one entry per line):
      203.0.113.42          # exact IP
      198.51.100.0/24       # CIDR block (entire subnet)
      # This is a comment   # ignored
    
    Returns: number of entries loaded.
    """
    global _loaded
    INTEL_FILE.parent.mkdir(parents=True, exist_ok=True)

    # Create a default file if none exists
    if not INTEL_FILE.exists():
        _create_default_intel_file()

    _MALICIOUS_IPS.clear()
    _MALICIOUS_CIDR.clear()

    count = 0
    with open(INTEL_FILE, "r") as f:
        for raw_line in f:
            line = raw_line.strip()

            # Skip blank lines and comments
            if not line or line.startswith("#"):
                continue

            # Strip inline comments
            if " #" in line:
                line = line[:line.index(" #")].strip()

            if "/" in line:
                # CIDR block like 203.0.113.0/24
                network, prefix = line.split("/", 1)
                try:
                    prefix_int = int(prefix)
                    _MALICIOUS_CIDR.append((network.strip(), prefix_int))
                    count += 1
                except ValueError:
                    pass
            elif re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", line):
                _MALICIOUS_IPS.add(line)
                count += 1

    _loaded = True
    print(f"[TI] Threat intel loaded: {len(_MALICIOUS_IPS)} IPs, {len(_MALICIOUS_CIDR)} CIDR blocks")
    return count


def _create_default_intel_file() -> None:
    """
    Write a starter threat intel file with documentation IPs
    (RFC 5737 — these are safe 'TEST-NET' addresses, not real machines).
    Replace these with real threat feeds in production.
    """
    content = """# ══════════════════════════════════════════════════════
# Mini SIEM — Threat Intelligence List
# ══════════════════════════════════════════════════════
# Format: one IP or CIDR block per line
# Lines starting with # are comments
#
# In production, replace this with feeds from:
#   - AbuseIPDB  (https://www.abuseipdb.com)
#   - Emerging Threats (https://rules.emergingthreats.net)
#   - Spamhaus DROP list
# ══════════════════════════════════════════════════════

# ── Known bad IPs (demo / RFC 5737 test addresses) ──
203.0.113.42       # known scanner
203.0.113.99       # brute-force bot
198.51.100.7       # credential-stuffing origin
198.51.100.200     # tor exit node (example)
192.0.2.100        # test malicious IP

# ── Malicious CIDR blocks ──
203.0.113.0/24     # entire test-net block (demo)
# 185.220.101.0/24  # real tor exit range (uncomment to enable)
"""
    INTEL_FILE.write_text(content)
    print(f"[TI] Created default threat intel file at {INTEL_FILE}")


# ════════════════════════════════════════════════════════
# LOOKUP
# ════════════════════════════════════════════════════════

def is_malicious(ip: str) -> bool:
    """
    Check if an IP is in the threat intel list.
    Checks exact match first, then CIDR blocks.
    """
    if not ip:
        return False
    if not _loaded:
        load_threat_intel()

    # Fast exact-match lookup (O(1) set lookup)
    if ip in _MALICIOUS_IPS:
        return True

    # Check CIDR blocks
    return _ip_in_any_cidr(ip)


def get_threat_info(ip: str) -> dict:
    """
    Return detailed threat information for an IP.
    Useful for building alert descriptions.
    """
    if not _loaded:
        load_threat_intel()

    matched_cidr = None
    for network, prefix in _MALICIOUS_CIDR:
        if _ip_in_cidr(ip, network, prefix):
            matched_cidr = f"{network}/{prefix}"
            break

    return {
        "ip":           ip,
        "is_malicious": ip in _MALICIOUS_IPS or matched_cidr is not None,
        "exact_match":  ip in _MALICIOUS_IPS,
        "cidr_match":   matched_cidr,
        "source":       "local_threat_intel",
    }


def check_events_against_intel(events: list[dict]) -> list[dict]:
    """
    Run all events through threat intel.
    Returns a list of NEW alerts for any events matching malicious IPs.
    
    This is called from detector.py after the normal rules run.
    """
    if not _loaded:
        load_threat_intel()

    alerts = []
    seen_ips: set[str] = set()   # one alert per IP per run

    for ev in events:
        ip = ev.get("source_ip", "")
        if not ip or ip in seen_ips:
            continue

        info = get_threat_info(ip)
        if info["is_malicious"]:
            seen_ips.add(ip)

            # Boost the event's risk score
            ev["risk_score"] = ev.get("risk_score", 0) + 10

            match_detail = (
                f"exact match" if info["exact_match"]
                else f"CIDR match ({info['cidr_match']})"
            )
            alerts.append({
                "rule":        "THREAT_INTEL_MATCH",
                "severity":    "CRITICAL",
                "timestamp":   ev["timestamp"],
                "description": (
                    f"IP {ip} matched threat intelligence list [{match_detail}] "
                    f"— user: {ev.get('user') or '?'}, "
                    f"event: {ev.get('event_type')}"
                ),
                "events":      [ev],
                "risk_score":  ev["risk_score"],
                "entity":      ip,
            })

    return alerts


def add_ip_to_intel(ip: str, comment: str = "") -> bool:
    """
    Add a new IP to the threat intel file at runtime.
    Useful for the dashboard's 'Block IP' button.
    """
    if not re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", ip):
        return False

    INTEL_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(INTEL_FILE, "a") as f:
        entry = f"\n{ip}"
        if comment:
            entry += f"  # {comment}"
        f.write(entry)

    _MALICIOUS_IPS.add(ip)
    print(f"[TI] Added {ip} to threat intel list")
    return True


def get_intel_stats() -> dict:
    """Return summary of what's loaded."""
    if not _loaded:
        load_threat_intel()
    return {
        "total_ips":    len(_MALICIOUS_IPS),
        "total_cidrs":  len(_MALICIOUS_CIDR),
        "file":         str(INTEL_FILE),
    }


# ════════════════════════════════════════════════════════
# CIDR HELPERS
# ════════════════════════════════════════════════════════

def _ip_to_int(ip: str) -> int:
    """Convert '192.168.1.1' → integer for bitwise comparison."""
    parts = ip.split(".")
    if len(parts) != 4:
        return -1
    result = 0
    for part in parts:
        try:
            result = (result << 8) | int(part)
        except ValueError:
            return -1
    return result


def _ip_in_cidr(ip: str, network: str, prefix: int) -> bool:
    """
    Check if 'ip' falls inside network/prefix.
    
    How CIDR works:
      192.168.1.0/24 means: first 24 bits are the network,
      last 8 bits are for hosts → covers 192.168.1.0 – 192.168.1.255
    """
    ip_int      = _ip_to_int(ip)
    network_int = _ip_to_int(network)
    if ip_int < 0 or network_int < 0:
        return False
    # Create a bitmask: /24 → 0xFFFFFF00
    mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    return (ip_int & mask) == (network_int & mask)


def _ip_in_any_cidr(ip: str) -> bool:
    return any(_ip_in_cidr(ip, net, pfx) for net, pfx in _MALICIOUS_CIDR)