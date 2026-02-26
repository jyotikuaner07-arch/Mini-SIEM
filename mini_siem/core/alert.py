"""
alert.py - Alert System
Handles console output (colored), email dispatch, and file persistence.
"""

import datetime
import smtplib
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path
from mini_siem.core.detector import severity_order

# ── Try to import colorama; graceful fallback if not installed ──
try:
    from colorama import Fore, Back, Style, init as colorama_init
    colorama_init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False
    print("[~] colorama not installed. Run: pip install colorama  (for colored output)")


SEVERITY_COLORS = {
    "LOW":      ("Fore.CYAN",     "\033[96m"),
    "MEDIUM":   ("Fore.YELLOW",   "\033[93m"),
    "HIGH":     ("Fore.RED",      "\033[91m"),
    "CRITICAL": ("Fore.WHITE",    "\033[97m"),  # white on red bg
}
SEVERITY_BG = {
    "CRITICAL": "\033[41m",  # red background
}
RESET = "\033[0m"

ALERTS_FILE = Path("alerts.txt")


# ──────────────────────────────────────────────
# CONSOLE ALERTS
# ──────────────────────────────────────────────

def print_alert(alert: dict) -> None:
    """Print a single alert to the console with color coding."""
    severity = alert["severity"]
    ts       = alert["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
    rule     = alert["rule"]
    desc     = alert["description"]
    score    = alert["risk_score"]

    # Build color prefix
    if HAS_COLOR:
        color = {
            "LOW":      Fore.CYAN,
            "MEDIUM":   Fore.YELLOW,
            "HIGH":     Fore.RED,
            "CRITICAL": Back.RED + Fore.WHITE + Style.BRIGHT,
        }.get(severity, "")
        reset = Style.RESET_ALL
    else:
        # ANSI escape codes as fallback
        _, color = SEVERITY_COLORS.get(severity, ("", ""))
        bg       = SEVERITY_BG.get(severity, "")
        color    = bg + color
        reset    = RESET

    banner = "!" * (6 if severity == "CRITICAL" else 3)
    line   = f"{color}[{banner} {severity} {banner}] [{ts}] {rule} | Score: {score}{reset}"
    detail = f"{color}  ↳ {desc}{reset}"

    print(line)
    print(detail)


def print_all_alerts(alerts: list[dict]) -> None:
    """Print all alerts sorted by severity (highest first), then time."""
    if not alerts:
        if HAS_COLOR:
            from colorama import Fore, Style
            print(Fore.GREEN + "[✓] No suspicious activity detected." + Style.RESET_ALL)
        else:
            print("[✓] No suspicious activity detected.")
        return

    sorted_alerts = sorted(alerts, key=lambda a: (-severity_order(a["severity"]), a["timestamp"]))
    print("\n" + "=" * 60)
    print("  🚨  SECURITY ALERTS")
    print("=" * 60)
    for alert in sorted_alerts:
        print_alert(alert)
    print("=" * 60 + "\n")


# ──────────────────────────────────────────────
# FILE PERSISTENCE
# ──────────────────────────────────────────────

def save_alerts_to_file(alerts: list[dict], path: Path = ALERTS_FILE) -> None:
    """
    Append alerts to a text file with timestamps.
    Each session is separated by a header line.
    """
    with open(path, "a", encoding="utf-8") as f:
        f.write(f"\n{'='*60}\n")
        f.write(f"Session: {datetime.datetime.now().isoformat()}\n")
        f.write(f"{'='*60}\n")
        if not alerts:
            f.write("No alerts generated.\n")
            return
        for alert in sorted(alerts, key=lambda a: a["timestamp"]):
            f.write(
                f"[{alert['severity']}] {alert['timestamp'].strftime('%Y-%m-%d %H:%M:%S')} "
                f"| Rule: {alert['rule']} | Score: {alert['risk_score']}\n"
                f"  {alert['description']}\n\n"
            )
    print(f"[*] Alerts saved to {path}")


# ──────────────────────────────────────────────
# EMAIL ALERTS
# ──────────────────────────────────────────────

class EmailConfig:
    """Simple email configuration container."""
    def __init__(
        self,
        smtp_host: str     = "smtp.gmail.com",
        smtp_port: int     = 587,
        sender: str        = "",
        password: str      = "",
        recipient: str     = "",
        min_severity: str  = "HIGH",
    ):
        self.smtp_host    = smtp_host
        self.smtp_port    = smtp_port
        self.sender       = sender
        self.password     = password
        self.recipient    = recipient
        self.min_severity = min_severity


def send_email_alerts(alerts: list[dict], config: EmailConfig) -> bool:
    """
    Send high/critical alerts via email using smtplib.
    Returns True on success, False on failure.
    """
    min_level = severity_order(config.min_severity)
    to_send   = [a for a in alerts if severity_order(a["severity"]) >= min_level]

    if not to_send:
        print("[*] No alerts meet the email severity threshold.")
        return True

    if not config.sender or not config.password or not config.recipient:
        print("[!] Email config incomplete — set sender/password/recipient.")
        return False

    subject = (
        f"[SIEM Alert] {len(to_send)} "
        f"{'CRITICAL ' if any(a['severity'] == 'CRITICAL' for a in to_send) else ''}"
        f"Security Alert(s) — {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}"
    )

    # Plain text body
    body_lines = [
        f"Security Alert Report — {datetime.datetime.now().isoformat()}",
        f"Total alerts: {len(to_send)}",
        "",
    ]
    for alert in sorted(to_send, key=lambda a: -severity_order(a["severity"])):
        body_lines.append(
            f"[{alert['severity']}] {alert['rule']}\n"
            f"  Time:  {alert['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"  Score: {alert['risk_score']}\n"
            f"  {alert['description']}\n"
        )

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = config.sender
    msg["To"]      = config.recipient
    msg.attach(MIMEText("\n".join(body_lines), "plain"))

    try:
        with smtplib.SMTP(config.smtp_host, config.smtp_port) as smtp:
            smtp.ehlo()
            smtp.starttls()
            smtp.login(config.sender, config.password)
            smtp.sendmail(config.sender, config.recipient, msg.as_string())
        print(f"[*] Email sent to {config.recipient} ({len(to_send)} alerts)")
        return True
    except smtplib.SMTPException as exc:
        print(f"[!] Email failed: {exc}")
        return False


# ──────────────────────────────────────────────
# CONVENIENCE: load email config from env vars
# ──────────────────────────────────────────────

def email_config_from_env() -> EmailConfig:
    """
    Load email settings from environment variables:
      SIEM_SMTP_HOST, SIEM_SMTP_PORT, SIEM_SENDER,
      SIEM_PASSWORD, SIEM_RECIPIENT, SIEM_MIN_SEVERITY
    """
    return EmailConfig(
        smtp_host    = os.getenv("SIEM_SMTP_HOST", "smtp.gmail.com"),
        smtp_port    = int(os.getenv("SIEM_SMTP_PORT", "587")),
        sender       = os.getenv("SIEM_SENDER", ""),
        password     = os.getenv("SIEM_PASSWORD", ""),
        recipient    = os.getenv("SIEM_RECIPIENT", ""),
        min_severity = os.getenv("SIEM_MIN_SEVERITY", "HIGH"),
    )