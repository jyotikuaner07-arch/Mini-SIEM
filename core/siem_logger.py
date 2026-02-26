"""
siem_logger.py - Internal SIEM Logging
Logs the SIEM tool's own activity to logs/siem.log

This is called "meta-logging" — logging the logger.
It records: startup, errors, alerts triggered, performance info.

Uses Python's built-in `logging` module — the professional
standard for application logging (not to be confused with
security logs, which are what we're *monitoring*).
"""

import logging
import logging.handlers
import datetime
import sys
from pathlib import Path

# ── Log file location ──
LOG_DIR  = Path(__file__).parent.parent / "logs"
LOG_FILE = LOG_DIR / "siem.log"

# ── Module-level logger — imported by all other modules ──
logger = logging.getLogger("mini_siem")

_configured = False


def setup_logging(
    level: str = "INFO",
    log_to_console: bool = True,
    log_to_file: bool    = True,
    max_bytes: int       = 5 * 1024 * 1024,  # 5 MB per file
    backup_count: int    = 3,                 # keep 3 rotated files
) -> None:
    """
    Configure the logging system. Call this once at startup (in main.py).
    
    level:          Minimum level to record (DEBUG < INFO < WARNING < ERROR < CRITICAL)
    log_to_console: Also print log lines to terminal
    log_to_file:    Write log lines to logs/siem.log
    max_bytes:      Rotate log file when it reaches this size
    backup_count:   How many old rotated files to keep
    
    RotatingFileHandler = automatically creates siem.log.1, siem.log.2, etc.
    when the file gets too big. Old files beyond backup_count are deleted.
    """
    global _configured
    if _configured:
        return   # Don't set up twice

    LOG_DIR.mkdir(parents=True, exist_ok=True)

    # Convert string level name to logging constant
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    logger.setLevel(numeric_level)

    # ── Formatter: what each log line looks like ──
    # Example output:
    #   2025-01-15 10:23:45 | INFO     | mini_siem | [STARTUP] SIEM started
    fmt = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # ── Handler 1: Write to rotating file ──
    if log_to_file:
        file_handler = logging.handlers.RotatingFileHandler(
            LOG_FILE,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
        file_handler.setFormatter(fmt)
        logger.addHandler(file_handler)

    # ── Handler 2: Write to terminal (stderr) ──
    if log_to_console:
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setFormatter(fmt)
        # Only show WARNING+ on console to avoid noise
        console_handler.setLevel(logging.WARNING)
        logger.addHandler(console_handler)

    _configured = True


# ════════════════════════════════════════════════════════
# CONVENIENCE WRAPPERS
# These give every module a clean API for common log events.
# ════════════════════════════════════════════════════════

def log_startup(mode: str, hours_back: int) -> None:
    logger.info(f"[STARTUP] SIEM started | mode={mode} | hours_back={hours_back}")


def log_shutdown(events_processed: int, alerts_fired: int, duration_sec: float) -> None:
    logger.info(
        f"[SHUTDOWN] Run complete | events={events_processed} | "
        f"alerts={alerts_fired} | duration={duration_sec:.2f}s"
    )


def log_collection(source: str, count: int) -> None:
    logger.info(f"[COLLECT] source={source} | collected={count} entries")


def log_parse_error(raw_entry: dict, reason: str) -> None:
    logger.warning(f"[PARSE_ERROR] reason={reason} | entry_keys={list(raw_entry.keys())}")


def log_alert_fired(rule: str, severity: str, entity: str, score: int) -> None:
    level = logging.CRITICAL if severity == "CRITICAL" else (
            logging.ERROR    if severity == "HIGH"     else
            logging.WARNING)
    logger.log(level, f"[ALERT] rule={rule} | severity={severity} | entity={entity} | score={score}")


def log_db_operation(operation: str, rows: int) -> None:
    logger.debug(f"[DB] op={operation} | rows={rows}")


def log_threat_intel_hit(ip: str, event_type: str) -> None:
    logger.critical(f"[THREAT_INTEL] Malicious IP detected | ip={ip} | event={event_type}")


def log_live_cycle(cycle: int, new_events: int, new_alerts: int) -> None:
    logger.info(
        f"[LIVE] cycle={cycle} | new_events={new_events} | new_alerts={new_alerts}"
    )


def log_error(context: str, error: Exception) -> None:
    logger.error(f"[ERROR] context={context} | {type(error).__name__}: {error}", exc_info=True)


def log_email_sent(recipient: str, alert_count: int) -> None:
    logger.info(f"[EMAIL] Sent {alert_count} alerts to {recipient}")


def get_recent_log_lines(n: int = 50) -> list[str]:
    """Read the last N lines from the log file (used by dashboard)."""
    if not LOG_FILE.exists():
        return []
    with open(LOG_FILE, "r", encoding="utf-8") as f:
        return f.readlines()[-n:]