"""
database.py - SQLite Persistent Storage Layer
Stores events and alerts permanently so data survives between runs.

SQLite is a file-based database — no server needed, built into Python.
The database file is stored at: data/siem.db
"""

import sqlite3
import datetime
import json
from pathlib import Path
from typing import Optional

# ── Where the database file lives on disk ──
DB_PATH = Path(__file__).parent.parent / "data" / "siem.db"


# ════════════════════════════════════════════════════════
# CONNECTION & SETUP
# ════════════════════════════════════════════════════════

def get_connection() -> sqlite3.Connection:
    """
    Open (or create) the SQLite database.
    
    sqlite3.connect() creates the file if it doesn't exist yet.
    detect_types lets SQLite automatically convert stored text
    back into Python datetime objects when reading.
    """
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(
        DB_PATH,
        detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES,
    )
    # Return rows as dict-like objects so you can do row["column_name"]
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """
    Create the tables if they don't already exist.
    
    'CREATE TABLE IF NOT EXISTS' is safe to call every startup —
    it only creates the table if it's missing, never destroys data.
    
    Tables:
      events  — every parsed log event
      alerts  — every alert fired by the detector
    """
    conn = get_connection()
    with conn:   # 'with conn' = auto-commit on success, auto-rollback on error
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT    NOT NULL,
                event_type  TEXT    NOT NULL,
                user        TEXT,
                source_ip   TEXT,
                status      TEXT,
                risk_score  INTEGER DEFAULT 0,
                raw_source  TEXT,
                raw_message TEXT,
                session_id  TEXT,          -- groups events from the same run together
                created_at  TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS alerts (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                rule        TEXT    NOT NULL,
                severity    TEXT    NOT NULL,
                timestamp   TEXT    NOT NULL,
                description TEXT,
                risk_score  INTEGER DEFAULT 0,
                entity      TEXT,
                session_id  TEXT,
                created_at  TEXT DEFAULT (datetime('now'))
            );

            -- Indexes speed up the common search queries
            CREATE INDEX IF NOT EXISTS idx_events_ip        ON events(source_ip);
            CREATE INDEX IF NOT EXISTS idx_events_user      ON events(user);
            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_events_type      ON events(event_type);
            CREATE INDEX IF NOT EXISTS idx_alerts_severity  ON alerts(severity);
            CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
            CREATE INDEX IF NOT EXISTS idx_alerts_session   ON alerts(session_id);
        """)
    conn.close()
    print(f"[DB] Database ready at {DB_PATH}")


# ════════════════════════════════════════════════════════
# WRITE OPERATIONS
# ════════════════════════════════════════════════════════

def save_events(events: list[dict], session_id: str) -> int:
    """
    Insert a batch of parsed events into the database.
    
    Uses executemany() which is much faster than running
    individual INSERT statements in a loop.
    
    Returns: number of rows inserted.
    """
    if not events:
        return 0

    rows = []
    for ev in events:
        ts = ev["timestamp"]
        # Convert datetime object to string for storage
        if isinstance(ts, datetime.datetime):
            ts = ts.isoformat()
        rows.append((
            ts,
            ev.get("event_type", "UNKNOWN"),
            ev.get("user", ""),
            ev.get("source_ip", ""),
            ev.get("status", "UNKNOWN"),
            ev.get("risk_score", 0),
            ev.get("raw_source", ""),
            ev.get("raw_message", "")[:1000],  # cap at 1000 chars
            session_id,
        ))

    conn = get_connection()
    with conn:
        conn.executemany("""
            INSERT INTO events
                (timestamp, event_type, user, source_ip, status,
                 risk_score, raw_source, raw_message, session_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, rows)
    count = len(rows)
    conn.close()
    print(f"[DB] Saved {count} events (session: {session_id})")
    return count


def save_alerts(alerts: list[dict], session_id: str) -> int:
    """
    Insert a batch of alerts into the database.
    Returns: number of rows inserted.
    """
    if not alerts:
        return 0

    rows = []
    for alert in alerts:
        ts = alert["timestamp"]
        if isinstance(ts, datetime.datetime):
            ts = ts.isoformat()
        rows.append((
            alert.get("rule", "UNKNOWN"),
            alert.get("severity", "LOW"),
            ts,
            alert.get("description", ""),
            alert.get("risk_score", 0),
            alert.get("entity", ""),
            session_id,
        ))

    conn = get_connection()
    with conn:
        conn.executemany("""
            INSERT INTO alerts
                (rule, severity, timestamp, description, risk_score, entity, session_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, rows)
    count = len(rows)
    conn.close()
    print(f"[DB] Saved {count} alerts (session: {session_id})")
    return count


# ════════════════════════════════════════════════════════
# QUERY OPERATIONS  (search / filter)
# ════════════════════════════════════════════════════════

def query_events(
    ip: Optional[str]        = None,
    user: Optional[str]      = None,
    event_type: Optional[str]= None,
    status: Optional[str]    = None,
    since: Optional[str]     = None,   # ISO datetime string e.g. "2025-01-15T00:00:00"
    until: Optional[str]     = None,
    limit: int               = 500,
) -> list[dict]:
    """
    Flexible event search. All parameters are optional — combine any of them.
    
    Example calls:
        query_events(ip="203.0.113.42")              # all events from this IP
        query_events(user="admin", status="FAILED")  # all failed logins for admin
        query_events(since="2025-01-15T00:00:00")    # events after a date
    """
    sql    = "SELECT * FROM events WHERE 1=1"
    params = []

    if ip:
        sql += " AND source_ip = ?"
        params.append(ip)
    if user:
        sql += " AND user LIKE ?"
        params.append(f"%{user}%")   # LIKE allows partial matches
    if event_type:
        sql += " AND event_type = ?"
        params.append(event_type.upper())
    if status:
        sql += " AND status = ?"
        params.append(status.upper())
    if since:
        sql += " AND timestamp >= ?"
        params.append(since)
    if until:
        sql += " AND timestamp <= ?"
        params.append(until)

    sql += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)

    conn = get_connection()
    rows = conn.execute(sql, params).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def query_alerts(
    severity: Optional[str]  = None,
    rule: Optional[str]      = None,
    since: Optional[str]     = None,
    limit: int               = 200,
) -> list[dict]:
    """
    Search stored alerts by severity, rule name, or date.
    
    Example:
        query_alerts(severity="CRITICAL")
        query_alerts(rule="BRUTE_FORCE", since="2025-01-15T00:00:00")
    """
    sql    = "SELECT * FROM alerts WHERE 1=1"
    params = []

    if severity:
        sql += " AND severity = ?"
        params.append(severity.upper())
    if rule:
        sql += " AND rule = ?"
        params.append(rule.upper())
    if since:
        sql += " AND timestamp >= ?"
        params.append(since)

    sql += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)

    conn = get_connection()
    rows = conn.execute(sql, params).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_top_ips(limit: int = 10) -> list[tuple]:
    """Return IPs with the most failed login attempts (all time)."""
    conn = get_connection()
    rows = conn.execute("""
        SELECT source_ip, COUNT(*) as attempt_count
        FROM events
        WHERE status = 'FAILED' AND source_ip != ''
        GROUP BY source_ip
        ORDER BY attempt_count DESC
        LIMIT ?
    """, (limit,)).fetchall()
    conn.close()
    return [(row["source_ip"], row["attempt_count"]) for row in rows]


def get_top_targeted_users(limit: int = 10) -> list[tuple]:
    """Return users with the most failed login attempts (all time)."""
    conn = get_connection()
    rows = conn.execute("""
        SELECT user, COUNT(*) as attempt_count
        FROM events
        WHERE status = 'FAILED' AND user != ''
        GROUP BY user
        ORDER BY attempt_count DESC
        LIMIT ?
    """, (limit,)).fetchall()
    conn.close()
    return [(row["user"], row["attempt_count"]) for row in rows]


def get_hourly_activity(days_back: int = 1) -> list[dict]:
    """Return event counts grouped by hour for trend charts."""
    since = (datetime.datetime.now() - datetime.timedelta(days=days_back)).isoformat()
    conn = get_connection()
    rows = conn.execute("""
        SELECT
            strftime('%Y-%m-%d %H:00', timestamp) as hour,
            COUNT(*) as total,
            SUM(CASE WHEN status = 'FAILED' THEN 1 ELSE 0 END) as failed
        FROM events
        WHERE timestamp >= ?
        GROUP BY hour
        ORDER BY hour ASC
    """, (since,)).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_db_stats() -> dict:
    """Return a quick summary of what's stored in the database."""
    conn = get_connection()
    total_events  = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    total_alerts  = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    oldest_event  = conn.execute("SELECT MIN(timestamp) FROM events").fetchone()[0]
    newest_event  = conn.execute("SELECT MAX(timestamp) FROM events").fetchone()[0]
    critical_cnt  = conn.execute(
        "SELECT COUNT(*) FROM alerts WHERE severity='CRITICAL'"
    ).fetchone()[0]
    conn.close()
    return {
        "total_events":    total_events,
        "total_alerts":    total_alerts,
        "oldest_event":    oldest_event,
        "newest_event":    newest_event,
        "critical_alerts": critical_cnt,
        "db_path":         str(DB_PATH),
        "db_size_kb":      round(DB_PATH.stat().st_size / 1024, 1) if DB_PATH.exists() else 0,
    }


def clear_old_data(days: int = 30) -> int:
    """
    Delete events and alerts older than N days.
    Call this periodically to keep the database from growing forever.
    Returns total rows deleted.
    """
    cutoff = (datetime.datetime.now() - datetime.timedelta(days=days)).isoformat()
    conn = get_connection()
    with conn:
        deleted_events = conn.execute(
            "DELETE FROM events WHERE timestamp < ?", (cutoff,)
        ).rowcount
        deleted_alerts = conn.execute(
            "DELETE FROM alerts WHERE timestamp < ?", (cutoff,)
        ).rowcount
    conn.close()
    total = deleted_events + deleted_alerts
    print(f"[DB] Purged {total} old records (older than {days} days)")
    return total