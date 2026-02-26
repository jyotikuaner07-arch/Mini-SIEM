"""
tests/test_database.py
Tests for the SQLite persistence layer.
Uses a temporary in-memory/file DB so it doesn't touch production data.

Run with:  pytest tests/ -v
"""

import sys
import datetime
import tempfile
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest


# ── Patch DB_PATH to a temp file for all tests ──
@pytest.fixture(autouse=True)
def temp_db(tmp_path):
    """Redirect the database to a temp file for every test."""
    temp_db_path = tmp_path / "test_siem.db"
    (tmp_path / "data").mkdir(exist_ok=True)
    with patch("database.DB_PATH", temp_db_path):
        import core.database as database
        database.DB_PATH = temp_db_path
        database.DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        database.init_db()
        yield temp_db_path


import core.database as database


def _make_event(offset_minutes=0) -> dict:
    ts = datetime.datetime(2025, 1, 15, 10, 0, 0) + datetime.timedelta(minutes=offset_minutes)
    return {
        "timestamp":   ts,
        "event_type":  "FAILED_LOGIN",
        "user":        "admin",
        "source_ip":   "203.0.113.1",
        "status":      "FAILED",
        "risk_score":  5,
        "raw_source":  "test",
        "raw_message": "test message",
    }


def _make_alert(offset_minutes=0) -> dict:
    ts = datetime.datetime(2025, 1, 15, 10, 0, 0) + datetime.timedelta(minutes=offset_minutes)
    return {
        "rule":        "BRUTE_FORCE",
        "severity":    "HIGH",
        "timestamp":   ts,
        "description": "Test alert",
        "risk_score":  15,
        "entity":      "203.0.113.1",
    }


class TestInitDB:
    def test_tables_created(self, tmp_path):
        import sqlite3
        conn = sqlite3.connect(database.DB_PATH)
        tables = {row[0] for row in
                  conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        conn.close()
        assert "events" in tables
        assert "alerts" in tables

    def test_init_db_idempotent(self):
        # Calling twice should not raise or wipe data
        database.save_events([_make_event()], "s1")
        database.init_db()  # second call
        results = database.query_events()
        assert len(results) == 1


class TestSaveEvents:
    def test_save_and_retrieve(self):
        events = [_make_event(i) for i in range(3)]
        count = database.save_events(events, "session_test")
        assert count == 3
        results = database.query_events()
        assert len(results) == 3

    def test_empty_list(self):
        count = database.save_events([], "s1")
        assert count == 0

    def test_session_id_stored(self):
        database.save_events([_make_event()], "my_session_123")
        results = database.query_events()
        assert results[0]["session_id"] == "my_session_123"


class TestSaveAlerts:
    def test_save_and_retrieve(self):
        alerts = [_make_alert(i) for i in range(2)]
        count = database.save_alerts(alerts, "s1")
        assert count == 2
        results = database.query_alerts()
        assert len(results) == 2


class TestQueryEvents:
    def _populate(self):
        events = [
            {**_make_event(), "user": "alice", "source_ip": "10.0.0.1", "status": "SUCCESS",
             "event_type": "SUCCESSFUL_LOGIN", "timestamp": datetime.datetime(2025,1,15,8,0,0)},
            {**_make_event(), "user": "bob",   "source_ip": "203.0.113.5", "status": "FAILED",
             "event_type": "FAILED_LOGIN",     "timestamp": datetime.datetime(2025,1,15,9,0,0)},
            {**_make_event(), "user": "admin", "source_ip": "203.0.113.5", "status": "FAILED",
             "event_type": "FAILED_LOGIN",     "timestamp": datetime.datetime(2025,1,15,10,0,0)},
        ]
        database.save_events(events, "s1")

    def test_filter_by_ip(self):
        self._populate()
        results = database.query_events(ip="203.0.113.5")
        assert len(results) == 2
        assert all(r["source_ip"] == "203.0.113.5" for r in results)

    def test_filter_by_user(self):
        self._populate()
        results = database.query_events(user="alice")
        assert len(results) == 1
        assert results[0]["user"] == "alice"

    def test_filter_by_status(self):
        self._populate()
        results = database.query_events(status="FAILED")
        assert len(results) == 2
        assert all(r["status"] == "FAILED" for r in results)

    def test_filter_by_since(self):
        self._populate()
        results = database.query_events(since="2025-01-15T09:30:00")
        assert len(results) == 1

    def test_limit_respected(self):
        for i in range(10):
            database.save_events([_make_event(i)], "s1")
        results = database.query_events(limit=3)
        assert len(results) == 3


class TestQueryAlerts:
    def test_filter_by_severity(self):
        alerts = [_make_alert(), {**_make_alert(), "severity": "CRITICAL"}]
        database.save_alerts(alerts, "s1")
        results = database.query_alerts(severity="CRITICAL")
        assert len(results) == 1
        assert results[0]["severity"] == "CRITICAL"


class TestTopStats:
    def test_top_ips(self):
        events = [
            {**_make_event(), "source_ip": "1.1.1.1", "status": "FAILED"},
            {**_make_event(), "source_ip": "1.1.1.1", "status": "FAILED"},
            {**_make_event(), "source_ip": "2.2.2.2", "status": "FAILED"},
        ]
        database.save_events(events, "s1")
        top = database.get_top_ips(5)
        assert top[0][0] == "1.1.1.1"
        assert top[0][1] == 2

    def test_top_targeted_users(self):
        events = [
            {**_make_event(), "user": "root",  "status": "FAILED"},
            {**_make_event(), "user": "root",  "status": "FAILED"},
            {**_make_event(), "user": "alice", "status": "FAILED"},
        ]
        database.save_events(events, "s1")
        top = database.get_top_targeted_users(5)
        assert top[0][0] == "root"

    def test_db_stats(self):
        database.save_events([_make_event()], "s1")
        database.save_alerts([_make_alert()], "s1")
        stats = database.get_db_stats()
        assert stats["total_events"] == 1
        assert stats["total_alerts"] == 1
        assert "db_path" in stats


class TestClearOldData:
    def test_clears_old_records(self):
        old_event = {**_make_event(),
                     "timestamp": datetime.datetime(2020, 1, 1, 0, 0, 0)}
        database.save_events([old_event], "s1")
        database.save_alerts([{**_make_alert(),
                                "timestamp": datetime.datetime(2020,1,1)}], "s1")
        deleted = database.clear_old_data(days=30)
        assert deleted > 0
        assert len(database.query_events()) == 0
