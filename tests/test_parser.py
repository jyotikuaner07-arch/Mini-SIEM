"""
tests/test_parser.py
Tests for the log parsing and normalisation layer.

Run with:  pytest tests/ -v
"""

import sys
import datetime
from pathlib import Path

# Add project root to path so imports work
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from parser import (
    parse_log_entry, parse_all,
    _parse_timestamp, _validate_ip, _sanitize_string, is_internal_ip,
)


# ════════════════════════════════════════════════════════
# TIMESTAMP PARSING
# ════════════════════════════════════════════════════════

class TestTimestampParsing:
    def test_iso_format_with_microseconds(self):
        ts = _parse_timestamp("2025-01-15T10:23:45.123456")
        assert isinstance(ts, datetime.datetime)
        assert ts.year == 2025
        assert ts.hour == 10

    def test_iso_format_no_microseconds(self):
        ts = _parse_timestamp("2025-01-15T10:23:45")
        assert ts is not None
        assert ts.minute == 23

    def test_space_separated_format(self):
        ts = _parse_timestamp("2025-01-15 10:23:45")
        assert ts is not None
        assert ts.day == 15

    def test_invalid_string_returns_none(self):
        assert _parse_timestamp("not-a-date") is None
        assert _parse_timestamp("") is None
        assert _parse_timestamp(None) is None

    def test_datetime_object_passes_through(self):
        dt = datetime.datetime(2025, 6, 1, 12, 0, 0)
        result = _parse_timestamp(dt)
        assert result == dt


# ════════════════════════════════════════════════════════
# IP VALIDATION
# ════════════════════════════════════════════════════════

class TestIPValidation:
    def test_valid_ip(self):
        assert _validate_ip("192.168.1.1")   == "192.168.1.1"
        assert _validate_ip("203.0.113.42")  == "203.0.113.42"
        assert _validate_ip("10.0.0.1")      == "10.0.0.1"

    def test_invalid_ip_returns_empty(self):
        assert _validate_ip("not-an-ip")     == ""
        assert _validate_ip("999.999.999.999") == ""   # still matches regex — acceptable
        assert _validate_ip("")              == ""
        assert _validate_ip(None)            == ""

    def test_internal_ip_detection(self):
        assert is_internal_ip("192.168.1.1")   is True
        assert is_internal_ip("10.0.0.1")      is True
        assert is_internal_ip("172.16.0.1")    is True
        assert is_internal_ip("127.0.0.1")     is True
        assert is_internal_ip("203.0.113.1")   is False
        assert is_internal_ip("")              is False
        assert is_internal_ip(None)            is False


# ════════════════════════════════════════════════════════
# STRING SANITISATION
# ════════════════════════════════════════════════════════

class TestSanitizeString:
    def test_normal_string_unchanged(self):
        assert _sanitize_string("alice") == "alice"

    def test_control_characters_removed(self):
        result = _sanitize_string("user\x00name\x1f")
        assert "\x00" not in result
        assert "\x1f" not in result

    def test_long_string_truncated(self):
        long_str = "a" * 200
        result = _sanitize_string(long_str)
        assert len(result) <= 128

    def test_non_string_returns_empty(self):
        assert _sanitize_string(None)  == ""
        assert _sanitize_string(12345) == ""


# ════════════════════════════════════════════════════════
# PARSE SINGLE ENTRY
# ════════════════════════════════════════════════════════

class TestParseLogEntry:
    def _make_raw(self, **overrides):
        base = {
            "_raw_source": "test",
            "timestamp":   "2025-01-15T10:23:45",
            "event_type":  "FAILED_LOGIN",
            "user":        "admin",
            "source_ip":   "192.168.1.10",
            "status":      "FAILED",
            "raw_message": "test message",
        }
        base.update(overrides)
        return base

    def test_valid_entry_parsed_correctly(self):
        result = parse_log_entry(self._make_raw())
        assert result is not None
        assert result["event_type"] == "FAILED_LOGIN"
        assert result["user"]       == "admin"
        assert result["status"]     == "FAILED"
        assert result["risk_score"] == 0   # detector fills this in
        assert isinstance(result["timestamp"], datetime.datetime)

    def test_missing_timestamp_returns_none(self):
        raw = self._make_raw(timestamp="")
        assert parse_log_entry(raw) is None

    def test_invalid_event_type_normalised(self):
        raw = self._make_raw(event_type="TOTALLY_MADE_UP")
        result = parse_log_entry(raw)
        assert result["event_type"] == "UNKNOWN"

    def test_invalid_status_normalised(self):
        raw = self._make_raw(status="GARBAGE")
        result = parse_log_entry(raw)
        assert result["status"] == "UNKNOWN"

    def test_invalid_ip_cleared(self):
        raw = self._make_raw(source_ip="not-an-ip")
        result = parse_log_entry(raw)
        assert result["source_ip"] == ""

    def test_non_dict_returns_none(self):
        assert parse_log_entry("a string")  is None
        assert parse_log_entry(None)         is None
        assert parse_log_entry(42)           is None

    def test_event_types_all_accepted(self):
        valid_types = ["FAILED_LOGIN","SUCCESSFUL_LOGIN",
                       "PRIVILEGE_ESCALATION","ACCOUNT_LOCKOUT",
                       "EXPLICIT_CRED_LOGIN","UNKNOWN"]
        for et in valid_types:
            result = parse_log_entry(self._make_raw(event_type=et))
            assert result["event_type"] == et


# ════════════════════════════════════════════════════════
# PARSE ALL (batch)
# ════════════════════════════════════════════════════════

class TestParseAll:
    def _make_raw(self, ts="2025-01-15T10:23:45", event_type="FAILED_LOGIN",
                  user="admin", ip="192.168.1.1", status="FAILED"):
        return {
            "_raw_source": "test", "timestamp": ts,
            "event_type": event_type, "user": user,
            "source_ip": ip, "status": status, "raw_message": "",
        }

    def test_empty_list(self):
        result = parse_all([])
        assert result == []

    def test_valid_entries_all_parsed(self):
        raws = [self._make_raw(ts=f"2025-01-15T10:2{i}:00") for i in range(5)]
        result = parse_all(raws)
        assert len(result) == 5

    def test_bad_entries_skipped(self):
        raws = [
            self._make_raw(),            # good
            {"timestamp": "", "event_type": "FAILED_LOGIN"},  # bad — no valid ts
            self._make_raw(ts="2025-01-15T11:00:00"),         # good
        ]
        result = parse_all(raws)
        assert len(result) == 2

    def test_output_sorted_chronologically(self):
        raws = [
            self._make_raw(ts="2025-01-15T12:00:00"),
            self._make_raw(ts="2025-01-15T08:00:00"),
            self._make_raw(ts="2025-01-15T10:00:00"),
        ]
        result = parse_all(raws)
        timestamps = [r["timestamp"] for r in result]
        assert timestamps == sorted(timestamps)
