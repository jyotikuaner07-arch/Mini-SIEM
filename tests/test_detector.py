"""
tests/test_detector.py
Tests for all detection rules and risk scoring.

Run with:  pytest tests/ -v
"""

import sys
import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from detector import (
    detect, _rule_brute_force, _rule_new_ip,
    _rule_privilege_escalation, _rule_error_spike,
    _rule_critical_risk, _deduplicate_alerts,
    BRUTE_FORCE_LIMIT, BRUTE_FORCE_WINDOW,
    CRITICAL_THRESHOLD, RISK_WEIGHTS,
)


# ════════════════════════════════════════════════════════
# HELPERS
# ════════════════════════════════════════════════════════

def _make_event(
    event_type="FAILED_LOGIN",
    status="FAILED",
    user="admin",
    ip="203.0.113.1",
    ts: datetime.datetime = None,
    risk_score=0,
) -> dict:
    return {
        "timestamp":   ts or datetime.datetime.now(),
        "event_type":  event_type,
        "user":        user,
        "source_ip":   ip,
        "status":      status,
        "risk_score":  risk_score,
        "raw_source":  "test",
        "raw_message": "",
    }


def _events_at_offsets(offsets_seconds: list[int], **kwargs) -> list[dict]:
    """Create multiple events spaced by the given second offsets."""
    base = datetime.datetime(2025, 1, 15, 10, 0, 0)
    return [_make_event(ts=base + datetime.timedelta(seconds=s), **kwargs)
            for s in offsets_seconds]


# ════════════════════════════════════════════════════════
# RISK SCORING
# ════════════════════════════════════════════════════════

class TestRiskScoring:
    def test_risk_weights_assigned(self):
        events = [
            _make_event("FAILED_LOGIN"),
            _make_event("PRIVILEGE_ESCALATION", status="SUCCESS"),
            _make_event("ACCOUNT_LOCKOUT", status="INFO"),
        ]
        # Run detect with threat intel disabled to isolate scoring
        result_events, _ = detect(events, known_ips=set(), use_threat_intel=False)
        assert result_events[0]["risk_score"] >= RISK_WEIGHTS["FAILED_LOGIN"]
        assert result_events[1]["risk_score"] >= RISK_WEIGHTS["PRIVILEGE_ESCALATION"]

    def test_external_ip_adds_risk(self):
        """Events from external unknown IPs should score higher."""
        internal = _make_event(ip="192.168.1.1")
        external = _make_event(ip="203.0.113.99")
        events, _ = detect([internal, external], known_ips=set(), use_threat_intel=False)
        ext_ev = next(e for e in events if e["source_ip"] == "203.0.113.99")
        int_ev = next(e for e in events if e["source_ip"] == "192.168.1.1")
        assert ext_ev["risk_score"] > int_ev["risk_score"]


# ════════════════════════════════════════════════════════
# BRUTE FORCE RULE
# ════════════════════════════════════════════════════════

class TestBruteForceRule:
    def test_fires_when_limit_exceeded(self):
        # 6 failures within 60s → should fire (limit is 5)
        events = _events_at_offsets([0, 10, 20, 30, 40, 50],
                                     ip="203.0.113.42")
        for e in events:
            e["risk_score"] = 2
        alerts = _rule_brute_force(events)
        assert any(a["rule"] == "BRUTE_FORCE" for a in alerts)

    def test_does_not_fire_below_limit(self):
        # Only 3 failures — should NOT fire
        events = _events_at_offsets([0, 30, 60], ip="203.0.113.42")
        for e in events:
            e["risk_score"] = 2
        alerts = _rule_brute_force(events)
        assert not any(a["rule"] == "BRUTE_FORCE" for a in alerts)

    def test_does_not_fire_outside_window(self):
        # 6 failures but spread over 10 minutes (600s > 120s window)
        events = _events_at_offsets([0, 100, 200, 300, 400, 500],
                                     ip="203.0.113.42")
        for e in events:
            e["risk_score"] = 2
        alerts = _rule_brute_force(events)
        assert not any(a["rule"] == "BRUTE_FORCE" for a in alerts)

    def test_groups_by_ip(self):
        # 6 failures from IP A, 2 from IP B — only A triggers
        base = datetime.datetime(2025, 1, 15, 10, 0, 0)
        events_a = [_make_event(ip="1.2.3.4", ts=base + datetime.timedelta(seconds=i*10))
                    for i in range(6)]
        events_b = [_make_event(ip="5.6.7.8", ts=base + datetime.timedelta(seconds=i*10))
                    for i in range(2)]
        for e in events_a + events_b:
            e["risk_score"] = 2
        alerts = _rule_brute_force(events_a + events_b)
        triggered_entities = [a["entity"] for a in alerts if a["rule"] == "BRUTE_FORCE"]
        assert "1.2.3.4" in triggered_entities
        assert "5.6.7.8" not in triggered_entities

    def test_severity_is_high(self):
        events = _events_at_offsets([0,10,20,30,40,50], ip="9.9.9.9")
        for e in events:
            e["risk_score"] = 2
        alerts = _rule_brute_force(events)
        for a in alerts:
            assert a["severity"] == "HIGH"


# ════════════════════════════════════════════════════════
# NEW IP RULE
# ════════════════════════════════════════════════════════

class TestNewIPRule:
    def test_fires_on_unknown_ip_success(self):
        ev = _make_event(event_type="SUCCESSFUL_LOGIN", status="SUCCESS", ip="9.9.9.9")
        ev["risk_score"] = 0
        alerts = _rule_new_ip([ev], known_ips=set())
        assert any(a["rule"] == "NEW_IP_LOGIN" for a in alerts)

    def test_does_not_fire_for_known_ip(self):
        ev = _make_event(event_type="SUCCESSFUL_LOGIN", status="SUCCESS", ip="192.168.1.1")
        ev["risk_score"] = 0
        alerts = _rule_new_ip([ev], known_ips={"192.168.1.1"})
        assert not any(a["rule"] == "NEW_IP_LOGIN" for a in alerts)

    def test_does_not_fire_for_failed_login(self):
        ev = _make_event(event_type="FAILED_LOGIN", status="FAILED", ip="9.9.9.9")
        ev["risk_score"] = 0
        alerts = _rule_new_ip([ev], known_ips=set())
        assert not any(a["rule"] == "NEW_IP_LOGIN" for a in alerts)

    def test_deduplicates_same_ip(self):
        # Same new IP logging in twice → only one alert
        base = datetime.datetime(2025, 1, 15, 10, 0, 0)
        events = [
            _make_event(event_type="SUCCESSFUL_LOGIN", status="SUCCESS",
                        ip="9.9.9.9", ts=base),
            _make_event(event_type="SUCCESSFUL_LOGIN", status="SUCCESS",
                        ip="9.9.9.9", ts=base + datetime.timedelta(minutes=1)),
        ]
        for e in events:
            e["risk_score"] = 0
        alerts = _rule_new_ip(events, known_ips=set())
        assert len([a for a in alerts if a["rule"] == "NEW_IP_LOGIN"]) == 1

    def test_severity_is_medium(self):
        ev = _make_event(event_type="SUCCESSFUL_LOGIN", status="SUCCESS", ip="8.8.8.8")
        ev["risk_score"] = 0
        alerts = _rule_new_ip([ev], known_ips=set())
        assert all(a["severity"] == "MEDIUM" for a in alerts)


# ════════════════════════════════════════════════════════
# PRIVILEGE ESCALATION RULE
# ════════════════════════════════════════════════════════

class TestPrivilegeEscalationRule:
    def test_fires_on_privilege_escalation(self):
        ev = _make_event(event_type="PRIVILEGE_ESCALATION", status="SUCCESS")
        ev["risk_score"] = 5
        alerts = _rule_privilege_escalation([ev])
        assert any(a["rule"] == "PRIVILEGE_ESCALATION" for a in alerts)

    def test_fires_on_explicit_cred(self):
        ev = _make_event(event_type="EXPLICIT_CRED_LOGIN", status="SUCCESS")
        ev["risk_score"] = 3
        alerts = _rule_privilege_escalation([ev])
        assert any(a["rule"] == "PRIVILEGE_ESCALATION" for a in alerts)

    def test_does_not_fire_on_normal_login(self):
        ev = _make_event(event_type="SUCCESSFUL_LOGIN", status="SUCCESS")
        ev["risk_score"] = 0
        alerts = _rule_privilege_escalation([ev])
        assert len(alerts) == 0

    def test_severity_is_high(self):
        ev = _make_event(event_type="PRIVILEGE_ESCALATION", status="SUCCESS")
        ev["risk_score"] = 5
        alerts = _rule_privilege_escalation([ev])
        assert all(a["severity"] == "HIGH" for a in alerts)


# ════════════════════════════════════════════════════════
# ERROR SPIKE RULE
# ════════════════════════════════════════════════════════

class TestErrorSpikeRule:
    def test_fires_when_spike_detected(self):
        # 12 failures in 30 seconds → spike (limit=10, window=60)
        events = _events_at_offsets(list(range(0, 55, 5)))  # 12 events in 55s
        for e in events:
            e["risk_score"] = 2
        alerts = _rule_error_spike(events)
        assert any(a["rule"] == "ERROR_SPIKE" for a in alerts)

    def test_does_not_fire_below_limit(self):
        events = _events_at_offsets([0, 30])  # only 2
        for e in events:
            e["risk_score"] = 2
        alerts = _rule_error_spike(events)
        assert not any(a["rule"] == "ERROR_SPIKE" for a in alerts)

    def test_ignores_successful_events(self):
        # 12 successful logins should NOT trigger error spike
        events = _events_at_offsets(list(range(0,55,5)),
                                     event_type="SUCCESSFUL_LOGIN", status="SUCCESS")
        for e in events:
            e["risk_score"] = 0
        alerts = _rule_error_spike(events)
        assert not any(a["rule"] == "ERROR_SPIKE" for a in alerts)


# ════════════════════════════════════════════════════════
# CRITICAL RISK RULE
# ════════════════════════════════════════════════════════

class TestCriticalRiskRule:
    def test_fires_above_threshold(self):
        events = [_make_event(risk_score=10) for _ in range(3)]  # total = 30 > 20
        alerts = _rule_critical_risk(events)
        assert any(a["rule"] == "CRITICAL_RISK_THRESHOLD" for a in alerts)
        assert all(a["severity"] == "CRITICAL" for a in alerts)

    def test_does_not_fire_below_threshold(self):
        events = [_make_event(risk_score=2) for _ in range(3)]  # total = 6 < 20
        alerts = _rule_critical_risk(events)
        assert not any(a["rule"] == "CRITICAL_RISK_THRESHOLD" for a in alerts)

    def test_fires_exactly_at_threshold(self):
        events = [_make_event(risk_score=CRITICAL_THRESHOLD)]
        alerts = _rule_critical_risk(events)
        assert any(a["rule"] == "CRITICAL_RISK_THRESHOLD" for a in alerts)

    def test_empty_events_list(self):
        alerts = _rule_critical_risk([])
        assert alerts == []


# ════════════════════════════════════════════════════════
# DEDUPLICATION
# ════════════════════════════════════════════════════════

class TestDeduplication:
    def _make_alert(self, rule="BRUTE_FORCE", entity="1.2.3.4",
                    offset_minutes=0) -> dict:
        base = datetime.datetime(2025, 1, 15, 10, 0, 0)
        return {
            "rule":        rule,
            "severity":    "HIGH",
            "timestamp":   base + datetime.timedelta(minutes=offset_minutes),
            "description": "test",
            "events":      [],
            "risk_score":  5,
            "entity":      entity,
        }

    def test_removes_duplicate_within_window(self):
        # Same rule + entity, 1 minute apart → only keep first
        alerts = [self._make_alert(offset_minutes=0), self._make_alert(offset_minutes=1)]
        result = _deduplicate_alerts(alerts)
        assert len(result) == 1

    def test_keeps_alert_outside_window(self):
        # Same rule + entity, 10 minutes apart → keep both (> 5 min window)
        alerts = [self._make_alert(offset_minutes=0), self._make_alert(offset_minutes=10)]
        result = _deduplicate_alerts(alerts)
        assert len(result) == 2

    def test_keeps_different_rules(self):
        alerts = [
            self._make_alert(rule="BRUTE_FORCE", entity="1.2.3.4"),
            self._make_alert(rule="NEW_IP_LOGIN", entity="1.2.3.4"),
        ]
        result = _deduplicate_alerts(alerts)
        assert len(result) == 2


# ════════════════════════════════════════════════════════
# FULL PIPELINE (detect())
# ════════════════════════════════════════════════════════

class TestDetectPipeline:
    def test_empty_events(self):
        events, alerts = detect([], use_threat_intel=False)
        assert events == []
        assert alerts == []

    def test_single_clean_event_no_alerts(self):
        ev = _make_event(event_type="SUCCESSFUL_LOGIN", status="SUCCESS",
                         ip="192.168.1.1")
        events, alerts = detect([ev], known_ips={"192.168.1.1"},
                                 use_threat_intel=False)
        # 192.168.1.1 is known, so no NEW_IP alert
        # No failures, so no BRUTE_FORCE
        assert not any(a["rule"] in ("BRUTE_FORCE","NEW_IP_LOGIN") for a in alerts)

    def test_brute_force_scenario(self):
        base = datetime.datetime(2025, 1, 15, 10, 0, 0)
        events = [
            _make_event(ip="9.9.9.9", ts=base + datetime.timedelta(seconds=i*10))
            for i in range(8)
        ]
        _, alerts = detect(events, known_ips=set(), use_threat_intel=False)
        rules = [a["rule"] for a in alerts]
        assert "BRUTE_FORCE" in rules

    def test_all_events_get_risk_scores(self):
        events = [
            _make_event("FAILED_LOGIN"),
            _make_event("PRIVILEGE_ESCALATION", status="SUCCESS"),
            _make_event("SUCCESSFUL_LOGIN", status="SUCCESS"),
        ]
        result_events, _ = detect(events, known_ips=set(), use_threat_intel=False)
        for ev in result_events:
            assert "risk_score" in ev
            assert isinstance(ev["risk_score"], int)
