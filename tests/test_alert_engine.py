"""
Tests for agent.alert_engine — rule evaluation, batch processing.
"""
import time
import pytest
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from core.event_queue import Event, EVENT_PROCESS, EVENT_NETWORK, EVENT_SESSION, EVENT_APP, PRIORITY_NORMAL
from agent.alert_engine import (
    UnknownProcessRule, RapidSpawnRule, HighConnectionRule, SessionAnomalyRule,
)

def _make_event(etype, data):
    return Event(event_type=etype, data=data, timestamp=time.time(), priority=PRIORITY_NORMAL)

class TestUnknownProcessRule:
    def test_known_system_process(self):
        rule = UnknownProcessRule()
        evt = _make_event(EVENT_PROCESS, {"process_name": "explorer.exe", "pid": 1})
        assert rule.evaluate(evt) is None

    def test_unknown_process_triggers(self):
        rule = UnknownProcessRule()
        evt = _make_event(EVENT_PROCESS, {"process_name": "evil_malware.exe", "pid": 666})
        result = rule.evaluate(evt)
        assert result is not None
        assert result["alert_type"] == "unknown_process"
        assert result["severity"] == "warning"

    def test_ignores_non_process_events(self):
        rule = UnknownProcessRule()
        evt = _make_event(EVENT_APP, {"process_name": "evil.exe"})
        assert rule.evaluate(evt) is None

class TestRapidSpawnRule:
    def test_below_threshold(self):
        rule = RapidSpawnRule()
        for i in range(5):
            evt = _make_event(EVENT_PROCESS, {"process_name": f"p{i}.exe"})
            result = rule.evaluate(evt)
        assert result is None

    def test_above_threshold_triggers(self):
        rule = RapidSpawnRule()
        rule._threshold = 3
        results = []
        for i in range(5):
            evt = _make_event(EVENT_PROCESS, {"process_name": f"p{i}.exe"})
            r = rule.evaluate(evt)
            if r:
                results.append(r)
        assert len(results) >= 1
        assert results[0]["severity"] == "critical"

class TestHighConnectionRule:
    def test_below_threshold(self):
        rule = HighConnectionRule()
        evt = _make_event(EVENT_NETWORK, {"connection_count": 5, "process_name": "chrome.exe"})
        assert rule.evaluate(evt) is None

    def test_above_threshold(self):
        rule = HighConnectionRule()
        evt = _make_event(EVENT_NETWORK, {"connection_count": 100, "process_name": "suspicious.exe"})
        result = rule.evaluate(evt)
        assert result is not None
        assert result["alert_type"] == "high_connections"

class TestSessionAnomalyRule:
    def test_normal_lock_unlock(self):
        rule = SessionAnomalyRule()
        rule.evaluate(_make_event(EVENT_SESSION, {"event_type": "lock"}))
        result = rule.evaluate(_make_event(EVENT_SESSION, {"event_type": "unlock"}))
        assert result is None

    def test_unlock_without_lock(self):
        rule = SessionAnomalyRule()
        rule.evaluate(_make_event(EVENT_SESSION, {"event_type": "login"}))
        result = rule.evaluate(_make_event(EVENT_SESSION, {"event_type": "unlock"}))
        assert result is not None
        assert result["alert_type"] == "session_anomaly"
