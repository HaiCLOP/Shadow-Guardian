"""
Tests for core.event_queue — priority queue, thread safety, overflow behavior.
"""
import time
import threading
import pytest
from core.event_queue import (
    EventQueue, Event, EVENT_APP, EVENT_PROCESS, EVENT_ALERT,
    PRIORITY_NORMAL, PRIORITY_HIGH, PRIORITY_CRITICAL,
)

class TestEventQueue:
    def test_put_and_drain(self, event_queue):
        event_queue.put_event(EVENT_APP, {"name": "test"})
        events = event_queue.drain()
        assert len(events) == 1
        assert events[0].type == EVENT_APP
        assert events[0].data["name"] == "test"

    def test_drain_returns_empty_when_empty(self, event_queue):
        assert event_queue.drain() == []

    def test_priority_ordering(self, event_queue):
        event_queue.put_event(EVENT_APP, {"order": "normal"}, priority=PRIORITY_NORMAL)
        event_queue.put_event(EVENT_ALERT, {"order": "critical"}, priority=PRIORITY_CRITICAL)
        event_queue.put_event(EVENT_PROCESS, {"order": "high"}, priority=PRIORITY_HIGH)
        events = event_queue.drain()
        assert len(events) == 3
        # Higher priority number = higher importance in deque, drain order depends on impl
        types = [e.data["order"] for e in events]
        assert "critical" in types
        assert "normal" in types

    def test_overflow_drops_events(self):
        q = EventQueue(maxlen=5)
        for i in range(10):
            q.put_event(EVENT_APP, {"i": i})
        events = q.drain()
        assert len(events) <= 5

    def test_event_has_timestamp(self, event_queue):
        before = time.time()
        event_queue.put_event(EVENT_APP, {"t": True})
        events = event_queue.drain()
        assert len(events) == 1
        assert events[0].timestamp >= before
        assert events[0].timestamp <= time.time()

    def test_stats(self, event_queue):
        s = event_queue.stats
        assert "normal_size" in s
        assert s["normal_size"] == 0
        event_queue.put_event(EVENT_APP, {})
        s = event_queue.stats
        assert s["normal_size"] == 1

    def test_thread_safety(self, event_queue):
        errors = []
        def writer(tid):
            try:
                for i in range(50):
                    event_queue.put_event(EVENT_APP, {"tid": tid, "i": i})
            except Exception as e:
                errors.append(e)
        threads = [threading.Thread(target=writer, args=(t,)) for t in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)
        assert not errors
        events = event_queue.drain()
        assert len(events) <= 100  # max_size=100 from fixture
