"""
Shadow Guardian — Event Queue

Thread-safe bounded in-memory event queue for buffering
monitoring events before batch DB writes.
"""

import time
import threading
from collections import deque
from typing import Optional

from utils.logger import get_logger

logger = get_logger("core.event_queue")

EVENT_APP = "app"
EVENT_SESSION = "session"
EVENT_ALERT = "alert"
EVENT_PROCESS = "process"
EVENT_NETWORK = "network"
EVENT_BROWSER = "browser"
EVENT_APP_LAUNCH = "app_launch"
EVENT_USB = "usb"
EVENT_CLIPBOARD = "clipboard"
EVENT_FILE = "file"

PRIORITY_NORMAL = 0
PRIORITY_HIGH = 1
PRIORITY_CRITICAL = 2


class Event:
    __slots__ = ("type", "timestamp", "data", "priority")

    def __init__(self, event_type: str, data: dict,
                 priority: int = PRIORITY_NORMAL,
                 timestamp: Optional[float] = None):
        self.type = event_type
        self.timestamp = timestamp or time.time()
        self.data = data
        self.priority = priority

    def to_dict(self) -> dict:
        return {
            "type": self.type, "timestamp": self.timestamp,
            "data": self.data, "priority": self.priority,
        }


class EventQueue:
    """Thread-safe bounded event queue with priority support."""

    def __init__(self, maxlen: int = 10000):
        self._queue: deque[Event] = deque(maxlen=maxlen)
        self._critical_queue: deque[Event] = deque(maxlen=1000)
        self._lock = threading.Lock()
        self._event_ready = threading.Event()
        self._overflow_count = 0
        self._total_enqueued = 0
        self._total_drained = 0
        self._maxlen = maxlen

    def put(self, event: Event) -> None:
        with self._lock:
            if event.priority >= PRIORITY_CRITICAL:
                self._critical_queue.append(event)
            else:
                if len(self._queue) >= self._maxlen:
                    self._overflow_count += 1
                self._queue.append(event)
            self._total_enqueued += 1
        self._event_ready.set()

    def put_event(self, event_type: str, data: dict,
                  priority: int = PRIORITY_NORMAL) -> None:
        self.put(Event(event_type, data, priority))

    def drain(self, max_count: int = 500) -> list[Event]:
        events = []
        with self._lock:
            while self._critical_queue and len(events) < max_count:
                events.append(self._critical_queue.popleft())
            while self._queue and len(events) < max_count:
                events.append(self._queue.popleft())
            self._total_drained += len(events)
            if not self._queue and not self._critical_queue:
                self._event_ready.clear()
        return events

    def wait_for_events(self, timeout: Optional[float] = None) -> bool:
        return self._event_ready.wait(timeout=timeout)

    def has_critical(self) -> bool:
        with self._lock:
            return len(self._critical_queue) > 0

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._queue) + len(self._critical_queue)

    @property
    def stats(self) -> dict:
        with self._lock:
            return {
                "normal_size": len(self._queue),
                "critical_size": len(self._critical_queue),
                "total_enqueued": self._total_enqueued,
                "total_drained": self._total_drained,
                "overflow": self._overflow_count,
            }

    def clear(self) -> None:
        with self._lock:
            self._queue.clear()
            self._critical_queue.clear()
            self._event_ready.clear()
