"""
Shadow Guardian — Alert Engine

Rule-based alert system that evaluates events and generates
security alerts. Includes comprehensive detection rules for
processes, sessions, network, browser, USB, clipboard, and files.
"""

import time
import threading
import os
from typing import Optional
from collections import deque
from datetime import datetime

from utils.logger import get_logger
from utils.config import get_config
from core.event_queue import (
    EventQueue, Event, EVENT_ALERT, EVENT_PROCESS,
    EVENT_SESSION, EVENT_APP, EVENT_NETWORK,
    EVENT_BROWSER, EVENT_USB, EVENT_CLIPBOARD, EVENT_FILE,
    PRIORITY_CRITICAL, PRIORITY_HIGH, PRIORITY_NORMAL,
)

logger = get_logger("agent.alert_engine")


class AlertRule:
    """Base class for alert rules."""
    name: str = "base_rule"
    description: str = ""

    def evaluate(self, event: Event) -> Optional[dict]:
        raise NotImplementedError


class UnknownProcessRule(AlertRule):
    """Detect processes not in the known system process list."""
    name = "unknown_process"
    description = "Alerts on unknown/unwhitelisted processes"

    def __init__(self):
        config = get_config()
        rules_config = config.get("alert_rules", {})
        self._whitelist = set(
            p.lower() for p in rules_config.get("unknown_process_whitelist", [])
        )
        # Core Windows system processes only — no blanket browser/app whitelisting
        self._system_processes = {
            "system", "smss.exe", "csrss.exe", "wininit.exe",
            "services.exe", "lsass.exe", "svchost.exe", "explorer.exe",
            "dwm.exe", "taskhostw.exe", "sihost.exe", "fontdrvhost.exe",
            "runtimebroker.exe", "searchhost.exe", "startmenuexperiencehost.exe",
            "shellexperiencehost.exe", "textinputhost.exe", "ctfmon.exe",
            "conhost.exe", "dllhost.exe", "searchindexer.exe",
            "securityhealthservice.exe", "sgrmbroker.exe",
            "spoolsv.exe", "winlogon.exe", "lsaiso.exe",
            "registry", "idle", "system idle process",
            "audiodg.exe", "wudfhost.exe", "wmiprvse.exe",
            "dashost.exe", "smartscreen.exe", "msdtc.exe",
        }

    def evaluate(self, event: Event) -> Optional[dict]:
        if event.type != EVENT_PROCESS:
            return None
        proc_name = event.data.get("process_name", "").lower()
        if not proc_name:
            return None
        if proc_name in self._system_processes or proc_name in self._whitelist:
            return None
        return {
            "alert_type": "unknown_process",
            "severity": "info",
            "message": f"New process detected: {proc_name}",
            "data": {
                "pid": event.data.get("pid"),
                "process_name": proc_name,
                "exe_path": event.data.get("exe_path", ""),
            },
        }


class RapidSpawnRule(AlertRule):
    """Detect rapid process spawning (potential fork bomb or malware)."""
    name = "rapid_spawn"
    description = "Alerts on rapid process creation"

    def __init__(self):
        config = get_config()
        rules_config = config.get("alert_rules", {})
        self._threshold = rules_config.get("rapid_spawn_threshold", 10)
        self._window = rules_config.get("rapid_spawn_window", 60)
        self._spawn_times: deque = deque()

    def evaluate(self, event: Event) -> Optional[dict]:
        if event.type != EVENT_PROCESS:
            return None
        now = time.time()
        self._spawn_times.append(now)
        cutoff = now - self._window
        while self._spawn_times and self._spawn_times[0] < cutoff:
            self._spawn_times.popleft()
        if len(self._spawn_times) >= self._threshold:
            alert = {
                "alert_type": "rapid_process_spawn",
                "severity": "critical",
                "message": f"Rapid process spawning: {len(self._spawn_times)} in {self._window}s",
                "data": {
                    "count": len(self._spawn_times),
                    "window_seconds": self._window,
                    "latest_process": event.data.get("process_name", ""),
                },
            }
            self._spawn_times.clear()
            return alert
        return None


class HighConnectionRule(AlertRule):
    """Detect processes with unusually high outbound connections."""
    name = "high_connections"
    description = "Alerts on high outbound connection counts"

    def __init__(self):
        config = get_config()
        rules_config = config.get("alert_rules", {})
        self._threshold = rules_config.get("high_connection_threshold", 50)

    def evaluate(self, event: Event) -> Optional[dict]:
        if event.type != EVENT_NETWORK:
            return None
        conn_count = event.data.get("connection_count", 0)
        if conn_count >= self._threshold:
            return {
                "alert_type": "high_connections",
                "severity": "warning",
                "message": f"High connections: {event.data.get('process_name', '?')} has {conn_count}",
                "data": {
                    "pid": event.data.get("pid"),
                    "process_name": event.data.get("process_name", ""),
                    "connection_count": conn_count,
                },
            }
        return None


class SessionAnomalyRule(AlertRule):
    """Detect session anomalies (e.g., unlock without prior lock)."""
    name = "session_anomaly"
    description = "Alerts on session state anomalies"

    def __init__(self):
        self._last_session_event: Optional[str] = None

    def evaluate(self, event: Event) -> Optional[dict]:
        if event.type != EVENT_SESSION:
            return None
        event_type = event.data.get("event_type", "")
        if event_type == "unlock" and self._last_session_event not in ("lock", None):
            alert = {
                "alert_type": "session_anomaly",
                "severity": "warning",
                "message": f"Unlock without prior lock (last: {self._last_session_event})",
                "data": {"last_event": self._last_session_event},
            }
            self._last_session_event = event_type
            return alert
        self._last_session_event = event_type
        return None


class SuspiciousPathRule(AlertRule):
    """Alert when processes run from temp dirs, downloads, or appdata."""
    name = "suspicious_path"
    description = "Alerts on processes from suspicious locations"

    SUSPICIOUS_DIRS = [
        "\\appdata\\local\\temp\\",
        "\\windows\\temp\\",
        "\\users\\public\\",
        "\\$recycle.bin\\",
        "\\downloads\\",
    ]

    def evaluate(self, event: Event) -> Optional[dict]:
        if event.type != EVENT_PROCESS:
            return None
        exe_path = (event.data.get("exe_path") or "").lower()
        if not exe_path:
            return None
        for pattern in self.SUSPICIOUS_DIRS:
            if pattern in exe_path:
                return {
                    "alert_type": "suspicious_path",
                    "severity": "warning",
                    "message": f"Process from suspicious path: {event.data.get('process_name', '')}",
                    "data": {
                        "pid": event.data.get("pid"),
                        "process_name": event.data.get("process_name", ""),
                        "exe_path": exe_path,
                        "pattern": pattern,
                    },
                }
        return None


class USBDeviceRule(AlertRule):
    """Alert when USB storage devices are connected."""
    name = "usb_device"
    description = "Alerts on USB device connections"

    def evaluate(self, event: Event) -> Optional[dict]:
        if event.type != EVENT_USB:
            return None
        if event.data.get("action") != "connected":
            return None
        is_storage = event.data.get("is_storage", False)
        severity = "critical" if is_storage else "info"
        return {
            "alert_type": "usb_storage_connected" if is_storage else "usb_device_connected",
            "severity": severity,
            "message": f"USB {'storage ' if is_storage else ''}device connected: {event.data.get('device_name', '?')}",
            "data": {
                "device_name": event.data.get("device_name", ""),
                "device_id": event.data.get("device_id", ""),
                "is_storage": is_storage,
            },
        }


class ClipboardSensitiveRule(AlertRule):
    """Alert when clipboard contains sensitive data patterns."""
    name = "clipboard_sensitive"
    description = "Alerts on sensitive clipboard content"

    def evaluate(self, event: Event) -> Optional[dict]:
        if event.type != EVENT_CLIPBOARD:
            return None
        flags = event.data.get("sensitive_flags", [])
        if not flags:
            return None
        return {
            "alert_type": "sensitive_clipboard",
            "severity": "warning",
            "message": f"Sensitive data copied: {', '.join(flags)}",
            "data": {
                "flags": flags,
                "source_app": event.data.get("source_app", ""),
                "content_type": event.data.get("content_type", ""),
            },
        }


class FileStartupRule(AlertRule):
    """Alert when executables are created in startup directories."""
    name = "file_startup"
    description = "Alerts on new files in startup directories"

    def evaluate(self, event: Event) -> Optional[dict]:
        if event.type != EVENT_FILE:
            return None
        if not event.data.get("is_startup_dir"):
            return None
        if event.data.get("action") not in ("created", "modified", "renamed_to"):
            return None
        return {
            "alert_type": "startup_modification",
            "severity": "critical",
            "message": f"File added to startup: {os.path.basename(event.data.get('file_path', ''))}",
            "data": {
                "file_path": event.data.get("file_path", ""),
                "action": event.data.get("action", ""),
            },
        }


class LateNightActivityRule(AlertRule):
    """Alert on activity during unusual hours."""
    name = "late_night_activity"
    description = "Alerts on activity during late night hours"

    def __init__(self):
        config = get_config()
        rules_config = config.get("alert_rules", {})
        self._start_hour = rules_config.get("late_night_start", 23)
        self._end_hour = rules_config.get("late_night_end", 5)
        self._last_alert_time = 0.0

    def evaluate(self, event: Event) -> Optional[dict]:
        if event.type != EVENT_SESSION:
            return None
        if event.data.get("event_type") != "unlock":
            return None
        now = time.time()
        if now - self._last_alert_time < 300:
            return None
        hour = datetime.now().hour
        is_late = hour >= self._start_hour or hour < self._end_hour
        if is_late:
            self._last_alert_time = now
            return {
                "alert_type": "late_night_access",
                "severity": "warning",
                "message": f"Computer accessed at unusual hour ({hour}:00)",
                "data": {"hour": hour, "username": event.data.get("username", "")},
            }
        return None


class AlertEngine:
    """Evaluates events against registered rules and generates alerts."""

    def __init__(self, event_queue: EventQueue):
        self._queue = event_queue
        self._rules: list[AlertRule] = []
        self._running = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._alert_count = 0

        config = get_config()
        if config.get("feature_flags.alert_engine", True):
            self._rules.extend([
                UnknownProcessRule(),
                RapidSpawnRule(),
                HighConnectionRule(),
                SessionAnomalyRule(),
                SuspiciousPathRule(),
                USBDeviceRule(),
                ClipboardSensitiveRule(),
                FileStartupRule(),
                LateNightActivityRule(),
            ])
            logger.info(f"Alert engine initialized with {len(self._rules)} rules")

    def add_rule(self, rule: AlertRule) -> None:
        self._rules.append(rule)

    def evaluate_event(self, event: Event) -> list[dict]:
        alerts = []
        for rule in self._rules:
            try:
                result = rule.evaluate(event)
                if result:
                    result["source"] = rule.name
                    result["timestamp"] = time.time()
                    alerts.append(result)
            except Exception as e:
                logger.error(f"Rule '{rule.name}' error: {e}")
        return alerts

    def process_events(self, events: list[Event]) -> list[dict]:
        all_alerts = []
        for event in events:
            alerts = self.evaluate_event(event)
            for alert in alerts:
                self._alert_count += 1
                priority = PRIORITY_CRITICAL if alert["severity"] == "critical" else PRIORITY_HIGH
                self._queue.put_event(EVENT_ALERT, alert, priority=priority)
                all_alerts.append(alert)
                logger.warning(
                    f"ALERT [{alert['severity'].upper()}]: {alert['message']}",
                    extra={"data": alert}
                )
        return all_alerts

    @property
    def alert_count(self) -> int:
        return self._alert_count

    @property
    def rule_count(self) -> int:
        return len(self._rules)
