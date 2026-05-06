"""
Shadow Guardian — Threat Detector

Detects potential keyloggers, RATs, and malware by analyzing
process behavior patterns.
"""

import threading
import time
from typing import Optional
from collections import defaultdict

from utils.logger import get_logger
from core.event_queue import EventQueue, EVENT_ALERT, PRIORITY_CRITICAL, PRIORITY_HIGH

logger = get_logger("agent.threat_detector")

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

KNOWN_RAT_NAMES = {
    "darkcomet", "njrat", "xtreme", "quasar", "poisonivy",
    "blackshades", "cybergate", "netbus", "subseven", "havex",
    "orcus", "luminosity", "nanocore", "asyncrat", "remcos",
    "warzone", "revenge", "imminent", "babylon",
}

SUSPICIOUS_PATH_PATTERNS = [
    "\\appdata\\local\\temp\\",
    "\\appdata\\roaming\\",
    "\\users\\public\\",
    "\\$recycle.bin\\",
    "\\windows\\temp\\",
]

LEGITIMATE_PATHS = [
    "\\windows\\system32\\",
    "\\windows\\syswow64\\",
    "\\program files\\",
    "\\program files (x86)\\",
]

KNOWN_NETWORK_PROCS = {
    "chrome.exe", "firefox.exe", "msedge.exe", "svchost.exe",
    "searchhost.exe", "teams.exe", "slack.exe", "discord.exe",
    "code.exe", "spotify.exe", "onedrive.exe", "dropbox.exe",
    "python.exe", "pythonw.exe", "node.exe",
}


class ThreatDetector:
    """Scans for potential malware, keyloggers, and RATs."""

    def __init__(self, event_queue: Optional[EventQueue]):
        self._queue = event_queue
        self._running = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._scan_interval = 60
        self._known_alerts: set[str] = set()

    def start(self) -> None:
        if not HAS_PSUTIL:
            logger.error("psutil required for threat detection")
            return
        self._running.set()
        self._thread = threading.Thread(target=self._scan_loop, name="ThreatDetector", daemon=True)
        self._thread.start()
        logger.info("Threat detector started")

    def stop(self) -> None:
        self._running.clear()
        if self._thread:
            self._thread.join(timeout=5.0)
        logger.info("Threat detector stopped")

    def _scan_loop(self) -> None:
        time.sleep(10)
        while self._running.is_set():
            try:
                self._scan_known_rats()
                self._scan_suspicious_paths()
                self._scan_hidden_network_processes()
                self._scan_suspicious_behavior()
            except Exception as e:
                logger.error(f"Threat scan error: {e}")
            deadline = time.time() + self._scan_interval
            while time.time() < deadline and self._running.is_set():
                time.sleep(1.0)

    def _scan_known_rats(self) -> None:
        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                name = (proc.info["name"] or "").lower()
                name_no_ext = name.replace(".exe", "")
                for rat_name in KNOWN_RAT_NAMES:
                    if rat_name in name_no_ext:
                        alert_key = f"rat:{proc.info['pid']}:{name}"
                        if alert_key not in self._known_alerts:
                            self._known_alerts.add(alert_key)
                            self._emit_alert("known_rat_detected", "critical",
                                f"Known RAT/malware detected: {name} (PID: {proc.info['pid']})",
                                {"pid": proc.info["pid"], "process_name": name,
                                 "exe_path": proc.info.get("exe", ""), "pattern": rat_name})
                        break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def _scan_suspicious_paths(self) -> None:
        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                exe = (proc.info.get("exe") or "").lower()
                name = (proc.info.get("name") or "").lower()
                if not exe or any(legit in exe for legit in LEGITIMATE_PATHS):
                    continue
                for pattern in SUSPICIOUS_PATH_PATTERNS:
                    if pattern in exe and name.endswith((".exe", ".scr", ".com", ".pif")):
                        alert_key = f"path:{exe}"
                        if alert_key not in self._known_alerts:
                            self._known_alerts.add(alert_key)
                            self._emit_alert("suspicious_path", "warning",
                                f"Process from suspicious location: {name}",
                                {"pid": proc.info["pid"], "process_name": name,
                                 "exe_path": exe, "pattern": pattern})
                        break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def _scan_hidden_network_processes(self) -> None:
        import ctypes, ctypes.wintypes
        user32 = ctypes.windll.user32
        try:
            connections = psutil.net_connections(kind="inet")
            network_pids: dict[int, int] = defaultdict(int)
            for conn in connections:
                if conn.pid and conn.status == "ESTABLISHED":
                    network_pids[conn.pid] += 1
            for pid, conn_count in network_pids.items():
                if conn_count < 3:
                    continue
                try:
                    proc = psutil.Process(pid)
                    name = proc.name().lower()
                    if name in KNOWN_NETWORK_PROCS:
                        continue
                    has_window = [False]
                    def _check_window(hwnd, _):
                        wnd_pid = ctypes.wintypes.DWORD()
                        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(wnd_pid))
                        if wnd_pid.value == pid and user32.IsWindowVisible(hwnd):
                            has_window[0] = True
                            return False
                        return True
                    WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.wintypes.HWND, ctypes.wintypes.LPARAM)
                    user32.EnumWindows(WNDENUMPROC(_check_window), 0)
                    if not has_window[0]:
                        alert_key = f"hidden_net:{pid}:{name}"
                        if alert_key not in self._known_alerts:
                            self._known_alerts.add(alert_key)
                            self._emit_alert("hidden_network_process", "warning",
                                f"Hidden process with {conn_count} connections: {name}",
                                {"pid": pid, "process_name": name, "connection_count": conn_count,
                                 "exe_path": proc.exe() if proc.is_running() else ""})
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            logger.debug(f"Hidden process scan error: {e}")

    def _scan_suspicious_behavior(self) -> None:
        for proc in psutil.process_iter(["pid", "name", "exe", "create_time"]):
            try:
                name = (proc.info.get("name") or "").lower()
                exe = (proc.info.get("exe") or "").lower()
                create_time = proc.info.get("create_time", 0)
                if time.time() - create_time < 30:
                    try:
                        conns = proc.net_connections(kind="inet")
                        established = [c for c in conns if c.status == "ESTABLISHED"]
                        if len(established) >= 2:
                            skip = {"setup", "install", "update", "patch", "chrome", "edge", "firefox"}
                            if not any(s in name for s in skip):
                                alert_key = f"fast_net:{proc.info['pid']}:{name}"
                                if alert_key not in self._known_alerts:
                                    self._known_alerts.add(alert_key)
                                    self._emit_alert("rapid_network_after_launch", "warning",
                                        f"New process immediately established network: {name}",
                                        {"pid": proc.info["pid"], "process_name": name, "exe_path": exe,
                                         "connections": len(established)})
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def _emit_alert(self, alert_type: str, severity: str, message: str, data: dict) -> None:
        if not self._queue:
            return
        priority = PRIORITY_CRITICAL if severity == "critical" else PRIORITY_HIGH
        self._queue.put_event(EVENT_ALERT, {
            "alert_type": alert_type, "severity": severity, "message": message,
            "data": data, "source": "threat_detector", "timestamp": time.time(),
        }, priority=priority)
        logger.warning(f"THREAT [{severity.upper()}]: {message}", extra={"data": data})

    def clear_alert_cache(self) -> None:
        self._known_alerts.clear()
