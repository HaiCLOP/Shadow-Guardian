"""
Shadow Guardian — Core Agent

Main orchestrator that starts all sensors, manages the DB writer,
IPC server, stealth features, and Windows message pump.
"""

import ctypes
import ctypes.wintypes
import os
import sys
import time
import json
import uuid
import signal
import threading
from pathlib import Path
from typing import Optional

from utils.logger import get_logger, initialize_logging
from utils.config import get_config
from utils.single_instance import SingleInstance
from db.database import get_database
from core.event_queue import (
    EventQueue, EVENT_APP, EVENT_SESSION, EVENT_ALERT,
    EVENT_PROCESS, EVENT_NETWORK, EVENT_BROWSER,
    EVENT_APP_LAUNCH, EVENT_USB, EVENT_CLIPBOARD, EVENT_FILE,
)
from core.ipc import IPCServer
from core.webjail import WebJail
from agent.window_tracker import WindowTracker
from agent.session_tracker import SessionTracker
from agent.process_monitor import ProcessMonitor
from agent.alert_engine import AlertEngine
from agent.browser_history import BrowserHistoryTracker
from agent.usb_monitor import USBMonitor
from agent.clipboard_monitor import ClipboardMonitor
from agent.file_monitor import FileMonitor
from agent.threat_detector import ThreatDetector
from agent.screen_capture import ScreenCapture

logger = get_logger("agent.core")

user32 = ctypes.windll.user32


class ShadowGuardianAgent:
    """
    Main agent process orchestrator.

    Startup sequence:
        1. Apply stealth (process name masquerade)
        2. Load config
        3. Initialize DB (WAL mode)
        4. Start event queue + DB writer
        5. Start IPC server
        6. Start all sensors
        7. Start alert engine + threat detector
        8. Lazy-start sync worker
        9. Write port breadcrumb file
        10. Enter Windows message pump
    """

    def __init__(self):
        self._config = get_config()
        initialize_logging(self._config.get("log_level", "production"))

        self._event_queue = EventQueue()
        self._db = get_database()
        self._shutdown = threading.Event()
        self._start_time = time.time()
        self._last_cleanup_time = 0.0

        # Components (lazy init)
        self._window_tracker: Optional[WindowTracker] = None
        self._session_tracker: Optional[SessionTracker] = None
        self._process_monitor: Optional[ProcessMonitor] = None
        self._alert_engine: Optional[AlertEngine] = None
        self._ipc_server: Optional[IPCServer] = None
        self._webjail: Optional[WebJail] = None
        self._browser_history: Optional[BrowserHistoryTracker] = None
        self._usb_monitor: Optional[USBMonitor] = None
        self._clipboard_monitor: Optional[ClipboardMonitor] = None
        self._file_monitor: Optional[FileMonitor] = None
        self._threat_detector: Optional[ThreatDetector] = None
        self._screen_capture: Optional[ScreenCapture] = None
        self._db_writer_thread: Optional[threading.Thread] = None
        self._sync_worker = None

        # Stealth
        self._breadcrumb_file: Optional[Path] = None

        # PID file for watchdog
        from utils.paths import get_app_data_dir
        self._pid_file = get_app_data_dir() / "agent.pid"
        self._data_dir = get_app_data_dir()
        self._instance_guard = SingleInstance("ShadowGuardianAgent")

    def start(self) -> None:
        """Start all agent components and enter the message pump."""
        logger.info("=" * 60)
        logger.info("Shadow Guardian Agent starting...")
        logger.info("=" * 60)

        try:
            if not self._instance_guard.acquire():
                raise RuntimeError("Shadow Guardian agent is already running")

            # Apply stealth features
            self._apply_stealth()

            # Write PID file
            self._write_pid_file()

            # Start DB writer thread
            self._start_db_writer()
            self._maybe_cleanup_db(force=True)

            # Start IPC server
            self._ipc_server = IPCServer(self._handle_ipc_command)
            self._ipc_server.start()

            # Initialize WebJail
            self._webjail = WebJail(cleanup_on_init=False)
            if self._webjail.is_admin:
                self._restore_webjail_state()
                # Start tamper watcher if WebJail is active
                if self._webjail.is_enabled:
                    self._webjail.start_tamper_watch()

            # Start core sensors
            self._window_tracker = WindowTracker(self._event_queue)
            self._window_tracker.start()

            self._session_tracker = SessionTracker(self._event_queue)
            self._session_tracker.start()

            self._process_monitor = ProcessMonitor(self._event_queue)
            self._process_monitor.start()

            # Start new security sensors
            if self._config.get("feature_flags.browser_history", True):
                self._browser_history = BrowserHistoryTracker(self._event_queue)
                self._browser_history.start()

            if self._config.get("feature_flags.usb_monitoring", True):
                self._usb_monitor = USBMonitor(self._event_queue)
                self._usb_monitor.start()

            if self._config.get("feature_flags.clipboard_monitoring", True):
                self._clipboard_monitor = ClipboardMonitor(self._event_queue)
                self._clipboard_monitor.start()

            if self._config.get("feature_flags.file_monitoring", True):
                self._file_monitor = FileMonitor(self._event_queue)
                self._file_monitor.start()

            if self._config.get("feature_flags.threat_detection", True):
                self._threat_detector = ThreatDetector(self._event_queue)
                self._threat_detector.start()

            if self._config.get("feature_flags.screen_capture", True):
                self._screen_capture = ScreenCapture()

            # Start alert engine
            self._alert_engine = AlertEngine(self._event_queue)

            # Lazy start cloud sync
            if self._is_cloud_sync_enabled():
                self._start_sync_worker()

            # Write port breadcrumb file (stealth feature)
            self._write_breadcrumb()

            # Register config change callback
            self._config.register_callback(self._on_config_change)
            self._config.start_watcher()

            # Install console ctrl handler for graceful shutdown
            self._install_ctrl_handler()

            logger.info("All components started successfully")
            logger.info(f"Agent PID: {os.getpid()}")

            # Enter Windows message pump (blocks until shutdown)
            self._message_pump()

        except Exception as e:
            logger.critical(f"Agent startup failed: {e}", exc_info=True)
            self.stop()
            raise

    def stop(self) -> None:
        """Gracefully shutdown all components and clean traces."""
        logger.info("Agent shutting down...")
        self._shutdown.set()

        # Stop all sensors
        for sensor in [
            self._window_tracker, self._session_tracker,
            self._process_monitor, self._browser_history,
            self._usb_monitor, self._clipboard_monitor,
            self._file_monitor, self._threat_detector,
        ]:
            if sensor:
                try:
                    sensor.stop()
                except Exception:
                    pass

        # Stop IPC
        if self._ipc_server:
            self._ipc_server.stop()

        if self._sync_worker:
            self._sync_worker.stop()

        # Stop config watcher
        self._config.stop_watcher()

        if self._db_writer_thread and self._db_writer_thread.is_alive():
            self._db_writer_thread.join(timeout=5.0)

        # Flush remaining events
        self._flush_events_to_db()

        # WebJail: Keep hosts entries if persisted as enabled (survive reboot).
        # Only clean up if the user explicitly disabled WebJail.
        if self._webjail and self._webjail.is_enabled:
            try:
                persisted = self._db.get_setting("webjail_enabled", "0")
                if persisted != "1":
                    # Not persisted — clean up on exit
                    self._webjail.disable()
                else:
                    logger.info("WebJail staying active (persisted) — hosts entries kept")
            except Exception:
                pass  # DB might be closed; keep entries to be safe

        # Close DB
        self._db.close()

        # Auto-clean traces (stealth)
        self._cleanup_traces()

        self._instance_guard.release()
        logger.info("Agent shutdown complete")

    # ─── Stealth Features ─────────────────────────────────────────────

    def _apply_stealth(self) -> None:
        """Apply stealth features — masquerade process name and hide window."""
        try:
            stealth_cfg = self._config.get("stealth", {})
            proc_desc = stealth_cfg.get("process_description", "Windows Service Helper")

            # Set console title to look like a system process
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleTitleW(proc_desc)

            # Minimize visible memory footprint
            try:
                kernel32.SetProcessWorkingSetSize(
                    kernel32.GetCurrentProcess(),
                    ctypes.c_size_t(-1),
                    ctypes.c_size_t(-1),
                )
            except Exception:
                pass

            logger.debug("Stealth features applied")
        except Exception as e:
            logger.debug(f"Stealth apply error (non-fatal): {e}")

    def _write_breadcrumb(self) -> None:
        """Write a random-named txt file with the current API port (stealth feature)."""
        try:
            random_name = f"sg_port_{uuid.uuid4().hex[:8]}.txt"
            self._breadcrumb_file = self._data_dir / random_name

            # Read port from API port file
            port_file = self._data_dir / "api_port.txt"
            if port_file.exists():
                port = port_file.read_text().strip()
                self._breadcrumb_file.write_text(
                    f"port={port}\nsession={uuid.uuid4().hex}\n",
                    encoding="utf-8",
                )
                logger.debug(f"Breadcrumb written: {random_name}")
        except Exception as e:
            logger.debug(f"Breadcrumb write error: {e}")

    def _cleanup_traces(self) -> None:
        """Remove all trace files on shutdown (stealth feature)."""
        try:
            # Remove PID file
            self._pid_file.unlink(missing_ok=True)

            # Remove breadcrumb file
            if self._breadcrumb_file and self._breadcrumb_file.exists():
                self._breadcrumb_file.unlink(missing_ok=True)

            # Remove all breadcrumb files (catch orphans from previous sessions)
            for f in self._data_dir.glob("sg_port_*.txt"):
                try:
                    f.unlink()
                except Exception:
                    pass

            logger.debug("Traces cleaned")
        except Exception:
            pass

    def _write_pid_file(self) -> None:
        """Write current PID to file for watchdog monitoring."""
        try:
            self._pid_file.write_text(str(os.getpid()))
        except Exception as e:
            logger.error(f"Failed to write PID file: {e}")

    def _install_ctrl_handler(self) -> None:
        """Install console control handler for graceful CTRL+C shutdown."""
        try:
            kernel32 = ctypes.windll.kernel32
            HANDLER_ROUTINE = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_ulong)

            def handler(ctrl_type):
                if ctrl_type in (0, 1, 2, 5, 6):
                    self.stop()
                    return True
                return False

            self._ctrl_handler = HANDLER_ROUTINE(handler)
            kernel32.SetConsoleCtrlHandler(self._ctrl_handler, True)
        except Exception as e:
            logger.warning(f"Failed to install ctrl handler: {e}")

    def _message_pump(self) -> None:
        """Windows message pump — required for event hooks to fire."""
        msg = ctypes.wintypes.MSG()
        while not self._shutdown.is_set():
            result = user32.PeekMessageW(
                ctypes.byref(msg), None, 0, 0, 1  # PM_REMOVE
            )
            if result:
                user32.TranslateMessage(ctypes.byref(msg))
                user32.DispatchMessageW(ctypes.byref(msg))
                if msg.message == 0x0012:  # WM_QUIT
                    break
            else:
                time.sleep(0.01)

    # ─── DB Writer ────────────────────────────────────────────────────

    def _start_db_writer(self) -> None:
        self._db_writer_thread = threading.Thread(
            target=self._db_writer_loop, name="DBWriter", daemon=True,
        )
        self._db_writer_thread.start()

    def _db_writer_loop(self) -> None:
        try:
            batch_interval = self._config.get("batch_write_interval", 3)
            while not self._shutdown.is_set():
                has_events = self._event_queue.wait_for_events(timeout=batch_interval)
                if self._event_queue.has_critical():
                    self._flush_events_to_db()
                elif has_events:
                    self._flush_events_to_db()
        except Exception as e:
            logger.critical(f"DBWriter thread crashed: {e}", exc_info=True)

    def _flush_events_to_db(self) -> None:
        """Drain the event queue and write to the database in batches."""
        events = self._event_queue.drain(max_count=500)
        if not events:
            return

        # Run events through alert engine first
        if self._alert_engine:
            non_alert_events = [e for e in events if e.type != EVENT_ALERT]
            self._alert_engine.process_events(non_alert_events)
            alert_events = self._event_queue.drain(max_count=100)
            events.extend(alert_events)

        # Capture screenshots on critical alerts
        if self._screen_capture:
            for event in events:
                if event.type == EVENT_ALERT and event.data.get("severity") == "critical":
                    try:
                        filepath = self._screen_capture.capture(
                            reason=event.data.get("message", "critical alert")
                        )
                        if filepath:
                            event.data["screenshot_path"] = filepath
                    except Exception:
                        pass

        # Categorize events by table
        app_rows, session_rows, alert_rows = [], [], []
        browser_rows, usb_rows, clipboard_rows, file_rows = [], [], [], []

        for event in events:
            if event.type == EVENT_APP:
                app_rows.append({
                    "timestamp": event.data.get("timestamp", event.timestamp),
                    "pid": event.data.get("pid", 0),
                    "process_name": event.data.get("process_name", ""),
                    "window_title": event.data.get("window_title", ""),
                    "duration": event.data.get("duration", 0),
                    "exe_path": event.data.get("exe_path", ""),
                    "is_foreground": event.data.get("is_foreground", 1),
                })
            elif event.type == EVENT_SESSION:
                session_rows.append({
                    "timestamp": event.data.get("timestamp", event.timestamp),
                    "event_type": event.data.get("event_type", ""),
                    "session_id": event.data.get("session_id", 0),
                    "username": event.data.get("username", ""),
                })
            elif event.type == EVENT_ALERT:
                alert_rows.append({
                    "timestamp": event.data.get("timestamp", event.timestamp),
                    "alert_type": event.data.get("alert_type", ""),
                    "severity": event.data.get("severity", "info"),
                    "source": event.data.get("source", ""),
                    "message": event.data.get("message", ""),
                    "data": json.dumps(event.data.get("data", {})),
                })
            elif event.type == EVENT_BROWSER:
                browser_rows.append({
                    "timestamp": event.data.get("timestamp", event.timestamp),
                    "url": event.data.get("url", ""),
                    "title": event.data.get("title", ""),
                    "browser": event.data.get("browser", ""),
                    "visit_time": event.data.get("visit_time", 0),
                })
            elif event.type == EVENT_USB:
                usb_rows.append({
                    "timestamp": event.data.get("timestamp", event.timestamp),
                    "device_name": event.data.get("device_name", ""),
                    "device_id": event.data.get("device_id", ""),
                    "action": event.data.get("action", ""),
                })
            elif event.type == EVENT_CLIPBOARD:
                clipboard_rows.append({
                    "timestamp": event.data.get("timestamp", event.timestamp),
                    "content_type": event.data.get("content_type", ""),
                    "content_preview": event.data.get("content_preview", ""),
                    "source_app": event.data.get("source_app", ""),
                })
            elif event.type == EVENT_FILE:
                file_rows.append({
                    "timestamp": event.data.get("timestamp", event.timestamp),
                    "file_path": event.data.get("file_path", ""),
                    "action": event.data.get("action", ""),
                    "process_name": event.data.get("process_name", ""),
                })

        # Batch write
        try:
            queue_sync = self._is_cloud_sync_enabled()
            for table, rows in [
                ("apps", app_rows), ("sessions", session_rows),
                ("alerts", alert_rows), ("browser_history", browser_rows),
                ("usb_events", usb_rows), ("clipboard_log", clipboard_rows),
                ("file_events", file_rows),
            ]:
                if rows:
                    self._db.insert_batch(table, rows, queue_sync=queue_sync)

            total = sum(len(r) for r in [
                app_rows, session_rows, alert_rows,
                browser_rows, usb_rows, clipboard_rows, file_rows,
            ])
            if total > 0:
                logger.debug(f"Flushed {total} events to DB")
            self._maybe_cleanup_db()
        except Exception as e:
            logger.error(f"DB batch write failed: {e}")

    # ─── IPC Command Handler ──────────────────────────────────────────

    def _handle_ipc_command(self, request: dict) -> dict:
        """Handle incoming IPC commands from the API server."""
        command = request.get("command", "")

        try:
            if command == "GET_APPS":
                limit = request.get("limit", 50)
                since = request.get("since")
                apps = self._db.get_apps(limit=limit, since=since)
                return {"status": "ok", "data": apps}

            elif command == "GET_SESSIONS":
                limit = request.get("limit", 50)
                since = request.get("since")
                sessions = self._db.get_sessions(limit=limit, since=since)
                return {"status": "ok", "data": sessions}

            elif command == "GET_ALERTS":
                limit = request.get("limit", 50)
                severity = request.get("severity")
                alerts = self._db.get_alerts(limit=limit, severity=severity)
                return {"status": "ok", "data": alerts}

            elif command == "GET_BROWSER_HISTORY":
                limit = request.get("limit", 50)
                since = request.get("since")
                history = self._db.get_browser_history(limit=limit, since=since)
                return {"status": "ok", "data": history}

            elif command == "GET_USB_EVENTS":
                limit = request.get("limit", 50)
                since = request.get("since")
                events = self._db.get_usb_events(limit=limit, since=since)
                return {"status": "ok", "data": events}

            elif command == "GET_CLIPBOARD_LOG":
                limit = request.get("limit", 50)
                since = request.get("since")
                log = self._db.get_clipboard_log(limit=limit, since=since)
                return {"status": "ok", "data": log}

            elif command == "GET_FILE_EVENTS":
                limit = request.get("limit", 50)
                since = request.get("since")
                events = self._db.get_file_events(limit=limit, since=since)
                return {"status": "ok", "data": events}

            elif command == "GET_ALL_WINDOWS":
                if self._window_tracker:
                    windows = self._window_tracker.get_all_open_windows()
                    return {"status": "ok", "data": windows}
                return {"status": "ok", "data": []}

            elif command == "WEBJAIL_TOGGLE":
                enabled = request.get("enabled", False)
                domains = request.get("domains", [])
                return self._handle_webjail(enabled, domains)

            elif command == "STATUS":
                return self._get_status()

            elif command == "GET_SETTINGS":
                key = request.get("key", "")
                value = self._db.get_setting(key)
                return {"status": "ok", "data": {"key": key, "value": value}}

            elif command == "SET_SETTINGS":
                key = request.get("key", "")
                value = request.get("value", "")
                self._db.set_setting(key, value)
                if key in {"cloud_sync_enabled", "supabase_url", "supabase_key", "encryption_passphrase"}:
                    self._restart_sync_worker()
                return {"status": "ok"}

            elif command == "ACK_ALERT":
                alert_id = request.get("alert_id", 0)
                success = self._db.acknowledge_alert(alert_id)
                return {"status": "ok" if success else "not_found"}

            elif command == "SHUTDOWN":
                threading.Thread(target=self.stop, daemon=True).start()
                return {"status": "ok", "message": "Shutdown initiated"}

            else:
                return {"status": "error", "error": f"Unknown command: {command}"}

        except Exception as e:
            logger.error(f"IPC command error: {e}")
            return {"status": "error", "error": str(e)}

    def _handle_webjail(self, enabled: bool, domains: list) -> dict:
        if not self._webjail:
            self._webjail = WebJail(cleanup_on_init=False)
        if not self._webjail.is_admin:
            return {"status": "error", "error": "Admin privileges required"}
        if enabled:
            if not domains:
                domains = WebJail.get_default_blocklist()
            success = self._webjail.apply_rules(domains)
        else:
            success = self._webjail.disable()

        # Persist state to DB so it survives restarts
        if success:
            try:
                self._db.set_setting("webjail_enabled", "1" if enabled else "0")
                if enabled and domains:
                    self._db.set_setting("webjail_domains", json.dumps(domains))
            except Exception as e:
                logger.warning(f"Failed to persist WebJail state: {e}")

            # Start/stop tamper protection
            if enabled:
                self._webjail.start_tamper_watch()
            else:
                self._webjail.stop_tamper_watch()

        return {
            "status": "ok" if success else "error",
            "enabled": self._webjail.is_enabled,
            "blocked_domains": self._webjail.blocked_domains,
        }

    def _restore_webjail_state(self) -> None:
        """Restore WebJail state from DB settings on startup."""
        try:
            enabled = self._db.get_setting("webjail_enabled", "")
            if enabled == "1":
                # Restore persisted domains
                domains_json = self._db.get_setting("webjail_domains", "")
                if domains_json:
                    try:
                        domains = json.loads(domains_json)
                    except (json.JSONDecodeError, TypeError):
                        domains = []
                if not domains:
                    domains = self._config.get("webjail_domains", [])
                if not domains:
                    domains = WebJail.get_default_blocklist()
                self._webjail.apply_rules(domains)
                logger.info(f"WebJail restored from saved state: {len(domains)} domains")
            elif self._config.get("feature_flags.webjail_enabled", False):
                # Fallback: config.json says enabled but no DB state yet
                domains = self._config.get("webjail_domains", [])
                if not domains:
                    domains = WebJail.get_default_blocklist()
                self._webjail.apply_rules(domains)
                logger.info(f"WebJail enabled from config: {len(domains)} domains")
            else:
                # WebJail is disabled — clean any stale entries from prior crash
                self._webjail.cleanup_stale()
        except Exception as e:
            logger.error(f"Failed to restore WebJail state: {e}")

    def _get_status(self) -> dict:
        import psutil
        proc = psutil.Process(os.getpid())
        return {
            "status": "ok",
            "uptime": round(time.time() - self._start_time, 1),
            "pid": os.getpid(),
            "cpu_percent": psutil.cpu_percent(interval=0.1),
            "memory_mb": round(proc.memory_info().rss / (1024 * 1024), 2),
            "event_queue": self._event_queue.stats,
            "db_stats": self._db.get_stats(),
            "sensors": {
                "window_tracker": bool(self._window_tracker),
                "session_tracker": self._session_tracker.is_active if self._session_tracker else False,
                "process_monitor": self._process_monitor.known_process_count if self._process_monitor else 0,
                "alert_engine_rules": self._alert_engine.rule_count if self._alert_engine else 0,
                "browser_history": bool(self._browser_history),
                "usb_monitor": bool(self._usb_monitor),
                "clipboard_monitor": bool(self._clipboard_monitor),
                "file_monitor": bool(self._file_monitor),
                "threat_detector": bool(self._threat_detector),
                "screen_capture": bool(self._screen_capture),
            },
            "webjail": {
                "enabled": self._webjail.is_enabled if self._webjail else False,
                "is_admin": self._webjail.is_admin if self._webjail else False,
                "blocked_count": len(self._webjail.blocked_domains) if self._webjail else 0,
                "blocked_domains": self._webjail.blocked_domains if self._webjail else [],
            },
        }

    # ─── Config Hot Reload ────────────────────────────────────────────

    def _on_config_change(self, new_config: dict) -> None:
        logger.info("Config changed — applying updates")
        log_level = new_config.get("log_level", "production")
        initialize_logging(log_level)
        if self._webjail and new_config.get("feature_flags", {}).get("webjail_enabled"):
            domains = new_config.get("webjail_domains", [])
            self._webjail.apply_rules(domains)

    # ─── Cloud Sync ──────────────────────────────────────────────────

    def _start_sync_worker(self) -> None:
        if self._sync_worker and self._sync_worker.stats.get("running"):
            return
        try:
            from sync.cloud_sync import CloudSyncWorker
            worker = CloudSyncWorker(self._db)
            worker.start()
            self._sync_worker = worker if worker.stats.get("running") else None
            if self._sync_worker:
                logger.info("Cloud sync worker started")
        except Exception as e:
            logger.warning(f"Cloud sync unavailable: {e}")

    def _restart_sync_worker(self) -> None:
        if self._sync_worker:
            self._sync_worker.stop()
            self._sync_worker = None
        if self._is_cloud_sync_enabled():
            self._start_sync_worker()

    def _is_cloud_sync_enabled(self) -> bool:
        setting = self._db.get_setting("cloud_sync_enabled", "").strip().lower()
        if setting:
            return setting in {"1", "true", "yes", "on"}
        return self._config.get("feature_flags.cloud_sync_enabled", False)

    def _maybe_cleanup_db(self, force: bool = False) -> None:
        now = time.time()
        if not force and now - self._last_cleanup_time < 3600:
            return
        self._last_cleanup_time = now
        retention_days = int(self._config.get("db_retention_days", 30))
        if retention_days <= 0:
            return
        try:
            result = self._db.cleanup_old_records(retention_days)
            if result.get("deleted", 0):
                logger.info(f"DB cleanup deleted {result['deleted']} rows")
        except Exception as e:
            logger.warning(f"DB cleanup failed: {e}")
