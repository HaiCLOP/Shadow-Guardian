"""
Shadow Guardian — SQLite Database Layer

WAL-mode SQLite with batch writes, proper indexing, thread-local
connections, and concurrent write safety via a single-writer pattern.
"""

import sqlite3
import threading
import time
import json
import os
from pathlib import Path
from typing import Any, Optional
from collections import deque

from utils.logger import get_logger
from utils.config import get_config

logger = get_logger("db.database")


# ─── Schema ─────────────────────────────────────────────────────────────────

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS apps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    pid INTEGER,
    process_name TEXT,
    window_title TEXT,
    duration REAL DEFAULT 0,
    exe_path TEXT,
    is_foreground INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    event_type TEXT NOT NULL,
    session_id INTEGER,
    username TEXT
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    alert_type TEXT NOT NULL,
    severity TEXT DEFAULT 'info',
    source TEXT,
    message TEXT,
    data TEXT,
    acknowledged INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS sync_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    table_name TEXT NOT NULL,
    record_id INTEGER NOT NULL,
    synced INTEGER DEFAULT 0,
    retry_count INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS browser_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    url TEXT NOT NULL,
    title TEXT,
    browser TEXT,
    visit_time REAL
);

CREATE TABLE IF NOT EXISTS app_launches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    process_name TEXT,
    exe_path TEXT,
    was_admin INTEGER DEFAULT 0,
    duration REAL DEFAULT 0,
    username TEXT
);

CREATE TABLE IF NOT EXISTS usb_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    device_name TEXT,
    device_id TEXT,
    action TEXT
);

CREATE TABLE IF NOT EXISTS clipboard_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    content_type TEXT,
    content_preview TEXT,
    source_app TEXT
);

CREATE TABLE IF NOT EXISTS file_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    file_path TEXT,
    action TEXT,
    process_name TEXT
);

CREATE TABLE IF NOT EXISTS screenshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    alert_id INTEGER,
    file_path TEXT,
    size_bytes INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_apps_timestamp ON apps(timestamp);
CREATE INDEX IF NOT EXISTS idx_apps_process ON apps(process_name);
CREATE INDEX IF NOT EXISTS idx_sessions_timestamp ON sessions(timestamp);
CREATE INDEX IF NOT EXISTS idx_sessions_type ON sessions(event_type);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts(alert_type);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_sync_queue_synced ON sync_queue(synced);
CREATE INDEX IF NOT EXISTS idx_browser_history_timestamp ON browser_history(timestamp);
CREATE INDEX IF NOT EXISTS idx_browser_history_browser ON browser_history(browser);
CREATE INDEX IF NOT EXISTS idx_app_launches_timestamp ON app_launches(timestamp);
CREATE INDEX IF NOT EXISTS idx_usb_events_timestamp ON usb_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_clipboard_log_timestamp ON clipboard_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_file_events_timestamp ON file_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_screenshots_alert ON screenshots(alert_id);
"""

CURRENT_SCHEMA_VERSION = 2

# Max lengths for text fields to prevent unbounded storage
_MAX_PROCESS_NAME_LEN = 260
_MAX_WINDOW_TITLE_LEN = 1024
_MAX_EXE_PATH_LEN = 520
_MAX_GENERIC_TEXT_LEN = 4096


class Database:
    """
    Thread-safe SQLite database with WAL mode and batch write support.
    
    Uses thread-local storage for connections to avoid SQLite threading issues.
    Write operations are serialized through a lock to prevent WAL conflicts.
    """

    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            config = get_config()
            db_path = config.get("db_path", "shadowguardian.db")

        # Resolve relative to data directory
        if not os.path.isabs(db_path):
            from utils.paths import get_app_data_dir
            db_path = str(get_app_data_dir() / db_path)

        self._db_path = db_path
        self._write_lock = threading.Lock()
        self._local = threading.local()
        self._all_connections: list[sqlite3.Connection] = []
        self._connections_lock = threading.Lock()
        self._closed = False

        # Initialize schema
        self._init_schema()
        self._apply_migrations()
        logger.info(f"Database initialized at {self._db_path}")

    def _get_connection(self) -> sqlite3.Connection:
        """Get thread-local database connection."""
        if not hasattr(self._local, "connection") or self._local.connection is None:
            conn = sqlite3.connect(
                self._db_path,
                timeout=10.0,
                check_same_thread=False,
            )
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA cache_size=-8000")  # 8MB cache
            conn.execute("PRAGMA temp_store=MEMORY")
            conn.execute("PRAGMA mmap_size=268435456")  # 256MB mmap
            conn.row_factory = sqlite3.Row
            self._local.connection = conn
            # Track for cleanup
            with self._connections_lock:
                self._all_connections.append(conn)
        return self._local.connection

    def _init_schema(self) -> None:
        """Create tables and indexes if they don't exist."""
        conn = self._get_connection()
        with self._write_lock:
            conn.executescript(SCHEMA_SQL)
            conn.commit()

    def _apply_migrations(self) -> None:
        """Apply schema migrations sequentially."""
        conn = self._get_connection()
        with self._write_lock:
            # Get current version
            try:
                row = conn.execute(
                    "SELECT MAX(version) as v FROM schema_version"
                ).fetchone()
                current = row["v"] if row and row["v"] is not None else 0
            except Exception:
                current = 0

            if current < CURRENT_SCHEMA_VERSION:
                # Mark initial schema as version 1
                if current < 1:
                    conn.execute(
                        "INSERT OR IGNORE INTO schema_version (version, applied_at) VALUES (?, ?)",
                        (1, time.time()),
                    )

                # v2: new monitoring tables (browser_history, app_launches, etc.)
                if current < 2:
                    # Tables are created via CREATE IF NOT EXISTS in SCHEMA_SQL
                    # so we just mark the migration as applied
                    conn.execute(
                        "INSERT OR IGNORE INTO schema_version (version, applied_at) VALUES (?, ?)",
                        (2, time.time()),
                    )

                conn.commit()
                logger.info(f"Schema at version {CURRENT_SCHEMA_VERSION}")

    @staticmethod
    def _sanitize_text(value: Any, max_len: int = _MAX_GENERIC_TEXT_LEN) -> Any:
        """Sanitize text values: strip null bytes and enforce max length."""
        if not isinstance(value, str):
            return value
        # Strip null bytes (can cause issues in SQLite and display)
        sanitized = value.replace("\x00", "")
        if len(sanitized) > max_len:
            sanitized = sanitized[:max_len]
        return sanitized

    # ─── Write Operations ────────────────────────────────────────────────

    def insert_app(self, timestamp: float, pid: int, process_name: str,
                   window_title: str, duration: float = 0, exe_path: str = "",
                   is_foreground: int = 1) -> int:
        """Insert a single app record. Returns the row ID."""
        conn = self._get_connection()
        with self._write_lock:
            cursor = conn.execute(
                "INSERT INTO apps (timestamp, pid, process_name, window_title, duration, exe_path, is_foreground) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (timestamp, pid, process_name, window_title, duration, exe_path, is_foreground),
            )
            conn.commit()
            return cursor.lastrowid

    def insert_session(self, timestamp: float, event_type: str,
                       session_id: int = 0, username: str = "") -> int:
        """Insert a session event. Returns the row ID."""
        conn = self._get_connection()
        with self._write_lock:
            cursor = conn.execute(
                "INSERT INTO sessions (timestamp, event_type, session_id, username) VALUES (?, ?, ?, ?)",
                (timestamp, event_type, session_id, username),
            )
            conn.commit()
            return cursor.lastrowid

    def insert_alert(self, timestamp: float, alert_type: str, severity: str = "info",
                     source: str = "", message: str = "", data: Optional[dict] = None) -> int:
        """Insert an alert. Returns the row ID."""
        conn = self._get_connection()
        data_json = json.dumps(data) if data else "{}"
        with self._write_lock:
            cursor = conn.execute(
                "INSERT INTO alerts (timestamp, alert_type, severity, source, message, data) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (timestamp, alert_type, severity, source, message, data_json),
            )
            conn.commit()
            return cursor.lastrowid

    def insert_batch(self, table: str, rows: list[dict], queue_sync: bool = False) -> int:
        """
        Batch insert rows into a table. Much faster than individual inserts.
        
        Args:
            table: Table name ('apps', 'sessions', 'alerts')
            rows: List of dicts with column names as keys
            queue_sync: Queue inserted row IDs for cloud sync in the same transaction
            
        Returns:
            Number of rows inserted
        """
        if not rows:
            return 0

        # Validate table name to prevent injection
        valid_tables = {
            "apps", "sessions", "alerts", "sync_queue",
            "browser_history", "app_launches", "usb_events",
            "clipboard_log", "file_events", "screenshots",
        }
        if table not in valid_tables:
            raise ValueError(f"Invalid table name: {table}")

        columns = list(rows[0].keys())
        placeholders = ", ".join(["?"] * len(columns))
        col_str = ", ".join(columns)
        sql = f"INSERT INTO {table} ({col_str}) VALUES ({placeholders})"

        # Apply field-specific sanitization limits
        field_limits = {
            "process_name": _MAX_PROCESS_NAME_LEN,
            "window_title": _MAX_WINDOW_TITLE_LEN,
            "exe_path": _MAX_EXE_PATH_LEN,
            "message": _MAX_GENERIC_TEXT_LEN,
            "source": _MAX_PROCESS_NAME_LEN,
            "username": _MAX_PROCESS_NAME_LEN,
            "event_type": 64,
            "alert_type": 64,
            "severity": 16,
        }

        sanitized_rows = []
        for row in rows:
            sanitized = {}
            for col in columns:
                val = row.get(col)
                limit = field_limits.get(col, _MAX_GENERIC_TEXT_LEN)
                sanitized[col] = self._sanitize_text(val, limit)
            sanitized_rows.append(sanitized)

        values = [tuple(row.get(col) for col in columns) for row in sanitized_rows]

        conn = self._get_connection()
        with self._write_lock:
            if queue_sync and table != "sync_queue":
                sync_rows = []
                now = time.time()
                for row_values in values:
                    cursor = conn.execute(sql, row_values)
                    sync_rows.append((now, table, cursor.lastrowid))
                if sync_rows:
                    conn.executemany(
                        "INSERT INTO sync_queue (timestamp, table_name, record_id) VALUES (?, ?, ?)",
                        sync_rows,
                    )
            else:
                conn.executemany(sql, values)
            conn.commit()

        logger.debug(f"Batch inserted {len(rows)} rows into {table}")
        return len(rows)

    # ─── Read Operations ─────────────────────────────────────────────────

    def get_apps(self, limit: int = 50, since: Optional[float] = None) -> list[dict]:
        """Get recent app activity records."""
        conn = self._get_connection()
        if since:
            rows = conn.execute(
                "SELECT * FROM apps WHERE timestamp > ? ORDER BY timestamp DESC LIMIT ?",
                (since, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM apps ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_record(self, table: str, record_id: int) -> Optional[dict]:
        """Get one record by table and ID."""
        valid_tables = {
            "apps", "sessions", "alerts",
            "browser_history", "app_launches", "usb_events",
            "clipboard_log", "file_events", "screenshots",
        }
        if table not in valid_tables:
            raise ValueError(f"Invalid table name: {table}")

        conn = self._get_connection()
        row = conn.execute(
            f"SELECT * FROM {table} WHERE id = ?",
            (record_id,),
        ).fetchone()
        return dict(row) if row else None

    def get_sessions(self, limit: int = 50, since: Optional[float] = None) -> list[dict]:
        """Get session events."""
        conn = self._get_connection()
        if since:
            rows = conn.execute(
                "SELECT * FROM sessions WHERE timestamp > ? ORDER BY timestamp DESC LIMIT ?",
                (since, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM sessions ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_alerts(self, limit: int = 50, severity: Optional[str] = None,
                   since: Optional[float] = None) -> list[dict]:
        """Get alerts, optionally filtered by severity."""
        conn = self._get_connection()
        conditions = []
        params = []

        if severity:
            conditions.append("severity = ?")
            params.append(severity)
        if since:
            conditions.append("timestamp > ?")
            params.append(since)

        where = "WHERE " + " AND ".join(conditions) if conditions else ""
        params.append(limit)

        rows = conn.execute(
            f"SELECT * FROM alerts {where} ORDER BY timestamp DESC LIMIT ?",
            tuple(params),
        ).fetchall()
        return [dict(row) for row in rows]

    def acknowledge_alert(self, alert_id: int) -> bool:
        """Mark an alert as acknowledged."""
        conn = self._get_connection()
        with self._write_lock:
            cursor = conn.execute(
                "UPDATE alerts SET acknowledged = 1 WHERE id = ?",
                (alert_id,),
            )
            conn.commit()
            return cursor.rowcount > 0

    def get_browser_history(self, limit: int = 50, since: Optional[float] = None) -> list[dict]:
        """Get browser history entries."""
        conn = self._get_connection()
        if since:
            rows = conn.execute(
                "SELECT * FROM browser_history WHERE timestamp > ? ORDER BY timestamp DESC LIMIT ?",
                (since, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM browser_history ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_app_launches(self, limit: int = 50, since: Optional[float] = None) -> list[dict]:
        """Get app launch history."""
        conn = self._get_connection()
        if since:
            rows = conn.execute(
                "SELECT * FROM app_launches WHERE timestamp > ? ORDER BY timestamp DESC LIMIT ?",
                (since, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM app_launches ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_usb_events(self, limit: int = 50, since: Optional[float] = None) -> list[dict]:
        """Get USB device events."""
        conn = self._get_connection()
        if since:
            rows = conn.execute(
                "SELECT * FROM usb_events WHERE timestamp > ? ORDER BY timestamp DESC LIMIT ?",
                (since, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM usb_events ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_clipboard_log(self, limit: int = 50, since: Optional[float] = None) -> list[dict]:
        """Get clipboard activity log."""
        conn = self._get_connection()
        if since:
            rows = conn.execute(
                "SELECT * FROM clipboard_log WHERE timestamp > ? ORDER BY timestamp DESC LIMIT ?",
                (since, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM clipboard_log ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_file_events(self, limit: int = 50, since: Optional[float] = None) -> list[dict]:
        """Get file monitoring events."""
        conn = self._get_connection()
        if since:
            rows = conn.execute(
                "SELECT * FROM file_events WHERE timestamp > ? ORDER BY timestamp DESC LIMIT ?",
                (since, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM file_events ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_screenshots(self, limit: int = 20, alert_id: Optional[int] = None) -> list[dict]:
        """Get screenshot records, optionally filtered by alert ID."""
        conn = self._get_connection()
        if alert_id:
            rows = conn.execute(
                "SELECT * FROM screenshots WHERE alert_id = ? ORDER BY timestamp DESC LIMIT ?",
                (alert_id, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM screenshots ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    # ─── Sync Queue ──────────────────────────────────────────────────────

    def queue_for_sync(self, table_name: str, record_id: int) -> None:
        """Add a record to the sync queue."""
        valid_tables = {
            "apps", "sessions", "alerts",
            "browser_history", "app_launches", "usb_events",
            "clipboard_log", "file_events", "screenshots",
        }
        if table_name not in valid_tables:
            raise ValueError(f"Invalid table name: {table_name}")

        conn = self._get_connection()
        with self._write_lock:
            conn.execute(
                "INSERT INTO sync_queue (timestamp, table_name, record_id) VALUES (?, ?, ?)",
                (time.time(), table_name, record_id),
            )
            conn.commit()

    def get_unsynced(self, limit: int = 100) -> list[dict]:
        """Get unsynced records from the queue."""
        conn = self._get_connection()
        rows = conn.execute(
            "SELECT * FROM sync_queue WHERE synced = 0 ORDER BY timestamp ASC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]

    def mark_synced(self, sync_ids: list[int]) -> None:
        """Mark sync queue entries as synced."""
        if not sync_ids:
            return
        conn = self._get_connection()
        placeholders = ", ".join(["?"] * len(sync_ids))
        with self._write_lock:
            conn.execute(
                f"UPDATE sync_queue SET synced = 1 WHERE id IN ({placeholders})",
                tuple(sync_ids),
            )
            conn.commit()

    # ─── Settings ─────────────────────────────────────────────────────────

    def get_setting(self, key: str, default: str = "") -> str:
        """Get a setting value."""
        conn = self._get_connection()
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else default

    def set_setting(self, key: str, value: str) -> None:
        """Set a setting value (upsert)."""
        conn = self._get_connection()
        with self._write_lock:
            conn.execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                (key, value),
            )
            conn.commit()

    # ─── Stats ────────────────────────────────────────────────────────────

    def get_stats(self) -> dict:
        """Get database statistics."""
        conn = self._get_connection()
        stats = {}
        for table in ("apps", "sessions", "alerts", "browser_history",
                      "app_launches", "usb_events", "clipboard_log",
                      "file_events", "screenshots"):
            row = conn.execute(f"SELECT COUNT(*) as count FROM {table}").fetchone()
            stats[f"{table}_count"] = row["count"]

        # DB file size
        try:
            stats["db_size_mb"] = round(os.path.getsize(self._db_path) / (1024 * 1024), 2)
        except OSError:
            stats["db_size_mb"] = 0

        return stats

    def cleanup_old_records(self, retention_days: int) -> dict:
        """Delete old local records and checkpoint WAL after cleanup."""
        if retention_days <= 0:
            return {"deleted": 0}

        cutoff = time.time() - (retention_days * 86400)
        deleted: dict[str, int] = {}
        conn = self._get_connection()

        with self._write_lock:
            for table in ("apps", "sessions", "alerts", "browser_history",
                          "app_launches", "usb_events", "clipboard_log",
                          "file_events", "screenshots"):
                cursor = conn.execute(
                    f"DELETE FROM {table} WHERE timestamp < ?",
                    (cutoff,),
                )
                deleted[table] = cursor.rowcount

            cursor = conn.execute(
                "DELETE FROM sync_queue WHERE synced = 1 AND timestamp < ?",
                (cutoff,),
            )
            deleted["sync_queue"] = cursor.rowcount
            conn.commit()

            try:
                conn.execute("PRAGMA wal_checkpoint(PASSIVE)")
            except Exception:
                pass

        deleted["deleted"] = sum(v for k, v in deleted.items() if k != "deleted")
        return deleted

    # ─── Lifecycle ────────────────────────────────────────────────────────

    def close(self) -> None:
        """Close all tracked database connections."""
        # Close the calling thread's connection
        if hasattr(self._local, "connection") and self._local.connection:
            try:
                self._local.connection.close()
            except Exception:
                pass
            self._local.connection = None

        # Close all tracked connections from other threads
        with self._connections_lock:
            for conn in self._all_connections:
                try:
                    conn.close()
                except Exception:
                    pass
            self._all_connections.clear()

        self._closed = True

    def __del__(self):
        if not self._closed:
            self.close()


# ─── Module-level singleton ──────────────────────────────────────────────────

_instance: Optional[Database] = None
_instance_lock = threading.Lock()


def get_database(db_path: Optional[str] = None) -> Database:
    """Get or create the global Database singleton."""
    global _instance
    if _instance is None:
        with _instance_lock:
            if _instance is None:
                _instance = Database(db_path)
    return _instance
