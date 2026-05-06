"""
Tests for db.database — schema, CRUD, batch insert, sanitization, versioning.
"""
import time
import threading
import pytest

class TestDatabaseSchema:
    def test_tables_exist(self, database):
        conn = database._get_connection()
        cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        tables = {row["name"] for row in cursor.fetchall()}
        expected = {"apps", "sessions", "alerts", "sync_queue", "settings", "schema_version"}
        assert expected.issubset(tables)

    def test_schema_version(self, database):
        conn = database._get_connection()
        row = conn.execute("SELECT MAX(version) as v FROM schema_version").fetchone()
        assert row["v"] == 1

    def test_wal_mode(self, database):
        conn = database._get_connection()
        row = conn.execute("PRAGMA journal_mode").fetchone()
        assert row[0].upper() == "WAL"

class TestDatabaseCRUD:
    def test_insert_and_get_app(self, database):
        now = time.time()
        database.insert_app(now, 1234, "test.exe", "Test Window", 5.0, "C:\\test.exe")
        results = database.get_apps(limit=10)
        assert len(results) == 1
        assert results[0]["process_name"] == "test.exe"

    def test_insert_and_get_session(self, database):
        now = time.time()
        database.insert_session(now, "login", 1, "TestUser")
        results = database.get_sessions(limit=10)
        assert len(results) == 1
        assert results[0]["event_type"] == "login"

    def test_insert_and_get_alert(self, database):
        now = time.time()
        database.insert_alert(now, "test_alert", "warning", "test", "Test alert", "{}")
        results = database.get_alerts(limit=10)
        assert len(results) == 1
        assert results[0]["alert_type"] == "test_alert"

    def test_settings_get_set(self, database):
        database.set_setting("test_key", "test_value")
        assert database.get_setting("test_key") == "test_value"

    def test_settings_default(self, database):
        assert database.get_setting("nonexistent", "fallback") == "fallback"

    def test_acknowledge_alert(self, database):
        now = time.time()
        database.insert_alert(now, "ack_test", "info", "test", "Test", "{}")
        alerts = database.get_alerts(limit=1)
        alert_id = alerts[0]["id"]
        database.acknowledge_alert(alert_id)
        alerts = database.get_alerts(limit=1)
        assert alerts[0]["acknowledged"] == 1

class TestDatabaseBatch:
    def test_batch_insert(self, database):
        now = time.time()
        rows = [
            {"timestamp": now, "pid": i, "process_name": f"proc{i}",
             "window_title": f"Window {i}", "duration": 1.0,
             "exe_path": f"C:\\proc{i}.exe", "is_foreground": 1}
            for i in range(5)
        ]
        count = database.insert_batch("apps", rows)
        assert count == 5
        results = database.get_apps(limit=10)
        assert len(results) == 5

class TestDatabaseSanitization:
    def test_null_bytes_stripped(self, database):
        now = time.time()
        rows = [{
            "timestamp": now, "pid": 1,
            "process_name": "test\x00.exe",
            "window_title": "Hello\x00World",
            "duration": 1.0, "exe_path": "C:\\test.exe", "is_foreground": 1,
        }]
        database.insert_batch("apps", rows)
        results = database.get_apps(limit=1)
        assert "\x00" not in results[0]["process_name"]
        assert "\x00" not in results[0]["window_title"]

    def test_long_text_truncated(self, database):
        now = time.time()
        long_title = "A" * 5000
        rows = [{
            "timestamp": now, "pid": 1,
            "process_name": "test.exe",
            "window_title": long_title,
            "duration": 1.0, "exe_path": "C:\\test.exe", "is_foreground": 1,
        }]
        database.insert_batch("apps", rows)
        results = database.get_apps(limit=1)
        assert len(results[0]["window_title"]) <= 1024

class TestDatabaseConnections:
    def test_close_idempotent(self, database):
        database.close()
        database.close()

    def test_multithread_connections(self, temp_db_path):
        from db.database import Database
        db = Database(db_path=temp_db_path)
        connection_ids = []
        lock = threading.Lock()
        def worker():
            conn = db._get_connection()
            with lock:
                connection_ids.append(id(conn))
        threads = [threading.Thread(target=worker) for _ in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)
        assert len(set(connection_ids)) == 3
        db.close()
