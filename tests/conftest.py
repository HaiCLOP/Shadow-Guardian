"""
Shared test fixtures for Shadow Guardian tests.
"""

import os
import sys
import json
import time
import tempfile
import shutil
import pytest
from pathlib import Path

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


@pytest.fixture
def temp_dir():
    """Provide a temporary directory that's cleaned up after the test."""
    d = tempfile.mkdtemp(prefix="sg_test_")
    yield Path(d)
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def temp_db_path(temp_dir):
    """Provide a path for a temporary SQLite database."""
    return str(temp_dir / "test.db")


@pytest.fixture
def temp_config_path(temp_dir):
    """Create a temporary config.json file with defaults."""
    config = {
        "dynamic_port": True,
        "api_port": 0,
        "feature_flags": {
            "webjail_enabled": False,
            "cloud_sync_enabled": False,
            "network_monitoring": True,
            "alert_engine": True,
        },
        "sync_interval": 300,
        "log_level": "production",
        "db_path": str(temp_dir / "test.db"),
        "db_retention_days": 30,
        "batch_write_interval": 3,
        "max_query_limit": 500,
        "auth_token_ttl_seconds": 43200,
        "max_restart_attempts": 10,
        "webjail_domains": [],
        "dashboard_auto_open": False,
        "adaptive_polling": {
            "active_interval": 5,
            "idle_interval": 30,
            "idle_threshold": 120,
        },
        "alert_rules": {
            "unknown_process_whitelist": [],
            "rapid_spawn_threshold": 10,
            "rapid_spawn_window": 60,
            "high_connection_threshold": 50,
        },
    }
    config_path = temp_dir / "config.json"
    config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")
    return str(config_path)


@pytest.fixture
def event_queue():
    """Create a fresh EventQueue instance."""
    from core.event_queue import EventQueue
    return EventQueue(maxlen=100)


@pytest.fixture
def database(temp_db_path):
    """Create a fresh Database instance with a temp DB."""
    from db.database import Database
    db = Database(db_path=temp_db_path)
    yield db
    db.close()
