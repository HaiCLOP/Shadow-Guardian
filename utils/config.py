"""
Shadow Guardian — Configuration Manager

Thread-safe config loader with hot-reload, integrity verification,
and schema validation. Watches config.json for changes and reloads
without requiring a process restart.
"""

import json
import hashlib
import threading
import time
import os
import copy
from pathlib import Path
from typing import Any, Optional, Callable


# Default config schema — used for validation and first-run generation
DEFAULT_CONFIG = {
    "dynamic_port": True,
    "api_port": 0,
    "feature_flags": {
        "webjail_enabled": False,
        "cloud_sync_enabled": False,
        "network_monitoring": True,
        "alert_engine": True,
        "browser_history": True,
        "usb_monitoring": True,
        "clipboard_monitoring": True,
        "file_monitoring": True,
        "threat_detection": True,
        "screen_capture": True,
    },
    "sync_interval": 300,
    # NOTE: supabase_url, supabase_key, encryption_passphrase are stored
    # encrypted in the DB settings table via utils.secrets_store.
    # They should NOT appear in this config file.
    "log_level": "production",
    "db_path": "shadowguardian.db",
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
        "late_night_start": 23,
        "late_night_end": 5,
    },
    "stealth": {
        "process_name": "WinServiceHelper.exe",
        "process_description": "Windows Service Helper",
    },
}

# Legacy keys that should not appear in config.json
_DEPRECATED_CONFIG_KEYS = {"supabase_url", "supabase_key", "encryption_passphrase"}


class ConfigIntegrityError(Exception):
    """Raised when config file integrity check fails."""
    pass


class ConfigValidationError(Exception):
    """Raised when config file schema validation fails."""
    pass


class ConfigManager:
    """
    Thread-safe configuration manager with hot-reload support.
    
    Features:
        - Loads config.json with schema validation
        - SHA-256 integrity hash tracking
        - File watcher thread for hot-reload (mtime-based)
        - Thread-safe reads via RLock
        - Change callbacks for reactive components
    """

    def __init__(self, config_path: Optional[str] = None):
        self._lock = threading.RLock()
        self._config: dict = {}
        self._config_hash: str = ""
        self._last_mtime: float = 0.0
        self._callbacks: list[Callable[[dict], None]] = []
        self._watcher_thread: Optional[threading.Thread] = None
        self._watcher_running = threading.Event()

        # Resolve config path relative to data directory
        if config_path is None:
            from utils.paths import get_app_data_dir
            self._config_path = get_app_data_dir() / "config.json"
        else:
            self._config_path = Path(config_path)

        self._ensure_config_exists()
        self._load()

    def _ensure_config_exists(self) -> None:
        """Create default config.json if it doesn't exist."""
        if not self._config_path.exists():
            self._config_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self._config_path, "w", encoding="utf-8") as f:
                json.dump(DEFAULT_CONFIG, f, indent=4)

    def _compute_hash(self, data: bytes) -> str:
        """Compute SHA-256 hash of raw config bytes."""
        return hashlib.sha256(data).hexdigest()

    def _legacy_validate_config(self, config: dict) -> dict:
        """
        Validate config against default schema.
        Fills missing keys with defaults, removes unknown top-level keys.
        """
        validated = copy.deepcopy(DEFAULT_CONFIG)

        for key, default_value in DEFAULT_CONFIG.items():
            if key in config:
                if isinstance(default_value, dict) and isinstance(config[key], dict):
                    # Merge nested dicts — keep known keys, fill missing
                    for sub_key, sub_default in default_value.items():
                        if sub_key in config[key]:
                            validated[key][sub_key] = config[key][sub_key]
                        else:
                            validated[key][sub_key] = sub_default
                else:
                    validated[key] = config[key]

        return validated

    def _coerce_value(self, value: Any, default_value: Any) -> Any:
        """Return value only when it matches the default schema shape."""
        if isinstance(default_value, bool):
            return value if isinstance(value, bool) else default_value
        if isinstance(default_value, int):
            return value if isinstance(value, int) and not isinstance(value, bool) else default_value
        if isinstance(default_value, float):
            return value if isinstance(value, (int, float)) and not isinstance(value, bool) else default_value
        if isinstance(default_value, str):
            return value if isinstance(value, str) else default_value
        if isinstance(default_value, list):
            return value if isinstance(value, list) else copy.deepcopy(default_value)
        if isinstance(default_value, dict):
            if not isinstance(value, dict):
                return copy.deepcopy(default_value)
            merged = copy.deepcopy(default_value)
            for sub_key, sub_default in default_value.items():
                if sub_key in value:
                    merged[sub_key] = self._coerce_value(value[sub_key], sub_default)
            return merged
        return value

    def _validate_config(self, config: dict) -> dict:
        """Validate config against the default schema."""
        validated = copy.deepcopy(DEFAULT_CONFIG)

        # Warn about deprecated keys
        for key in _DEPRECATED_CONFIG_KEYS:
            if key in config and config[key]:
                from utils.logger import get_logger
                _logger = get_logger("utils.config")
                _logger.warning(
                    f"Config key '{key}' found in config.json — this is insecure. "
                    f"Secrets should be stored via the dashboard setup flow (encrypted in DB)."
                )

        for key, default_value in DEFAULT_CONFIG.items():
            if key in config:
                validated[key] = self._coerce_value(config[key], default_value)

        validated["batch_write_interval"] = max(1, int(validated["batch_write_interval"]))
        validated["max_restart_attempts"] = max(1, int(validated["max_restart_attempts"]))
        validated["max_query_limit"] = min(max(1, int(validated["max_query_limit"])), 5000)
        validated["auth_token_ttl_seconds"] = max(300, int(validated["auth_token_ttl_seconds"]))
        validated["db_retention_days"] = max(0, int(validated["db_retention_days"]))

        return validated

    def _load(self) -> None:
        """Load and validate config from disk."""
        try:
            raw = self._config_path.read_bytes()
            config = json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise ConfigValidationError(f"Config file is malformed: {e}")
        except FileNotFoundError:
            self._ensure_config_exists()
            raw = self._config_path.read_bytes()
            config = json.loads(raw.decode("utf-8"))

        validated = self._validate_config(config)
        new_hash = self._compute_hash(raw)

        with self._lock:
            self._config = validated
            self._config_hash = new_hash
            self._last_mtime = self._config_path.stat().st_mtime

    def get(self, key: str, default: Any = None) -> Any:
        """Thread-safe config value retrieval. Supports dot notation for nested keys."""
        with self._lock:
            keys = key.split(".")
            value = self._config
            for k in keys:
                if isinstance(value, dict) and k in value:
                    value = value[k]
                else:
                    return default
            return copy.deepcopy(value) if isinstance(value, (dict, list)) else value

    def get_all(self) -> dict:
        """Return a deep copy of the entire config."""
        with self._lock:
            return copy.deepcopy(self._config)

    @property
    def config_hash(self) -> str:
        """Current config integrity hash."""
        with self._lock:
            return self._config_hash

    def verify_integrity(self) -> bool:
        """Verify config file hasn't been tampered with since last load."""
        try:
            raw = self._config_path.read_bytes()
            current_hash = self._compute_hash(raw)
            with self._lock:
                return current_hash == self._config_hash
        except Exception:
            return False

    def register_callback(self, callback: Callable[[dict], None]) -> None:
        """Register a callback to be invoked when config changes."""
        self._callbacks.append(callback)

    def _check_for_changes(self) -> bool:
        """Check if config file has been modified. Returns True if reloaded."""
        try:
            current_mtime = self._config_path.stat().st_mtime
            with self._lock:
                if current_mtime <= self._last_mtime:
                    return False

            # File changed — reload
            self._load()

            # Notify callbacks
            config_snapshot = self.get_all()
            for callback in self._callbacks:
                try:
                    callback(config_snapshot)
                except Exception:
                    pass  # Don't let callback errors crash the watcher

            return True
        except Exception:
            return False

    def start_watcher(self, interval: float = 2.0) -> None:
        """Start background thread that watches for config file changes."""
        if self._watcher_thread and self._watcher_thread.is_alive():
            return

        self._watcher_running.set()

        def _watch_loop():
            while self._watcher_running.is_set():
                self._check_for_changes()
                # Use event wait for clean shutdown instead of time.sleep
                self._watcher_running.wait(timeout=interval)
                if not self._watcher_running.is_set():
                    break

        self._watcher_thread = threading.Thread(
            target=_watch_loop,
            name="ConfigWatcher",
            daemon=True,
        )
        self._watcher_thread.start()

    def stop_watcher(self) -> None:
        """Stop the config file watcher thread."""
        self._watcher_running.clear()
        if self._watcher_thread:
            self._watcher_thread.join(timeout=5.0)
            self._watcher_thread = None

    def reload(self) -> None:
        """Force reload config from disk."""
        self._load()
        config_snapshot = self.get_all()
        for callback in self._callbacks:
            try:
                callback(config_snapshot)
            except Exception:
                pass


# Module-level singleton
_instance: Optional[ConfigManager] = None
_instance_lock = threading.Lock()


def get_config(config_path: Optional[str] = None) -> ConfigManager:
    """Get or create the global ConfigManager singleton."""
    global _instance
    if _instance is None:
        with _instance_lock:
            if _instance is None:
                _instance = ConfigManager(config_path)
    return _instance
