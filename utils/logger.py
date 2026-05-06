"""
Shadow Guardian — Structured Logging System

JSON-formatted structured logs with rotation, module-scoped loggers,
and debug/production mode switching via config.
"""

import json
import logging
import logging.handlers
import os
import time
import threading
from pathlib import Path
from typing import Any, Optional


class StructuredJsonFormatter(logging.Formatter):
    """
    Formats log records as single-line JSON objects.
    
    Output format:
        {"timestamp": "...", "level": "INFO", "module": "agent.core", "message": "...", "data": {...}}
    """

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S.") + f"{int(record.msecs):03d}Z",
            "level": record.levelname,
            "module": record.name,
            "message": record.getMessage(),
        }

        # Attach extra structured data if present
        if hasattr(record, "data") and record.data:
            log_entry["data"] = record.data

        # Attach exception info if present
        if record.exc_info and record.exc_info[0] is not None:
            log_entry["exception"] = self.formatException(record.exc_info)

        try:
            return json.dumps(log_entry, default=str, ensure_ascii=False)
        except (TypeError, ValueError):
            # Fallback for non-serializable data
            log_entry.pop("data", None)
            return json.dumps(log_entry, default=str, ensure_ascii=False)


class StructuredLogger(logging.Logger):
    """
    Extended logger that supports structured data fields.
    
    Usage:
        logger = get_logger("agent.window_tracker")
        logger.info("Window changed", extra={"data": {"pid": 1234, "title": "Notepad"}})
    """

    def _log_with_data(self, level: int, msg: str, data: Optional[dict] = None,
                       exc_info: Any = None, **kwargs) -> None:
        """Internal helper to attach structured data to log records."""
        extra = kwargs.pop("extra", {})
        if data is not None:
            extra["data"] = data
        super().log(level, msg, exc_info=exc_info, extra=extra, **kwargs)

    def info_data(self, msg: str, data: Optional[dict] = None, **kwargs) -> None:
        self._log_with_data(logging.INFO, msg, data, **kwargs)

    def warning_data(self, msg: str, data: Optional[dict] = None, **kwargs) -> None:
        self._log_with_data(logging.WARNING, msg, data, **kwargs)

    def error_data(self, msg: str, data: Optional[dict] = None, **kwargs) -> None:
        self._log_with_data(logging.ERROR, msg, data, **kwargs)

    def debug_data(self, msg: str, data: Optional[dict] = None, **kwargs) -> None:
        self._log_with_data(logging.DEBUG, msg, data, **kwargs)

    def critical_data(self, msg: str, data: Optional[dict] = None, **kwargs) -> None:
        self._log_with_data(logging.CRITICAL, msg, data, **kwargs)


# Register our custom logger class
logging.setLoggerClass(StructuredLogger)


# Module-level state
_initialized = False
_init_lock = threading.Lock()
_log_dir: Optional[Path] = None


def _ensure_log_dir() -> Path:
    """Ensure the logs directory exists and return its path."""
    global _log_dir
    if _log_dir is None:
        from utils.paths import get_app_data_dir
        _log_dir = get_app_data_dir() / "logs"
        _log_dir.mkdir(parents=True, exist_ok=True)
    return _log_dir


def initialize_logging(log_level: str = "production", log_dir: Optional[str] = None) -> None:
    """
    Initialize the logging system. Should be called once at startup.
    
    Args:
        log_level: "debug" for verbose output, "production" for WARNING+
        log_dir: Optional custom log directory path
    """
    global _initialized, _log_dir
    with _init_lock:
        if _initialized:
            return

        if log_dir:
            _log_dir = Path(log_dir)
            _log_dir.mkdir(parents=True, exist_ok=True)
        else:
            _ensure_log_dir()

        # Determine log level
        level = logging.DEBUG if log_level == "debug" else logging.INFO

        # Root logger setup
        root = logging.getLogger("shadowguardian")
        root.setLevel(logging.DEBUG)  # Capture everything, filter at handler level

        # Clear any existing handlers
        root.handlers.clear()

        # JSON formatter
        json_formatter = StructuredJsonFormatter()

        # File handler — rotating, 5MB per file, 5 backups
        log_file = _log_dir / "shadowguardian.log"
        file_handler = logging.handlers.RotatingFileHandler(
            str(log_file),
            maxBytes=5 * 1024 * 1024,  # 5 MB
            backupCount=5,
            encoding="utf-8",
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(json_formatter)
        root.addHandler(file_handler)

        # Console handler — respects log_level setting
        console_handler = logging.StreamHandler()
        console_handler.setLevel(level)
        if log_level == "debug":
            # Human-readable format for debug console
            console_formatter = logging.Formatter(
                "%(asctime)s [%(levelname)-7s] %(name)-30s │ %(message)s",
                datefmt="%H:%M:%S",
            )
            console_handler.setFormatter(console_formatter)
        else:
            console_handler.setFormatter(json_formatter)
        root.addHandler(console_handler)

        # Error-only file handler for critical issues
        error_file = _log_dir / "errors.log"
        error_handler = logging.handlers.RotatingFileHandler(
            str(error_file),
            maxBytes=2 * 1024 * 1024,  # 2 MB
            backupCount=3,
            encoding="utf-8",
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(json_formatter)
        root.addHandler(error_handler)

        _initialized = True


def get_logger(name: str) -> StructuredLogger:
    """
    Get a module-scoped structured logger.
    
    Args:
        name: Module name, e.g. "agent.window_tracker"
        
    Returns:
        StructuredLogger instance under the shadowguardian namespace
    """
    if not _initialized:
        # Auto-initialize with defaults if not yet initialized
        initialize_logging()

    full_name = f"shadowguardian.{name}" if not name.startswith("shadowguardian.") else name
    logger = logging.getLogger(full_name)
    return logger
