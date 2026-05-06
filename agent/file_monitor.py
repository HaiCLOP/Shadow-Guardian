"""
Shadow Guardian — File Integrity Monitor

Watches critical system directories for file changes using
Windows ReadDirectoryChangesW API for efficient OS-level notifications.
Detects new executables in startup folders, system file modifications,
and suspicious file drops.
"""

import ctypes
import ctypes.wintypes
import os
import threading
import time
from pathlib import Path
from typing import Optional

from utils.logger import get_logger
from core.event_queue import EventQueue, EVENT_FILE, PRIORITY_HIGH, PRIORITY_NORMAL

logger = get_logger("agent.file_monitor")

# ReadDirectoryChangesW constants
FILE_NOTIFY_CHANGE_FILE_NAME = 0x00000001
FILE_NOTIFY_CHANGE_DIR_NAME = 0x00000002
FILE_NOTIFY_CHANGE_LAST_WRITE = 0x00000010
FILE_NOTIFY_CHANGE_CREATION = 0x00000040

FILE_ACTION_ADDED = 0x00000001
FILE_ACTION_REMOVED = 0x00000002
FILE_ACTION_MODIFIED = 0x00000003
FILE_ACTION_RENAMED_OLD = 0x00000004
FILE_ACTION_RENAMED_NEW = 0x00000005

ACTION_NAMES = {
    FILE_ACTION_ADDED: "created",
    FILE_ACTION_REMOVED: "deleted",
    FILE_ACTION_MODIFIED: "modified",
    FILE_ACTION_RENAMED_OLD: "renamed_from",
    FILE_ACTION_RENAMED_NEW: "renamed_to",
}

# Suspicious file extensions
SUSPICIOUS_EXTENSIONS = {
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js",
    ".wsf", ".scr", ".pif", ".msi", ".reg", ".com",
}

# Directories to watch
def _get_watch_dirs() -> list[str]:
    """Get list of critical directories to monitor."""
    dirs = []
    
    # User startup folder
    appdata = os.environ.get("APPDATA", "")
    if appdata:
        startup = os.path.join(appdata, "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
        if os.path.isdir(startup):
            dirs.append(startup)

    # Common startup (all users)
    programdata = os.environ.get("PROGRAMDATA", "")
    if programdata:
        common_startup = os.path.join(programdata, "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
        if os.path.isdir(common_startup):
            dirs.append(common_startup)

    # User Downloads folder
    userprofile = os.environ.get("USERPROFILE", "")
    if userprofile:
        downloads = os.path.join(userprofile, "Downloads")
        if os.path.isdir(downloads):
            dirs.append(downloads)

    # Temp directories
    temp = os.environ.get("TEMP", "")
    if temp and os.path.isdir(temp):
        dirs.append(temp)

    return dirs


class FileMonitor:
    """
    Monitors critical directories for file changes.
    
    Features:
        - Watches startup folders for new executables
        - Monitors temp/downloads for suspicious file drops
        - Uses ReadDirectoryChangesW for efficient OS-level events
        - Alerts on executable file creation in monitored dirs
    """

    def __init__(self, event_queue: Optional[EventQueue]):
        self._queue = event_queue
        self._running = threading.Event()
        self._threads: list[threading.Thread] = []
        self._watch_dirs = _get_watch_dirs()

    def start(self) -> None:
        """Start file monitoring threads (one per directory)."""
        self._running.set()

        for watch_dir in self._watch_dirs:
            t = threading.Thread(
                target=self._watch_directory,
                args=(watch_dir,),
                name=f"FileMonitor-{Path(watch_dir).name}",
                daemon=True,
            )
            t.start()
            self._threads.append(t)

        logger.info(f"File monitor started — watching {len(self._watch_dirs)} directories")

    def stop(self) -> None:
        """Stop all file monitoring threads."""
        self._running.clear()
        for t in self._threads:
            t.join(timeout=3.0)
        self._threads.clear()
        logger.info("File monitor stopped")

    def _watch_directory(self, dir_path: str) -> None:
        """Watch a single directory using ReadDirectoryChangesW."""
        kernel32 = ctypes.windll.kernel32

        OPEN_EXISTING = 3
        FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
        FILE_LIST_DIRECTORY = 0x0001
        FILE_SHARE_READ = 0x0001
        FILE_SHARE_WRITE = 0x0002
        FILE_SHARE_DELETE = 0x0004
        INVALID_HANDLE_VALUE = ctypes.wintypes.HANDLE(-1).value

        try:
            handle = kernel32.CreateFileW(
                dir_path,
                FILE_LIST_DIRECTORY,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                None,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                None,
            )

            if handle == INVALID_HANDLE_VALUE:
                logger.error(f"Cannot watch directory: {dir_path}")
                return

            try:
                buf = ctypes.create_string_buffer(8192)
                bytes_returned = ctypes.wintypes.DWORD()
                notify_filter = (
                    FILE_NOTIFY_CHANGE_FILE_NAME |
                    FILE_NOTIFY_CHANGE_DIR_NAME |
                    FILE_NOTIFY_CHANGE_LAST_WRITE |
                    FILE_NOTIFY_CHANGE_CREATION
                )

                while self._running.is_set():
                    result = kernel32.ReadDirectoryChangesW(
                        handle,
                        buf,
                        len(buf),
                        True,  # Watch subtree
                        notify_filter,
                        ctypes.byref(bytes_returned),
                        None,
                        None,
                    )

                    if not result:
                        if self._running.is_set():
                            logger.error(f"ReadDirectoryChangesW failed for {dir_path}")
                        break

                    self._parse_notifications(buf, bytes_returned.value, dir_path)

            finally:
                kernel32.CloseHandle(handle)

        except Exception as e:
            logger.error(f"File monitor error for {dir_path}: {e}")

    def _parse_notifications(self, buf, size: int, base_dir: str) -> None:
        """Parse FILE_NOTIFY_INFORMATION structures from the buffer."""
        offset = 0
        while offset < size:
            try:
                next_offset = ctypes.c_ulong.from_buffer_copy(buf, offset).value
                action = ctypes.c_ulong.from_buffer_copy(buf, offset + 4).value
                name_length = ctypes.c_ulong.from_buffer_copy(buf, offset + 8).value
                
                # File name is UTF-16LE encoded
                name_data = buf[offset + 12: offset + 12 + name_length]
                filename = name_data.decode("utf-16-le", errors="replace")
                
                self._handle_file_event(action, filename, base_dir)

                if next_offset == 0:
                    break
                offset += next_offset

            except Exception as e:
                logger.debug(f"Notification parse error: {e}")
                break

    def _handle_file_event(self, action: int, filename: str, base_dir: str) -> None:
        """Process a single file system event."""
        action_name = ACTION_NAMES.get(action, f"action_{action}")
        full_path = os.path.join(base_dir, filename)
        ext = os.path.splitext(filename)[1].lower()
        
        is_suspicious = ext in SUSPICIOUS_EXTENSIONS
        is_startup = "startup" in base_dir.lower()
        
        # Determine priority
        priority = PRIORITY_NORMAL
        if is_suspicious and action == FILE_ACTION_ADDED:
            priority = PRIORITY_HIGH
        if is_startup and action in (FILE_ACTION_ADDED, FILE_ACTION_MODIFIED):
            priority = PRIORITY_HIGH

        if self._queue:
            self._queue.put_event(EVENT_FILE, {
                "file_path": full_path,
                "action": action_name,
                "process_name": "",  # Can't easily determine which process caused it
                "is_suspicious": is_suspicious,
                "is_startup_dir": is_startup,
                "timestamp": time.time(),
            }, priority=priority)

        if is_suspicious and action == FILE_ACTION_ADDED:
            logger.warning(
                f"Suspicious file created: {filename} in {Path(base_dir).name}",
                extra={"data": {"path": full_path, "action": action_name}}
            )

    @property
    def watched_directories(self) -> list[str]:
        return list(self._watch_dirs)
