"""
Shadow Guardian — Foreground Window Tracker

Event-driven window tracking using Windows SetWinEventHook API
PLUS periodic full window enumeration to capture ALL open windows,
browser tabs, and background applications.
"""

import ctypes
import ctypes.wintypes
import time
import threading
from typing import Optional

from utils.logger import get_logger
from core.event_queue import EventQueue, Event, EVENT_APP, PRIORITY_NORMAL

logger = get_logger("agent.window_tracker")

# Windows constants
EVENT_SYSTEM_FOREGROUND = 0x0003
EVENT_SYSTEM_MINIMIZEEND = 0x0017
WINEVENT_OUTOFCONTEXT = 0x0000
WINEVENT_SKIPOWNPROCESS = 0x0002

user32 = ctypes.windll.user32
ole32 = ctypes.windll.ole32
kernel32 = ctypes.windll.kernel32

# Callback type
WinEventProcType = ctypes.WINFUNCTYPE(
    None,
    ctypes.wintypes.HANDLE,   # hWinEventHook
    ctypes.wintypes.DWORD,    # event
    ctypes.wintypes.HWND,     # hwnd
    ctypes.wintypes.LONG,     # idObject
    ctypes.wintypes.LONG,     # idChild
    ctypes.wintypes.DWORD,    # dwEventThread
    ctypes.wintypes.DWORD,    # dwmsEventTime
)

# EnumWindows callback type
WNDENUMPROC = ctypes.WINFUNCTYPE(
    ctypes.c_bool,
    ctypes.wintypes.HWND,
    ctypes.wintypes.LPARAM,
)

# Browser patterns for extracting tab info from window titles
BROWSER_TITLE_PATTERNS = {
    "chrome.exe": " - Google Chrome",
    "msedge.exe": " - Microsoft\u200B Edge",  # Edge uses a zero-width space
    "firefox.exe": " — Mozilla Firefox",
    "brave.exe": " - Brave",
    "opera.exe": " - Opera",
    "vivaldi.exe": " - Vivaldi",
}
# Fallback patterns (check title suffix)
BROWSER_TITLE_SUFFIXES = [
    " - Google Chrome",
    " - Microsoft Edge",
    " — Mozilla Firefox", 
    " - Brave",
    " - Opera",
    " - Vivaldi",
]


class WindowTracker:
    """
    Tracks foreground window changes AND all open windows.

    Foreground: Event-driven via SetWinEventHook (zero CPU when idle).
    All windows: Periodic EnumWindows scan every 10 seconds.
    Extracts browser tab titles from window names.
    """

    def __init__(self, event_queue: EventQueue):
        self._queue = event_queue
        self._hooks: list = []
        self._current_window: Optional[dict] = None
        self._current_start: float = 0.0
        self._lock = threading.Lock()
        self._all_windows: list[dict] = []
        self._all_windows_lock = threading.Lock()
        self._enum_thread: Optional[threading.Thread] = None
        self._running = threading.Event()
        self._enum_interval = 10  # seconds

        # CRITICAL: Must keep reference to prevent garbage collection crash
        self._callback = WinEventProcType(self._win_event_callback)

    def start(self) -> None:
        """Install Windows event hooks and start enumeration thread."""
        self._running.set()

        # Hook foreground window change
        hook1 = user32.SetWinEventHook(
            EVENT_SYSTEM_FOREGROUND,
            EVENT_SYSTEM_FOREGROUND,
            0,
            self._callback,
            0, 0,
            WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS,
        )

        # Hook minimize end (restore)
        hook2 = user32.SetWinEventHook(
            EVENT_SYSTEM_MINIMIZEEND,
            EVENT_SYSTEM_MINIMIZEEND,
            0,
            self._callback,
            0, 0,
            WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS,
        )

        if hook1:
            self._hooks.append(hook1)
        if hook2:
            self._hooks.append(hook2)

        # Start enumeration thread for ALL windows
        self._enum_thread = threading.Thread(
            target=self._enumeration_loop,
            name="WindowEnum",
            daemon=True,
        )
        self._enum_thread.start()

        if self._hooks:
            logger.info(f"Window tracker started with {len(self._hooks)} hooks + enumeration")
        else:
            logger.error("Failed to install window event hooks")

    def stop(self) -> None:
        """Remove all event hooks and stop enumeration."""
        self._running.clear()

        # Flush the last tracked window
        self._flush_current()

        for hook in self._hooks:
            try:
                user32.UnhookWinEvent(hook)
            except Exception:
                pass
        self._hooks.clear()

        if self._enum_thread:
            self._enum_thread.join(timeout=3.0)

        logger.info("Window tracker stopped")

    def _win_event_callback(self, hWinEventHook, event, hwnd,
                            idObject, idChild, dwEventThread, dwmsEventTime):
        """Callback fired by Windows when foreground window changes."""
        try:
            if not hwnd:
                return

            now = time.time()

            # Get window title
            length = user32.GetWindowTextLengthW(hwnd)
            if length == 0:
                return

            buf = ctypes.create_unicode_buffer(length + 1)
            user32.GetWindowTextW(hwnd, buf, length + 1)
            title = buf.value

            if not title:
                return

            # Get process ID
            pid = ctypes.wintypes.DWORD()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            pid_val = pid.value

            # Get process info via psutil
            process_name = ""
            exe_path = ""
            try:
                import psutil
                proc = psutil.Process(pid_val)
                process_name = proc.name()
                exe_path = proc.exe()
            except Exception:
                process_name = f"PID:{pid_val}"

            # Extract browser tab info
            tab_title = self._extract_browser_tab(title, process_name)

            # Flush duration of previous window
            self._flush_current()

            # Record new window
            window_info = {
                "pid": pid_val,
                "process_name": process_name,
                "window_title": title,
                "exe_path": exe_path,
                "tab_title": tab_title,
            }

            with self._lock:
                self._current_window = window_info
                self._current_start = now

            # Emit event
            self._queue.put_event(EVENT_APP, {
                **window_info,
                "duration": 0.0,
                "timestamp": now,
                "is_foreground": 1,
            })

        except Exception as e:
            logger.error(f"Window event callback error: {e}")

    def _flush_current(self) -> None:
        """Flush the currently tracked window with its duration."""
        with self._lock:
            if self._current_window and self._current_start > 0:
                duration = time.time() - self._current_start
                if duration > 0.5:  # Ignore sub-second flickers
                    self._queue.put_event(EVENT_APP, {
                        **self._current_window,
                        "duration": round(duration, 2),
                        "timestamp": self._current_start,
                        "is_foreground": 1,
                    })
                self._current_window = None
                self._current_start = 0.0

    def _enumeration_loop(self) -> None:
        """Periodically enumerate ALL visible windows."""
        time.sleep(3)  # Initial delay

        while self._running.is_set():
            try:
                self._enumerate_all_windows()
            except Exception as e:
                logger.error(f"Window enumeration error: {e}")

            deadline = time.time() + self._enum_interval
            while time.time() < deadline and self._running.is_set():
                time.sleep(1.0)

    def _enumerate_all_windows(self) -> None:
        """Enumerate all visible windows and capture their info."""
        windows = []

        def _enum_callback(hwnd, _):
            try:
                # Skip invisible windows
                if not user32.IsWindowVisible(hwnd):
                    return True

                # Get title
                length = user32.GetWindowTextLengthW(hwnd)
                if length == 0:
                    return True

                buf = ctypes.create_unicode_buffer(length + 1)
                user32.GetWindowTextW(hwnd, buf, length + 1)
                title = buf.value
                if not title or title.strip() == "":
                    return True

                # Get PID
                pid = ctypes.wintypes.DWORD()
                user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))

                # Get process name
                process_name = ""
                exe_path = ""
                try:
                    import psutil
                    proc = psutil.Process(pid.value)
                    process_name = proc.name()
                    exe_path = proc.exe()
                except Exception:
                    process_name = f"PID:{pid.value}"

                tab_title = self._extract_browser_tab(title, process_name)

                windows.append({
                    "pid": pid.value,
                    "process_name": process_name,
                    "window_title": title,
                    "exe_path": exe_path,
                    "tab_title": tab_title,
                    "is_foreground": 0,
                })
            except Exception:
                pass
            return True

        callback = WNDENUMPROC(_enum_callback)
        user32.EnumWindows(callback, 0)

        # Mark the actual foreground window
        fg_hwnd = user32.GetForegroundWindow()
        if fg_hwnd:
            fg_pid = ctypes.wintypes.DWORD()
            user32.GetWindowThreadProcessId(fg_hwnd, ctypes.byref(fg_pid))
            for w in windows:
                if w["pid"] == fg_pid.value:
                    w["is_foreground"] = 1
                    break

        with self._all_windows_lock:
            self._all_windows = windows

    @staticmethod
    def _extract_browser_tab(title: str, process_name: str) -> str:
        """Extract the browser tab/page title from a window title."""
        proc_lower = process_name.lower()

        # Check if this is a browser window
        for suffix in BROWSER_TITLE_SUFFIXES:
            if title.endswith(suffix):
                return title[:-len(suffix)].strip()

        # Also check Edge with zero-width space
        if "edge" in proc_lower and " - " in title:
            parts = title.rsplit(" - ", 1)
            if len(parts) == 2 and "edge" in parts[1].lower():
                return parts[0].strip()

        return ""

    @property
    def current_window(self) -> Optional[dict]:
        """Get the currently tracked foreground window."""
        with self._lock:
            return self._current_window.copy() if self._current_window else None

    def get_all_open_windows(self) -> list[dict]:
        """Get all currently open visible windows."""
        with self._all_windows_lock:
            return list(self._all_windows)
