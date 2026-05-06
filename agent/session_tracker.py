"""
Shadow Guardian — Session Tracker

Detects login, logout, lock, and unlock events using
WTSRegisterSessionNotification via an invisible message window.
"""

import ctypes
import ctypes.wintypes
import threading
import time
import os
from typing import Optional

from utils.logger import get_logger
from core.event_queue import EventQueue, EVENT_SESSION, PRIORITY_HIGH

logger = get_logger("agent.session_tracker")

# Windows message constants
WM_WTSSESSION_CHANGE = 0x02B1
WM_DESTROY = 0x0002
WM_CLOSE = 0x0010

# Session notification types
WTS_CONSOLE_CONNECT = 0x1
WTS_CONSOLE_DISCONNECT = 0x2
WTS_REMOTE_CONNECT = 0x3
WTS_REMOTE_DISCONNECT = 0x4
WTS_SESSION_LOGON = 0x5
WTS_SESSION_LOGOFF = 0x6
WTS_SESSION_LOCK = 0x7
WTS_SESSION_UNLOCK = 0x8

NOTIFY_FOR_THIS_SESSION = 0

SESSION_EVENT_NAMES = {
    WTS_SESSION_LOGON: "login",
    WTS_SESSION_LOGOFF: "logout",
    WTS_SESSION_LOCK: "lock",
    WTS_SESSION_UNLOCK: "unlock",
    WTS_CONSOLE_CONNECT: "console_connect",
    WTS_CONSOLE_DISCONNECT: "console_disconnect",
    WTS_REMOTE_CONNECT: "remote_connect",
    WTS_REMOTE_DISCONNECT: "remote_disconnect",
}

user32 = ctypes.windll.user32
wtsapi32 = ctypes.windll.wtsapi32

# Proper 64-bit types for Win64 API
LRESULT = ctypes.c_ssize_t  # LONG_PTR on x64

# Set proper signature for DefWindowProcW to avoid overflow on 64-bit
user32.DefWindowProcW.argtypes = [
    ctypes.wintypes.HWND,
    ctypes.c_uint,
    ctypes.wintypes.WPARAM,
    ctypes.wintypes.LPARAM,
]
user32.DefWindowProcW.restype = LRESULT

# Window class callback type — must use LRESULT (c_ssize_t) not c_long on x64
WNDPROC = ctypes.WINFUNCTYPE(
    LRESULT,
    ctypes.wintypes.HWND,
    ctypes.c_uint,
    ctypes.wintypes.WPARAM,
    ctypes.wintypes.LPARAM,
)


class WNDCLASSEXW(ctypes.Structure):
    _fields_ = [
        ("cbSize", ctypes.c_uint),
        ("style", ctypes.c_uint),
        ("lpfnWndProc", WNDPROC),
        ("cbClsExtra", ctypes.c_int),
        ("cbWndExtra", ctypes.c_int),
        ("hInstance", ctypes.wintypes.HINSTANCE),
        ("hIcon", ctypes.wintypes.HICON),
        ("hCursor", ctypes.wintypes.HANDLE),
        ("hbrBackground", ctypes.wintypes.HBRUSH),
        ("lpszMenuName", ctypes.wintypes.LPCWSTR),
        ("lpszClassName", ctypes.wintypes.LPCWSTR),
        ("hIconSm", ctypes.wintypes.HICON),
    ]


class SessionTracker:
    """
    Tracks Windows session events (login, logout, lock, unlock).

    Creates an invisible message-only window and registers for
    WTS session notifications. Fully event-driven.
    """

    def __init__(self, event_queue: EventQueue):
        self._queue = event_queue
        self._hwnd: Optional[int] = None
        self._registered = False
        self._running = threading.Event()

        # Keep reference to prevent GC
        self._wndproc = WNDPROC(self._window_proc)
        self._class_name = "ShadowGuardianSession"

    def start(self) -> bool:
        """Register for session notifications. Must be called from message pump thread."""
        try:
            hInstance = ctypes.windll.kernel32.GetModuleHandleW(None)

            # Register window class
            wc = WNDCLASSEXW()
            wc.cbSize = ctypes.sizeof(WNDCLASSEXW)
            wc.lpfnWndProc = self._wndproc
            wc.hInstance = hInstance
            wc.lpszClassName = self._class_name

            atom = user32.RegisterClassExW(ctypes.byref(wc))
            if not atom:
                logger.error("Failed to register session window class")
                return False

            # Create message-only window (HWND_MESSAGE parent)
            HWND_MESSAGE = ctypes.wintypes.HWND(-3)
            self._hwnd = user32.CreateWindowExW(
                0,
                self._class_name,
                "ShadowGuardian Session Monitor",
                0,
                0, 0, 0, 0,
                HWND_MESSAGE,
                None,
                hInstance,
                None,
            )

            if not self._hwnd:
                logger.error("Failed to create session monitor window")
                return False

            # Register for session notifications
            result = wtsapi32.WTSRegisterSessionNotification(
                self._hwnd,
                NOTIFY_FOR_THIS_SESSION,
            )

            if result:
                self._registered = True
                self._running.set()
                logger.info("Session tracker started — monitoring lock/unlock/login/logout")
            else:
                logger.warning("WTSRegisterSessionNotification failed — session tracking degraded")

            return self._registered

        except Exception as e:
            logger.error(f"Session tracker start failed: {e}")
            return False

    def stop(self) -> None:
        """Unregister and destroy the session window."""
        self._running.clear()
        if self._hwnd:
            if self._registered:
                try:
                    wtsapi32.WTSUnRegisterSessionNotification(self._hwnd)
                except Exception:
                    pass
                self._registered = False
            try:
                user32.DestroyWindow(self._hwnd)
            except Exception:
                pass
            self._hwnd = None

        try:
            hInstance = ctypes.windll.kernel32.GetModuleHandleW(None)
            user32.UnregisterClassW(self._class_name, hInstance)
        except Exception:
            pass

        logger.info("Session tracker stopped")

    def _window_proc(self, hwnd, msg, wParam, lParam):
        """Window procedure — handles session change messages."""
        if msg == WM_WTSSESSION_CHANGE:
            event_name = SESSION_EVENT_NAMES.get(wParam)
            if event_name:
                session_id = lParam
                username = ""
                try:
                    username = os.getlogin()
                except Exception:
                    pass

                self._queue.put_event(
                    EVENT_SESSION,
                    {
                        "event_type": event_name,
                        "session_id": session_id,
                        "username": username,
                        "timestamp": time.time(),
                    },
                    priority=PRIORITY_HIGH,
                )

                logger.info(f"Session event: {event_name}", extra={
                    "data": {"session_id": session_id, "username": username}
                })

            return 0

        return user32.DefWindowProcW(hwnd, msg, wParam, lParam)

    @property
    def is_active(self) -> bool:
        return self._registered and self._running.is_set()
