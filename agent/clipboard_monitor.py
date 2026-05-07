"""
Shadow Guardian — Clipboard Monitor

Monitors clipboard changes using Windows clipboard viewer chain.
Logs content previews, detects sensitive data patterns (CC numbers,
SSNs, API keys), and tracks which application performed the copy.
Rate-limited to avoid log spam.
"""

import ctypes
import ctypes.wintypes
import re
import threading
import time
from typing import Optional

from utils.logger import get_logger
from core.event_queue import EventQueue, EVENT_CLIPBOARD, PRIORITY_NORMAL, PRIORITY_HIGH

logger = get_logger("agent.clipboard_monitor")

user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32

# Clipboard formats
CF_TEXT = 1
CF_UNICODETEXT = 13
CF_HDROP = 15  # File list

# Sensitive data patterns
SENSITIVE_PATTERNS = {
    "credit_card": re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "api_key": re.compile(r"\b(?:sk|pk|api|key|token|secret)[-_][a-zA-Z0-9]{20,}\b", re.IGNORECASE),
    "password_field": re.compile(r"(?:password|passwd|pwd)\s*[:=]\s*\S+", re.IGNORECASE),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
}

# Luhn check for credit cards
def _luhn_check(num_str: str) -> bool:
    """Verify a number string passes the Luhn algorithm."""
    digits = [int(d) for d in num_str if d.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


class ClipboardMonitor:
    """
    Monitors Windows clipboard for changes.
    
    Features:
        - Detects text, file, and image clipboard content
        - Logs content preview (first 200 chars for text)
        - Flags sensitive data patterns (CC, SSN, API keys)
        - Rate-limited: max 1 log per 2 seconds
        - Tracks source application
    """

    def __init__(self, event_queue: Optional[EventQueue]):
        self._queue = event_queue
        self._running = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._last_content_hash = ""
        self._last_log_time = 0.0
        self._min_interval = 0.5  # seconds between logs
        self._poll_interval = 0.25

    def start(self) -> None:
        """Start clipboard monitoring thread."""
        self._running.set()
        self._thread = threading.Thread(
            target=self._monitor_loop,
            name="ClipboardMonitor",
            daemon=True,
        )
        self._thread.start()
        logger.info("Clipboard monitor started")

    def stop(self) -> None:
        """Stop clipboard monitoring."""
        self._running.clear()
        if self._thread:
            self._thread.join(timeout=5.0)
        logger.info("Clipboard monitor stopped")

    def _monitor_loop(self) -> None:
        """Poll clipboard for changes."""
        # Get initial sequence number
        last_seq = user32.GetClipboardSequenceNumber()

        while self._running.is_set():
            try:
                current_seq = user32.GetClipboardSequenceNumber()

                if current_seq != last_seq:
                    now = time.time()
                    if now - self._last_log_time >= self._min_interval:
                        success = self._process_clipboard_change()
                        if success:
                            self._last_log_time = now
                            last_seq = current_seq
                        else:
                            # Failed to read (e.g., locked). Don't update last_seq so we retry.
                            pass

            except Exception as e:
                logger.error(f"Clipboard monitor error: {e}")

            time.sleep(self._poll_interval)

    def _process_clipboard_change(self) -> bool:
        """Read and log current clipboard content. Returns True if processed or explicitly skipped, False if it should be retried."""
        content_type = "unknown"
        preview = ""
        sensitive_flags = []

        try:
            max_retries = 3
            clipboard_opened = False
            for _ in range(max_retries):
                if user32.OpenClipboard(0):
                    clipboard_opened = True
                    break
                time.sleep(0.05)
            
            if not clipboard_opened:
                return False

            try:
                # Check for text content
                if user32.IsClipboardFormatAvailable(CF_UNICODETEXT):
                    handle = user32.GetClipboardData(CF_UNICODETEXT)
                    if handle:
                        kernel32.GlobalLock.restype = ctypes.c_wchar_p
                        text = kernel32.GlobalLock(ctypes.c_void_p(handle))
                        if text:
                            content_type = "text"
                            preview = text[:200]
                            if len(text) > 200:
                                preview += f"... ({len(text)} chars)"

                            # Check for sensitive patterns
                            sensitive_flags = self._check_sensitive(text)

                            kernel32.GlobalUnlock(ctypes.c_void_p(handle))

                elif user32.IsClipboardFormatAvailable(CF_HDROP):
                    content_type = "files"
                    preview = "[File(s) copied]"

                elif user32.IsClipboardFormatAvailable(2):  # CF_BITMAP
                    content_type = "image"
                    preview = "[Image copied]"

                else:
                    content_type = "other"
                    preview = "[Non-text content]"

            finally:
                user32.CloseClipboard()

        except Exception as e:
            logger.debug(f"Clipboard read error: {e}")
            return False

        # Avoid duplicate logs for same content
        import hashlib
        content_hash = hashlib.md5(preview.encode("utf-8", errors="replace")).hexdigest()
        if content_hash == self._last_content_hash:
            return True
        self._last_content_hash = content_hash

        # Get source application
        source_app = self._get_foreground_app()

        # Determine priority
        priority = PRIORITY_HIGH if sensitive_flags else PRIORITY_NORMAL

        if self._queue:
            self._queue.put_event(EVENT_CLIPBOARD, {
                "content_type": content_type,
                "content_preview": preview,
                "source_app": source_app,
                "sensitive_flags": sensitive_flags,
                "timestamp": time.time(),
            }, priority=priority)

        if sensitive_flags:
            logger.warning(
                f"Sensitive clipboard content detected: {', '.join(sensitive_flags)}",
                extra={"data": {"source": source_app}}
            )

        return True

    def _check_sensitive(self, text: str) -> list[str]:
        """Check text for sensitive data patterns."""
        flags = []
        for name, pattern in SENSITIVE_PATTERNS.items():
            matches = pattern.findall(text)
            if matches:
                if name == "credit_card":
                    # Verify with Luhn algorithm
                    for match in matches:
                        digits = re.sub(r"[^0-9]", "", match)
                        if _luhn_check(digits):
                            flags.append("credit_card")
                            break
                else:
                    flags.append(name)
        return flags

    @staticmethod
    def _get_foreground_app() -> str:
        """Get the name of the current foreground application."""
        try:
            hwnd = user32.GetForegroundWindow()
            if not hwnd:
                return ""

            pid = ctypes.wintypes.DWORD()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))

            import psutil
            proc = psutil.Process(pid.value)
            return proc.name()
        except Exception:
            return ""
