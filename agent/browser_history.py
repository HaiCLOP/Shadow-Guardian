"""
Shadow Guardian — Browser History Tracker

Reads browser history from Chrome, Edge, and Firefox local SQLite databases.
Copies DBs to temp files to avoid lock conflicts with running browsers.
Polls periodically for new entries since the last check.
"""

import os
import shutil
import sqlite3
import tempfile
import threading
import time
import glob
from pathlib import Path
from typing import Optional

from utils.logger import get_logger
from core.event_queue import EventQueue, EVENT_BROWSER, PRIORITY_NORMAL

logger = get_logger("agent.browser_history")


# Browser history database paths (Windows)
def _get_chrome_history_paths() -> list[Path]:
    """Get all Chrome profile history DB paths."""
    local = os.environ.get("LOCALAPPDATA", "")
    if not local:
        return []
    base = Path(local) / "Google" / "Chrome" / "User Data"
    paths = []
    if (base / "Default" / "History").exists():
        paths.append(base / "Default" / "History")
    # Check numbered profiles
    for profile_dir in base.glob("Profile *"):
        h = profile_dir / "History"
        if h.exists():
            paths.append(h)
    return paths


def _get_edge_history_paths() -> list[Path]:
    """Get all Edge profile history DB paths."""
    local = os.environ.get("LOCALAPPDATA", "")
    if not local:
        return []
    base = Path(local) / "Microsoft" / "Edge" / "User Data"
    paths = []
    if (base / "Default" / "History").exists():
        paths.append(base / "Default" / "History")
    for profile_dir in base.glob("Profile *"):
        h = profile_dir / "History"
        if h.exists():
            paths.append(h)
    return paths


def _get_firefox_history_paths() -> list[Path]:
    """Get all Firefox profile places.sqlite paths."""
    appdata = os.environ.get("APPDATA", "")
    if not appdata:
        return []
    profiles_dir = Path(appdata) / "Mozilla" / "Firefox" / "Profiles"
    if not profiles_dir.exists():
        return []
    paths = []
    for profile_dir in profiles_dir.iterdir():
        if profile_dir.is_dir():
            places = profile_dir / "places.sqlite"
            if places.exists():
                paths.append(places)
    return paths


class BrowserHistoryTracker:
    """
    Polls browser history databases for new entries.
    
    Copies database files to temp before reading to avoid
    locking conflicts with running browser processes.
    Tracks last-seen timestamps per browser to only emit new entries.
    """

    def __init__(self, event_queue: Optional[EventQueue]):
        self._queue = event_queue
        self._running = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._last_check: dict[str, float] = {}  # browser -> last visit_time
        self._poll_interval = 30  # seconds

    def start(self) -> None:
        """Start the browser history polling thread."""
        self._running.set()
        self._thread = threading.Thread(
            target=self._poll_loop,
            name="BrowserHistory",
            daemon=True,
        )
        self._thread.start()
        logger.info("Browser history tracker started")

    def stop(self) -> None:
        """Stop the polling thread."""
        self._running.clear()
        if self._thread:
            self._thread.join(timeout=5.0)
        logger.info("Browser history tracker stopped")

    def _poll_loop(self) -> None:
        """Main polling loop."""
        # Initial delay to let system settle
        time.sleep(5)

        while self._running.is_set():
            try:
                self._scan_all_browsers()
            except Exception as e:
                logger.error(f"Browser history scan error: {e}")

            # Sleep in small increments for responsive shutdown
            deadline = time.time() + self._poll_interval
            while time.time() < deadline and self._running.is_set():
                time.sleep(1.0)

    def _scan_all_browsers(self) -> None:
        """Scan all supported browsers for new history entries."""
        # Chrome
        for path in _get_chrome_history_paths():
            entries = self._read_chromium_history(path, "Chrome")
            self._emit_entries(entries)

        # Edge
        for path in _get_edge_history_paths():
            entries = self._read_chromium_history(path, "Edge")
            self._emit_entries(entries)

        # Firefox
        for path in _get_firefox_history_paths():
            entries = self._read_firefox_history(path)
            self._emit_entries(entries)

    def _copy_db_to_temp(self, db_path: Path) -> Optional[str]:
        """Copy a locked DB file to a temp location for safe reading."""
        try:
            fd, tmp_path = tempfile.mkstemp(suffix=".sqlite")
            os.close(fd)
            shutil.copy2(str(db_path), tmp_path)
            return tmp_path
        except Exception as e:
            logger.debug(f"Failed to copy {db_path}: {e}")
            return None

    def _read_chromium_history(self, db_path: Path, browser: str) -> list[dict]:
        """Read history from a Chromium-based browser (Chrome, Edge)."""
        tmp_path = self._copy_db_to_temp(db_path)
        if not tmp_path:
            return []

        entries = []
        last_time = self._last_check.get(f"{browser}:{db_path}", 0)

        try:
            conn = sqlite3.connect(tmp_path, timeout=5.0)
            conn.row_factory = sqlite3.Row
            try:
                # Chromium stores timestamps as microseconds since 1601-01-01
                # Convert to Unix epoch: subtract 11644473600 seconds
                CHROMIUM_EPOCH_OFFSET = 11644473600
                
                rows = conn.execute("""
                    SELECT url, title, last_visit_time
                    FROM urls
                    WHERE last_visit_time > ?
                    ORDER BY last_visit_time DESC
                    LIMIT 100
                """, (last_time,)).fetchall()

                max_time = last_time
                for row in rows:
                    visit_time = row["last_visit_time"]
                    # Convert Chromium timestamp to Unix epoch
                    unix_time = (visit_time / 1_000_000) - CHROMIUM_EPOCH_OFFSET
                    
                    entries.append({
                        "url": row["url"] or "",
                        "title": row["title"] or "",
                        "browser": browser,
                        "visit_time": unix_time,
                        "timestamp": time.time(),
                    })
                    if visit_time > max_time:
                        max_time = visit_time

                if max_time > last_time:
                    self._last_check[f"{browser}:{db_path}"] = max_time

            finally:
                conn.close()
        except Exception as e:
            logger.debug(f"Failed to read {browser} history: {e}")
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

        return entries

    def _read_firefox_history(self, db_path: Path) -> list[dict]:
        """Read history from Firefox places.sqlite."""
        tmp_path = self._copy_db_to_temp(db_path)
        if not tmp_path:
            return []

        entries = []
        last_time = self._last_check.get(f"Firefox:{db_path}", 0)

        try:
            conn = sqlite3.connect(tmp_path, timeout=5.0)
            conn.row_factory = sqlite3.Row
            try:
                # Firefox stores timestamps as microseconds since Unix epoch
                rows = conn.execute("""
                    SELECT p.url, p.title, h.visit_date
                    FROM moz_historyvisits h
                    JOIN moz_places p ON h.place_id = p.id
                    WHERE h.visit_date > ?
                    ORDER BY h.visit_date DESC
                    LIMIT 100
                """, (last_time,)).fetchall()

                max_time = last_time
                for row in rows:
                    visit_date = row["visit_date"] or 0
                    unix_time = visit_date / 1_000_000  # microseconds to seconds

                    entries.append({
                        "url": row["url"] or "",
                        "title": row["title"] or "",
                        "browser": "Firefox",
                        "visit_time": unix_time,
                        "timestamp": time.time(),
                    })
                    if visit_date > max_time:
                        max_time = visit_date

                if max_time > last_time:
                    self._last_check[f"Firefox:{db_path}"] = max_time

            finally:
                conn.close()
        except Exception as e:
            logger.debug(f"Failed to read Firefox history: {e}")
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

        return entries

    def _emit_entries(self, entries: list[dict]) -> None:
        """Emit browser history entries to the event queue."""
        if not self._queue or not entries:
            return

        for entry in entries:
            self._queue.put_event(EVENT_BROWSER, entry)

        if entries:
            logger.debug(
                f"Captured {len(entries)} new {entries[0].get('browser', '')} history entries"
            )

    def get_chrome_history(self, limit: int = 20) -> list[dict]:
        """Direct read of Chrome history (for testing)."""
        all_entries = []
        for path in _get_chrome_history_paths():
            all_entries.extend(self._read_chromium_history(path, "Chrome"))
        return all_entries[:limit]
