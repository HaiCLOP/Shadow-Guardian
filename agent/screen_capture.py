"""
Shadow Guardian — Screen Capture

Captures screenshots on critical alerts for forensic evidence.
Saves to encrypted local storage with configurable retention.
Supports multi-monitor capture.
"""

import os
import time
import threading
from pathlib import Path
from typing import Optional

from utils.logger import get_logger

logger = get_logger("agent.screen_capture")


class ScreenCapture:
    """
    Captures and stores screenshots when triggered by critical alerts.
    
    Features:
        - Multi-monitor support via mss or PIL.ImageGrab
        - Saves as compressed PNG to local encrypted directory
        - Configurable max storage (default 500MB)
        - Auto-cleanup of old screenshots
    """

    def __init__(self, storage_dir: Optional[Path] = None, max_storage_mb: int = 500):
        if storage_dir is None:
            from utils.paths import get_app_data_dir
            storage_dir = get_app_data_dir() / "screenshots"
        
        self._storage_dir = storage_dir
        self._storage_dir.mkdir(parents=True, exist_ok=True)
        self._max_storage_bytes = max_storage_mb * 1024 * 1024
        self._lock = threading.Lock()
        self._capture_method = self._detect_capture_method()

    @staticmethod
    def _detect_capture_method() -> str:
        """Detect the best available screenshot method."""
        try:
            import mss
            return "mss"
        except ImportError:
            pass
        try:
            from PIL import ImageGrab
            return "pil"
        except ImportError:
            pass
        return "none"

    def capture(self, alert_id: Optional[int] = None, reason: str = "") -> Optional[str]:
        """
        Capture a screenshot.
        
        Args:
            alert_id: Associated alert ID (for linking)
            reason: Why the capture was triggered
            
        Returns:
            File path to the saved screenshot, or None on failure
        """
        if self._capture_method == "none":
            logger.warning("No screenshot library available (install mss or Pillow)")
            return None

        with self._lock:
            try:
                timestamp = int(time.time())
                filename = f"capture_{timestamp}_{alert_id or 'manual'}.png"
                filepath = self._storage_dir / filename

                if self._capture_method == "mss":
                    self._capture_mss(filepath)
                else:
                    self._capture_pil(filepath)

                if filepath.exists():
                    size = filepath.stat().st_size
                    logger.info(
                        f"Screenshot captured: {filename} ({size // 1024}KB)",
                        extra={"data": {"alert_id": alert_id, "reason": reason}}
                    )
                    
                    # Enforce storage limit
                    self._enforce_storage_limit()
                    
                    return str(filepath)
                else:
                    logger.error("Screenshot file was not created")
                    return None

            except Exception as e:
                logger.error(f"Screenshot capture failed: {e}")
                return None

    def _capture_mss(self, filepath: Path) -> None:
        """Capture using mss (multi-monitor support)."""
        import mss
        import mss.tools

        with mss.mss() as sct:
            # Capture all monitors combined
            monitor = sct.monitors[0]  # All monitors combined
            screenshot = sct.grab(monitor)
            mss.tools.to_png(screenshot.rgb, screenshot.size, output=str(filepath))

    def _capture_pil(self, filepath: Path) -> None:
        """Capture using PIL ImageGrab."""
        from PIL import ImageGrab
        
        img = ImageGrab.grab(all_screens=True)
        img.save(str(filepath), "PNG", optimize=True)
        img.close()

    def _enforce_storage_limit(self) -> None:
        """Delete oldest screenshots if storage limit exceeded."""
        try:
            files = sorted(
                self._storage_dir.glob("capture_*.png"),
                key=lambda f: f.stat().st_mtime,
            )
            
            total_size = sum(f.stat().st_size for f in files)
            
            while total_size > self._max_storage_bytes and files:
                oldest = files.pop(0)
                total_size -= oldest.stat().st_size
                oldest.unlink()
                logger.debug(f"Deleted old screenshot: {oldest.name}")
                
        except Exception as e:
            logger.error(f"Screenshot cleanup error: {e}")

    def get_storage_info(self) -> dict:
        """Get screenshot storage statistics."""
        try:
            files = list(self._storage_dir.glob("capture_*.png"))
            total_size = sum(f.stat().st_size for f in files)
            return {
                "count": len(files),
                "total_size_mb": round(total_size / (1024 * 1024), 2),
                "max_size_mb": self._max_storage_bytes // (1024 * 1024),
                "storage_dir": str(self._storage_dir),
            }
        except Exception:
            return {"count": 0, "total_size_mb": 0}
