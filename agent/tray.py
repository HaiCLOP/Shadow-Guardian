"""
Shadow Guardian — System Tray Icon

Provides a system tray icon with context menu for controlling
the agent, opening the dashboard, and managing the service.
Uses pystray for cross-platform tray support on Windows.
"""

import sys
import os
import threading
import time
import subprocess
import webbrowser
import signal
from pathlib import Path
from typing import Optional

from utils.logger import get_logger, initialize_logging
from utils.config import get_config

logger = get_logger("agent.tray")

try:
    import pystray
    from PIL import Image, ImageDraw, ImageFont
    HAS_TRAY = True
except ImportError:
    HAS_TRAY = False
    logger.warning("pystray/Pillow not installed — tray icon disabled")


def _create_icon_image() -> 'Image.Image':
    """Create the tray icon programmatically (no external file needed)."""
    size = 64
    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Shield shape — dark background
    draw.rounded_rectangle(
        [4, 2, 60, 58],
        radius=12,
        fill=(10, 14, 23, 240),
        outline=(34, 211, 238, 255),
        width=3,
    )

    # Inner shield accent
    draw.rounded_rectangle(
        [14, 14, 50, 46],
        radius=6,
        fill=(34, 211, 238, 40),
        outline=(0, 255, 136, 180),
        width=2,
    )

    # Center eye/dot
    draw.ellipse([26, 24, 38, 36], fill=(0, 255, 136, 255))

    return img


class TrayApplication:
    """
    System tray application that manages the watchdog, agent, and API server.
    Provides a user-friendly interface for the background service.
    """

    def __init__(self):
        self._config = get_config()
        initialize_logging(self._config.get("log_level", "production"))

        self._agent_process: Optional[subprocess.Popen] = None
        self._api_process: Optional[subprocess.Popen] = None
        self._tray_icon: Optional[pystray.Icon] = None
        self._health_thread: Optional[threading.Thread] = None
        self._port_thread: Optional[threading.Thread] = None
        self._running = threading.Event()
        self._api_port: int = 0

        # Determine executable path
        if getattr(sys, 'frozen', False):
            self._exe_path = sys.executable
        else:
            self._exe_path = sys.executable  # python.exe
            self._script_root = Path(__file__).parent.parent

    def start(self) -> None:
        """Start the tray application."""
        logger.info("Shadow Guardian Tray starting...")
        self._running.set()

        # Start agent and API in background
        self._start_services()

        # Create and run tray icon (blocks until exit)
        self._run_tray()

    def _start_services(self) -> None:
        """Start the agent and API server as child processes."""
        if getattr(sys, 'frozen', False):
            # Frozen mode — use the same executable with flags
            agent_cmd = [self._exe_path, "--agent"]
            api_cmd = [self._exe_path, "--api"]
            cwd = os.path.dirname(self._exe_path)
        else:
            # Development mode — use python interpreter
            agent_cmd = [self._exe_path, str(self._script_root / "shadowguardian.py"), "--agent"]
            api_cmd = [self._exe_path, str(self._script_root / "shadowguardian.py"), "--api"]
            cwd = str(self._script_root)

        try:
            if not self._agent_process or self._agent_process.poll() is not None:
                self._agent_process = subprocess.Popen(
                    agent_cmd,
                    cwd=cwd,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                logger.info(f"Agent started (PID: {self._agent_process.pid})")
        except Exception as e:
            logger.error(f"Failed to start agent: {e}")

        try:
            if not self._api_process or self._api_process.poll() is not None:
                self._api_process = subprocess.Popen(
                    api_cmd,
                    cwd=cwd,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                logger.info(f"API server started (PID: {self._api_process.pid})")
        except Exception as e:
            logger.error(f"Failed to start API server: {e}")

        # Wait for API port file
        if not self._port_thread or not self._port_thread.is_alive():
            self._port_thread = threading.Thread(target=self._wait_for_api_port, daemon=True)
            self._port_thread.start()

        # Start health monitor
        if not self._health_thread or not self._health_thread.is_alive():
            self._health_thread = threading.Thread(target=self._health_monitor, daemon=True)
            self._health_thread.start()

    def _wait_for_api_port(self) -> None:
        """Wait for the API server to write its port file."""
        from utils.paths import get_app_data_dir
        port_file = get_app_data_dir() / "api_port.txt"

        for _ in range(30):  # Wait up to 15 seconds
            if port_file.exists():
                try:
                    self._api_port = int(port_file.read_text().strip())
                    logger.info(f"API server on port {self._api_port}")

                    # Check if first-run — auto-open browser
                    from db.database import get_database
                    db = get_database()
                    pw = db.get_setting("password_hash")
                    if not pw:
                        self._open_dashboard()
                    return
                except Exception:
                    pass
            time.sleep(0.5)

    def _health_monitor(self) -> None:
        """Monitor child processes and restart on crash."""
        backoff_delays = [1, 2, 5, 10, 30]
        agent_restarts = 0
        api_restarts = 0

        while self._running.is_set():
            time.sleep(5)

            # Check agent
            if self._agent_process and self._agent_process.poll() is not None:
                exit_code = self._agent_process.returncode
                if exit_code != 0 and self._running.is_set():
                    delay = backoff_delays[min(agent_restarts, len(backoff_delays) - 1)]
                    logger.warning(f"Agent crashed (code {exit_code}) — restarting in {delay}s")
                    time.sleep(delay)
                    if self._running.is_set():
                        self._start_services()
                        agent_restarts += 1

            # Check API
            if self._api_process and self._api_process.poll() is not None:
                exit_code = self._api_process.returncode
                if exit_code != 0 and self._running.is_set():
                    delay = backoff_delays[min(api_restarts, len(backoff_delays) - 1)]
                    logger.warning(f"API crashed (code {exit_code}) — restarting in {delay}s")
                    time.sleep(delay)
                    if self._running.is_set():
                        self._start_services()
                        api_restarts += 1

    def _run_tray(self) -> None:
        """Create and run the system tray icon."""
        icon_image = _create_icon_image()

        menu = pystray.Menu(
            pystray.MenuItem("Shadow Guardian", None, enabled=False),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Open Dashboard", self._on_open_dashboard, default=True),
            pystray.MenuItem("Status", pystray.Menu(
                pystray.MenuItem(
                    lambda item: f"Agent: {'Running' if self._agent_process and self._agent_process.poll() is None else 'Stopped'}",
                    None, enabled=False,
                ),
                pystray.MenuItem(
                    lambda item: f"API: {'Running' if self._api_process and self._api_process.poll() is None else 'Stopped'}",
                    None, enabled=False,
                ),
                pystray.MenuItem(
                    lambda item: f"Port: {self._api_port or 'Pending...'}",
                    None, enabled=False,
                ),
            )),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Restart Services", self._on_restart),
            pystray.MenuItem("Open Logs Folder", self._on_open_logs),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Exit", self._on_exit),
        )

        self._tray_icon = pystray.Icon(
            "ShadowGuardian",
            icon_image,
            "Shadow Guardian — Monitoring Active",
            menu,
        )

        logger.info("Tray icon running")
        self._tray_icon.run()  # Blocks until stopped

    # ─── Menu Handlers ───────────────────────────────────────────

    def _on_open_dashboard(self, icon=None, item=None) -> None:
        self._open_dashboard()

    def _open_dashboard(self) -> None:
        if self._api_port:
            webbrowser.open(f"http://127.0.0.1:{self._api_port}")
        else:
            logger.warning("API port not available yet")

    def _on_restart(self, icon=None, item=None) -> None:
        logger.info("Restarting services...")
        self._stop_services()
        time.sleep(1)
        self._start_services()

    def _on_open_logs(self, icon=None, item=None) -> None:
        from utils.paths import get_app_data_dir
        logs_dir = get_app_data_dir() / "logs"
        logs_dir.mkdir(exist_ok=True)
        os.startfile(str(logs_dir))

    def _on_exit(self, icon=None, item=None) -> None:
        logger.info("Exiting Shadow Guardian...")
        self._running.clear()
        self._stop_services()
        if self._tray_icon:
            self._tray_icon.stop()

    def _stop_services(self) -> None:
        """Stop all child processes."""
        for name, proc in [("Agent", self._agent_process), ("API", self._api_process)]:
            if proc and proc.poll() is None:
                try:
                    proc.terminate()
                    proc.wait(timeout=5)
                    logger.info(f"{name} stopped")
                except subprocess.TimeoutExpired:
                    proc.kill()
                    logger.warning(f"{name} force-killed")
                except Exception as e:
                    logger.error(f"Error stopping {name}: {e}")
        self._agent_process = None
        self._api_process = None


def run_tray():
    """Entry point for tray mode."""
    if not HAS_TRAY:
        print("ERROR: pystray and Pillow are required for tray mode.")
        print("Install them: pip install pystray Pillow")
        print("Falling back to watchdog mode...")
        from watchdog.supervisor import Watchdog
        wd = Watchdog()
        wd.start()
        return

    app = TrayApplication()
    try:
        app.start()
    except KeyboardInterrupt:
        app._on_exit()
    except Exception as e:
        logger.critical(f"Tray app fatal: {e}", exc_info=True)
        app._on_exit()
        sys.exit(1)
