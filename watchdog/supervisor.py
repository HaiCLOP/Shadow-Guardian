"""
Shadow Guardian — Watchdog Supervisor

Lightweight supervisor that monitors the agent process and restarts
it on crash with exponential backoff. Prevents infinite restart loops.
"""

import subprocess
import sys
import os
import time
import signal
import threading
from pathlib import Path
from typing import Optional

from utils.logger import get_logger, initialize_logging
from utils.config import get_config

logger = get_logger("watchdog.supervisor")

# Backoff schedule in seconds
BACKOFF_SCHEDULE = [1, 2, 5, 10, 30]
STABILITY_THRESHOLD = 60  # Seconds of uptime before resetting backoff


class Watchdog:
    """
    Supervisor process that monitors and restarts the agent.

    Features:
        - Exponential backoff: 1s → 2s → 5s → 10s → max 30s
        - Backoff resets after 60s of stable running
        - Max restart limit to prevent infinite loops
        - Clean shutdown propagation
        - Also manages the API server process
    """

    def __init__(self):
        self._config = get_config()
        initialize_logging(self._config.get("log_level", "production"))

        self._max_restarts = self._config.get("max_restart_attempts", 10)
        self._agent_process: Optional[subprocess.Popen] = None
        self._api_process: Optional[subprocess.Popen] = None
        self._restart_count = 0
        self._shutdown = threading.Event()
        self._project_root = Path(__file__).parent.parent

        # Detect frozen (PyInstaller) vs development mode
        self._frozen = getattr(sys, 'frozen', False)
        if self._frozen:
            self._exe_path = sys.executable
            self._cwd = os.path.dirname(self._exe_path)
        else:
            self._exe_path = sys.executable
            self._cwd = str(self._project_root)

    def start(self) -> None:
        """Start the watchdog supervisor loop."""
        logger.info("=" * 60)
        logger.info("Shadow Guardian Watchdog starting...")
        logger.info(f"Max restarts: {self._max_restarts}")
        logger.info("=" * 60)

        # Install signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

        # Start API server
        self._start_api_server()

        # Main supervision loop
        try:
            self._supervise_agent()
        except KeyboardInterrupt:
            pass
        finally:
            self._shutdown_all()

    def _signal_handler(self, signum, frame):
        """Handle shutdown signals."""
        logger.info(f"Received signal {signum} — shutting down")
        self._shutdown.set()

    def _start_agent(self) -> Optional[subprocess.Popen]:
        """Start the agent process."""
        if self._frozen:
            cmd = [self._exe_path, "--agent"]
        else:
            entry = self._project_root / "shadowguardian.py"
            cmd = [self._exe_path, str(entry), "--agent"]

        try:
            proc = subprocess.Popen(
                cmd,
                cwd=self._cwd,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            logger.info(f"Agent started (PID: {proc.pid})")
            return proc
        except Exception as e:
            logger.error(f"Failed to start agent: {e}")
            return None

    def _start_api_server(self) -> None:
        """Start the API server process."""
        if self._frozen:
            cmd = [self._exe_path, "--api"]
        else:
            entry = self._project_root / "shadowguardian.py"
            cmd = [self._exe_path, str(entry), "--api"]

        try:
            self._api_process = subprocess.Popen(
                cmd,
                cwd=self._cwd,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            logger.info(f"API server started (PID: {self._api_process.pid})")
        except Exception as e:
            logger.error(f"Failed to start API server: {e}")

    def _get_backoff_delay(self) -> float:
        """Get current backoff delay based on restart count."""
        idx = min(self._restart_count, len(BACKOFF_SCHEDULE) - 1)
        return BACKOFF_SCHEDULE[idx]

    def _supervise_agent(self) -> None:
        """Main supervision loop with exponential backoff."""
        while not self._shutdown.is_set():
            # Check restart limit
            if self._restart_count >= self._max_restarts:
                logger.critical(
                    f"Max restart limit ({self._max_restarts}) reached — "
                    f"stopping watchdog"
                )
                break

            # Start agent
            self._agent_process = self._start_agent()
            if not self._agent_process:
                delay = self._get_backoff_delay()
                logger.warning(f"Agent failed to start — retrying in {delay}s")
                self._restart_count += 1
                if self._shutdown.wait(timeout=delay):
                    break
                continue

            # Monitor agent
            start_time = time.time()

            while not self._shutdown.is_set():
                exit_code = self._agent_process.poll()

                if exit_code is not None:
                    # Agent exited
                    uptime = time.time() - start_time

                    if exit_code == 0:
                        logger.info("Agent exited normally (code 0)")
                        self._shutdown.set()
                        break

                    logger.warning(
                        f"Agent crashed (code: {exit_code}, uptime: {uptime:.1f}s)"
                    )

                    # Reset backoff if agent was stable
                    if uptime >= STABILITY_THRESHOLD:
                        logger.info("Agent was stable — resetting backoff")
                        self._restart_count = 0
                    else:
                        self._restart_count += 1

                    delay = self._get_backoff_delay()
                    logger.info(
                        f"Restarting agent in {delay}s "
                        f"(attempt {self._restart_count}/{self._max_restarts})"
                    )

                    if self._shutdown.wait(timeout=delay):
                        break
                    break  # Break inner loop to restart

                # Brief sleep to avoid busy loop
                time.sleep(1.0)

            # Also check API server
            if self._api_process and self._api_process.poll() is not None:
                logger.warning("API server exited — restarting")
                self._start_api_server()

    def _shutdown_all(self) -> None:
        """Shutdown all child processes."""
        logger.info("Shutting down all processes...")

        for name, proc in [("Agent", self._agent_process), ("API", self._api_process)]:
            if proc and proc.poll() is None:
                try:
                    # Send CTRL_BREAK first for graceful shutdown
                    proc.send_signal(signal.CTRL_BREAK_EVENT)
                    proc.wait(timeout=5)
                    logger.info(f"{name} process stopped gracefully")
                except subprocess.TimeoutExpired:
                    proc.terminate()
                    try:
                        proc.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                    logger.warning(f"{name} process force-killed")
                except Exception as e:
                    logger.error(f"Error stopping {name}: {e}")
                    try:
                        proc.kill()
                    except Exception:
                        pass

        logger.info("All processes stopped")
