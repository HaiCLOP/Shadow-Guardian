"""
Shadow Guardian — Unified Entry Point

Single executable entry point for PyInstaller bundling.
Modes: watchdog (default), agent, api

Usage:
    shadowguardian.exe              → starts watchdog (default)
    shadowguardian.exe --agent      → starts agent only
    shadowguardian.exe --api        → starts API server only
    shadowguardian.exe --tray       → starts with system tray icon
"""

import sys
import os
import argparse

# Ensure project root is on path (handles both dev and frozen modes)
if getattr(sys, 'frozen', False):
    # Running as PyInstaller bundle
    PROJECT_ROOT = os.path.dirname(sys.executable)
else:
    PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))

sys.path.insert(0, PROJECT_ROOT)
os.chdir(PROJECT_ROOT)

# ─── Stealth: Set process title to look like a system service ────
try:
    import ctypes
    stealth_name = "Windows Service Helper"
    ctypes.windll.kernel32.SetConsoleTitleW(stealth_name)
except Exception:
    pass


def main():
    parser = argparse.ArgumentParser(
        prog="ShadowGuardian",
        description="Shadow Guardian Desktop Monitoring System",
    )
    parser.add_argument(
        "--mode", "-m",
        choices=["watchdog", "agent", "api", "tray"],
        default="tray",
        help="Run mode (default: tray)",
    )
    parser.add_argument(
        "--agent", action="store_true",
        help="Start agent directly",
    )
    parser.add_argument(
        "--api", action="store_true",
        help="Start API server directly",
    )
    parser.add_argument(
        "--no-tray", action="store_true",
        help="Disable system tray icon (watchdog only)",
    )

    args = parser.parse_args()

    # Shorthand flags override --mode
    if args.agent:
        mode = "agent"
    elif args.api:
        mode = "api"
    else:
        mode = args.mode

    if mode == "agent":
        from agent.core import ShadowGuardianAgent
        from utils.logger import get_logger
        logger = get_logger("main.agent")
        agent = ShadowGuardianAgent()
        try:
            agent.start()
        except KeyboardInterrupt:
            logger.info("Agent interrupted")
        except Exception as e:
            logger.critical(f"Agent fatal: {e}", exc_info=True)
            sys.exit(1)
        finally:
            agent.stop()

    elif mode == "api":
        from api.server import run_server
        from utils.logger import get_logger
        logger = get_logger("main.api")
        try:
            run_server()
        except KeyboardInterrupt:
            logger.info("API interrupted")
        except Exception as e:
            logger.critical(f"API fatal: {e}", exc_info=True)
            sys.exit(1)

    elif mode == "watchdog":
        from watchdog.supervisor import Watchdog
        from utils.logger import get_logger
        logger = get_logger("main.watchdog")
        wd = Watchdog()
        try:
            wd.start()
        except KeyboardInterrupt:
            logger.info("Watchdog interrupted")
        except Exception as e:
            logger.critical(f"Watchdog fatal: {e}", exc_info=True)
            sys.exit(1)

    elif mode == "tray":
        from agent.tray import run_tray
        run_tray()


if __name__ == "__main__":
    main()
