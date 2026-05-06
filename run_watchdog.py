"""
Shadow Guardian — Watchdog Entry Point

Starts the supervisor process that monitors and restarts
the agent and API server.
"""

import sys
import os

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from watchdog.supervisor import Watchdog
from utils.logger import get_logger

logger = get_logger("main.watchdog")


def main():
    logger.info("Starting Shadow Guardian Watchdog...")
    wd = Watchdog()
    try:
        wd.start()
    except KeyboardInterrupt:
        logger.info("Watchdog interrupted by user")
    except Exception as e:
        logger.critical(f"Watchdog fatal error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
