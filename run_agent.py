"""
Shadow Guardian — Agent Entry Point

Starts the core monitoring agent. Run this directly
or via the watchdog supervisor.
"""

import sys
import os

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agent.core import ShadowGuardianAgent
from utils.logger import get_logger

logger = get_logger("main.agent")


def main():
    agent = ShadowGuardianAgent()
    try:
        agent.start()
    except KeyboardInterrupt:
        logger.info("Agent interrupted by user")
    except Exception as e:
        logger.critical(f"Agent fatal error: {e}", exc_info=True)
        sys.exit(1)
    finally:
        agent.stop()


if __name__ == "__main__":
    main()
