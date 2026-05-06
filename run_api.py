"""
Shadow Guardian — API Server Entry Point

Starts the Flask localhost-only API server.
"""

import sys
import os

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from api.server import run_server
from utils.logger import get_logger

logger = get_logger("main.api")


def main():
    logger.info("Starting Shadow Guardian API Server...")
    try:
        run_server()
    except KeyboardInterrupt:
        logger.info("API server interrupted by user")
    except Exception as e:
        logger.critical(f"API server fatal error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
