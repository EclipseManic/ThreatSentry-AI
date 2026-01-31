"""
Application entry point

Initializes the database, starts the background scheduler and launches the
GUI. Suitable for running the application locally.
"""

import sys

# Ensure UTF-8 encoding for console output (fixes font corruption on Windows)
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass

from data import init_db
from core import start as start_scheduler
from core import get_logger
from gui.app import start_gui

logger = get_logger("run")


def main():
    try:
        logger.info("Initializing database...")
        init_db()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error("Failed to initialize database: %s", str(e))
        raise

    try:
        logger.info("Starting scheduler...")
        start_scheduler()
        logger.info("Scheduler started successfully")
    except Exception as e:
        logger.error("Failed to start scheduler: %s", str(e))
        raise

    try:
        logger.info("Starting GUI...")
        start_gui(dark_theme=True)  # Use dark theme by default
    except Exception as e:
        logger.error("Failed to start GUI: %s", str(e))
        raise


if __name__ == "__main__":
    main()
