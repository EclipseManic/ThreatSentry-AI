"""
Application entry point

Initializes the database, starts the background scheduler and launches the
GUI. Suitable for running the application locally.
"""

from db import init_db
from scheduler import start as start_scheduler
from gui.app import start_gui
from logger import get_logger

logger = get_logger("run")


def main():
    init_db()
    start_scheduler()
    start_gui()


if __name__ == "__main__":
    main()
