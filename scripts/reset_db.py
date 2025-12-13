"""
Reset database with new schema
"""
import os
import sys
from pathlib import Path

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent))

from core.config import SQLITE_PATH
from core import get_logger

logger = get_logger("db_reset")

def reset_database():
    """Delete the existing database and initialize a new one"""
    try:
        # Delete existing database
        if os.path.exists(SQLITE_PATH):
            os.remove(SQLITE_PATH)
            logger.info("Deleted existing database at %s", SQLITE_PATH)
        
        # Import after deletion to avoid schema conflicts
        from db import init_db
        
        # Initialize new database with updated schema
        init_db()
        logger.info("Database initialized with new schema")
        return True
        
    except Exception as e:
        logger.error("Failed to reset database: %s", str(e))
        return False

if __name__ == "__main__":
    reset_database()