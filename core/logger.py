"""
Simple logger factory

Provides a lightweight get_logger(name) that ensures handlers are attached
and the logging level is read from `config.LOG_LEVEL`. Logs are written to
both console and file (with rotation).
"""

import logging
import sys
import os
from logging.handlers import RotatingFileHandler
from .config import LOG_LEVEL, LOG_FILE_PATH, LOG_FILE_MAX_BYTES, LOG_FILE_BACKUP_COUNT


def _ensure_log_directory():
    """Ensure the log directory exists"""
    log_dir = os.path.dirname(LOG_FILE_PATH)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)


def get_logger(name: str = __name__):
    logger = logging.getLogger(name)
    if not logger.handlers:
        # Console handler: simplified format for normal operations (no logger name, less verbose)
        console_formatter = logging.Formatter("%(levelname)s - %(message)s")
        
        # Use UTF-8 encoding for console output (fixes font corruption on Windows)
        ch = logging.StreamHandler(stream=sys.stdout)
        if hasattr(sys.stdout, 'reconfigure'):
            # Python 3.7+ on Windows: reconfigure to use UTF-8
            try:
                sys.stdout.reconfigure(encoding='utf-8')
            except Exception:
                pass
        ch.setFormatter(console_formatter)
        logger.addHandler(ch)
        
        # File handler with rotation: detailed format for debugging
        try:
            _ensure_log_directory()
            file_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(name)s - %(message)s")
            fh = RotatingFileHandler(
                LOG_FILE_PATH,
                maxBytes=LOG_FILE_MAX_BYTES,
                backupCount=LOG_FILE_BACKUP_COUNT
            )
            fh.setFormatter(file_formatter)
            logger.addHandler(fh)
        except Exception as e:
            logger.warning(f"Failed to setup file logging: {e}")
        
        try:
            level = getattr(logging, LOG_LEVEL.upper(), logging.INFO)
        except (AttributeError, TypeError):
            level = logging.INFO
        logger.setLevel(level)
    return logger
