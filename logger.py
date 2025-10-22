"""
Simple logger factory

Provides a lightweight get_logger(name) that ensures a single stream handler
is attached and the logging level is read from `config.LOG_LEVEL`.
"""

import logging
import sys
import config


def get_logger(name: str = __name__):
    logger = logging.getLogger(name)
    if not logger.handlers:
        formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(name)s - %(message)s")
        ch = logging.StreamHandler(stream=sys.stdout)
        ch.setFormatter(formatter)
        logger.addHandler(ch)
        try:
            level = getattr(logging, config.LOG_LEVEL.upper(), logging.INFO)
        except Exception:
            level = logging.INFO
        logger.setLevel(level)
    return logger
