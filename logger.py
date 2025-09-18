# logger.py
import logging
import sys

def get_logger(name=__name__):
    logger = logging.getLogger(name)
    if not logger.handlers:
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(name)s - %(message)s')
        ch = logging.StreamHandler(stream=sys.stdout)
        ch.setFormatter(formatter)
        logger.addHandler(ch)
        logger.setLevel(logging.INFO)
    return logger
