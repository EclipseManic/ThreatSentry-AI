"""
Core module - Configuration, logging, and scheduling
"""
from .config import *
from .logger import get_logger

def start():
    """Lazy import to avoid circular dependencies"""
    from .scheduler import sched
    if not sched.running:
        sched.start()

__all__ = ['get_logger', 'start', 'config']
