"""
Alerts module - Email alerting utilities
"""
from .email_alerts import send_email_alert, build_device_summary, notify_new_high_risk_devices

__all__ = ['send_email_alert', 'build_device_summary', 'notify_new_high_risk_devices']
