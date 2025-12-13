"""
Application configuration.

This file centralizes simple configuration values that can be set via environment
variables (or a .env file). Keep this module small and easy to edit for new users.

Key Shodan-related settings:
- SHODAN_API_KEY: API key used to access the Shodan service.
- SHODAN_QUERY: optional single global query string. If set, scheduled scans use
	this single query. If empty and SHODAN_QUERY_EMPTY_TO_PRESET is True, the
	scheduler will iterate the `SHODAN_QUERIES` presets.
- SHODAN_QUERIES: dictionary of named preset queries exposed to the GUI.
- SHODAN_QUERY_EMPTY_TO_PRESET: boolean flag controlling whether the scheduler
	should run all presets when SHODAN_QUERY is empty.
"""

import os
from dotenv import load_dotenv

# Load .env file (if present) and environment variables
load_dotenv()

# --- Shodan configuration ---
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")

# Optional single query string (highest priority for scheduled scans). Leave
# empty to allow using presets defined in SHODAN_QUERIES.
SHODAN_QUERY = os.getenv("SHODAN_QUERY", "")

# Preset queries available in the GUI and used by the scheduler when
# SHODAN_QUERY is empty and SHODAN_QUERY_EMPTY_TO_PRESET is True.
SHODAN_QUERIES = {
		"default": "product:apache",
		"org": 'org:"Your Company Name"',
		"net": 'net:"123.45.67.0/24"',
		"ssl": 'ssl:"yourcompany.com"',
		"hostname": 'hostname:".yourcompany.com"',
		"rdp": 'port:3389 "remote desktop"',
		"mongodb": 'port:27017 "mongodb"',
		"ics_modbus": 'port:502 "modbus"',
		"vuln_example": 'vuln:CVE-2024-12345',
		"http_login": 'http.title:"Login" org:"Your Company"'
}

# When True, the scheduler runs every preset from SHODAN_QUERIES if
# SHODAN_QUERY is unset/empty. When False, the scheduler skips preset iteration
# and will pass an empty query to the collector (collector may apply its own
# fallback).
SHODAN_QUERY_EMPTY_TO_PRESET = os.getenv("SHODAN_QUERY_EMPTY_TO_PRESET", "True").lower() in ("1", "true", "yes")

# --- Database ---
SQLITE_PATH = os.getenv("SQLITE_PATH", "threat_sentric_ai.db")

# --- Model ---
MODEL_PATH = os.getenv("MODEL_PATH", "rf_model.pkl")
RETRAIN_ON_SCHEDULE = os.getenv("RETRAIN_ON_SCHEDULE", "True").lower() in ("1", "true", "yes")
RETRAIN_INTERVAL_MINUTES = int(os.getenv("RETRAIN_INTERVAL_MINUTES", "60"))

# --- Scheduler for scanning ---
SCAN_INTERVAL_MINUTES = int(os.getenv("SCAN_INTERVAL_MINUTES", "30"))

# --- SendGrid Email (API) ---
SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY", "")
SENDER_EMAIL = os.getenv("SENDER_EMAIL", "")  # must be verified in SendGrid
ALERT_RECIPIENTS = [e.strip() for e in os.getenv("ALERT_RECIPIENTS", "").split(",") if e.strip()]

# --- Application ---
GUI_WINDOW_TITLE = "Threat Sentric AI - Threat Hunting Dashboard (Local)"
MAX_SHODAN_RESULTS = int(os.getenv("MAX_SHODAN_RESULTS", "50"))

# --- Feature Flags ---
ENABLE_EMAIL_ALERTS = bool(SENDGRID_API_KEY and SENDER_EMAIL and ALERT_RECIPIENTS)

# Optional internal collector endpoints and API keys (set these in your .env if available)
CMDB_API_ENDPOINT = os.getenv("CMDB_API_ENDPOINT")
CMDB_API_KEY = os.getenv("CMDB_API_KEY")

SIEM_API_ENDPOINT = os.getenv("SIEM_API_ENDPOINT")
SIEM_API_KEY = os.getenv("SIEM_API_KEY")

PATCH_API_ENDPOINT = os.getenv("PATCH_API_ENDPOINT")
PATCH_API_KEY = os.getenv("PATCH_API_KEY")

NETWORK_MONITOR_ENDPOINT = os.getenv("NETWORK_MONITOR_ENDPOINT")
NETWORK_MONITOR_KEY = os.getenv("NETWORK_MONITOR_KEY")

# Logging
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
