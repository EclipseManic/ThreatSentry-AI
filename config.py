# config.py
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# --- Shodan ---
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
SHODAN_QUERY = os.getenv("SHODAN_QUERY", "product:apache")

# Optional: named Shodan query presets. Users can customize these in their .env
# Example usage: set DEFAULT_SHODAN_QUERY_KEY to one of the keys below or pass a custom query
# via SHODAN_QUERY. Each entry is a complete Shodan query string.
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

# Which preset key to pick by default when the GUI preset selector is left alone.
DEFAULT_SHODAN_QUERY_KEY = os.getenv("DEFAULT_SHODAN_QUERY_KEY", "default")

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
