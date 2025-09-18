# config.py
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# --- Shodan ---
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")

# --- Database ---
SQLITE_PATH = os.getenv("SQLITE_PATH", "threathunt.db")

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
GUI_WINDOW_TITLE = "Threat Hunting Dashboard (Local)"
MAX_SHODAN_RESULTS = int(os.getenv("MAX_SHODAN_RESULTS", "50"))

# --- Feature Flags ---
ENABLE_EMAIL_ALERTS = bool(SENDGRID_API_KEY and SENDER_EMAIL and ALERT_RECIPIENTS)
