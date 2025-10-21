# scheduler.py
from apscheduler.schedulers.background import BackgroundScheduler
from logger import get_logger
import datetime
from collectors import shodan_collector, nvd_collector
from model import train_and_save_model
from email_alerts import notify_new_high_risk_devices
from config import SCAN_INTERVAL_MINUTES, RETRAIN_INTERVAL_MINUTES, RETRAIN_ON_SCHEDULE, SHODAN_QUERY, MAX_SHODAN_RESULTS

logger = get_logger("scheduler")
sched = BackgroundScheduler()

def scheduled_scan():
    logger.info("Scheduled scan started.")
    try:
        # Use configured SHODAN_QUERY and MAX_SHODAN_RESULTS. If empty, the collector defaults will apply.
        shodan_collector.scan_shodan(query=SHODAN_QUERY, limit=MAX_SHODAN_RESULTS)
        nvd_collector.enrich_devices_with_vulns()
        logger.info("Scan/enrichment complete.")
    except Exception as e:
        logger.exception("Scheduled scan failed: %s", e)

def scheduled_retrain():
    logger.info("Scheduled retrain started.")
    try:
        train_and_save_model()
    except Exception as e:
        logger.exception("Retrain failed: %s", e)

def scheduled_notify():
    logger.info("Scheduled notify started.")
    try:
        notify_new_high_risk_devices()
    except Exception as e:
        logger.exception("Notify failed: %s", e)

def start():
    logger.info("Starting scheduler.")
    now = datetime.datetime.utcnow()
    sched.add_job(scheduled_scan, 'interval', minutes=max(1, SCAN_INTERVAL_MINUTES), id='scan_job', next_run_time=now)
    if RETRAIN_ON_SCHEDULE:
        sched.add_job(scheduled_retrain, 'interval', minutes=max(1, RETRAIN_INTERVAL_MINUTES), id='retrain_job', next_run_time=now)
    sched.add_job(scheduled_notify, 'interval', minutes=max(1, SCAN_INTERVAL_MINUTES), id='notify_job', next_run_time=now)
    sched.start()
