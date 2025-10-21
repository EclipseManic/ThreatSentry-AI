# scheduler.py
from apscheduler.schedulers.background import BackgroundScheduler
from logger import get_logger
import datetime
from collectors import shodan_collector, nvd_collector
from collectors import enrich_from_cmdb, enrich_from_siem, enrich_from_patch_system, enrich_from_network_monitor
from model import train_and_save_model
from email_alerts import notify_new_high_risk_devices
from config import SCAN_INTERVAL_MINUTES, RETRAIN_INTERVAL_MINUTES, RETRAIN_ON_SCHEDULE, SHODAN_QUERY, MAX_SHODAN_RESULTS, SHODAN_QUERIES, DEFAULT_SHODAN_QUERY_KEY

logger = get_logger("scheduler")
sched = BackgroundScheduler()

def scheduled_scan():
    logger.info("Scheduled scan started.")
    try:
        # Use configured SHODAN_QUERY and MAX_SHODAN_RESULTS. If empty, the collector defaults will apply.
        shodan_collector.scan_shodan(query=SHODAN_QUERY, limit=MAX_SHODAN_RESULTS)
        nvd_collector.enrich_devices_with_vulns()

        # Enrich with additional internal data sources (CMDB, SIEM, Patch, Network Monitor)
        try:
            enrich_from_cmdb()
        except Exception:
            logger.exception("CMDB enrichment failed")
        try:
            enrich_from_siem()
        except Exception:
            logger.exception("SIEM enrichment failed")
        try:
            enrich_from_patch_system()
        except Exception:
            logger.exception("Patch enrichment failed")
        try:
            enrich_from_network_monitor()
        except Exception:
            logger.exception("Network monitor enrichment failed")

        logger.info("Scan/enrichment complete.")
    except Exception as e:
        logger.exception("Scheduled scan failed: %s", e)


def scheduled_initial_scan():
    """Run one-time startup scans using both the configured SHODAN_QUERY (if set)
    and the configured default preset. This helps seed the DB with both perspectives
    at application start without requiring a manual scan.
    """
    logger.info("Initial startup scan started (configured + preset queries).")
    try:
        queries = []
        try:
            if SHODAN_QUERY and str(SHODAN_QUERY).strip():
                queries.append(str(SHODAN_QUERY).strip())
        except Exception:
            pass
        try:
            preset = SHODAN_QUERIES.get(DEFAULT_SHODAN_QUERY_KEY)
            if preset and preset not in queries:
                queries.append(preset)
        except Exception:
            pass

        if not queries:
            # Nothing configured; allow collector defaults to run via scheduled_scan instead
            logger.info("No startup Shodan queries configured; skipping initial startup scan.")
            return

        for q in queries:
            try:
                logger.info("Running startup Shodan scan for query: %s", q)
                shodan_collector.scan_shodan(query=q, limit=MAX_SHODAN_RESULTS)
            except Exception:
                logger.exception("Startup shodan scan failed for query: %s", q)

        # Run enrichment once after seeding devices
        try:
            nvd_collector.enrich_devices_with_vulns()
        except Exception:
            logger.exception("NVD enrichment after startup scan failed")

        # Run other internal enrichers once at startup
        try:
            enrich_from_cmdb()
        except Exception:
            logger.exception("CMDB enrichment (startup) failed")
        try:
            enrich_from_siem()
        except Exception:
            logger.exception("SIEM enrichment (startup) failed")
        try:
            enrich_from_patch_system()
        except Exception:
            logger.exception("Patch enrichment (startup) failed")
        try:
            enrich_from_network_monitor()
        except Exception:
            logger.exception("Network monitor enrichment (startup) failed")

        logger.info("Initial startup scan/enrichment complete.")
    except Exception as e:
        logger.exception("Initial startup scan failed: %s", e)

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
    # Add a small startup delay so the initial scan can run without overlapping scheduled jobs
    now = datetime.datetime.utcnow()
    start_delay = datetime.timedelta(seconds=10)
    sched.add_job(scheduled_scan, 'interval', minutes=max(1, SCAN_INTERVAL_MINUTES), id='scan_job', next_run_time=now + start_delay)
    if RETRAIN_ON_SCHEDULE:
        sched.add_job(scheduled_retrain, 'interval', minutes=max(1, RETRAIN_INTERVAL_MINUTES), id='retrain_job', next_run_time=now + start_delay)
    sched.add_job(scheduled_notify, 'interval', minutes=max(1, SCAN_INTERVAL_MINUTES), id='notify_job', next_run_time=now + start_delay)
    # Run an immediate initial startup scan (non-blocking)
    try:
        sched.add_job(scheduled_initial_scan, 'date', run_date=now + datetime.timedelta(seconds=1), id='initial_scan')
    except Exception:
        # If job scheduling fails for any reason, run it synchronously as a fallback
        try:
            scheduled_initial_scan()
        except Exception:
            logger.exception("Failed to run initial scan fallback")
    sched.start()
