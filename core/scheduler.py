"""
Scheduler: periodic scanning, retraining and notification jobs.

This module schedules the recurring background tasks that keep the application
up-to-date: Shodan scans, vulnerability enrichment, retraining of the ML model,
and notification emails. Shodan query selection follows this precedence:

1. If `config.SHODAN_QUERY` is set (non-empty) the scheduler runs that single
    query.
2. If `config.SHODAN_QUERY` is empty and `config.SHODAN_QUERY_EMPTY_TO_PRESET`
    is True, the scheduler will iterate all values in `config.SHODAN_QUERIES` and
    run each preset.
3. Otherwise the scheduler calls the collector with an empty query and the
    collector's internal fallback will apply.
"""

from apscheduler.schedulers.background import BackgroundScheduler
import logging
import datetime
import threading
from concurrent.futures import ThreadPoolExecutor

from .config import SHODAN_QUERY, SHODAN_QUERY_EMPTY_TO_PRESET, SHODAN_QUERIES, MAX_SHODAN_RESULTS, RETRAIN_ON_SCHEDULE, SCAN_INTERVAL_MINUTES, RETRAIN_INTERVAL_MINUTES
from .logger import get_logger
from collectors import shodan_collector, nvd_collector
from collectors import enrich_from_cmdb, enrich_from_siem, enrich_from_patch_system, enrich_from_network_monitor
from model import train_and_save_model
from alerts import notify_new_high_risk_devices

logger = get_logger("scheduler")
sched = BackgroundScheduler()

# Thread pool for network I/O operations (Shodan, NVD)
_network_executor = ThreadPoolExecutor(max_workers=3, thread_name_prefix="network_io")

def _run_shodan_queries(queries):
    """Execute a sequence of Shodan queries safely using thread pool.

    Each configured preset is attempted regardless of individual failures. The
    collector handles API errors and logs; this wrapper ensures failures for
    one query don't abort the rest. Uses thread pool for non-blocking execution.
    """
    futures = []
    for q in queries:
        try:
            logger.info("Submitting Shodan scan for query: %s", q)
            future = _network_executor.submit(_scan_shodan_safe, q)
            futures.append(future)
        except Exception:
            logger.exception("Failed to submit Shodan scan for query: %s", q)
    
    # Wait for all queries to complete
    for future in futures:
        try:
            future.result(timeout=300)  # 5 minute timeout per query
        except Exception:
            logger.exception("Shodan query execution failed")

def _scan_shodan_safe(query):
    """Safely execute a single Shodan scan in thread pool"""
    try:
        logger.info("Starting Shodan scan for query: %s", query)
        shodan_collector.scan_shodan(query=query, limit=MAX_SHODAN_RESULTS)
        logger.info("Finished Shodan scan for query: %s", query)
    except Exception:
        logger.exception("Failed Shodan scan for query: %s", query)


def scheduled_scan():
    """Called by the scheduler on each interval."""
    start_time = datetime.datetime.now(datetime.timezone.utc)
    logger.info("Scheduled scan triggered at %s", start_time.isoformat())

    # Query selection precedence described at module top. Use trimmed string
    # checks to avoid accidental whitespace-only values being treated as set.
    if SHODAN_QUERY and str(SHODAN_QUERY).strip():
        queries = [SHODAN_QUERY]
    elif SHODAN_QUERY_EMPTY_TO_PRESET and SHODAN_QUERIES:
        queries = list(SHODAN_QUERIES.values())
    else:
        # allow the collector to apply its own fallback by passing an empty string
        queries = [SHODAN_QUERY or ""]

    _run_shodan_queries(queries)
    
    # Run NVD enrichment in parallel with Shodan scan (in thread pool)
    logger.debug("Submitting NVD enrichment to thread pool")
    _network_executor.submit(_enrich_nvd_safe)

def _enrich_nvd_safe():
    """Safely run NVD enrichment in thread pool"""
    try:
        logger.info("Starting NVD enrichment")
        nvd_collector.enrich_devices_with_vulns()
        logger.info("Finished NVD enrichment")
    except Exception:
        logger.exception("NVD enrichment failed")

def scheduled_initial_scan():
    """Optional startup scan. Reuse same behavior as scheduled_scan."""
    logger.info("Initial scheduled scan starting")
    scheduled_scan()

def scheduled_retrain():
    logger.info("Scheduled retrain started.")
    # Run training in a background daemon thread to prevent blocking the scheduler
    training_thread = threading.Thread(target=_train_in_background, daemon=True)
    training_thread.start()
    logger.debug("Training thread started (daemon mode)")

def _train_in_background():
    """Run model training in a background thread"""
    try:
        train_and_save_model()
        logger.info("Scheduled retrain completed successfully")
    except Exception as e:
        logger.exception("Retrain failed: %s", e)

def scheduled_notify():
    logger.info("Scheduled notify started.")
    try:
        notify_new_high_risk_devices()
    except Exception as e:
        logger.exception("Notify failed: %s", e)

def start():
    try:
        logger.info("Starting scheduler.")
        # Add a small startup delay so the initial scan can run without overlapping scheduled jobs
        now = datetime.datetime.now(datetime.timezone.utc)
        start_delay = datetime.timedelta(seconds=10)
        sched.add_job(scheduled_scan, 'interval', minutes=max(1, config.SCAN_INTERVAL_MINUTES), id='scan_job', next_run_time=now + start_delay)
        if config.RETRAIN_ON_SCHEDULE:
            sched.add_job(scheduled_retrain, 'interval', minutes=max(1, config.RETRAIN_INTERVAL_MINUTES), id='retrain_job', next_run_time=now + start_delay)
        sched.add_job(scheduled_notify, 'interval', minutes=max(1, config.SCAN_INTERVAL_MINUTES), id='notify_job', next_run_time=now + start_delay)
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
        logger.info("Scheduler started successfully")
    except Exception as e:
        logger.error("Failed to start scheduler: %s", str(e))
        raise
