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

import config
from logger import get_logger
from collectors import shodan_collector, nvd_collector
from collectors import enrich_from_cmdb, enrich_from_siem, enrich_from_patch_system, enrich_from_network_monitor
from model import train_and_save_model
from email_alerts import notify_new_high_risk_devices

logger = get_logger("scheduler")
sched = BackgroundScheduler()

log = logging.getLogger(__name__)

def _run_shodan_queries(queries):
    """Execute a sequence of Shodan queries safely.

    Each configured preset is attempted regardless of individual failures. The
    collector handles API errors and logs; this wrapper ensures failures for
    one query don't abort the rest.
    """
    for q in queries:
        try:
            log.info("Starting Shodan scan for query: %s", q)
            shodan_collector.scan_shodan(query=q, limit=config.MAX_SHODAN_RESULTS)
            log.info("Finished Shodan scan for query: %s", q)
        except Exception:
            log.exception("Failed Shodan scan for query: %s", q)

def scheduled_scan():
    """Called by the scheduler on each interval."""
    start_time = datetime.datetime.now(datetime.timezone.utc)
    log.info("Scheduled scan triggered at %s", start_time.isoformat())

    # Query selection precedence described at module top. Use trimmed string
    # checks to avoid accidental whitespace-only values being treated as set.
    if config.SHODAN_QUERY and str(config.SHODAN_QUERY).strip():
        queries = [config.SHODAN_QUERY]
    elif config.SHODAN_QUERY_EMPTY_TO_PRESET and config.SHODAN_QUERIES:
        queries = list(config.SHODAN_QUERIES.values())
    else:
        # allow the collector to apply its own fallback by passing an empty string
        queries = [config.SHODAN_QUERY or ""]

    _run_shodan_queries(queries)

def scheduled_initial_scan():
    """Optional startup scan. Reuse same behavior as scheduled_scan."""
    log.info("Initial scheduled scan starting")
    scheduled_scan()

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
