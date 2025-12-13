"""SIEM collector - fetch auth failure counts and suspicious activity metrics."""
from data import get_session, Device
from core import get_logger
from core import config
import requests

logger = get_logger("siem_collector")


def enrich_from_siem():
    session = get_session()
    try:
        devices = session.query(Device).all()
        ips = [getattr(d, 'ip', None) for d in devices]
        ips = [ip for ip in ips if ip]
        if not ips:
            logger.info("No devices for SIEM enrichment.")
            return

        endpoint = getattr(config, 'SIEM_API_ENDPOINT', None)
        api_key = getattr(config, 'SIEM_API_KEY', None)
        if not endpoint:
            logger.info("SIEM_API_ENDPOINT not configured; skipping SIEM enrichment")
            return

        try:
            resp = requests.post(endpoint, json={"ips": ips}, headers={"Authorization": f"Bearer {api_key}"} if api_key else {}, timeout=30)
            resp.raise_for_status()
            data = resp.json()
        except Exception:
            logger.exception("SIEM query failed; skipping SIEM enrichment")
            return

        updated = 0
        for d in devices:
            ip_val = getattr(d, 'ip', None)
            info = data.get(ip_val) if isinstance(data, dict) else None
            if not info:
                continue
            try:
                d.auth_failures_24h = int(info.get("auth_failures_24h", getattr(d, 'auth_failures_24h', 0) or 0))
            except Exception:
                pass
            try:
                d.suspicious_activities_count = int(info.get("suspicious_activities_count", getattr(d, 'suspicious_activities_count', 0) or 0))
            except Exception:
                pass
            updated += 1

        session.commit()
        logger.info("SIEM enrichment finished. Updated %d devices.", updated)
    except Exception:
        session.rollback()
        logger.exception("SIEM enrichment failed")
    finally:
        session.close()
