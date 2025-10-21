"""Patch management collector - pull patch lag / missing-patch counts from patch systems."""
from db import get_session, Device
from logger import get_logger
import config
import requests

logger = get_logger("patch_collector")


def enrich_from_patch_system():
    session = get_session()
    try:
        devices = session.query(Device).all()
        ips = [getattr(d, 'ip', None) for d in devices]
        ips = [ip for ip in ips if ip]
        if not ips:
            logger.info("No devices for patch enrichment.")
            return

        endpoint = getattr(config, 'PATCH_API_ENDPOINT', None)
        api_key = getattr(config, 'PATCH_API_KEY', None)
        if not endpoint:
            logger.info("PATCH_API_ENDPOINT not configured; skipping Patch enrichment")
            return

        try:
            resp = requests.post(endpoint, json={"ips": ips}, headers={"Authorization": f"Bearer {api_key}"} if api_key else {}, timeout=30)
            resp.raise_for_status()
            data = resp.json()
        except Exception:
            logger.exception("Patch system query failed; skipping patch enrichment")
            return

        updated = 0
        for d in devices:
            ip_val = getattr(d, 'ip', None)
            info = data.get(ip_val) if isinstance(data, dict) else None
            if not info:
                continue
            try:
                d.patch_lag_days = int(info.get("patch_lag_days", getattr(d, 'patch_lag_days', 0) or 0))
            except Exception:
                pass
            updated += 1

        session.commit()
        logger.info(f"Patch enrichment finished. Updated {updated} devices.")
    except Exception:
        session.rollback()
        logger.exception("Patch enrichment failed")
    finally:
        session.close()
