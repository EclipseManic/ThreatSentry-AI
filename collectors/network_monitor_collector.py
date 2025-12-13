"""Network monitoring collector - fetch traffic anomaly scores and related metrics."""
from data import get_session, Device
from core import get_logger
from core import config
import requests

logger = get_logger("network_monitor_collector")


def enrich_from_network_monitor():
    session = get_session()
    try:
        devices = session.query(Device).all()
        ips = [getattr(d, 'ip', None) for d in devices]
        ips = [ip for ip in ips if ip]
        if not ips:
            logger.info("No devices for network monitor enrichment.")
            return

        endpoint = getattr(config, 'NETWORK_MONITOR_ENDPOINT', None)
        api_key = getattr(config, 'NETWORK_MONITOR_KEY', None)
        if not endpoint:
            logger.info("NETWORK_MONITOR_ENDPOINT not configured; skipping network monitor enrichment")
            return

        try:
            resp = requests.post(endpoint, json={"ips": ips}, headers={"Authorization": f"Bearer {api_key}"} if api_key else {}, timeout=30)
            resp.raise_for_status()
            data = resp.json()
        except Exception:
            logger.exception("Network monitor query failed; skipping enrichment")
            return

        updated = 0
        for d in devices:
            ip_val = getattr(d, 'ip', None)
            info = data.get(ip_val) if isinstance(data, dict) else None
            if not info:
                continue
            try:
                d.traffic_anomaly_score = float(info.get("traffic_anomaly_score", getattr(d, 'traffic_anomaly_score', 0.0) or 0.0))
            except Exception:
                pass
            try:
                d.connected_critical_assets = int(info.get("connected_critical_assets", getattr(d, 'connected_critical_assets', 0) or 0))
            except Exception:
                pass
            updated += 1

        session.commit()
        logger.info("Network monitor enrichment finished. Updated %d devices.", updated)
    except Exception:
        session.rollback()
        logger.exception("Network monitor enrichment failed")
    finally:
        session.close()
