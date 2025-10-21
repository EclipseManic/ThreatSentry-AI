"""CMDB collector - enrich devices with CMDB/asset-inventory data."""
from db import get_session, Device
from logger import get_logger
import config
import requests

logger = get_logger("cmdb_collector")


def enrich_from_cmdb():
    session = get_session()
    try:
        devices = session.query(Device).all()
        ips = [d.ip for d in devices if d.ip]
        if not ips:
            logger.info("No devices to enrich from CMDB.")
            return

        endpoint = getattr(config, 'CMDB_API_ENDPOINT', None)
        api_key = getattr(config, 'CMDB_API_KEY', None)
        if not endpoint:
            logger.info("CMDB_API_ENDPOINT not configured; skipping CMDB enrichment")
            return

        # Simple batch query example - real CMDB APIs vary widely
        try:
            resp = requests.post(
                endpoint,
                json={"ips": ips},
                headers={"Authorization": f"Bearer {api_key}"} if api_key else {},
                timeout=20,
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception:
            logger.exception("CMDB query failed; skipping CMDB enrichment")
            return

        updated = 0
        for d in devices:
            info = data.get(d.ip) if isinstance(data, dict) else None
            if not info:
                continue
            # Map known fields safely
            d.network_segment = info.get("network_segment") or d.network_segment
            d.is_critical_service = bool(info.get("is_critical", d.is_critical_service))
            d.service_category = info.get("service_category") or d.service_category
            d.infrastructure_type = info.get("infrastructure_type") or d.infrastructure_type
            d.data_sensitivity_level = info.get("data_sensitivity_level") or d.data_sensitivity_level
            d.compliance_requirements = ",".join(info.get("compliance", [])) if info.get("compliance") else d.compliance_requirements
            updated += 1

        session.commit()
        logger.info(f"CMDB enrichment finished. Updated {updated} devices.")
    except Exception:
        session.rollback()
        logger.exception("CMDB enrichment failed")
    finally:
        session.close()
