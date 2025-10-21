# collectors/nvd_collector.py
import nvdlib
from logger import get_logger
from db import get_session, Device, Vulnerability

logger = get_logger("nvd_collector")

def extract_product_keywords(banner_text):
    text = (banner_text or "").lower()
    kws = set()
    if "apache" in text:
        kws.add("Apache")
    if "nginx" in text:
        kws.add("nginx")
    if "forti" in text or "fortinet" in text:
        kws.add("Fortinet")
    if "cisco" in text:
        kws.add("Cisco")
    # Add more heuristics as needed
    return kws

def search_cves_for_keyword(keyword, limit=20):
    results = []
    try:
        for cve in nvdlib.searchCVE(keywordSearch=keyword, limit=limit):
            score = None
            try:
                score = float(getattr(cve, "v31score", None) or getattr(cve, "cvssScore", None) or 0.0)
            except Exception:
                score = None
            summary = ""
            try:
                summary = cve.descriptions[0].value
            except Exception:
                summary = getattr(cve, 'summary', '')
            results.append({"id": cve.id, "score": score, "summary": summary})
    except Exception as e:
        logger.exception("NVD query failed for %s: %s", keyword, e)
    return results

def enrich_devices_with_vulns():
    session = get_session()
    try:
        devices = session.query(Device).all()
        for d in devices:
            banners = d.banners or ""
            keywords = extract_product_keywords(banners)
            all_cves = []
            for kw in keywords:
                cves = search_cves_for_keyword(kw)
                all_cves.extend(cves)
            unique = {c['id']: c for c in all_cves}
            d.cve_count = len(unique)
            if unique:
                max_score = max((c['score'] or 0.0) for c in unique.values())
                d.max_cvss = max_score
            else:
                d.max_cvss = None
            session.query(Vulnerability).filter(Vulnerability.device_id == d.id).delete()
            for c in unique.values():
                v = Vulnerability(device_id=d.id, cve_id=c['id'], cvss=c.get('score'), summary=c.get('summary'))
                session.add(v)
        session.commit()
        logger.info("Enriched devices with vulnerabilities.")
    except Exception as e:
        logger.exception("Failed to enrich devices: %s", e)
    finally:
        session.close()
