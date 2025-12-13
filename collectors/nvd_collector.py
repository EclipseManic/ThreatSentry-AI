# collectors/nvd_collector.py
import nvdlib
from core import get_logger
from data import get_session, Device, Vulnerability

logger = get_logger("nvd_collector")

def extract_product_keywords(banner_text):
    import re
    text = (banner_text or "").lower()
    kws = set()

    # Common product tokens
    simple_keywords = [
        'apache', 'nginx', 'fortinet', 'forti', 'cisco', 'openssh', 'mysql',
        'postgresql', 'mongodb', 'iis', 'exchange', 'vmware', 'citrix', 'tomcat'
    ]
    for kw in simple_keywords:
        if kw in text:
            kws.add(kw.capitalize())

    # Regex patterns for product/version pairs
    patterns = [
        (r'apache/(\d+\.\d+)', 'Apache {}'),
        (r'microsoft-iis/(\d+\.\d+)', 'IIS {}'),
        (r'openssh_(\d+\.\d+)', 'OpenSSH {}'),
        (r'mysql.*?ver\s+(\d+\.\d+)', 'MySQL {}'),
        (r'postgresql\s+([0-9]+\.[0-9]+)', 'PostgreSQL {}'),
    ]
    for pat, fmt in patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            try:
                kws.add(fmt.format(m.group(1)))
            except Exception:
                pass

    # Fallback: split common separators and attempt to capture product tokens
    tokens = re.split(r'[\s/;()\[\],]+', text)
    for t in tokens:
        if len(t) > 2 and any(sk in t for sk in simple_keywords):
            kws.add(t.capitalize())

    # Limit keywords to avoid too many NVD queries
    return list(kws)[:12]

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
        session.rollback()
    finally:
        session.close()
