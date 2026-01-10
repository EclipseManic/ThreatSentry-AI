# collectors/nvd_collector.py
import nvdlib
import time
from core import get_logger
from data import get_session, Device, Vulnerability

logger = get_logger("nvd_collector")


def _retry_with_backoff(func, max_retries=3, base_delay=1):
    """Execute a function with exponential backoff retry logic.
    
    Args:
        func: Callable to execute
        max_retries: Maximum number of retry attempts
        base_delay: Initial delay in seconds (doubles each retry)
    
    Returns:
        Result of func() or raises exception after max retries
    """
    last_exception = None
    for attempt in range(max_retries):
        try:
            return func()
        except Exception as e:
            last_exception = e
            if attempt < max_retries - 1:
                delay = base_delay * (2 ** attempt)  # Exponential backoff: 1s, 2s, 4s
                logger.warning("Attempt %d failed, retrying in %ds: %s", attempt + 1, delay, str(e))
                time.sleep(delay)
            else:
                logger.error("All %d retry attempts failed", max_retries)
    raise last_exception


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
    
    def do_search():
        cve_results = []
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
            cve_results.append({"id": cve.id, "score": score, "summary": summary})
        return cve_results
    
    try:
        # Use retry logic for NVD API queries (rate-limited, often fails on first attempt)
        results = _retry_with_backoff(do_search, max_retries=3, base_delay=2)
    except Exception as e:
        logger.exception("NVD query failed for keyword '%s' after retries: %s", keyword, e)
    
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
            
            # Only update CVE data if we actually found vulnerabilities
            # This prevents overwriting existing data with zeros
            if unique:
                d.cve_count = len(unique)
                max_score = max((c['score'] or 0.0) for c in unique.values())
                d.max_cvss = max_score
                # Delete old vulnerabilities and add new ones
                session.query(Vulnerability).filter(Vulnerability.device_id == d.id).delete()
                for c in unique.values():
                    v = Vulnerability(device_id=d.id, cve_id=c['id'], cvss=c.get('score'), summary=c.get('summary'))
                    session.add(v)
                logger.info("Updated device %s with %d CVEs", d.ip, len(unique))
            else:
                # No CVEs found - log but don't reset existing data
                logger.debug("No CVEs found for device %s (keywords: %s)", d.ip, keywords)
        
        session.commit()
        logger.info("Enriched devices with vulnerabilities.")
    except Exception as e:
        logger.exception("Failed to enrich devices: %s", e)
        session.rollback()
        raise  # Re-raise so caller knows enrichment failed
    finally:
        session.close()
