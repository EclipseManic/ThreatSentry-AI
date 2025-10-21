# collectors/shodan_collector.py
import shodan
import datetime
from logger import get_logger
from config import SHODAN_API_KEY, MAX_SHODAN_RESULTS, SHODAN_QUERY
from db import get_session, Device

logger = get_logger("shodan_collector")

api = None
if SHODAN_API_KEY:
    try:
        api = shodan.Shodan(SHODAN_API_KEY)
    except Exception:
        api = None
        logger.exception("Failed to initialize Shodan client. Check your SHODAN_API_KEY.")

def parse_banners(host_data):
    banners = []
    for d in host_data.get('data', []):
        banners.append(d.get('data', '')[:1000])
    return "\n---\n".join(banners)

def scan_shodan(query: str = None, limit: int = None):
    """
    Query Shodan and persist devices to DB (or update existing).
    If query is None or empty, falls back to config.SHODAN_QUERY.
    If limit is None, falls back to config.MAX_SHODAN_RESULTS.
    """
    if not query:
        query = SHODAN_QUERY or "product:apache"
    if not limit:
        limit = MAX_SHODAN_RESULTS or 50
    if api is None:
        logger.error("Shodan API not configured.")
        return

    session = get_session()
    logger.info(f"Starting Shodan scan: query={query} limit={limit}")
    try:
        results = api.search(query, limit=limit)
        for match in results.get('matches', []):
            ip = match.get('ip_str') or match.get('ip')
            try:
                host = api.host(ip)
            except Exception:
                host = match
            org = host.get('org') or 'N/A'
            country = host.get('country_name') or host.get('country') or 'N/A'
            ports = host.get('ports', [])
            banners = parse_banners(host)
            last_seen = datetime.datetime.utcnow()
            existing = session.query(Device).filter_by(ip=ip).one_or_none()
            if existing:
                existing.org = org
                existing.country = country
                existing.num_open_ports = len(ports)
                existing.banners = banners
                existing.last_seen = last_seen
            else:
                d = Device(
                    ip=ip, org=org, country=country,
                    num_open_ports=len(ports), banners=banners,
                    last_seen=last_seen
                )
                session.add(d)
        session.commit()
        logger.info("Shodan scan finished and persisted.")
    except Exception as e:
        logger.exception("Shodan scan failed: %s", e)
    finally:
        session.close()
