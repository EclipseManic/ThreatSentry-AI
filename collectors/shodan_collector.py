"""
Shodan collector

This module encapsulates Shodan API access, result parsing and persisting into
the local database. The collector is defensive: missing API key or API errors
are logged and do not crash the application.
"""

import shodan
import datetime
from logger import get_logger
from config import SHODAN_API_KEY, MAX_SHODAN_RESULTS, SHODAN_QUERY
from db import get_session, Device

logger = get_logger("shodan_collector")

# Initialize the Shodan API client if an API key is configured. If not, api
# remains None and scan_shodan will no-op with an error log.
api = None
if SHODAN_API_KEY:
    try:
        api = shodan.Shodan(SHODAN_API_KEY)
    except Exception:
        api = None
        logger.exception("Failed to initialize Shodan client. Check your SHODAN_API_KEY.")


def parse_banners(host_data: dict) -> str:
    """Extract and concatenate service banner snippets from a Shodan host result.

    The function limits each banner to ~1000 characters and separates entries
    with a visible delimiter. This keeps stored banner text concise for the DB.
    """
    banners = []
    for d in host_data.get("data", []):
        banners.append(d.get("data", "")[:1000])
    return "\n---\n".join(banners)


def scan_shodan(query: str = None, limit: int = None):
    """Run a Shodan search and upsert matching hosts into the Device table.

    Parameters
    - query: Shodan query string. If falsy, falls back to `config.SHODAN_QUERY` or
      a sensible hard-coded default ('product:apache').
    - limit: maximum number of results to request. If falsy uses
      `config.MAX_SHODAN_RESULTS`.

    The function writes/updates Device rows and commits once at the end. Each
    host's banners, ports, org and country fields are recorded when available.
    """
    # Query and limit fallbacks
    if not query:
        query = SHODAN_QUERY or "product:apache"
    if not limit:
        limit = MAX_SHODAN_RESULTS or 50

    if api is None:
        logger.error("Shodan API not configured; skipping scan.")
        return

    session = get_session()
    logger.info("Starting Shodan scan: query=%s limit=%s", query, limit)
    try:
        results = api.search(query, limit=limit)
        for match in results.get("matches", []):
            ip = match.get("ip_str") or match.get("ip")
            try:
                host = api.host(ip)
            except Exception:
                # If detailed host lookup fails, fall back to match summary
                host = match

            org = host.get("org") or "N/A"
            country = host.get("country_name") or host.get("country") or "N/A"
            ports = host.get("ports", [])
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
                    ip=ip,
                    org=org,
                    country=country,
                    num_open_ports=len(ports),
                    banners=banners,
                    last_seen=last_seen,
                )
                session.add(d)

        session.commit()
        logger.info("Shodan scan finished and persisted.")
    except Exception as e:
        logger.exception("Shodan scan failed: %s", e)
    finally:
        session.close()
