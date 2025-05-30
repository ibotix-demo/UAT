#!/usr/bin/env python3
"""
location.py

A demo script that fetches your public IP address and then
retrieves geolocation data for that IP. All steps are logged
(with DEBUG verbosity) and written to a rotating log file.
If the HTTPS request to ip-api.com is forbidden, it will
automatically retry over HTTP.
"""

import logging
from logging.handlers import RotatingFileHandler
import requests
import sys

# --- Configuration ---
IP_SERVICE_URL = "https://api.ipify.org?format=json"
GEO_URL_HTTPS = "https://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,zip,lat,lon,timezone,isp"
GEO_URL_HTTP  = "http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,zip,lat,lon,timezone,isp"
LOG_FILE = "location.log"
LOG_MAX_BYTES = 1_000_000  # rotate when file >1MB
LOG_BACKUP_COUNT = 3       # keep last 3 log files


def setup_logger() -> logging.Logger:
    logger = logging.getLogger("LocationDemo")
    logger.setLevel(logging.DEBUG)

    # Console handler (INFO+)
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S"
    ))
    logger.addHandler(ch)

    # Rotating file handler (DEBUG+)
    fh = RotatingFileHandler(
        LOG_FILE, maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUP_COUNT
    )
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s - %(message)s", "%Y-%m-%d %H:%M:%S"
    ))
    logger.addHandler(fh)

    return logger


def get_public_ip(logger: logging.Logger) -> str:
    logger.debug("Requesting public IP from %s", IP_SERVICE_URL)
    resp = requests.get(IP_SERVICE_URL, timeout=5)
    resp.raise_for_status()
    data = resp.json()
    ip = data.get("ip")
    if not ip:
        raise ValueError("No 'ip' field in response JSON")
    logger.info("Obtained public IP: %s", ip)
    return ip


def get_geolocation(logger: logging.Logger, ip: str) -> dict:
    """
    Try HTTPS first; if a 403 Forbidden comes back, retry via HTTP.
    """
    url_https = GEO_URL_HTTPS.format(ip=ip)
    url_http  = GEO_URL_HTTP.format(ip=ip)
    logger.debug("Attempting HTTPS geolocation lookup: %s", url_https)
    try:
        resp = requests.get(url_https, timeout=5)
        resp.raise_for_status()
    except requests.exceptions.HTTPError as e:
        if e.response is not None and e.response.status_code == 403:
            logger.warning("HTTPS forbidden; retrying over HTTP")
            resp = requests.get(url_http, timeout=5)
            resp.raise_for_status()
        else:
            raise
    geo = resp.json()
    if geo.get("status") != "success":
        raise RuntimeError(f"Geo lookup failed: {geo.get('message')}")
    logger.info(
        "Geolocation success: %s, %s, %s",
        geo.get("city"), geo.get("regionName"), geo.get("country")
    )
    return geo


def print_location(geo: dict):
    print("\n=== Your Geolocation Info ===")
    print(f"Country : {geo.get('country')}")
    print(f"Region  : {geo.get('regionName')}")
    print(f"City    : {geo.get('city')} ({geo.get('zip')})")
    print(f"Coords  : {geo.get('lat')}, {geo.get('lon')}")
    print(f"Timezone: {geo.get('timezone')}")
    print(f"ISP     : {geo.get('isp')}")
    print("=============================\n")


def main():
    logger = setup_logger()
    logger.info("Starting location_demo")

    try:
        ip = get_public_ip(logger)
        geo = get_geolocation(logger, ip)
        print_location(geo)
    except requests.RequestException as e:
        logger.error("Network error: %s", e, exc_info=True)
        sys.exit(1)
    except Exception as e:
        logger.error("Unexpected error: %s", e, exc_info=True)
        sys.exit(1)

    logger.info("location_demo completed successfully")


if __name__ == "__main__":
    main()
