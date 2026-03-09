"""
core/geo_lookup.py
GeoIP lookup utility.
Uses MaxMind GeoLite2 database if available, otherwise gracefully degrades.
"""

import logging
from typing import Optional, Dict, Any

logger = logging.getLogger("nids.geo")

# Private / reserved IP ranges
PRIVATE_RANGES = [
    ("10.", "Private (RFC1918)"),
    ("172.16.", "Private (RFC1918)"),
    ("172.17.", "Private (RFC1918)"),
    ("172.18.", "Private (RFC1918)"),
    ("172.19.", "Private (RFC1918)"),
    ("172.20.", "Private (RFC1918)"),
    ("172.21.", "Private (RFC1918)"),
    ("172.22.", "Private (RFC1918)"),
    ("172.23.", "Private (RFC1918)"),
    ("172.24.", "Private (RFC1918)"),
    ("172.25.", "Private (RFC1918)"),
    ("172.26.", "Private (RFC1918)"),
    ("172.27.", "Private (RFC1918)"),
    ("172.28.", "Private (RFC1918)"),
    ("172.29.", "Private (RFC1918)"),
    ("172.30.", "Private (RFC1918)"),
    ("172.31.", "Private (RFC1918)"),
    ("192.168.", "Private (RFC1918)"),
    ("127.",     "Loopback"),
    ("169.254.", "Link-Local"),
    ("::1",      "Loopback (IPv6)"),
    ("fe80:",    "Link-Local (IPv6)"),
]


def is_private(ip: str) -> bool:
    for prefix, _ in PRIVATE_RANGES:
        if ip.startswith(prefix):
            return True
    return False


class GeoLookup:
    """Wraps MaxMind geoip2 reader with a simple dict cache."""

    def __init__(self, config: Dict[str, Any]):
        geo_cfg    = config.get("geo", {})
        self._enabled = geo_cfg.get("enabled", True)
        self._mmdb  = geo_cfg.get("mmdb_path", "data/GeoLite2-City.mmdb")
        self._reader = None
        self._cache: Dict[str, Optional[Dict]] = {}

        if not self._enabled:
            return

        try:
            import geoip2.database
            self._reader = geoip2.database.Reader(self._mmdb)
            logger.info("GeoIP database loaded: %s", self._mmdb)
        except FileNotFoundError:
            logger.warning(
                "GeoLite2 database not found at '%s'. "
                "Download from https://dev.maxmind.com/geoip/geolite2-free-geolocation-data",
                self._mmdb,
            )
        except ImportError:
            logger.warning("geoip2 package not installed — geo lookup disabled")
        except Exception as exc:
            logger.warning("GeoIP init error: %s", exc)

    def lookup(self, ip: str) -> Optional[Dict[str, Any]]:
        if not ip or is_private(ip):
            return {"country": "Private", "city": "LAN", "lat": None, "lon": None}

        if ip in self._cache:
            return self._cache[ip]

        result = None
        if self._reader:
            try:
                resp   = self._reader.city(ip)
                result = {
                    "country": resp.country.name or "Unknown",
                    "country_iso": resp.country.iso_code or "XX",
                    "city":    resp.city.name or "Unknown",
                    "lat":     resp.location.latitude,
                    "lon":     resp.location.longitude,
                }
            except Exception:
                result = {"country": "Unknown", "city": "Unknown", "lat": None, "lon": None}
        else:
            result = {"country": "Unknown", "city": "Unknown", "lat": None, "lon": None}

        self._cache[ip] = result
        return result

    def close(self):
        if self._reader:
            self._reader.close()
