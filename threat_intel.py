"""
threat_intel.py  — v3.0

Phase 3 Upgrade: Real Threat Intelligence Integration

Live feeds (no API key):
  - Feodo Tracker — botnet C2 IP blocklist
  - TOR Exit Nodes — anonymization infrastructure
  - ipsum Blocklist — multi-source aggregated badlist (level 3+)
  - Spamhaus DROP — Don't Route Or Peer lists

API-integrated feeds (requires API keys in config):
  - AbuseIPDB    — community-reported malicious IPs with confidence scores
  - AlienVault OTX — threat intel pulses with indicator context

Per-IP reputation tracking:
  - Threat score 0-100
  - Feed source tags
  - ASN / country enrichment (from ip-api.com, no key needed)
  - Alert count correlation
"""

import time
import json
import threading
import logging
import urllib.request
import urllib.error
import urllib.parse
from typing import Set, Dict, Any, Optional, List
from datetime import datetime

logger = logging.getLogger("nids.threat_intel")


# ─── Feed URLs ────────────────────────────────────────────────────────────
FEEDS = {
    "feodo_tracker": {
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        "format": "lines",
        "skip_prefix": "#",
        "threat_score": 90,
        "label": "Feodo Botnet C2",
    },
    "tor_exits": {
        "url": "https://check.torproject.org/torbulkexitlist",
        "format": "lines",
        "threat_score": 60,
        "label": "TOR Exit Node",
    },
    "ipsum_3": {
        "url": "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt",
        "format": "first_col",
        "threat_score": 75,
        "label": "ipsum Level-3",
    },
    "spamhaus_drop": {
        "url": "https://www.spamhaus.org/drop/drop.txt",
        "format": "cidr_prefix",
        "threat_score": 85,
        "label": "Spamhaus DROP",
    },
}


class ThreatIntel:
    def __init__(self, config: Dict[str, Any] = None):
        config = config or {}
        ti_cfg = config.get("threat_intel", {})
        self._abuseipdb_key:  Optional[str] = ti_cfg.get("abuseipdb_key") or None
        self._otx_key:        Optional[str] = ti_cfg.get("alientvault_key") or None
        self._update_interval = ti_cfg.get("update_interval", 3600)
        self._timeout         = ti_cfg.get("fetch_timeout", 5)

        # IP → metadata dict
        self._ip_data: Dict[str, Dict[str, Any]] = {}
        # CIDR blocks (Spamhaus) — simple prefix match
        self._cidr_blocks: List[str] = []
        self._geo_cache:   Dict[str, Dict] = {}
        self._alert_counts: Dict[str, int] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()

        # Seed with simulation IPs for demo mode
        self._seed_demo_ips()

        # Start background feed updater
        self._update_thread = threading.Thread(target=self._update_loop, daemon=True)
        self._update_thread.start()
        # Initial load (async so startup is fast)
        threading.Thread(target=self.refresh_all_feeds, daemon=True, name="TI-Init").start()

    # ─── Public API ─────────────────────────────────────────────────────────
    def is_malicious(self, ip: str) -> bool:
        if not ip: return False
        with self._lock:
            if ip in self._ip_data:
                return self._ip_data[ip].get("threat_score", 0) >= 50
            # CIDR check (simple /16 and /24 prefix)
            for prefix in self._cidr_blocks:
                if ip.startswith(prefix): return True
        return False

    def get_reputation(self, ip: str) -> Dict[str, Any]:
        with self._lock:
            data = self._ip_data.get(ip, {}).copy()
        data["ip"] = ip
        data["alert_count"] = self._alert_counts.get(ip, 0)
        data["is_blocked"] = data.get("threat_score", 0) >= 50
        # Enrich with geo if not present
        if "country" not in data:
            geo = self._geo_lookup(ip)
            data.update(geo)
        return data

    def record_alert(self, ip: str, alert_type: str):
        """Called by alert manager to correlate alert volume with IP reputation."""
        with self._lock:
            self._alert_counts[ip] = self._alert_counts.get(ip, 0) + 1
            if ip in self._ip_data:
                # Bump score for IPs actively generating alerts
                current = self._ip_data[ip].get("threat_score", 50)
                self._ip_data[ip]["threat_score"] = min(100, current + 2)
                self._ip_data[ip]["last_seen"] = datetime.utcnow().isoformat()
            else:
                self._ip_data[ip] = {
                    "threat_score": 30,
                    "sources": ["alert_correlation"],
                    "label": f"Seen in alerts ({alert_type})",
                    "first_seen": datetime.utcnow().isoformat(),
                    "last_seen": datetime.utcnow().isoformat(),
                }

    def top_ips(self, n: int = 20) -> List[Dict[str, Any]]:
        with self._lock:
            items = [
                {**v, "ip": k, "alert_count": self._alert_counts.get(k, 0)}
                for k, v in self._ip_data.items()
            ]
        return sorted(items, key=lambda x: x.get("threat_score", 0), reverse=True)[:n]

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            total = len(self._ip_data)
            high  = sum(1 for v in self._ip_data.values() if v.get("threat_score", 0) >= 80)
        return {"total_ips": total, "high_risk_ips": high, "cidr_blocks": len(self._cidr_blocks)}

    # ─── Feed Loading ────────────────────────────────────────────────────────
    def refresh_all_feeds(self):
        logger.info("Refreshing threat intel feeds…")
        for feed_name, feed_cfg in FEEDS.items():
            self._load_feed(feed_name, feed_cfg)
        if self._abuseipdb_key:
            self._load_abuseipdb()
        else:
            logger.info("AbuseIPDB key not set — skipping (add threat_intel.abuseipdb_key to config)")
        if self._otx_key:
            self._load_otx()
        else:
            logger.info("AlienVault OTX key not set — skipping (add threat_intel.alientvault_key to config)")
        with self._lock:
            total = len(self._ip_data)
        logger.info("Threat intel ready: %d IPs", total)

    def _load_feed(self, name: str, cfg: Dict):
        url   = cfg["url"]
        fmt   = cfg.get("format", "lines")
        score = cfg.get("threat_score", 70)
        label = cfg.get("label", name)
        skip  = cfg.get("skip_prefix", "#")
        new_ips = []
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "AI-NIDS/3.0"})
            with urllib.request.urlopen(req, timeout=self._timeout) as r:
                text = r.read().decode("utf-8", errors="ignore")
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith(skip): continue
                if fmt == "first_col":
                    ip = line.split()[0]
                elif fmt == "cidr_prefix":
                    # Store as prefix string for quick matching
                    cidr = line.split(";")[0].strip()
                    if "/" in cidr:
                        prefix = ".".join(cidr.split("/")[0].split(".")[:2]) + "."
                        with self._lock:
                            if prefix not in self._cidr_blocks:
                                self._cidr_blocks.append(prefix)
                    continue
                else:
                    ip = line.split(",")[0].strip()
                # Validate: basic IPv4 check
                parts = ip.split(".")
                if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                    new_ips.append(ip)
        except Exception as e:
            logger.warning("Feed %s failed: %s", name, e)
            return
        now = datetime.utcnow().isoformat()
        with self._lock:
            for ip in new_ips:
                if ip not in self._ip_data:
                    self._ip_data[ip] = {
                        "threat_score": score, "sources": [name],
                        "label": label, "first_seen": now, "last_seen": now,
                    }
                else:
                    self._ip_data[ip]["sources"] = list(
                        set(self._ip_data[ip].get("sources", []) + [name]))
                    self._ip_data[ip]["threat_score"] = min(
                        100, self._ip_data[ip]["threat_score"] + 5)
        logger.info("Feed %s: %d IPs loaded", name, len(new_ips))

    # ─── AbuseIPDB ────────────────────────────────────────────────────────────
    def _load_abuseipdb(self):
        """
        Fetch the AbuseIPDB blocklist (top 10,000 abusive IPs).
        Requires free API key: https://www.abuseipdb.com/api
        """
        url = "https://api.abuseipdb.com/api/v2/blacklist"
        headers = {
            "Key": self._abuseipdb_key,
            "Accept": "application/json",
            "User-Agent": "AI-NIDS/3.0",
        }
        params = urllib.parse.urlencode({"confidenceMinimum": 90, "limit": 10000})
        try:
            req = urllib.request.Request(f"{url}?{params}", headers=headers)
            with urllib.request.urlopen(req, timeout=10) as r:
                data = json.loads(r.read())
            ips = data.get("data", [])
            now = datetime.utcnow().isoformat()
            with self._lock:
                for entry in ips:
                    ip    = entry.get("ipAddress", "")
                    score = entry.get("abuseConfidenceScore", 50)
                    cats  = entry.get("usageType", "unknown")
                    if ip:
                        self._ip_data[ip] = {
                            "threat_score": min(100, score),
                            "sources": ["abuseipdb"],
                            "label": f"AbuseIPDB (confidence {score}%)",
                            "usage_type": cats,
                            "country": entry.get("countryCode", ""),
                            "first_seen": now, "last_seen": now,
                        }
            logger.info("AbuseIPDB: %d IPs loaded", len(ips))
        except Exception as e:
            logger.warning("AbuseIPDB failed: %s", e)

    def check_abuseipdb_single(self, ip: str) -> Dict[str, Any]:
        """Check a single IP against AbuseIPDB (real-time lookup)."""
        if not self._abuseipdb_key:
            return {"error": "AbuseIPDB key not configured"}
        url = f"https://api.abuseipdb.com/api/v2/check"
        params = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": 90})
        headers = {"Key": self._abuseipdb_key, "Accept": "application/json"}
        try:
            req = urllib.request.Request(f"{url}?{params}", headers=headers)
            with urllib.request.urlopen(req, timeout=5) as r:
                data = json.loads(r.read())
            d = data.get("data", {})
            return {
                "ip": ip,
                "abuse_confidence": d.get("abuseConfidenceScore", 0),
                "country": d.get("countryCode", ""),
                "isp": d.get("isp", ""),
                "domain": d.get("domain", ""),
                "total_reports": d.get("totalReports", 0),
                "last_reported": d.get("lastReportedAt", ""),
                "is_whitelisted": d.get("isWhitelisted", False),
                "source": "abuseipdb_realtime",
            }
        except Exception as e:
            return {"error": str(e)}

    # ─── AlienVault OTX ────────────────────────────────────────────────────
    def _load_otx(self):
        """
        Fetch AlienVault OTX subscribed pulse indicators.
        Free API key: https://otx.alienvault.com
        """
        url = "https://otx.alienvault.com/api/v1/indicators/IPv4"
        headers = {"X-OTX-API-KEY": self._otx_key, "User-Agent": "AI-NIDS/3.0"}
        # Fetch recent IPv4 indicators from subscribed pulses
        try:
            req = urllib.request.Request(url + "?limit=5000", headers=headers)
            with urllib.request.urlopen(req, timeout=10) as r:
                data = json.loads(r.read())
            indicators = data.get("results", [])
            now = datetime.utcnow().isoformat()
            with self._lock:
                for ind in indicators:
                    ip = ind.get("indicator", "")
                    if not ip: continue
                    self._ip_data[ip] = {
                        "threat_score": 80,
                        "sources": ["alienvault_otx"],
                        "label": "AlienVault OTX: " + (ind.get("title") or "Malicious IP")[:60],
                        "first_seen": now, "last_seen": now,
                    }
            logger.info("OTX: %d indicators loaded", len(indicators))
        except Exception as e:
            logger.warning("OTX failed: %s", e)

    def check_otx_single(self, ip: str) -> Dict[str, Any]:
        """Real-time OTX reputation check for a single IP."""
        if not self._otx_key:
            return {"error": "AlienVault OTX key not configured"}
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
        headers = {"X-OTX-API-KEY": self._otx_key}
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=5) as r:
                data = json.loads(r.read())
            return {
                "ip": ip,
                "pulse_count": data.get("pulse_info", {}).get("count", 0),
                "reputation": data.get("reputation", 0),
                "country": data.get("country_code", ""),
                "asn": data.get("asn", ""),
                "related_malware": [
                    m.get("name") for m in data.get("malware_families", [])[:5]
                ],
                "source": "otx_realtime",
            }
        except Exception as e:
            return {"error": str(e)}

    # ─── GeoIP enrichment ────────────────────────────────────────────────────
    def _geo_lookup(self, ip: str) -> Dict[str, str]:
        """Free GeoIP via ip-api.com (no key, 45 req/min limit)."""
        with self._lock:
            if ip in self._geo_cache:
                return self._geo_cache[ip]
        # Skip private IPs
        if ip.startswith(("10.", "192.168.", "127.", "172.")):
            return {"country": "Private", "city": "", "asn": ""}
        try:
            url = f"http://ip-api.com/json/{ip}?fields=status,country,city,isp,org,as"
            req = urllib.request.Request(url, headers={"User-Agent": "AI-NIDS/3.0"})
            with urllib.request.urlopen(req, timeout=3) as r:
                data = json.loads(r.read())
            if data.get("status") == "success":
                geo = {
                    "country": data.get("country", ""),
                    "city":    data.get("city", ""),
                    "isp":     data.get("isp", ""),
                    "asn":     data.get("as", ""),
                }
                with self._lock:
                    self._geo_cache[ip] = geo
                return geo
        except Exception:
            pass
        return {"country": "", "city": "", "asn": ""}

    # ─── Demo seeding ─────────────────────────────────────────────────────────
    def _seed_demo_ips(self):
        """Seed known-bad IPs for demo mode (realistic simulation)."""
        demo_ips = {
            "192.168.1.99":   {"threat_score": 90, "label": "Demo: Port Scanner",   "sources": ["demo"]},
            "10.0.0.99":      {"threat_score": 85, "label": "Demo: Brute Forcer",   "sources": ["demo"]},
            "203.0.113.50":   {"threat_score": 92, "label": "Demo: Botnet C2",      "sources": ["feodo_tracker"]},
            "198.51.100.22":  {"threat_score": 78, "label": "Demo: TOR Exit",       "sources": ["tor_exits"]},
            "203.0.113.111":  {"threat_score": 88, "label": "Demo: Malware Dropper","sources": ["ipsum_3"]},
            "192.0.2.77":     {"threat_score": 82, "label": "Demo: Spam Source",    "sources": ["spamhaus_drop"]},
        }
        now = datetime.utcnow().isoformat()
        for ip, data in demo_ips.items():
            data["first_seen"] = now; data["last_seen"] = now
        with self._lock:
            self._ip_data.update(demo_ips)

    def _update_loop(self):
        while not self._stop.wait(self._update_interval):
            self.refresh_all_feeds()

    def stop(self):
        self._stop.set()
