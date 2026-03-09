"""
alerting/alert_manager.py
Alert Manager — enriches, stores, and dispatches all alerts.

Enrichment pipeline:
  1. GeoIP lookup  → country / city
  2. Threat score  → from ip_reputation table
  3. DB insert     → alerts + ip_reputation
  4. Log           → alerts.log
  5. Notify        → email / Slack / webhook (async)
  6. Socket.IO     → real-time push to dashboard
  7. Auto-block    → ONLY if explicitly enabled in config AND IP not on allowlist

Auto-block safety notes
-----------------------
Auto-blocking is DISABLED by default (alerting.auto_block.enabled: false).

Before enabling it, understand the risk:
  - An attacker can spoof a trusted IP (your gateway, your DNS server, a CDN)
    to trigger a block and cut off your own infrastructure.
  - False positives from the ML layer or misconfigured thresholds will block
    legitimate hosts.
  - The allowlist check in _safe_to_block() is a partial mitigation only.
    It covers RFC1918 ranges and configured trusted IPs, but not every
    possible spoofable address (e.g. your upstream provider's IPs).

Real SOC practice: flag for human review instead of auto-blocking.
Use auto-block only in isolated lab environments or with a very tight allowlist.
"""

import ipaddress
import threading
import logging
import json
from datetime import datetime
from typing import Dict, Any, List, Callable, Optional

logger = logging.getLogger("nids.alerts")


# ── Built-in never-block ranges ───────────────────────────────────────────────
# These ranges are ALWAYS protected regardless of threat score.
# An alert from these IPs should be investigated manually — do not auto-block.
_ALWAYS_ALLOWED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),       # RFC1918
    ipaddress.ip_network("172.16.0.0/12"),     # RFC1918
    ipaddress.ip_network("192.168.0.0/16"),    # RFC1918
    ipaddress.ip_network("127.0.0.0/8"),       # Loopback
    ipaddress.ip_network("169.254.0.0/16"),    # Link-local
    ipaddress.ip_network("224.0.0.0/4"),       # Multicast
    ipaddress.ip_network("::1/128"),           # IPv6 loopback
    ipaddress.ip_network("fe80::/10"),         # IPv6 link-local
]


class AlertManager:
    """Central hub that all alert sources feed into."""

    SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

    def __init__(self, config: Dict[str, Any], db=None,
                 geo_lookup=None, email_alerter=None,
                 slack_alerter=None):
        self._config      = config
        self._db          = db
        self._geo         = geo_lookup
        self._email       = email_alerter
        self._slack       = slack_alerter

        alert_cfg         = config.get("alerting", {})
        self._min_severity = self.SEVERITY_ORDER.get(
            alert_cfg.get("min_severity", "LOW").upper(), 0
        )

        # Auto-block config — off by default
        ab_cfg = alert_cfg.get("auto_block", {})
        self._auto_block_enabled   = ab_cfg.get("enabled", False)
        self._auto_block_score     = ab_cfg.get("score_threshold", 85)
        self._auto_block_allowlist = self._build_allowlist(
            ab_cfg.get("allowlist", [])
        )
        if self._auto_block_enabled:
            logger.warning(
                "Auto-block is ENABLED (threshold=%d). Ensure your allowlist "
                "includes your gateway and DNS servers. See README for risks.",
                self._auto_block_score,
            )

        # Registered real-time callbacks (Socket.IO, etc.)
        self._rt_callbacks: List[Callable[[Dict], None]] = []

        # Recent alerts buffer (last 200) for dashboard
        self._recent:   List[Dict] = []
        self._recent_lock = threading.Lock()

        # Counters
        self._total      = 0
        self._by_type:   Dict[str, int] = {}
        self._lock       = threading.Lock()

    # ──────────────────────────────────────────────────────────────

    def register_realtime_callback(self, fn: Callable[[Dict], None]):
        """Register a callback for real-time alert dispatch (e.g. Socket.IO)."""
        self._rt_callbacks.append(fn)

    def receive(self, alert: Dict[str, Any]):
        """Entry point: process, enrich, store, and dispatch one alert."""
        severity = alert.get("severity", "LOW").upper()
        if self.SEVERITY_ORDER.get(severity, 0) < self._min_severity:
            return

        # Ensure UTC timestamp
        if "timestamp" not in alert:
            alert["timestamp"] = datetime.utcnow().isoformat()

        # ── 1. GeoIP enrichment ───────────────────────────────────
        if self._geo and alert.get("src_ip"):
            geo = self._geo.lookup(alert["src_ip"])
            if geo:
                alert["country"] = geo.get("country")
                alert["city"]    = geo.get("city")
                alert["lat"]     = geo.get("lat")
                alert["lon"]     = geo.get("lon")

        # ── 2. DB: persist + ip_reputation ───────────────────────
        alert_id = None
        if self._db:
            try:
                alert_id = self._db.insert_alert(alert)
                alert["id"] = alert_id
                rep = self._db.get_ip_reputation(alert.get("src_ip"))
                if rep:
                    alert["cumulative_score"] = rep["threat_score"]
                    alert["total_incidents"]  = rep["alert_count"]
            except Exception as exc:
                logger.error("DB insert error: %s", exc)

        # ── 3. Log ────────────────────────────────────────────────
        self._log_alert(alert)

        # ── 4. Internal buffer ────────────────────────────────────
        with self._recent_lock:
            self._recent.insert(0, alert)
            if len(self._recent) > 200:
                self._recent.pop()

        with self._lock:
            self._total += 1
            self._by_type[alert.get("alert_type", "UNKNOWN")] = \
                self._by_type.get(alert.get("alert_type", "UNKNOWN"), 0) + 1

        # ── 5. Real-time push ──────────────────────────────────────
        for cb in self._rt_callbacks:
            try:
                cb(alert)
            except Exception as exc:
                logger.error("RT callback error: %s", exc)

        # ── 6. Async external notifications ───────────────────────
        t = threading.Thread(
            target=self._notify_async, args=(alert,), daemon=True
        )
        t.start()

        # ── 7. Auto-block (disabled by default — see README) ─────────
        if self._auto_block_enabled:
            score = alert.get("cumulative_score", alert.get("threat_score", 0))
            ip    = alert.get("src_ip")
            if score >= self._auto_block_score and ip and self._db:
                if not self._db.is_blocked(ip) and self._safe_to_block(ip):
                    self._auto_block(alert)
                elif not self._safe_to_block(ip):
                    logger.warning(
                        "AUTO-BLOCK SUPPRESSED for %s — IP is on allowlist. "
                        "Investigate manually.", ip
                    )

    # ──────────────────────────────────────────────────────────────

    def get_recent_alerts(self, limit: int = 100,
                          severity: Optional[str] = None) -> List[Dict]:
        with self._recent_lock:
            if severity:
                filtered = [a for a in self._recent
                            if a.get("severity") == severity.upper()]
                return filtered[:limit]
            return list(self._recent[:limit])

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "total":   self._total,
                "by_type": dict(self._by_type),
            }

    # ──────────────────────────────────────────────────────────────

    def _log_alert(self, alert: Dict):
        sev_logfn = {
            "LOW":      logger.info,
            "MEDIUM":   logger.warning,
            "HIGH":     logger.error,
            "CRITICAL": logger.critical,
        }.get(alert.get("severity", "LOW").upper(), logger.warning)

        sev_logfn(
            "[%s] %s | src=%s | %s",
            alert.get("severity"), alert.get("alert_type"),
            alert.get("src_ip", "N/A"), alert.get("description"),
        )

    def _notify_async(self, alert: Dict):
        """Send external notifications if configured."""
        alert_cfg    = self._config.get("alerting", {})
        sev_min_ext  = self.SEVERITY_ORDER.get(
            alert_cfg.get("min_severity", "HIGH").upper(), 2
        )
        sev_current  = self.SEVERITY_ORDER.get(
            alert.get("severity", "LOW").upper(), 0
        )
        if sev_current < sev_min_ext:
            return

        if self._email:
            email_cfg = self._config.get("alerting", {}).get("email", {})
            if email_cfg.get("enabled"):
                try:
                    self._email.send(alert)
                except Exception as exc:
                    logger.error("Email send error: %s", exc)

        if self._slack:
            slack_cfg = self._config.get("alerting", {}).get("slack", {})
            if slack_cfg.get("enabled"):
                try:
                    self._slack.send(alert)
                except Exception as exc:
                    logger.error("Slack send error: %s", exc)

    def _safe_to_block(self, ip: str) -> bool:
        """
        Return False if this IP must never be auto-blocked.

        Checks:
          1. Built-in RFC1918 / loopback / link-local ranges
          2. User-configured allowlist from config.yaml

        Note: this does NOT protect against all spoofing scenarios.
        A determined attacker can spoof public IPs not on this list.
        Always maintain a comprehensive allowlist and treat auto-block
        as a last resort, not a first response.
        """
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False  # malformed IP — don't block

        # RFC1918 and special ranges
        for network in _ALWAYS_ALLOWED_NETWORKS:
            try:
                if addr in network:
                    return False
            except TypeError:
                pass

        # User allowlist
        for network in self._auto_block_allowlist:
            try:
                if addr in network:
                    return False
            except TypeError:
                pass

        return True

    def _auto_block(self, alert: Dict):
        ip     = alert["src_ip"]
        reason = (f"Auto-blocked: {alert['alert_type']} — "
                  f"cumulative threat score {alert.get('cumulative_score', '?')}. "
                  f"Review before applying iptables rule.")
        logger.critical("AUTO-BLOCK FLAGGED: %s — %s", ip, reason)
        logger.critical(
            "Run manually to enforce: iptables -A INPUT -s %s -j DROP", ip
        )
        # Record the block intent in DB but NOTE: this does NOT execute iptables.
        # Executing iptables from application code is dangerous in production.
        # Copy the iptables_cmd from the dashboard and run it manually after review.
        self._db.block_ip(ip, reason, auto=True)
        block_alert = {
            "timestamp":   datetime.utcnow().isoformat(),
            "alert_type":  "IP_BLOCK_RECOMMENDED",
            "severity":    "CRITICAL",
            "src_ip":      ip,
            "description": reason,
            "details": {
                "iptables_cmd": f"iptables -A INPUT -s {ip} -j DROP",
                "warning": (
                    "This is a recommendation only. The rule has NOT been applied "
                    "automatically. Review and run the iptables command manually."
                ),
            },
            "threat_score": 100,
        }
        for cb in self._rt_callbacks:
            try:
                cb(block_alert)
            except Exception:
                pass

    @staticmethod
    def _build_allowlist(entries: list):
        """Parse allowlist entries into ip_network objects."""
        networks = []
        for entry in entries:
            try:
                networks.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                logger.warning("Invalid allowlist entry (skipped): %s", entry)
        return networks
