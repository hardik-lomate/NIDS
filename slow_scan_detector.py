"""
core/slow_scan_detector.py
Slow Scan Detector — catches port scanners that deliberately stay
under short-window thresholds by using a much longer observation window.

The standard port scan rule (20 ports / 10 seconds) is trivially bypassed
by scanning 1 port every 10 seconds. This module tracks port contact over
a 10-minute window and fires on patterns that the fast rule misses.

Limitations this module does NOT solve:
- An attacker scanning 1 port per hour will still evade detection.
- We have no TCP state machine, so we cannot distinguish SYN-only probes
  from legitimate connection attempts at the packet level alone.
- IP rotation (1 scan per IP across many source IPs) is not tracked here.
  That requires correlation across IPs — a much harder problem.
"""

import time
import threading
import logging
from collections import defaultdict
from datetime import datetime
from typing import Dict, Any, Optional, List, Callable

logger = logging.getLogger("nids.slowscan")


class SlowScanDetector:
    """
    Tracks port contact per source IP over a configurable long window
    (default: 10 minutes). Fires when unique port count exceeds a threshold
    that would not trigger the fast scanner rule.

    Design decision: we keep this as a separate module so it can be toggled
    independently and so its longer-lived state doesn't affect the fast
    detection loop's latency.
    """

    def __init__(self, config: Dict[str, Any]):
        det = config.get("detection", {})
        slow_cfg = det.get("slow_scan", {})

        self.enabled     = slow_cfg.get("enabled", True)
        self.threshold   = slow_cfg.get("threshold", 50)    # distinct ports
        self.window      = slow_cfg.get("time_window", 600) # 10 minutes
        self.severity    = slow_cfg.get("severity", "MEDIUM")

        # ip → {port: last_seen_monotonic}
        self._port_log: Dict[str, Dict[int, float]] = defaultdict(dict)
        self._lock      = threading.Lock()

        # Cooldown: ip → last_alert_monotonic
        self._alerted: Dict[str, float] = {}
        self._cooldown = 300  # re-alert at most once per 5 minutes per IP

        self._callbacks: List[Callable[[Dict], None]] = []

        if self.enabled:
            # Cleanup thread — prune expired entries every 60 seconds
            self._stop = threading.Event()
            t = threading.Thread(target=self._cleanup_loop, daemon=True, name="SlowScanGC")
            t.start()

    def register_callback(self, fn: Callable[[Dict], None]):
        self._callbacks.append(fn)

    def process(self, pkt: Dict[str, Any]):
        if not self.enabled:
            return
        src_ip = pkt.get("src_ip")
        dport  = pkt.get("dst_port")
        proto  = pkt.get("protocol", "")

        if not src_ip or not dport or proto not in ("TCP", "UDP"):
            return

        now    = time.monotonic()
        cutoff = now - self.window

        with self._lock:
            log = self._port_log[src_ip]
            log[dport] = now

            # Expire ports outside the window
            expired = [p for p, t in log.items() if t < cutoff]
            for p in expired:
                del log[p]

            count = len(log)

        if count < self.threshold:
            return

        # Cooldown check
        now_wall = time.monotonic()
        with self._lock:
            last = self._alerted.get(src_ip, 0)
            if now_wall - last < self._cooldown:
                return
            self._alerted[src_ip] = now_wall

        alert = {
            "timestamp":   datetime.utcnow().isoformat(),
            "alert_type":  "SLOW_PORT_SCAN",
            "severity":    self.severity,
            "src_ip":      src_ip,
            "description": (
                f"Slow port scan detected from {src_ip}: "
                f"{count} distinct ports contacted over {self.window}s window. "
                f"This pattern evades fast-window rules — manually verify."
            ),
            "details": {
                "ports_seen":  count,
                "time_window": self.window,
                "threshold":   self.threshold,
                "note": (
                    "Slow scans are harder to distinguish from legitimate "
                    "multi-service access. Investigate before blocking."
                ),
            },
            "threat_score": 20,
        }

        logger.warning("[SLOW_PORT_SCAN] %s — %d ports in %ds window",
                       src_ip, count, self.window)
        for cb in self._callbacks:
            try:
                cb(alert)
            except Exception as exc:
                logger.error("SlowScan callback error: %s", exc)

    def _cleanup_loop(self):
        while not self._stop.wait(60):
            now    = time.monotonic()
            cutoff = now - self.window
            with self._lock:
                for ip in list(self._port_log.keys()):
                    log = self._port_log[ip]
                    expired = [p for p, t in log.items() if t < cutoff]
                    for p in expired:
                        del log[p]
                    if not log:
                        del self._port_log[ip]

    def stop(self):
        if self.enabled:
            self._stop.set()
