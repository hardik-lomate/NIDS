"""
core/traffic_analyzer.py
Traffic Analyzer — maintains rolling statistics about network traffic.
Feeds the attack detection engine and the dashboard.
"""

import threading
import time
import logging
from collections import defaultdict, deque
from datetime import datetime
from typing import Dict, Any, List, Optional
from flow_tracker import FlowTracker

logger = logging.getLogger("nids.analyzer")


class TrafficWindow:
    """Sliding time window counter (thread-safe)."""

    def __init__(self, window_seconds: int = 60):
        self.window  = window_seconds
        self._lock   = threading.Lock()
        self._events: deque = deque()   # (timestamp, value)

    def add(self, value: float = 1.0):
        now = time.monotonic()
        with self._lock:
            self._events.append((now, value))
            self._expire(now)

    def count(self) -> int:
        now = time.monotonic()
        with self._lock:
            self._expire(now)
            return len(self._events)

    def sum(self) -> float:
        now = time.monotonic()
        with self._lock:
            self._expire(now)
            return sum(v for _, v in self._events)

    def _expire(self, now: float):
        cutoff = now - self.window
        while self._events and self._events[0][0] < cutoff:
            self._events.popleft()


class PerIPTracker:
    """Per-source-IP rolling counters for each detection dimension."""

    def __init__(self, window_seconds: int = 60):
        self._window  = window_seconds
        self._lock    = threading.Lock()
        # ip → TrafficWindow (general packet count)
        self._packet_windows:  Dict[str, TrafficWindow] = defaultdict(
            lambda: TrafficWindow(self._window))
        # ip → set of ports (for port scan)
        self._port_times:      Dict[str, Dict[int, float]] = defaultdict(dict)
        # ip → TrafficWindow (SYN count)
        self._syn_windows:     Dict[str, TrafficWindow] = defaultdict(
            lambda: TrafficWindow(self._window))
        # ip → TrafficWindow (ICMP count)
        self._icmp_windows:    Dict[str, TrafficWindow] = defaultdict(
            lambda: TrafficWindow(self._window))
        # ip → TrafficWindow (UDP count)
        self._udp_windows:     Dict[str, TrafficWindow] = defaultdict(
            lambda: TrafficWindow(self._window))
        # ip → TrafficWindow (DNS count)
        self._dns_windows:     Dict[str, TrafficWindow] = defaultdict(
            lambda: TrafficWindow(self._window))
        # ip → (dport → attempts) for brute-force
        self._login_windows:   Dict[str, Dict[int, TrafficWindow]] = defaultdict(
            lambda: defaultdict(lambda: TrafficWindow(60)))

    def record_packet(self, ip: str):
        with self._lock:
            self._packet_windows[ip].add()

    def record_port(self, ip: str, port: int) -> int:
        """Return count of distinct ports from this IP in time window."""
        now = time.monotonic()
        with self._lock:
            pt = self._port_times[ip]
            pt[port] = now
            # expire old ports
            cutoff = now - 10  # 10-second scan window
            expired = [p for p, t in pt.items() if t < cutoff]
            for p in expired:
                del pt[p]
            return len(pt)

    def record_syn(self, ip: str) -> int:
        with self._lock:
            w = self._syn_windows[ip]
        w.add()
        return w.count()

    def record_icmp(self, ip: str) -> int:
        with self._lock:
            w = self._icmp_windows[ip]
        w.add()
        return w.count()

    def record_udp(self, ip: str) -> int:
        with self._lock:
            w = self._udp_windows[ip]
        w.add()
        return w.count()

    def record_dns(self, ip: str) -> int:
        with self._lock:
            w = self._dns_windows[ip]
        w.add()
        return w.count()

    def record_login_attempt(self, ip: str, port: int) -> int:
        with self._lock:
            w = self._login_windows[ip][port]
        w.add()
        return w.count()

    def get_packet_rate(self, ip: str) -> int:
        with self._lock:
            return self._packet_windows[ip].count()

    def get_active_ips(self) -> List[str]:
        with self._lock:
            return list(self._packet_windows.keys())


class TrafficAnalyzer:
    """
    Aggregates real-time traffic metrics from parsed packet dicts.
    Maintains:
      - Global packets-per-second / bytes-per-second
      - Per-IP counters (packet rate, port scan, SYN, ICMP, …)
      - Protocol distribution
      - Top talkers / top targeted ports
      - Rolling 60-second timeline for dashboard charts
    """

    TIMELINE_LEN = 120  # points kept in the timeline (seconds)

    def __init__(self, config: Dict[str, Any]):
        self._config     = config
        self._lock       = threading.Lock()
        self.per_ip      = PerIPTracker(window_seconds=60)
        self.flow_tracker = FlowTracker(active_timeout=30) # shortened for tests, normally 300

        # Global 5-second window (smoothed for polling)
        self._global_5s  = TrafficWindow(5)
        self._global_byte_5s = TrafficWindow(5)

        # Protocol tallies (all time)
        self._proto_counts: Dict[str, int] = defaultdict(int)

        # Top-ports tally (all time)
        self._port_counts:  Dict[int, int] = defaultdict(int)

        # IP byte totals (all time, for "top talkers")
        self._ip_bytes:     Dict[str, int] = defaultdict(int)
        self._ip_packets:   Dict[str, int] = defaultdict(int)

        # Rolling 1-second buckets for charting
        self._timeline: deque = deque(maxlen=self.TIMELINE_LEN)
        self._current_bucket: Dict[str, Any] = self._new_bucket()

        # ARP table: ip → set of MACs
        self._arp_table: Dict[str, str] = {}

        # Start periodic ticker
        self._stop  = threading.Event()
        self._timer = threading.Thread(
            target=self._tick_loop, daemon=True, name="TrafficTick"
        )
        self._timer.start()

    # ──────────────────────────────────────────────────────────────

    def process(self, pkt: Dict[str, Any]):
        """Ingest one parsed packet dict."""
        src = pkt.get("src_ip")
        dst = pkt.get("dst_ip")
        proto = pkt.get("protocol", "UNKNOWN")
        size  = pkt.get("size", 0)
        dport = pkt.get("dst_port")
        flags = pkt.get("flags", "")

        self._global_5s.add()
        self._global_byte_5s.add(size)

        self.flow_tracker.process_packet(pkt)

        if src:
            self.per_ip.record_packet(src)
            with self._lock:
                self._ip_bytes[src]   += size
                self._ip_packets[src] += 1

        with self._lock:
            self._proto_counts[proto] += 1
            if dport:
                self._port_counts[dport] += 1

            bucket = self._current_bucket
            bucket["packets"] += 1
            bucket["bytes"]   += size
            bucket[proto.lower() if proto in ("TCP","UDP","ICMP","ARP") else "other"] += 1

        # ── Port scan tracking ────────────────────────────────────
        if src and dport:
            self.per_ip.record_port(src, dport)

        # ── SYN tracking ─────────────────────────────────────────
        if proto == "TCP" and "S" in (flags or "") and "A" not in (flags or ""):
            if src:
                self.per_ip.record_syn(src)

        # ── ICMP tracking ─────────────────────────────────────────
        if proto == "ICMP" and src:
            self.per_ip.record_icmp(src)

        # ── UDP tracking ──────────────────────────────────────────
        if proto == "UDP" and src:
            self.per_ip.record_udp(src)

        # ── DNS tracking ──────────────────────────────────────────
        if pkt.get("is_dns") and src:
            self.per_ip.record_dns(src)

        # ── Brute-force tracking ──────────────────────────────────
        bf_ports = self._config.get("detection", {}).get("brute_force", {}).get("monitored_ports", {})
        if dport and dport in bf_ports and src:
            self.per_ip.record_login_attempt(src, dport)

        # ── ARP table update ──────────────────────────────────────
        if pkt.get("is_arp") and pkt.get("arp_op") == 2:
            # is-at packet: update IP→MAC binding
            with self._lock:
                self._arp_table[pkt["src_ip"]] = pkt.get("src_mac")

    # ──────────────────────────────────────────────────────────────
    # Read-only accessors
    # ──────────────────────────────────────────────────────────────

    def get_pps(self) -> int:
        """Current packets-per-second (5s smoothed average)."""
        return max(1, self._global_5s.count() // 5) if self._global_5s.count() > 0 else 0

    def get_bps(self) -> int:
        """Current bytes-per-second (5s smoothed average)."""
        return int(self._global_byte_5s.sum() / 5)

    def get_protocol_distribution(self) -> Dict[str, int]:
        with self._lock:
            return dict(self._proto_counts)

    def get_top_ports(self, n: int = 10) -> List[tuple]:
        with self._lock:
            return sorted(self._port_counts.items(), key=lambda x: x[1], reverse=True)[:n]

    def get_top_talkers(self, n: int = 10) -> List[Dict]:
        with self._lock:
            items = [(ip, pkt, self._ip_bytes[ip])
                     for ip, pkt in self._ip_packets.items()]
        items.sort(key=lambda x: x[1], reverse=True)
        return [{"ip": ip, "packets": pkts, "bytes": byt} for ip, pkts, byt in items[:n]]

    def get_arp_table(self) -> Dict[str, str]:
        with self._lock:
            return dict(self._arp_table)

    def update_arp_table(self, ip: str, mac: str):
        """Called by attack detector to check ARP spoofing."""
        with self._lock:
            old = self._arp_table.get(ip)
            if old and old != mac:
                return old   # Return the old MAC — signals a change!
            self._arp_table[ip] = mac
            return None

    def get_timeline(self) -> List[Dict]:
        with self._lock:
            return list(self._timeline)

    def get_unique_ips_1min(self) -> int:
        return len(self.per_ip.get_active_ips())

    def get_snapshot(self) -> Dict[str, Any]:
        """Full stats snapshot for dashboard and DB storage."""
        return {
            "timestamp":     datetime.utcnow().isoformat(),
            "pps":           self.get_pps(),
            "bps":           self.get_bps(),
            "protocols":     self.get_protocol_distribution(),
            "top_ports":     self.get_top_ports(),
            "top_talkers":   self.get_top_talkers(),
            "unique_ips":    self.get_unique_ips_1min(),
            "active_flows":  len(self.flow_tracker.get_active_flows()),
            "timeline":      self.get_timeline()[-30:],
        }

    # ──────────────────────────────────────────────────────────────

    @staticmethod
    def _new_bucket() -> Dict[str, Any]:
        return {
            "ts": datetime.utcnow().isoformat(),
            "packets": 0, "bytes": 0,
            "tcp": 0, "udp": 0, "icmp": 0, "arp": 0, "other": 0,
        }

    def _tick_loop(self):
        """Every second, seal the current bucket and start a new one."""
        ticks = 0
        while not self._stop.wait(1):
            with self._lock:
                bucket = self._current_bucket
                self._timeline.append(bucket)
                self._current_bucket = self._new_bucket()

            # Tick the flow tracker cleanup every 5 seconds
            ticks += 1
            if ticks % 5 == 0:
                expired = self.flow_tracker.cleanup_flows()
                # Optionally emit expired flows to a SIEM or long-term storage
                # if expired:
                #     logger.debug(f"Expired {len(expired)} flows")

    def stop(self):
        self._stop.set()
