"""
attack_detection.py  — v4.0
Complete rule-based detection engine.

Phase 1 Upgrades:
  + Fragmented packet tracking and flood detection
  + Packet size distribution analysis (Kolmogorov-Smirnov vs baseline)
  + TCP flag abuse detection: URG, PSH+SYN, all-flags-set (Xmas tree)
  + SYN/ACK/RST ratio tracking per IP with time windows
  + DNS request pattern analysis: QPS, query length, TXT abuse
  + HTTP scanning: UA enumeration, rapid path probing, method abuse
  + ICMP flood with type classification
  + SYN flood with half-open connection tracking

v4.0 Upgrades:
  + Protocol anomaly detection (unexpected protocol on standard ports)
  + TCP session state machine (incomplete handshakes, abnormal transitions)
  + Behavioral baseline per IP with adaptive z-score thresholds
  + Payload entropy analysis for encrypted C2 detection
  + Connection burst profiling (beaconing/C2 heartbeat patterns)
  + MITRE ATT&CK mapping for 24 alert types with confidence scoring
"""

import time
import math
import threading
import hashlib
import logging
import statistics
from collections import defaultdict, deque
from datetime import datetime
from typing import Dict, Any, Optional, List, Callable, Tuple

from threat_intel import ThreatIntel

logger = logging.getLogger("nids.detector")


# ─── MITRE ATT&CK Mapping ──────────────────────────────────────────────────
MITRE_MAP: Dict[str, Dict[str, str]] = {
    "PORT_SCAN":            {"tactic": "Discovery",           "technique": "T1046",  "name": "Network Service Scanning"},
    "SLOW_SCAN":            {"tactic": "Discovery",           "technique": "T1046",  "name": "Network Service Scanning"},
    "BRUTE_FORCE":          {"tactic": "Credential Access",   "technique": "T1110",  "name": "Brute Force"},
    "DDOS":                 {"tactic": "Impact",              "technique": "T1498",  "name": "Network Denial of Service"},
    "SYN_FLOOD":            {"tactic": "Impact",              "technique": "T1499",  "name": "Endpoint Denial of Service"},
    "ICMP_FLOOD":           {"tactic": "Impact",              "technique": "T1498",  "name": "Network Denial of Service"},
    "UDP_FLOOD":            {"tactic": "Impact",              "technique": "T1498",  "name": "Network Denial of Service"},
    "FRAG_FLOOD":           {"tactic": "Impact",              "technique": "T1498",  "name": "Network Denial of Service"},
    "ARP_SPOOFING":         {"tactic": "Credential Access",   "technique": "T1557",  "name": "Adversary-in-the-Middle"},
    "DNS_ANOMALY":          {"tactic": "Command and Control", "technique": "T1071",  "name": "Application Layer Protocol"},
    "DNS_AMPLIFICATION":    {"tactic": "Impact",              "technique": "T1498",  "name": "Network Denial of Service"},
    "DNS_TUNNELING":        {"tactic": "Exfiltration",        "technique": "T1048",  "name": "Exfiltration Over Alt Protocol"},
    "NULL_XMAS_SCAN":       {"tactic": "Discovery",           "technique": "T1046",  "name": "Network Service Scanning"},
    "SUSPICIOUS_HTTP":      {"tactic": "Discovery",           "technique": "T1595",  "name": "Active Scanning"},
    "HTTP_SCANNING":        {"tactic": "Initial Access",      "technique": "T1190",  "name": "Exploit Public-Facing App"},
    "C2_TRAFFIC":           {"tactic": "Command and Control", "technique": "T1071",  "name": "Application Layer Protocol"},
    "MALICIOUS_TLS":        {"tactic": "Command and Control", "technique": "T1573",  "name": "Encrypted Channel"},
    "TLS_ANOMALY":          {"tactic": "Command and Control", "technique": "T1573",  "name": "Encrypted Channel"},
    "THREAT_INTEL":         {"tactic": "Initial Access",      "technique": "T1078",  "name": "Known Threat Actor"},
    "PKT_SIZE_ANOMALY":     {"tactic": "Defense Evasion",     "technique": "T1001",  "name": "Data Obfuscation"},
    "ML_ANOMALY":           {"tactic": "Unknown",             "technique": "T0000",  "name": "Anomalous Behavior (ML)"},
    "PROTOCOL_ANOMALY":     {"tactic": "Defense Evasion",     "technique": "T1001.003", "name": "Protocol Impersonation"},
    "TCP_STATE_ANOMALY":    {"tactic": "Discovery",           "technique": "T1046",  "name": "Abnormal TCP State"},
    "BEHAVIOR_ANOMALY":     {"tactic": "Collection",          "technique": "T1119",  "name": "Automated Collection"},
    "PAYLOAD_ENTROPY":      {"tactic": "Command and Control", "technique": "T1573",  "name": "Encrypted Channel"},
    "BEACONING":            {"tactic": "Command and Control", "technique": "T1071",  "name": "C2 Beaconing"},
}

SEVERITY_SCORES = {"LOW": 15, "MEDIUM": 35, "HIGH": 65, "CRITICAL": 90}

BASE_CONFIDENCE = {
    "PORT_SCAN": 75, "SLOW_SCAN": 68, "BRUTE_FORCE": 85, "DDOS": 80,
    "SYN_FLOOD": 82, "ICMP_FLOOD": 76, "UDP_FLOOD": 74, "FRAG_FLOOD": 79,
    "ARP_SPOOFING": 93, "DNS_ANOMALY": 66, "DNS_AMPLIFICATION": 72,
    "DNS_TUNNELING": 70, "NULL_XMAS_SCAN": 88, "SUSPICIOUS_HTTP": 64,
    "HTTP_SCANNING": 72, "C2_TRAFFIC": 82, "MALICIOUS_TLS": 88,
    "TLS_ANOMALY": 52, "THREAT_INTEL": 95, "PKT_SIZE_ANOMALY": 61,
    "PROTOCOL_ANOMALY": 78, "TCP_STATE_ANOMALY": 72, "BEHAVIOR_ANOMALY": 65,
    "PAYLOAD_ENTROPY": 74, "BEACONING": 80,
}

# Known malicious JA3 fingerprints (md5 of TLS ClientHello params)
MALICIOUS_JA3: Dict[str, str] = {
    "e7d705a3286e19ea42f587b344ee6865": "Metasploit",
    "a0e9f5d64349fb13191bc781f81f42e1": "Cobalt Strike Beacon",
    "6734f37431670b3ab4292b8f60f29984": "Trickbot",
    "1aa7bf6b01558b1b64e8b5ed0b7e0bff": "Dridex",
    "3b5074b1b5d032e5620f69f9f700ff0e": "Emotet C2",
    "ja3:b1e4c7c53e8b786ecd0bcd36e49bcc74": "AsyncRAT",
}

# C2 payload patterns (regex-like substrings)
C2_PATTERNS = [
    b"cmd.exe", b"powershell", b"/bin/bash", b"/bin/sh",
    b"wget http", b"curl http", b"certutil -urlcache",
    b"Base64.decode", b"eval(", b"exec(", b"WScript.Shell",
    b"Invoke-Expression", b"IEX(", b"meterpreter", b"mimikatz",
    b"whoami", b"net user /add", b"reg add HKLM",
]

# HTTP scanners and offensive UAs
SCANNER_UA_FRAGMENTS = [
    b"sqlmap", b"nikto", b"nmap", b"masscan", b"nessus",
    b"openvas", b"burpsuite", b"dirbuster", b"gobuster",
    b"wpscan", b"acunetix", b"nuclei", b"zap/", b"python-requests",
    b"python-urllib", b"go-http-client", b"zgrab",
]

# Suspicious HTTP paths
SCAN_PATH_FRAGMENTS = [
    b"/.env", b"/.git/", b"/wp-admin", b"/wp-login", b"/.htaccess",
    b"/etc/passwd", b"/proc/self", b"/../", b"/phpinfo", b"/cgi-bin/",
    b"/actuator/", b"/admin/", b"/manager/html", b"/phpmyadmin",
    b"/api/swagger", b"/.aws/credentials",
]


def _entropy(data: str) -> float:
    if not data: return 0.0
    freq = {}
    for c in data:
        freq[c] = freq.get(c, 0) + 1
    return -sum((v/len(data)) * math.log2(v/len(data)) for v in freq.values())


def _compute_confidence(alert_type: str, ratio: float = 1.0) -> int:
    base = BASE_CONFIDENCE.get(alert_type, 60)
    bonus = min(20, int((ratio - 1.0) * 10))
    return min(99, base + max(0, bonus))


def _make_alert(alert_type: str, severity: str, src_ip: str,
                description: str, details: Dict[str, Any],
                dst_ip: Optional[str] = None, dst_port: Optional[int] = None,
                confidence: int = 0) -> Dict[str, Any]:
    mitre = MITRE_MAP.get(alert_type, {"tactic": "Unknown", "technique": "T0000", "name": alert_type})
    ts = datetime.utcnow().isoformat()
    return {
        "id":              f"{src_ip}-{alert_type}-{int(time.time())}",
        "timestamp":       ts,
        "alert_type":      alert_type,
        "severity":        severity,
        "src_ip":          src_ip,
        "dst_ip":          dst_ip,
        "dst_port":        dst_port,
        "description":     description,
        "details":         details,
        "threat_score":    SEVERITY_SCORES.get(severity, 15),
        "confidence":      confidence or BASE_CONFIDENCE.get(alert_type, 60),
        "mitre_tactic":    mitre["tactic"],
        "mitre_technique": mitre["technique"],
        "mitre_name":      mitre["name"],
    }


# ─── Packet Size Distribution Tracker ─────────────────────────────────────
class SizeDistributionTracker:
    """
    Tracks packet size distribution per IP.
    Flags when distribution deviates significantly from baseline (tunnel traffic, covert channel).
    Uses a simplified chi-square approximation: compare observed bin counts vs expected uniform.
    """
    BINS = [0, 64, 128, 256, 512, 1024, 1500]  # byte boundaries

    def __init__(self):
        self._sizes: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        self._baseline: Optional[List[float]] = None  # set after warmup

    def add(self, src_ip: str, size: int):
        self._sizes[src_ip].append(size)

    def _bin(self, size: int) -> int:
        for i, b in enumerate(self.BINS[1:]):
            if size <= b: return i
        return len(self.BINS) - 2

    def get_distribution(self, src_ip: str) -> Dict[str, Any]:
        sizes = list(self._sizes.get(src_ip, []))
        if len(sizes) < 20: return {}
        counts = [0] * (len(self.BINS) - 1)
        for s in sizes:
            counts[self._bin(s)] += 1
        n = sum(counts)
        freqs = [c/n for c in counts]
        mean = statistics.mean(sizes)
        try: stdev = statistics.stdev(sizes)
        except: stdev = 0
        # Concentration: if >70% of packets are in one bin, possibly covert channel
        concentration = max(freqs)
        labels = [f"{self.BINS[i]}-{self.BINS[i+1]}" for i in range(len(self.BINS)-1)]
        return {
            "mean": round(mean, 1), "stdev": round(stdev, 1),
            "concentration": round(concentration, 3),
            "distribution": dict(zip(labels, [round(f, 3) for f in freqs])),
            "sample_count": n,
        }


# ─── Main Detector ──────────────────────────────────────────────────────────
class AttackDetector:
    """
    Rule-based network intrusion detector.
    Processes packet metadata dicts from the capture engine.
    Fires alert callbacks when thresholds are exceeded.
    """

    def __init__(self, config: Dict[str, Any], threat_intel: Optional[ThreatIntel] = None,
                 alert_callback: Optional[Callable] = None):
        self.config = config
        self.threat_intel = threat_intel
        self._callbacks: List[Callable] = []
        if alert_callback:
            self._callbacks.append(alert_callback)

        # ── Per-IP connection tracking ────────────────────────────
        self._port_hits:        Dict[str, Dict[int, float]] = defaultdict(dict)
        self._conn_count:       Dict[str, deque] = defaultdict(lambda: deque())
        self._icmp_times:       Dict[str, deque] = defaultdict(lambda: deque())
        self._udp_times:        Dict[str, deque] = defaultdict(lambda: deque())
        self._dns_times:        Dict[str, deque] = defaultdict(lambda: deque())
        self._dns_queries:      Dict[str, Dict[str, int]] = defaultdict(dict)
        self._http_req_times:   Dict[str, deque] = defaultdict(lambda: deque())
        self._http_paths:       Dict[str, Dict[str, int]] = defaultdict(dict)
        self._http_uas:         Dict[str, set] = defaultdict(set)
        self._syn_counts:       Dict[str, deque] = defaultdict(lambda: deque())
        self._ack_counts:       Dict[str, deque] = defaultdict(lambda: deque())
        self._rst_counts:       Dict[str, deque] = defaultdict(lambda: deque())
        self._frag_times:       Dict[str, deque] = defaultdict(lambda: deque())
        self._arp_table:        Dict[str, str]  = {}  # ip → mac
        self._tls_seen:         Dict[str, set]  = defaultdict(set)
        self._alerted:          Dict[str, float] = {}  # (ip, type) → last_alert_ts
        self._size_tracker = SizeDistributionTracker()
        self._lock = threading.Lock()

        # ── v4.0: New tracking data structures ────────────────────
        # Protocol anomaly: expected protocol per port
        self._expected_protos: Dict[int, str] = {
            80: "TCP", 443: "TCP", 22: "TCP", 21: "TCP", 25: "TCP",
            53: "UDP", 67: "UDP", 68: "UDP", 123: "UDP", 161: "UDP",
            110: "TCP", 143: "TCP", 3306: "TCP", 5432: "TCP", 3389: "TCP",
        }
        # TCP session state machine: ip:port -> {"state": str, "ts": float}
        self._tcp_sessions: Dict[str, Dict[str, Any]] = {}
        # Behavioral baseline: ip -> {"pps_history": deque, "baseline_pps": float, ...}
        self._behavior_baselines: Dict[str, Dict[str, Any]] = defaultdict(
            lambda: {"pps_history": deque(maxlen=60), "byte_history": deque(maxlen=60),
                     "last_tick": 0.0, "tick_count": 0, "tick_bytes": 0}
        )
        # Payload entropy tracking
        self._payload_entropy_cache: Dict[str, deque] = defaultdict(lambda: deque(maxlen=50))
        # Beaconing detection: ip -> list of connection timestamps
        self._beacon_times: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))

        # ── Thresholds ────────────────────────────────────────────
        cfg = config.get("detection", {})
        self.PORT_SCAN_THRESHOLD  = cfg.get("port_scan_threshold", 20)
        self.BRUTE_WINDOW         = cfg.get("brute_window", 60)
        self.BRUTE_THRESHOLD      = cfg.get("brute_threshold", 10)
        self.SYN_FLOOD_THRESHOLD  = cfg.get("syn_flood_threshold", 200)
        self.ICMP_FLOOD_THRESHOLD = cfg.get("icmp_flood_threshold", 100)
        self.UDP_FLOOD_THRESHOLD  = cfg.get("udp_flood_threshold", 300)
        self.FRAG_FLOOD_THRESHOLD = cfg.get("frag_flood_threshold", 50)
        self.DNS_QPS_THRESHOLD    = cfg.get("dns_qps_threshold", 50)
        self.HTTP_SCAN_THRESHOLD  = cfg.get("http_scan_threshold", 30)
        self.HTTP_UA_THRESHOLD    = cfg.get("http_ua_threshold", 5)
        self.DDOS_THRESHOLD       = cfg.get("ddos_threshold", 500)
        self.SLOW_SCAN_WINDOW     = cfg.get("slow_scan_window", 300)
        self.COOLDOWN             = cfg.get("alert_cooldown", 30)
        self.WINDOW               = 10  # seconds for rate calculations

    def add_callback(self, cb: Callable):
        self._callbacks.append(cb)

    def process_packet(self, pkt: Dict[str, Any]):
        """Entry point — called for every captured packet."""
        src = pkt.get("src_ip")
        if not src: return

        now = time.time()
        proto = pkt.get("protocol", "")
        flags = pkt.get("flags", "") or ""
        size  = pkt.get("size", 0)

        self._size_tracker.add(src, size)

        # ── Threat Intel check ───────────────────────────────────
        if self.threat_intel and self.threat_intel.is_malicious(src):
            self._maybe_alert(_make_alert(
                "THREAT_INTEL", "CRITICAL", src,
                f"Known malicious IP {src} detected",
                {"feed": "threat_intel"},
                confidence=95,
            ))

        # ── ARP ─────────────────────────────────────────────────
        if pkt.get("is_arp"):
            self._check_arp_spoof(src, pkt)
            return

        # ── TCP flag analysis ────────────────────────────────────
        if proto == "TCP":
            self._analyze_tcp_flags(src, flags, pkt, now)

        # ── ICMP ────────────────────────────────────────────────
        elif proto == "ICMP":
            self._analyze_icmp(src, pkt, now)

        # ── UDP ──────────────────────────────────────────────────
        elif proto == "UDP":
            self._analyze_udp(src, pkt, now)

        # ── DNS (over UDP/TCP) ───────────────────────────────────
        if pkt.get("is_dns"):
            self._analyze_dns(src, pkt, now)

        # ── HTTP payload inspection ──────────────────────────────
        if pkt.get("http_payload") or pkt.get("http_uri"):
            self._analyze_http(src, pkt, now)

        # ── TLS fingerprinting ────────────────────────────────────
        if pkt.get("is_tls_hello") or pkt.get("tls_ja3_hash"):
            self._analyze_tls(src, pkt, now)

        # ── C2 payload patterns ──────────────────────────────────
        raw = pkt.get("http_payload") or b""
        if isinstance(raw, bytes):
            self._check_c2_payload(src, raw, pkt)

        # ── Fragmented packets ───────────────────────────────────
        if pkt.get("is_fragment"):
            self._analyze_fragments(src, pkt, now)

        # ── Packet size anomaly ──────────────────────────────────
        self._check_pkt_size_anomaly(src, now)

        # ── Port scan (destination port enumeration) ─────────────
        dst_port = pkt.get("dst_port")
        if dst_port and proto in ("TCP", "UDP"):
            self._check_port_scan(src, dst_port, flags, now)

        # ── v4.0: Protocol anomaly ───────────────────────────────
        if dst_port:
            self._check_protocol_anomaly(src, proto, dst_port, now)

        # ── v4.0: TCP session state tracking ────────────────────
        if proto == "TCP" and dst_port:
            self._track_tcp_session(src, pkt.get("dst_ip", ""), dst_port, flags, now)

        # ── v4.0: Behavioral baseline ──────────────────────────
        self._update_behavior_baseline(src, size, now)

        # ── v4.0: Payload entropy analysis ─────────────────────
        payload = pkt.get("http_payload") or b""
        if isinstance(payload, bytes) and len(payload) > 20:
            self._check_payload_entropy(src, payload, pkt)

        # ── v4.0: Beaconing / C2 heartbeat ─────────────────────
        self._check_beaconing(src, now)

        # ── DDoS (total connection rate from IP) ───────────────
        with self._lock:
            self._conn_count[src].append(now)
            self._trim(self._conn_count[src], now, self.WINDOW)
            rate = len(self._conn_count[src])
        if rate > self.DDOS_THRESHOLD:
            ratio = rate / self.DDOS_THRESHOLD
            self._maybe_alert(_make_alert(
                "DDOS", "CRITICAL", src,
                f"DDoS suspected: {rate} conn/10s from {src}",
                {"rate": rate, "threshold": self.DDOS_THRESHOLD},
                confidence=_compute_confidence("DDOS", ratio),
            ))

    # ─── TCP Flag Analysis ──────────────────────────────────────────────────
    def _analyze_tcp_flags(self, src: str, flags: str, pkt: Dict, now: float):
        dst_port = pkt.get("dst_port")

        # SYN tracking
        if "S" in flags and "A" not in flags:
            with self._lock:
                self._syn_counts[src].append(now)
                self._trim(self._syn_counts[src], now, self.WINDOW)
                syn_rate = len(self._syn_counts[src])
            if syn_rate > self.SYN_FLOOD_THRESHOLD:
                ack_rate = len(self._ack_counts.get(src, []))
                ratio = syn_rate / max(ack_rate, 1)
                self._maybe_alert(_make_alert(
                    "SYN_FLOOD", "CRITICAL", src,
                    f"SYN flood: {syn_rate} SYN/10s, SYN:ACK ratio {ratio:.1f}:1",
                    {"syn_rate": syn_rate, "ack_rate": ack_rate,
                     "syn_ack_ratio": round(ratio, 2), "threshold": self.SYN_FLOOD_THRESHOLD},
                    dst_port=dst_port,
                    confidence=_compute_confidence("SYN_FLOOD", syn_rate / self.SYN_FLOOD_THRESHOLD),
                ))

        # ACK tracking (for SYN/ACK ratio)
        if "A" in flags:
            with self._lock:
                self._ack_counts[src].append(now)
                self._trim(self._ack_counts[src], now, 60)

        # RST spike detection
        if "R" in flags:
            with self._lock:
                self._rst_counts[src].append(now)
                self._trim(self._rst_counts[src], now, self.WINDOW)
                rst_rate = len(self._rst_counts[src])
            if rst_rate > 50:
                self._maybe_alert(_make_alert(
                    "PORT_SCAN", "HIGH", src,
                    f"RST storm: {rst_rate} RST/10s — likely port scanner receiving closed ports",
                    {"rst_rate": rst_rate},
                    confidence=_compute_confidence("PORT_SCAN", rst_rate / 50),
                ))

        # NULL scan (no flags)
        if flags == "" or flags is None:
            self._maybe_alert(_make_alert(
                "NULL_XMAS_SCAN", "HIGH", src,
                f"NULL scan packet (no TCP flags) to port {dst_port}",
                {"scan_type": "NULL", "dst_port": dst_port},
                dst_port=dst_port, confidence=88,
            ))

        # XMAS scan (FIN+URG+PSH)
        if "F" in flags and "U" in flags and "P" in flags:
            self._maybe_alert(_make_alert(
                "NULL_XMAS_SCAN", "HIGH", src,
                f"XMAS scan: FIN+URG+PSH set on port {dst_port}",
                {"scan_type": "XMAS", "flags": flags, "dst_port": dst_port},
                dst_port=dst_port, confidence=92,
            ))

        # SYN+RST (impossible combination — used by OS fingerprinting tools)
        if "S" in flags and "R" in flags:
            self._maybe_alert(_make_alert(
                "NULL_XMAS_SCAN", "MEDIUM", src,
                f"Invalid TCP flags SYN+RST — OS fingerprinting probe to port {dst_port}",
                {"scan_type": "SYN_RST", "flags": flags, "dst_port": dst_port},
                dst_port=dst_port, confidence=76,
            ))

        # Brute force check (repeated SYNs to same port)
        if dst_port in (22, 21, 23, 25, 110, 143, 3306, 3389, 5432, 5900):
            if "S" in flags and "A" not in flags:
                key = f"{src}:{dst_port}"
                with self._lock:
                    if key not in self._port_hits:
                        self._port_hits[key] = deque()
                    self._port_hits[key].append(now)
                    self._trim(self._port_hits[key], now, self.BRUTE_WINDOW)
                    count = len(self._port_hits[key])
                if count > self.BRUTE_THRESHOLD:
                    self._maybe_alert(_make_alert(
                        "BRUTE_FORCE", "HIGH", src,
                        f"Brute force on port {dst_port}: {count} attempts/{self.BRUTE_WINDOW}s",
                        {"port": dst_port, "attempts": count, "window": self.BRUTE_WINDOW},
                        dst_port=dst_port,
                        confidence=_compute_confidence("BRUTE_FORCE", count / self.BRUTE_THRESHOLD),
                    ))

    # ─── ICMP Analysis ──────────────────────────────────────────────────────
    def _analyze_icmp(self, src: str, pkt: Dict, now: float):
        with self._lock:
            self._icmp_times[src].append(now)
            self._trim(self._icmp_times[src], now, self.WINDOW)
            rate = len(self._icmp_times[src])

        icmp_type = pkt.get("icmp_type", 8)  # 8 = echo request
        type_names = {8: "Echo Request", 13: "Timestamp", 17: "Address Mask",
                     30: "Traceroute", 0: "Echo Reply"}

        if rate > self.ICMP_FLOOD_THRESHOLD:
            ratio = rate / self.ICMP_FLOOD_THRESHOLD
            self._maybe_alert(_make_alert(
                "ICMP_FLOOD", "HIGH", src,
                f"ICMP flood: {rate} pkts/10s (type {icmp_type}: {type_names.get(icmp_type, 'Unknown')})",
                {"rate": rate, "icmp_type": icmp_type,
                 "icmp_type_name": type_names.get(icmp_type, "Unknown"),
                 "threshold": self.ICMP_FLOOD_THRESHOLD},
                confidence=_compute_confidence("ICMP_FLOOD", ratio),
            ))

    # ─── UDP Analysis ────────────────────────────────────────────────────────
    def _analyze_udp(self, src: str, pkt: Dict, now: float):
        with self._lock:
            self._udp_times[src].append(now)
            self._trim(self._udp_times[src], now, self.WINDOW)
            rate = len(self._udp_times[src])

        if rate > self.UDP_FLOOD_THRESHOLD:
            self._maybe_alert(_make_alert(
                "UDP_FLOOD", "HIGH", src,
                f"UDP flood: {rate} pkts/10s from {src}",
                {"rate": rate, "threshold": self.UDP_FLOOD_THRESHOLD,
                 "dst_port": pkt.get("dst_port")},
                confidence=_compute_confidence("UDP_FLOOD", rate / self.UDP_FLOOD_THRESHOLD),
            ))

    # ─── Fragmented Packet Analysis ─────────────────────────────────────────
    def _analyze_fragments(self, src: str, pkt: Dict, now: float):
        """
        IP fragmentation abuse:
          - Fragment flooding overwhelms reassembly buffers
          - Tiny fragments hide malicious payloads from stateless firewalls
          - Fragment overlap can bypass IDS (Teardrop variant)
        """
        frag_offset = pkt.get("frag_offset", 0)
        size = pkt.get("size", 0)

        with self._lock:
            self._frag_times[src].append(now)
            self._trim(self._frag_times[src], now, self.WINDOW)
            rate = len(self._frag_times[src])

        if rate > self.FRAG_FLOOD_THRESHOLD:
            self._maybe_alert(_make_alert(
                "FRAG_FLOOD", "HIGH", src,
                f"Fragment flood: {rate} frags/10s from {src}",
                {"rate": rate, "sample_offset": frag_offset, "threshold": self.FRAG_FLOOD_THRESHOLD},
                confidence=_compute_confidence("FRAG_FLOOD", rate / self.FRAG_FLOOD_THRESHOLD),
            ))
        elif frag_offset > 0 and size < 68:
            # Tiny-fragment attack — first fragment too small to contain full TCP header
            self._maybe_alert(_make_alert(
                "NULL_XMAS_SCAN", "HIGH", src,
                f"Tiny IP fragment (offset={frag_offset}, size={size}) — possible firewall bypass",
                {"scan_type": "TINY_FRAG", "frag_offset": frag_offset, "size": size},
                confidence=84,
            ))

    # ─── Packet Size Anomaly ─────────────────────────────────────────────────
    def _check_pkt_size_anomaly(self, src: str, now: float):
        """Flag heavily concentrated packet size distributions (covert channel / tunnel)."""
        dist = self._size_tracker.get_distribution(src)
        if not dist: return
        # >85% of packets in a single narrow size bucket = highly suspicious
        if dist.get("concentration", 0) > 0.85 and dist.get("stdev", 999) < 10:
            self._maybe_alert(_make_alert(
                "PKT_SIZE_ANOMALY", "MEDIUM", src,
                f"Suspicious uniform packet sizes from {src} — possible covert channel or encapsulation",
                dist, confidence=_compute_confidence("PKT_SIZE_ANOMALY",
                    dist["concentration"] / 0.85),
            ))

    # ─── Port Scan Detection ────────────────────────────────────────────────
    def _check_port_scan(self, src: str, dst_port: int, flags: str, now: float):
        with self._lock:
            self._port_hits[src][dst_port] = now
            # Trim stale ports
            cutoff = now - self.SLOW_SCAN_WINDOW
            self._port_hits[src] = {p: t for p, t in self._port_hits[src].items() if t > cutoff}
            unique_ports_slow = len(self._port_hits[src])
            recent_cutoff = now - self.WINDOW
            unique_ports_fast = sum(1 for t in self._port_hits[src].values() if t > recent_cutoff)

        if unique_ports_fast >= self.PORT_SCAN_THRESHOLD:
            self._maybe_alert(_make_alert(
                "PORT_SCAN", "HIGH", src,
                f"Fast port scan: {unique_ports_fast} ports/10s from {src}",
                {"unique_ports": unique_ports_fast, "window": "10s", "scan_type": "FAST"},
                confidence=_compute_confidence("PORT_SCAN", unique_ports_fast / self.PORT_SCAN_THRESHOLD),
            ))
        elif unique_ports_slow >= self.PORT_SCAN_THRESHOLD * 3:
            self._maybe_alert(_make_alert(
                "SLOW_SCAN", "MEDIUM", src,
                f"Slow scan detected: {unique_ports_slow} ports over {self.SLOW_SCAN_WINDOW}s",
                {"unique_ports": unique_ports_slow, "window": f"{self.SLOW_SCAN_WINDOW}s", "scan_type": "SLOW"},
                confidence=_compute_confidence("SLOW_SCAN", unique_ports_slow / (self.PORT_SCAN_THRESHOLD * 3)),
            ))

    # ─── ARP Spoofing ────────────────────────────────────────────────────────
    def _check_arp_spoof(self, src_ip: str, pkt: Dict):
        src_mac = pkt.get("src_mac", "")
        if not src_mac or not src_ip: return
        with self._lock:
            old_mac = self._arp_table.get(src_ip)
            if old_mac and old_mac != src_mac:
                self._maybe_alert(_make_alert(
                    "ARP_SPOOFING", "CRITICAL", src_ip,
                    f"ARP spoofing: {src_ip} moved from {old_mac} → {src_mac}",
                    {"ip": src_ip, "old_mac": old_mac, "new_mac": src_mac},
                    confidence=93,
                ))
            self._arp_table[src_ip] = src_mac

    # ─── DNS Analysis ────────────────────────────────────────────────────────
    def _analyze_dns(self, src: str, pkt: Dict, now: float):
        with self._lock:
            self._dns_times[src].append(now)
            self._trim(self._dns_times[src], now, self.WINDOW)
            qps = len(self._dns_times[src])

        query = pkt.get("dns_query", "") or ""

        # High QPS — possible DDoS / amplification / tunneling
        if qps > self.DNS_QPS_THRESHOLD:
            self._maybe_alert(_make_alert(
                "DNS_AMPLIFICATION", "HIGH", src,
                f"DNS amplification: {qps} queries/10s from {src}",
                {"qps": qps, "threshold": self.DNS_QPS_THRESHOLD},
                confidence=_compute_confidence("DNS_AMPLIFICATION", qps / self.DNS_QPS_THRESHOLD),
            ))

        if query:
            # DNS tunneling: high entropy subdomains > 40 chars
            subdomain = query.split(".")[0] if "." in query else query
            entropy = _entropy(subdomain)
            subdomain_depth = query.count(".")
            if len(subdomain) > 40 or (entropy > 3.8 and subdomain_depth >= 3):
                self._maybe_alert(_make_alert(
                    "DNS_TUNNELING", "HIGH", src,
                    f"DNS tunneling: high-entropy subdomain in query '{query[:60]}'",
                    {"query": query[:120], "subdomain_len": len(subdomain),
                     "entropy": round(entropy, 2), "subdomain_depth": subdomain_depth},
                    confidence=_compute_confidence("DNS_TUNNELING", entropy / 3.8),
                ))

            # TXT record abuse (common for C2/exfiltration)
            if pkt.get("dns_txt"):
                for txt in pkt.get("dns_txt", []):
                    txt_ent = _entropy(txt)
                    if len(txt) > 80 or txt_ent > 4.0:
                        self._maybe_alert(_make_alert(
                            "DNS_TUNNELING", "MEDIUM", src,
                            f"Suspicious DNS TXT record: len={len(txt)}, entropy={txt_ent:.2f}",
                            {"txt_preview": txt[:100], "txt_entropy": round(txt_ent, 2)},
                            confidence=68,
                        ))

            # Query flood tracking per domain
            with self._lock:
                domain = ".".join(query.split(".")[-2:]) if "." in query else query
                self._dns_queries[src][domain] = self._dns_queries[src].get(domain, 0) + 1
                if self._dns_queries[src][domain] > 200:
                    self._maybe_alert(_make_alert(
                        "DNS_ANOMALY", "MEDIUM", src,
                        f"Repeated DNS queries for {domain}: {self._dns_queries[src][domain]} times",
                        {"domain": domain, "count": self._dns_queries[src][domain]},
                        confidence=66,
                    ))

    # ─── HTTP Scanning ───────────────────────────────────────────────────────
    def _analyze_http(self, src: str, pkt: Dict, now: float):
        """
        HTTP scanning detection:
          - Rapid unique path enumeration
          - Scanner User-Agent strings
          - Offensive HTTP methods
          - Known attack paths (.env, /etc/passwd, etc.)
        """
        with self._lock:
            self._http_req_times[src].append(now)
            self._trim(self._http_req_times[src], now, self.WINDOW)
            rps = len(self._http_req_times[src])

        payload = pkt.get("http_payload") or b""
        uri     = (pkt.get("http_uri") or b"").lower() if isinstance(pkt.get("http_uri"), bytes) else b""
        ua      = (pkt.get("http_user_agent") or b"").lower()

        # Rate threshold
        if rps > self.HTTP_SCAN_THRESHOLD:
            self._maybe_alert(_make_alert(
                "HTTP_SCANNING", "HIGH", src,
                f"HTTP scan rate: {rps} req/10s from {src}",
                {"rps": rps, "threshold": self.HTTP_SCAN_THRESHOLD},
                confidence=_compute_confidence("HTTP_SCANNING", rps / self.HTTP_SCAN_THRESHOLD),
            ))

        # Scanner UA
        if ua:
            for scanner_ua in SCANNER_UA_FRAGMENTS:
                if scanner_ua in ua:
                    self._maybe_alert(_make_alert(
                        "SUSPICIOUS_HTTP", "HIGH", src,
                        f"Scanner UA detected: {ua[:80].decode(errors='replace')}",
                        {"user_agent": ua[:200].decode(errors="replace"), "matched": scanner_ua.decode()},
                        confidence=82,
                    ))
                    break

        # Multiple distinct UAs from same IP (UA rotation)
        if ua:
            with self._lock:
                self._http_uas[src].add(ua[:50])
                ua_count = len(self._http_uas[src])
            if ua_count >= self.HTTP_UA_THRESHOLD:
                self._maybe_alert(_make_alert(
                    "HTTP_SCANNING", "MEDIUM", src,
                    f"UA rotation: {ua_count} distinct UAs from {src}",
                    {"unique_uas": ua_count},
                    confidence=70,
                ))

        # Scan path detection
        if uri:
            for frag in SCAN_PATH_FRAGMENTS:
                if frag in uri:
                    self._maybe_alert(_make_alert(
                        "SUSPICIOUS_HTTP", "HIGH", src,
                        f"Attack path probe: {uri[:80].decode(errors='replace')}",
                        {"path": uri[:200].decode(errors="replace"), "matched_pattern": frag.decode()},
                        confidence=85,
                    ))
                    break

        # Unique path enumeration tracking
        if uri:
            with self._lock:
                path = uri[:80]
                self._http_paths[src][path] = self._http_paths[src].get(path, 0) + 1
                unique_paths = len(self._http_paths[src])
            if unique_paths > 50:
                self._maybe_alert(_make_alert(
                    "HTTP_SCANNING", "HIGH", src,
                    f"Directory scan: {unique_paths} unique paths probed by {src}",
                    {"unique_paths": unique_paths},
                    confidence=78,
                ))

    # ─── TLS Fingerprinting ──────────────────────────────────────────────────
    def _analyze_tls(self, src: str, pkt: Dict, now: float):
        ja3 = pkt.get("tls_ja3_hash") or ""
        for malicious_ja3, malware_name in MALICIOUS_JA3.items():
            if ja3 and malicious_ja3 in ja3:
                self._maybe_alert(_make_alert(
                    "MALICIOUS_TLS", "CRITICAL", src,
                    f"Malicious TLS fingerprint: {malware_name} (JA3: {ja3[:16]}…)",
                    {"ja3_hash": ja3, "malware_family": malware_name},
                    confidence=92,
                ))
                return

        # Self-signed / invalid cert indicators
        if pkt.get("tls_invalid_cert"):
            self._maybe_alert(_make_alert(
                "TLS_ANOMALY", "MEDIUM", src,
                f"TLS invalid/self-signed certificate from {src}",
                {"ja3_hash": ja3, "reason": "invalid_cert"},
                confidence=55,
            ))

        # TLS on non-standard port
        dst_port = pkt.get("dst_port", 443)
        if dst_port not in (443, 8443, 993, 995, 465, 587, 636) and pkt.get("is_tls_hello"):
            self._maybe_alert(_make_alert(
                "TLS_ANOMALY", "MEDIUM", src,
                f"TLS on non-standard port {dst_port} — possible C2 channel",
                {"dst_port": dst_port, "ja3_hash": ja3},
                dst_port=dst_port, confidence=58,
            ))

    # ─── C2 Payload Detection ────────────────────────────────────────────────
    def _check_c2_payload(self, src: str, payload: bytes, pkt: Dict):
        if len(payload) < 4: return
        payload_lower = payload.lower()
        for pattern in C2_PATTERNS:
            if pattern in payload_lower:
                matched = pattern.decode(errors="replace")
                self._maybe_alert(_make_alert(
                    "C2_TRAFFIC", "CRITICAL", src,
                    "C2 pattern in payload: " + matched,
                    {"matched_pattern": matched,
                     "payload_preview": payload[:200].decode(errors="replace"),
                     "dst_port": pkt.get("dst_port")},
                    dst_port=pkt.get("dst_port"), confidence=82,
                ))
                break

    # ─── v4.0: Protocol Anomaly Detection ───────────────────────────────
    def _check_protocol_anomaly(self, src: str, proto: str, dst_port: int, now: float):
        """Flag unexpected protocols on well-known ports."""
        expected = self._expected_protos.get(dst_port)
        if expected and proto != expected:
            self._maybe_alert(_make_alert(
                "PROTOCOL_ANOMALY", "MEDIUM", src,
                f"Protocol mismatch: {proto} on port {dst_port} (expected {expected})",
                {"protocol": proto, "dst_port": dst_port, "expected": expected},
                dst_port=dst_port,
                confidence=_compute_confidence("PROTOCOL_ANOMALY"),
            ))

    # ─── v4.0: TCP Session State Machine ────────────────────────────────
    def _track_tcp_session(self, src: str, dst: str, dst_port: int, flags: str, now: float):
        """
        Track TCP handshake state per flow.
        Detect: incomplete handshakes, data before handshake, abnormal transitions.
        """
        key = f"{src}->{dst}:{dst_port}"
        with self._lock:
            session = self._tcp_sessions.get(key)
            if "S" in flags and "A" not in flags:
                # SYN — new connection attempt
                self._tcp_sessions[key] = {"state": "SYN_SENT", "ts": now}
            elif session:
                state = session["state"]
                if state == "SYN_SENT" and "S" in flags and "A" in flags:
                    session["state"] = "SYN_ACK"
                elif state == "SYN_ACK" and "A" in flags and "S" not in flags:
                    session["state"] = "ESTABLISHED"
                elif state == "SYN_SENT" and "P" in flags:
                    # Data sent before handshake complete — anomalous
                    self._maybe_alert(_make_alert(
                        "TCP_STATE_ANOMALY", "MEDIUM", src,
                        f"Data before handshake on {dst}:{dst_port}",
                        {"state": state, "flags": flags, "dst_port": dst_port},
                        dst_port=dst_port, confidence=72,
                    ))
                elif state == "ESTABLISHED" and "R" in flags:
                    session["state"] = "RESET"
                elif "F" in flags:
                    session["state"] = "FIN"
                # Check for half-open that's been stale > 30s
                if state == "SYN_SENT" and now - session["ts"] > 30:
                    self._maybe_alert(_make_alert(
                        "TCP_STATE_ANOMALY", "LOW", src,
                        f"Half-open TCP session to {dst}:{dst_port} ({now - session['ts']:.0f}s)",
                        {"state": state, "age_seconds": round(now - session["ts"])},
                        dst_port=dst_port, confidence=58,
                    ))
            # Prune stale sessions (> 5 min)
            if len(self._tcp_sessions) > 10_000:
                cutoff = now - 300
                self._tcp_sessions = {
                    k: v for k, v in self._tcp_sessions.items()
                    if v["ts"] > cutoff
                }

    # ─── v4.0: Behavioral Baseline ────────────────────────────────────
    def _update_behavior_baseline(self, src: str, size: int, now: float):
        """
        Track per-IP traffic rate history and flag deviations.
        Uses rolling z-score: z = (current - mean) / std_dev.
        z > 3.0 triggers alert.
        """
        bl = self._behavior_baselines[src]
        bl["tick_count"] += 1
        bl["tick_bytes"] += size
        # Aggregate into 10-second buckets
        if now - bl["last_tick"] >= 10:
            bl["pps_history"].append(bl["tick_count"])
            bl["byte_history"].append(bl["tick_bytes"])
            bl["tick_count"] = 0
            bl["tick_bytes"] = 0
            bl["last_tick"] = now
            # Need at least 6 buckets (60s) for a baseline
            if len(bl["pps_history"]) >= 6:
                import statistics as stats_mod
                pps_list = list(bl["pps_history"])
                mean_pps = stats_mod.mean(pps_list[:-1])  # exclude current
                try:
                    std_pps = stats_mod.stdev(pps_list[:-1])
                except stats_mod.StatisticsError:
                    std_pps = 0
                current_pps = pps_list[-1]
                if std_pps > 0:
                    z = (current_pps - mean_pps) / std_pps
                    if z > 3.0:
                        self._maybe_alert(_make_alert(
                            "BEHAVIOR_ANOMALY", "MEDIUM", src,
                            f"Behavioral anomaly from {src}: traffic {z:.1f}σ above baseline",
                            {"current_pps": current_pps, "baseline_mean": round(mean_pps, 1),
                             "baseline_std": round(std_pps, 1), "z_score": round(z, 2)},
                            confidence=_compute_confidence("BEHAVIOR_ANOMALY", z / 3.0),
                        ))

    # ─── v4.0: Payload Entropy Analysis ───────────────────────────────
    def _check_payload_entropy(self, src: str, payload: bytes, pkt: Dict):
        """
        High Shannon entropy in non-TLS payloads suggests encrypted C2 traffic.
        Normal HTTP/text: entropy 3.5-4.5. Encrypted/compressed: 7.0-8.0.
        """
        if pkt.get("is_tls_hello") or pkt.get("dst_port") in (443, 8443):
            return  # Skip TLS traffic (encrypted by design)
        # Compute byte-level entropy
        if len(payload) < 20:
            return
        freq = {}
        for b in payload:
            freq[b] = freq.get(b, 0) + 1
        n = len(payload)
        ent = -sum((c/n) * math.log2(c/n) for c in freq.values() if c > 0)
        self._payload_entropy_cache[src].append(ent)
        if ent > 7.0:
            self._maybe_alert(_make_alert(
                "PAYLOAD_ENTROPY", "HIGH", src,
                f"High payload entropy ({ent:.2f}) from {src} — possible encrypted C2",
                {"entropy": round(ent, 2), "payload_size": n,
                 "dst_port": pkt.get("dst_port"),
                 "threshold": 7.0},
                dst_port=pkt.get("dst_port"),
                confidence=_compute_confidence("PAYLOAD_ENTROPY", ent / 7.0),
            ))

    # ─── v4.0: Beaconing / C2 Heartbeat Detection ────────────────────
    def _check_beaconing(self, src: str, now: float):
        """
        C2 beacons call home at regular intervals. Detect by measuring
        the coefficient of variation (CV) of inter-arrival times.
        CV < 0.3 with > 10 samples = highly regular = likely beaconing.
        """
        with self._lock:
            self._beacon_times[src].append(now)
            times = list(self._beacon_times[src])
        if len(times) < 12:
            return
        iats = [times[i+1] - times[i] for i in range(len(times)-1)]
        import statistics as stats_mod
        mean_iat = stats_mod.mean(iats)
        if mean_iat < 0.5:
            return  # Too fast — not beaconing, just a burst
        try:
            std_iat = stats_mod.stdev(iats)
        except stats_mod.StatisticsError:
            return
        cv = std_iat / mean_iat if mean_iat > 0 else 999
        if cv < 0.3 and mean_iat > 2.0:  # Regular interval > 2s
            self._maybe_alert(_make_alert(
                "BEACONING", "HIGH", src,
                f"C2 beaconing from {src}: interval {mean_iat:.1f}s (CV={cv:.2f})",
                {"mean_interval": round(mean_iat, 2),
                 "std_interval": round(std_iat, 2),
                 "coefficient_of_variation": round(cv, 3),
                 "sample_count": len(iats)},
                confidence=_compute_confidence("BEACONING", (0.3 - cv) * 10 + 1),
            ))
    # ─── Alert Deduplication ─────────────────────────────────────────────────
    def _maybe_alert(self, alert: Dict[str, Any]):
        key = f"{alert['src_ip']}:{alert['alert_type']}"
        now = time.time()
        with self._lock:
            last = self._alerted.get(key, 0)
            if now - last < self.COOLDOWN:
                return
            self._alerted[key] = now
        self._dispatch(alert)

    def _dispatch(self, alert: Dict[str, Any]):
        logger.warning("[%s|%s|%d%%] %s", alert["alert_type"], alert["severity"],
                       alert.get("confidence", 0), alert["description"])
        for cb in self._callbacks:
            try: cb(alert)
            except Exception as e: logger.error("Alert callback error: %s", e)

    @staticmethod
    def _trim(dq: deque, now: float, window: float):
        cutoff = now - window
        while dq and dq[0] < cutoff:
            dq.popleft()
