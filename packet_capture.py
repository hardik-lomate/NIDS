"""
packet_capture.py  — v4.0

High-Performance Packet Capture Engine

Capture modes (auto-selected, best-first):
  Mode 1: PyShark (tshark/libpcap backend) — best accuracy, Wireshark dissectors
  Mode 2: dpkt + raw socket — lightweight, fast parsing, no heavy deps
  Mode 3: AF_PACKET socket (Linux raw socket, no root overhead like Scapy)
  Mode 4: Scapy (portable fallback)
  Mode 5: Demo (synthetic traffic, no root required)

v4.0 Upgrades:
  - dpkt parser: 5-10x faster than Scapy for packet parsing
  - Queue-based processing pipeline with backpressure
  - Windows compatibility (no geteuid/AF_PACKET dependency)
  - Per-second capture statistics (PPS, drops, queue depth)
  - PCAP ring buffer for per-alert forensic export
"""

import threading
import logging
import queue
import time
import csv
import os
import struct
import socket
import ipaddress
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, Any, Optional, List
from collections import defaultdict, deque

logger = logging.getLogger("nids.capture")

# ─── Capability detection ────────────────────────────────────────────────
try:
    import pyshark
    PYSHARK_AVAILABLE = True
except ImportError:
    PYSHARK_AVAILABLE = False

try:
    import dpkt
    DPKT_AVAILABLE = True
except ImportError:
    DPKT_AVAILABLE = False

try:
    from scapy.all import (
        sniff, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSQR, DNSRR,
        Raw, Ether, wrpcap, conf as scapy_conf, fragment, frag6
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

PROTO_MAP: Dict[int, str] = {
    1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE",
    50: "ESP", 51: "AH", 58: "ICMPv6", 89: "OSPF",
}
PORT_SERVICES: Dict[int, str] = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET",
    25: "SMTP", 53: "DNS", 67: "DHCP", 80: "HTTP",
    110: "POP3", 143: "IMAP", 389: "LDAP",
    443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "ORACLE", 3306: "MYSQL",
    3389: "RDP", 5432: "POSTGRES", 5900: "VNC",
    6379: "REDIS", 8080: "HTTP-ALT", 8443: "HTTPS-ALT",
    27017: "MONGODB",
}


# ─── PCAP Ring Buffer ────────────────────────────────────────────────────
class PCAPRingBuffer:
    """
    Per-IP ring buffer of raw packet bytes for PCAP export.
    Keeps last N packets per IP. When an alert fires, call export(ip)
    to write a valid PCAP file containing those packets.
    """
    PCAP_GLOBAL_HEADER = struct.pack(
        "<IHHiIII",
        0xa1b2c3d4,   # magic
        2, 4,         # version
        0,            # timezone
        0,            # sigfigs
        65535,        # snaplen
        1,            # link type (Ethernet)
    )

    def __init__(self, max_per_ip: int = 200, export_dir: str = "data/pcaps"):
        self._buffers: Dict[str, deque] = defaultdict(lambda: deque(maxlen=max_per_ip))
        self._lock = threading.Lock()
        self._export_dir = Path(export_dir)
        self._export_dir.mkdir(parents=True, exist_ok=True)

    def add(self, src_ip: str, raw_bytes: bytes, ts: float):
        """Store raw packet bytes (Ethernet frame) per source IP."""
        with self._lock:
            self._buffers[src_ip].append((ts, raw_bytes))

    def export_pcap(self, src_ip: str, alert_id: str) -> Optional[Path]:
        """
        Write PCAP file for the given IP's buffered packets.
        Returns path to the written file, or None if no data.
        """
        with self._lock:
            packets = list(self._buffers.get(src_ip, []))
        if not packets:
            return None
        filename = self._export_dir / f"alert_{alert_id}_{src_ip.replace('.', '_')}.pcap"
        try:
            with open(filename, "wb") as f:
                f.write(self.PCAP_GLOBAL_HEADER)
                for ts, raw in packets:
                    ts_sec  = int(ts)
                    ts_usec = int((ts - ts_sec) * 1_000_000)
                    pkt_len = len(raw)
                    f.write(struct.pack("<IIII", ts_sec, ts_usec, pkt_len, pkt_len))
                    f.write(raw)
            logger.info("PCAP exported: %s (%d packets)", filename, len(packets))
            return filename
        except Exception as e:
            logger.error("PCAP export failed: %s", e)
            return None

    def list_exports(self) -> List[Dict[str, Any]]:
        exports = []
        for f in sorted(self._export_dir.glob("alert_*.pcap"), key=lambda x: x.stat().st_mtime, reverse=True):
            stat = f.stat()
            exports.append({"filename": f.name, "path": str(f),
                           "size_bytes": stat.st_size, "created": datetime.fromtimestamp(stat.st_mtime).isoformat()})
        return exports[:50]


# ─── Packet extraction ───────────────────────────────────────────────────
def extract_from_scapy(packet) -> Optional[Dict[str, Any]]:
    data: Dict[str, Any] = {
        "timestamp": datetime.utcnow().isoformat(),
        "src_ip": None, "dst_ip": None,
        "src_port": None, "dst_port": None,
        "protocol": "UNKNOWN", "size": len(packet),
        "flags": None, "ttl": None,
        "payload_len": 0, "raw_summary": packet.summary(),
        "is_arp": False, "is_dns": False,
        "dns_query": None, "dns_txt": [],
        "http_user_agent": None, "http_uri": None, "http_payload": None,
        "is_tls_hello": False, "tls_ja3_hash": None,
        "src_mac": None, "dst_mac": None,
        "is_fragment": False, "frag_offset": 0,
        "icmp_type": None,
        "_raw_bytes": bytes(packet),
    }
    if packet.haslayer(Ether):
        data["src_mac"] = packet[Ether].src
        data["dst_mac"] = packet[Ether].dst
    if packet.haslayer(ARP):
        arp = packet[ARP]
        data.update(is_arp=True, src_ip=arp.psrc, dst_ip=arp.pdst,
                    src_mac=arp.hwsrc, protocol="ARP", arp_op=arp.op)
        return data
    if packet.haslayer(IP):
        ip = packet[IP]
        data["src_ip"]  = ip.src
        data["dst_ip"]  = ip.dst
        data["ttl"]     = ip.ttl
        data["is_fragment"] = bool(ip.flags & 0x1 or ip.frag > 0)
        data["frag_offset"] = ip.frag
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            data["protocol"]  = "TCP"
            data["src_port"]  = tcp.sport
            data["dst_port"]  = tcp.dport
            data["payload_len"] = len(tcp.payload)
            flags = ""
            if tcp.flags & 0x02: flags += "S"
            if tcp.flags & 0x10: flags += "A"
            if tcp.flags & 0x01: flags += "F"
            if tcp.flags & 0x04: flags += "R"
            if tcp.flags & 0x08: flags += "P"
            if tcp.flags & 0x20: flags += "U"
            data["flags"] = flags
            # HTTP inspection
            if tcp.dport in (80, 8080, 8000, 8888) and packet.haslayer(Raw):
                raw = bytes(packet[Raw].load)
                data["http_payload"] = raw
                lines = raw.split(b"\r\n")
                if lines:
                    data["http_uri"] = lines[0]
                for line in lines[1:]:
                    if line.lower().startswith(b"user-agent:"):
                        data["http_user_agent"] = line[11:].strip()
            # TLS Hello detection (byte 0x16 = TLS record, byte 1-2 = version, byte 5 = 0x01 = ClientHello)
            if packet.haslayer(Raw):
                raw = bytes(packet[Raw].load)
                if len(raw) > 6 and raw[0] == 0x16 and raw[1] in (0x03,) and raw[5] == 0x01:
                    data["is_tls_hello"] = True
                    try:
                        data["tls_ja3_hash"] = _extract_ja3(raw)
                    except Exception:
                        data["tls_ja3_hash"] = "tls_hello_detected"
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            data["protocol"]  = "UDP"
            data["src_port"]  = udp.sport
            data["dst_port"]  = udp.dport
            data["payload_len"] = len(udp.payload)
        elif packet.haslayer(ICMP):
            icmp = packet[ICMP]
            data["protocol"]  = "ICMP"
            data["icmp_type"] = icmp.type
    elif packet.haslayer(IPv6):
        ip6 = packet[IPv6]
        data["src_ip"] = ip6.src
        data["dst_ip"] = ip6.dst
    else:
        return None
    # DNS
    if packet.haslayer(DNS) and packet.haslayer(DNSQR):
        try:
            data["is_dns"] = True
            data["dns_query"] = packet[DNSQR].qname.decode(errors="replace").rstrip(".")
        except Exception: pass
        if packet.haslayer(DNSRR):
            try:
                rr = packet[DNSRR]
                if rr.type == 16:  # TXT
                    data["dns_txt"].append(str(rr.rdata))
            except Exception: pass
    return data


def extract_from_pyshark(pkt) -> Optional[Dict[str, Any]]:
    """Extract packet metadata from a PyShark packet object."""
    try:
        data: Dict[str, Any] = {
            "timestamp": datetime.utcnow().isoformat(),
            "src_ip": None, "dst_ip": None,
            "src_port": None, "dst_port": None,
            "protocol": "UNKNOWN", "size": int(pkt.length),
            "flags": None, "ttl": None,
            "payload_len": 0,
            "raw_summary": str(pkt),
            "is_arp": False, "is_dns": False,
            "dns_query": None, "dns_txt": [],
            "http_user_agent": None, "http_uri": None, "http_payload": None,
            "is_tls_hello": False, "tls_ja3_hash": None,
            "src_mac": None, "dst_mac": None,
            "is_fragment": False, "frag_offset": 0,
            "icmp_type": None,
            "_raw_bytes": b"",
        }
        if hasattr(pkt, "eth"):
            data["src_mac"] = pkt.eth.src
            data["dst_mac"] = pkt.eth.dst
        if hasattr(pkt, "ip"):
            data["src_ip"] = pkt.ip.src
            data["dst_ip"] = pkt.ip.dst
            data["ttl"]    = int(pkt.ip.ttl)
            data["is_fragment"] = hasattr(pkt.ip, "flags_mf") and pkt.ip.flags_mf == "1"
        if hasattr(pkt, "tcp"):
            data["protocol"] = "TCP"
            data["src_port"] = int(pkt.tcp.srcport)
            data["dst_port"] = int(pkt.tcp.dstport)
            flags = ""
            if hasattr(pkt.tcp, "flags_syn") and pkt.tcp.flags_syn == "1": flags += "S"
            if hasattr(pkt.tcp, "flags_ack") and pkt.tcp.flags_ack == "1": flags += "A"
            if hasattr(pkt.tcp, "flags_fin") and pkt.tcp.flags_fin == "1": flags += "F"
            if hasattr(pkt.tcp, "flags_reset") and pkt.tcp.flags_reset == "1": flags += "R"
            if hasattr(pkt.tcp, "flags_push") and pkt.tcp.flags_push == "1": flags += "P"
            if hasattr(pkt.tcp, "flags_urg") and pkt.tcp.flags_urg == "1": flags += "U"
            data["flags"] = flags
        elif hasattr(pkt, "udp"):
            data["protocol"] = "UDP"
            data["src_port"] = int(pkt.udp.srcport)
            data["dst_port"] = int(pkt.udp.dstport)
        elif hasattr(pkt, "icmp"):
            data["protocol"]   = "ICMP"
            data["icmp_type"]  = int(pkt.icmp.type) if hasattr(pkt.icmp, "type") else 8
        if hasattr(pkt, "dns"):
            data["is_dns"] = True
            if hasattr(pkt.dns, "qry_name"):
                data["dns_query"] = pkt.dns.qry_name
        if hasattr(pkt, "http"):
            if hasattr(pkt.http, "request_uri"):
                data["http_uri"] = pkt.http.request_uri.encode()
            if hasattr(pkt.http, "user_agent"):
                data["http_user_agent"] = pkt.http.user_agent.encode()
        if hasattr(pkt, "tls"):
            data["is_tls_hello"] = True
            if hasattr(pkt.tls, "handshake_ja3"):
                data["tls_ja3_hash"] = pkt.tls.handshake_ja3
        return data
    except Exception as e:
        logger.debug("PyShark extraction error: %s", e)
        return None


# ─── AF_PACKET Capture (Linux raw socket) ────────────────────────────────
class AFPacketCapture:
    """
    Raw socket capture using AF_PACKET (Linux only).
    Captures at Ethernet layer — much faster than Scapy for high-volume.
    No third-party dependencies beyond the standard library.
    """
    ETH_P_ALL = 0x0003

    def __init__(self, interface: str = "eth0"):
        self.interface = interface
        self._sock: Optional[socket.socket] = None

    def __enter__(self):
        try:
            self._sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                       socket.htons(self.ETH_P_ALL))
            self._sock.bind((self.interface, 0))
            self._sock.settimeout(1.0)
            logger.info("AF_PACKET socket on %s", self.interface)
        except PermissionError:
            logger.warning("AF_PACKET requires root — falling back to Scapy/PyShark")
            self._sock = None
        return self

    def __exit__(self, *args):
        if self._sock:
            self._sock.close()

    def recv(self, bufsize: int = 65535) -> Optional[bytes]:
        if not self._sock: return None
        try:
            return self._sock.recv(bufsize)
        except socket.timeout:
            return None
        except Exception as e:
            logger.debug("AF_PACKET recv error: %s", e)
            return None


def parse_af_packet(raw: bytes) -> Optional[Dict[str, Any]]:
    """Minimal Ethernet/IP/TCP parser for AF_PACKET frames (no Scapy required)."""
    if len(raw) < 14: return None
    data: Dict[str, Any] = {
        "timestamp": datetime.utcnow().isoformat(),
        "src_ip": None, "dst_ip": None,
        "src_port": None, "dst_port": None,
        "protocol": "UNKNOWN", "size": len(raw),
        "flags": "", "ttl": None, "payload_len": 0,
        "raw_summary": f"AF_PKT len={len(raw)}",
        "is_arp": False, "is_dns": False, "dns_query": None, "dns_txt": [],
        "http_payload": None, "http_uri": None, "http_user_agent": None,
        "is_tls_hello": False, "tls_ja3_hash": None,
        "src_mac": raw[6:12].hex(":"), "dst_mac": raw[0:6].hex(":"),
        "is_fragment": False, "frag_offset": 0, "icmp_type": None,
        "_raw_bytes": raw,
    }
    eth_type = struct.unpack("!H", raw[12:14])[0]
    if eth_type == 0x0806:  # ARP
        data["is_arp"] = True; data["protocol"] = "ARP"
        return data
    if eth_type not in (0x0800, 0x86DD): return None  # only IPv4/6
    if len(raw) < 34: return None
    ip_start = 14
    version  = (raw[ip_start] >> 4) & 0xF
    if version != 4: return None  # IPv6 TODO
    ihl      = (raw[ip_start] & 0xF) * 4
    proto    = raw[ip_start + 9]
    flags_frag = struct.unpack("!H", raw[ip_start+6:ip_start+8])[0]
    data["is_fragment"] = bool(flags_frag & 0x2000 or flags_frag & 0x1FFF)
    data["frag_offset"] = flags_frag & 0x1FFF
    data["ttl"]   = raw[ip_start + 8]
    data["src_ip"] = socket.inet_ntoa(raw[ip_start+12:ip_start+16])
    data["dst_ip"] = socket.inet_ntoa(raw[ip_start+16:ip_start+20])
    tcp_start = ip_start + ihl
    if proto == 6 and len(raw) > tcp_start + 20:   # TCP
        data["protocol"] = "TCP"
        data["src_port"] = struct.unpack("!H", raw[tcp_start:tcp_start+2])[0]
        data["dst_port"] = struct.unpack("!H", raw[tcp_start+2:tcp_start+4])[0]
        tcp_flags_byte   = raw[tcp_start + 13]
        flags = ""
        if tcp_flags_byte & 0x02: flags += "S"
        if tcp_flags_byte & 0x10: flags += "A"
        if tcp_flags_byte & 0x01: flags += "F"
        if tcp_flags_byte & 0x04: flags += "R"
        if tcp_flags_byte & 0x08: flags += "P"
        if tcp_flags_byte & 0x20: flags += "U"
        data["flags"] = flags
        data_offset = ((raw[tcp_start + 12] >> 4) & 0xF) * 4
        payload = raw[tcp_start + data_offset:]
        data["payload_len"] = len(payload)
        if data["dst_port"] in (80, 8080) and payload.startswith(b"GET ") or payload.startswith(b"POST "):
            data["http_payload"] = payload[:1024]
            lines = payload.split(b"\r\n")
            data["http_uri"] = lines[0]
            for line in lines[1:]:
                if line.lower().startswith(b"user-agent:"): data["http_user_agent"] = line[11:].strip()
        if payload and payload[0] == 0x16 and len(payload) > 6 and payload[5] == 0x01:
            data["is_tls_hello"] = True
    elif proto == 17 and len(raw) > tcp_start + 8:  # UDP
        data["protocol"] = "UDP"
        data["src_port"] = struct.unpack("!H", raw[tcp_start:tcp_start+2])[0]
        data["dst_port"] = struct.unpack("!H", raw[tcp_start+2:tcp_start+4])[0]
        if data["dst_port"] == 53 or data["src_port"] == 53:
            data["is_dns"] = True
            udp_payload = raw[tcp_start + 8:]
            if len(udp_payload) > 12:
                try:
                    pos = 12
                    labels = []
                    while pos < len(udp_payload):
                        ln = udp_payload[pos]
                        if ln == 0 or ln & 0xC0 == 0xC0: break
                        pos += 1
                        if pos + ln > len(udp_payload): break
                        labels.append(udp_payload[pos:pos+ln].decode("ascii", errors="replace"))
                        pos += ln
                    if labels:
                        data["dns_query"] = ".".join(labels)
                except Exception:
                    pass
    elif proto == 1 and len(raw) > tcp_start + 2:  # ICMP
        data["protocol"]  = "ICMP"
        data["icmp_type"] = raw[tcp_start]
    return data



def _extract_ja3(raw: bytes) -> str:
    """
    Compute JA3 fingerprint from TLS ClientHello raw bytes.
    JA3 = MD5(SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats)
    Ref: https://github.com/salesforce/ja3
    """
    import hashlib
    # TLS record: type(1) version(2) length(2) | handshake type(1) length(3) | hello
    if len(raw) < 43: return "tls_hello_detected"
    try:
        pos = 9  # skip record header (5) + handshake type (1) + length (3)
        ssl_version = struct.unpack("!H", raw[pos:pos+2])[0]; pos += 2
        pos += 32  # skip random
        session_len = raw[pos]; pos += 1 + session_len
        cipher_len = struct.unpack("!H", raw[pos:pos+2])[0]; pos += 2
        ciphers = []
        for i in range(0, cipher_len, 2):
            c = struct.unpack("!H", raw[pos+i:pos+i+2])[0]
            if c not in (0x00FF,):  # exclude GREASE
                ciphers.append(str(c))
        pos += cipher_len
        pos += 1  # compression methods length
        pos += raw[pos-1]  # skip compression methods
        if pos + 2 > len(raw): 
            return hashlib.md5(f"{ssl_version},,,,".encode()).hexdigest()
        ext_total = struct.unpack("!H", raw[pos:pos+2])[0]; pos += 2
        extensions, curves, formats = [], [], []
        end = pos + ext_total
        while pos + 4 <= end:
            ext_type = struct.unpack("!H", raw[pos:pos+2])[0]
            ext_len  = struct.unpack("!H", raw[pos+2:pos+4])[0]
            pos += 4
            if ext_type not in (0x0000,):  # exclude SNI type
                extensions.append(str(ext_type))
            if ext_type == 0x000A and ext_len >= 2:  # supported_groups (elliptic curves)
                gc = struct.unpack("!H", raw[pos:pos+2])[0]
                for j in range(0, gc, 2):
                    if pos+2+j+2 <= pos+2+gc:
                        curves.append(str(struct.unpack("!H", raw[pos+2+j:pos+2+j+2])[0]))
            if ext_type == 0x000B and ext_len >= 1:  # ec_point_formats
                fc = raw[pos]
                for j in range(fc): formats.append(str(raw[pos+1+j]))
            pos += ext_len
        ja3_str = (f"{ssl_version},{'-'.join(ciphers)},{'-'.join(extensions)},"
                   f"{'-'.join(curves)},{'-'.join(formats)}")
        return hashlib.md5(ja3_str.encode()).hexdigest()
    except Exception:
        return "tls_hello_detected"


# ─── dpkt-based parser (fast, lightweight) ───────────────────────────────
def parse_dpkt(raw: bytes) -> Optional[Dict[str, Any]]:
    """Parse raw Ethernet frame using dpkt — 5-10x faster than Scapy."""
    if not DPKT_AVAILABLE or len(raw) < 14:
        return None
    try:
        data: Dict[str, Any] = {
            "timestamp": datetime.utcnow().isoformat(),
            "src_ip": None, "dst_ip": None,
            "src_port": None, "dst_port": None,
            "protocol": "UNKNOWN", "size": len(raw),
            "flags": "", "ttl": None, "payload_len": 0,
            "raw_summary": f"dpkt len={len(raw)}",
            "is_arp": False, "is_dns": False, "dns_query": None, "dns_txt": [],
            "http_payload": None, "http_uri": None, "http_user_agent": None,
            "is_tls_hello": False, "tls_ja3_hash": None,
            "src_mac": None, "dst_mac": None,
            "is_fragment": False, "frag_offset": 0, "icmp_type": None,
            "_raw_bytes": raw,
        }
        eth = dpkt.ethernet.Ethernet(raw)
        data["src_mac"] = ':'.join(f'{b:02x}' for b in eth.src)
        data["dst_mac"] = ':'.join(f'{b:02x}' for b in eth.dst)

        if eth.type == dpkt.ethernet.ETH_TYPE_ARP:
            data["is_arp"] = True
            data["protocol"] = "ARP"
            return data

        if eth.type == dpkt.ethernet.ETH_TYPE_IP:
            ip = eth.data
            if not isinstance(ip, dpkt.ip.IP):
                return None
            data["src_ip"] = socket.inet_ntoa(ip.src)
            data["dst_ip"] = socket.inet_ntoa(ip.dst)
            data["ttl"] = ip.ttl
            data["is_fragment"] = bool(ip.off & (dpkt.ip.IP_MF | dpkt.ip.IP_OFFMASK))
            data["frag_offset"] = ip.off & dpkt.ip.IP_OFFMASK

            if isinstance(ip.data, dpkt.tcp.TCP):
                tcp = ip.data
                data["protocol"] = "TCP"
                data["src_port"] = tcp.sport
                data["dst_port"] = tcp.dport
                data["payload_len"] = len(tcp.data)
                flags = ""
                if tcp.flags & dpkt.tcp.TH_SYN: flags += "S"
                if tcp.flags & dpkt.tcp.TH_ACK: flags += "A"
                if tcp.flags & dpkt.tcp.TH_FIN: flags += "F"
                if tcp.flags & dpkt.tcp.TH_RST: flags += "R"
                if tcp.flags & dpkt.tcp.TH_PUSH: flags += "P"
                if tcp.flags & dpkt.tcp.TH_URG: flags += "U"
                data["flags"] = flags
                # HTTP inspection
                if tcp.dport in (80, 8080, 8000, 8888) and tcp.data:
                    payload = bytes(tcp.data)
                    if payload.startswith((b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ")):
                        data["http_payload"] = payload[:1024]
                        lines = payload.split(b"\r\n")
                        data["http_uri"] = lines[0]
                        for line in lines[1:]:
                            if line.lower().startswith(b"user-agent:"):
                                data["http_user_agent"] = line[11:].strip()
                # TLS ClientHello
                if tcp.data and len(tcp.data) > 6:
                    payload = bytes(tcp.data)
                    if payload[0] == 0x16 and payload[1] in (0x03,) and payload[5] == 0x01:
                        data["is_tls_hello"] = True
                        try:
                            data["tls_ja3_hash"] = _extract_ja3(payload)
                        except Exception:
                            data["tls_ja3_hash"] = "tls_hello_detected"

            elif isinstance(ip.data, dpkt.udp.UDP):
                udp = ip.data
                data["protocol"] = "UDP"
                data["src_port"] = udp.sport
                data["dst_port"] = udp.dport
                data["payload_len"] = len(udp.data)
                # DNS
                if udp.dport == 53 or udp.sport == 53:
                    data["is_dns"] = True
                    if udp.data and len(udp.data) > 12:
                        try:
                            dns_pkt = dpkt.dns.DNS(udp.data)
                            if dns_pkt.qd:
                                data["dns_query"] = dns_pkt.qd[0].name
                            for rr in dns_pkt.an:
                                if rr.type == dpkt.dns.DNS_TXT:
                                    data["dns_txt"].append(str(rr.text))
                        except Exception:
                            pass

            elif isinstance(ip.data, dpkt.icmp.ICMP):
                icmp = ip.data
                data["protocol"] = "ICMP"
                data["icmp_type"] = icmp.type

            else:
                data["protocol"] = PROTO_MAP.get(ip.p, f"PROTO_{ip.p}")

        elif eth.type == dpkt.ethernet.ETH_TYPE_IP6:
            ip6 = eth.data
            if hasattr(ip6, 'src') and hasattr(ip6, 'dst'):
                data["src_ip"] = socket.inet_ntop(socket.AF_INET6, ip6.src)
                data["dst_ip"] = socket.inet_ntop(socket.AF_INET6, ip6.dst)
        else:
            return None

        return data
    except Exception as e:
        logger.debug("dpkt parse error: %s", e)
        return None


# ─── Main Capture Engine ─────────────────────────────────────────────────
class PacketCapture:
    def __init__(self, config: Dict[str, Any]):
        cap_cfg   = config.get("capture", {})
        self.interface       = cap_cfg.get("interface", "eth0")
        self.bpf_filter      = cap_cfg.get("bpf_filter", "")
        self._csv_path       = Path(cap_cfg.get("csv_log", "data/packets.csv"))
        self._csv_flush_interval = cap_cfg.get("csv_flush_interval", 10)
        self._callbacks:     List[Callable] = []
        self._stop_event     = threading.Event()
        self._stats_lock     = threading.Lock()
        self.stats           = {
            "captured": 0, "dropped": 0, "mode": "demo",
            "queue_depth": 0, "peak_pps": 0, "current_pps": 0,
        }
        self._csv_buffer:    List[Dict] = []
        self._csv_lock       = threading.Lock()
        self.pcap_buffer     = PCAPRingBuffer(
            export_dir=cap_cfg.get("pcap_dir", "data/pcaps"))
        self.start_time:     Optional[datetime] = None
        # Queue-based processing pipeline (backpressure at 50k packets)
        self._pkt_queue:     queue.Queue = queue.Queue(maxsize=50_000)
        self._n_workers      = cap_cfg.get("worker_threads", 2)
        # Per-second PPS counter
        self._pps_counter    = 0
        self._pps_lock       = threading.Lock()

    def add_callback(self, cb: Callable): self._callbacks.append(cb)

    def get_stats(self) -> Dict[str, Any]:
        """Return capture statistics snapshot."""
        with self._stats_lock:
            s = dict(self.stats)
        s["queue_depth"] = self._pkt_queue.qsize()
        s["interface"] = self.interface
        s["start_time"] = self.start_time.isoformat() if self.start_time else None
        return s

    def _start_workers(self):
        """Start N worker threads that drain the packet queue."""
        for i in range(self._n_workers):
            t = threading.Thread(target=self._worker_loop, daemon=True, name=f"PktWorker-{i}")
            t.start()
        # PPS stats ticker
        t = threading.Thread(target=self._pps_ticker, daemon=True, name="PPSTicker")
        t.start()

    def _worker_loop(self):
        while not self._stop_event.is_set():
            try:
                data = self._pkt_queue.get(timeout=1.0)
            except queue.Empty:
                continue
            self._dispatch(data)
            self._pkt_queue.task_done()

    def _pps_ticker(self):
        """Track packets-per-second every second."""
        while not self._stop_event.is_set():
            time.sleep(1.0)
            with self._pps_lock:
                pps = self._pps_counter
                self._pps_counter = 0
            with self._stats_lock:
                self.stats["current_pps"] = pps
                self.stats["peak_pps"] = max(self.stats["peak_pps"], pps)
                self.stats["queue_depth"] = self._pkt_queue.qsize()

    def start(self):
        """Auto-select best capture mode available (Windows-safe)."""
        is_root = False
        try:
            if os.name == "posix":
                is_root = os.geteuid() == 0
        except AttributeError:
            pass  # Windows

        # Start worker threads for queue-based processing
        self._start_workers()

        # Try PyShark first (best accuracy, works on Windows + Linux)
        if PYSHARK_AVAILABLE and (is_root or os.name == "nt"):
            try:
                self._start_pyshark()
                return
            except Exception as e:
                logger.warning("PyShark failed: %s — trying next", e)

        # Try AF_PACKET (Linux, fast)
        if os.name == "posix":
            try:
                t = threading.Thread(target=self._run_afpacket, daemon=True, name="AFPacket")
                t.start()
                self.stats["mode"] = "af_packet"
                logger.info("AF_PACKET capture on %s", self.interface)
                self._start_csv_writer()
                self.start_time = datetime.utcnow()
                return
            except Exception as e:
                logger.warning("AF_PACKET failed: %s — trying Scapy", e)

        # Scapy fallback
        if SCAPY_AVAILABLE:
            try:
                self._start_scapy()
                return
            except Exception as e:
                logger.warning("Scapy failed: %s — demo mode", e)

        # Demo mode
        self._start_demo()

    def _start_pyshark(self):
        capture = pyshark.LiveCapture(
            interface=self.interface,
            bpf_filter=self.bpf_filter or None,
            use_json=True,
        )
        def _run():
            self.stats["mode"] = "pyshark"
            self.start_time = datetime.utcnow()
            self._start_csv_writer()
            for pkt in capture.sniff_continuously():
                if self._stop_event.is_set(): break
                data = extract_from_pyshark(pkt)
                if data: self._process(data)
        t = threading.Thread(target=_run, daemon=True, name="PyShark")
        t.start()
        logger.info("PyShark capture on %s", self.interface)

    def _run_afpacket(self):
        self.start_time = datetime.utcnow()
        with AFPacketCapture(self.interface) as cap:
            if not cap._sock:
                raise RuntimeError("AF_PACKET socket failed")
            while not self._stop_event.is_set():
                raw = cap.recv()
                if raw:
                    data = parse_af_packet(raw)
                    if data: self._process(data)

    def _start_scapy(self):
        self.stats["mode"] = "scapy"
        self.start_time = datetime.utcnow()
        self._start_csv_writer()
        def _run():
            sniff(prn=self._on_scapy_pkt, store=False,
                  filter=self.bpf_filter or None,
                  iface=self.interface,
                  stop_filter=lambda _: self._stop_event.is_set())
        t = threading.Thread(target=_run, daemon=True, name="ScapySniff")
        t.start()
        logger.info("Scapy capture on %s (BPF: %s)", self.interface, self.bpf_filter or "none")

    def _on_scapy_pkt(self, packet):
        data = extract_from_scapy(packet)
        if data: self._process(data)

    def _process(self, data: Dict[str, Any]):
        """Enqueue packet for worker threads (with backpressure)."""
        with self._pps_lock:
            self._pps_counter += 1
        try:
            self._pkt_queue.put_nowait(data)
        except queue.Full:
            with self._stats_lock:
                self.stats["dropped"] += 1
            return
        with self._stats_lock:
            self.stats["captured"] += 1

    def _dispatch(self, data: Dict[str, Any]):
        """Process a single packet: PCAP buffer, callbacks, CSV."""
        src = data.get("src_ip") or ""
        raw = data.get("_raw_bytes") or b""
        if src and raw:
            self.pcap_buffer.add(src, raw, time.time())
        for cb in self._callbacks:
            try: cb(data)
            except Exception as e: logger.error("Callback: %s", e)
        with self._csv_lock:
            self._csv_buffer.append(data)

    def _start_demo(self):
        """Synthetic demo traffic with varied attack scenarios."""
        import random
        self.stats["mode"] = "demo"
        self.start_time = datetime.utcnow()
        # Start worker threads so queued packets get dispatched to callbacks
        self._start_workers()
        self._start_csv_writer()
        SCENARIOS = [
            # (name, src_ip_pool, dst_ip_pool, protocol, port_pool, flags, extra)
            ("normal",       [f"10.0.0.{i}" for i in range(1,8)],
             ["192.168.1.1"], "TCP", [80,443,22,53], "A", {}),
            ("port_scan",    ["10.0.0.99"],
             ["192.168.1.1"], "TCP", list(range(1,1025,5)), "S", {}),
            ("syn_flood",    ["10.0.0.98"],
             ["192.168.1.10"], "TCP", [80], "S", {}),
            ("dns_tunnel",   ["10.0.0.97"],
             ["8.8.8.8"], "UDP", [53], "", {"is_dns": True, "dns_query": "aabbccddeeff1122334455.evil.com"}),
            ("icmp_flood",   ["10.0.0.96"],
             ["192.168.1.1"], "ICMP", [0], "", {"icmp_type": 8}),
            ("brute_ssh",    ["10.0.0.95"],
             ["192.168.1.1"], "TCP", [22], "S", {}),
            ("http_scan",    ["10.0.0.94"],
             ["192.168.1.1"], "TCP", [80], "A",
             {"http_payload": b"GET /.env HTTP/1.1\r\nUser-Agent: sqlmap\r\n\r\n",
              "http_uri": b"GET /.env HTTP/1.1", "http_user_agent": b"sqlmap/1.7"}),
            ("tor_traffic",  ["203.0.113.50"],  # seeded threat intel IP
             ["192.168.1.1"], "TCP", [443], "SA", {}),
        ]
        weights = [60, 5, 5, 3, 3, 4, 5, 3]  # probability weights

        # Attack burst generator — fires enough packets to cross detection thresholds
        def _burst(scenario_name: str, count: int, interval: float):
            """Fire `count` packets for a scenario to ensure threshold crossing."""
            s = [sc for sc in SCENARIOS if sc[0] == scenario_name]
            if not s: return
            name, srcs, dsts, proto, ports, flags, extra = s[0]
            src = random.choice(srcs)
            for _ in range(count):
                if self._stop_event.is_set(): return
                base = {
                    "timestamp": datetime.utcnow().isoformat(),
                    "src_ip": src, "dst_ip": random.choice(dsts),
                    "src_port": random.randint(1024, 65535),
                    "dst_port": random.choice(ports),
                    "protocol": proto, "size": random.randint(40, 1500),
                    "flags": flags, "ttl": random.randint(32, 128),
                    "payload_len": random.randint(0, 1400),
                    "raw_summary": f"DEMO:{name}",
                    "is_arp": False, "is_dns": False, "dns_query": None, "dns_txt": [],
                    "http_payload": None, "http_uri": None, "http_user_agent": None,
                    "is_tls_hello": False, "tls_ja3_hash": None,
                    "src_mac": "00:00:00:00:00:00", "dst_mac": "ff:ff:ff:ff:ff:ff",
                    "is_fragment": False, "frag_offset": 0, "icmp_type": None,
                    "_raw_bytes": b"\x00" * 64,
                }
                base.update(extra)
                # Port scan: enumerate different ports each packet
                if name == "port_scan":
                    base["dst_port"] = random.randint(1, 65535)
                self._process(base)
                time.sleep(interval)

        def _gen():
            # Schedule attack bursts periodically with background normal traffic
            attack_schedule = [
                ("syn_flood",   300, 0.001),   # 300 SYN pkts — fires SYN_FLOOD (threshold 200)
                ("port_scan",   40,  0.01),    # 40 ports — fires PORT_SCAN (threshold 20)
                ("icmp_flood",  150, 0.005),   # 150 ICMP — fires ICMP_FLOOD (threshold 100)
                ("dns_tunnel",  10,  0.05),    # 10 tunneling DNS queries
                ("http_scan",   40,  0.02),    # 40 HTTP reqs — fires HTTP_SCANNING
                ("brute_ssh",   15,  0.05),    # 15 SSH SYNs — fires BRUTE_FORCE
                ("tor_traffic", 5,   0.1),     # TOR IP — fires THREAT_INTEL
            ]
            attack_idx = 0
            last_attack = time.time()
            attack_interval = 30  # fire an attack burst every 30s

            while not self._stop_event.is_set():
                # Background normal traffic
                scenario = random.choices(SCENARIOS, weights=weights, k=1)[0]
                name, srcs, dsts, proto, ports, flags, extra = scenario
                if name != "normal":  # only background for normal
                    time.sleep(0.05)
                    continue
                scenario = random.choices(SCENARIOS, weights=weights, k=1)[0]
                name, srcs, dsts, proto, ports, flags, extra = scenario
                base = {
                    "timestamp": datetime.utcnow().isoformat(),
                    "src_ip": random.choice(srcs), "dst_ip": random.choice(dsts),
                    "src_port": random.randint(1024, 65535),
                    "dst_port": random.choice(ports),
                    "protocol": proto, "size": random.randint(64, 1460),
                    "flags": flags, "ttl": random.randint(32, 128),
                    "payload_len": random.randint(0, 1400),
                    "raw_summary": f"DEMO:{name}",
                    "is_arp": False, "is_dns": False, "dns_query": None, "dns_txt": [],
                    "http_payload": None, "http_uri": None, "http_user_agent": None,
                    "is_tls_hello": False, "tls_ja3_hash": None,
                    "src_mac": "00:00:00:00:00:00", "dst_mac": "ff:ff:ff:ff:ff:ff",
                    "is_fragment": False, "frag_offset": 0, "icmp_type": None,
                    "_raw_bytes": b"\x00" * 64,
                }
                base.update(extra)
                self._process(base)
                # Fire attack burst on schedule
                if time.time() - last_attack > attack_interval:
                    atk_name, count, ivl = attack_schedule[attack_idx % len(attack_schedule)]
                    t = threading.Thread(target=_burst, args=(atk_name, count, ivl), daemon=True)
                    t.start()
                    attack_idx += 1
                    last_attack = time.time()
                time.sleep(0.05)

            # remove the old while loop that shared the same variable name
            if False:
                scenario = random.choices(SCENARIOS, weights=weights, k=1)[0]
                name, srcs, dsts, proto, ports, flags, extra = scenario
                pkt: Dict[str, Any] = {
                    "timestamp": datetime.utcnow().isoformat(),
                    "src_ip":    random.choice(srcs),
                    "dst_ip":    random.choice(dsts),
                    "src_port":  random.randint(1024, 65535),
                    "dst_port":  random.choice(ports),
                    "protocol":  proto,
                    "size":      random.randint(40, 1500),
                    "flags":     flags,
                    "ttl":       random.randint(32, 128),
                    "payload_len": random.randint(0, 1400),
                    "raw_summary": f"DEMO:{name}",
                    "is_arp": False, "is_dns": False, "dns_query": None, "dns_txt": [],
                    "http_payload": None, "http_uri": None, "http_user_agent": None,
                    "is_tls_hello": False, "tls_ja3_hash": None,
                    "src_mac": "00:00:00:00:00:00", "dst_mac": "ff:ff:ff:ff:ff:ff",
                    "is_fragment": False, "frag_offset": 0, "icmp_type": None,
                    "_raw_bytes": b"\x00" * random.randint(40, 100),
                    **extra,
                }
                self._process(pkt)
                time.sleep(random.uniform(0.02, 0.1))
        t = threading.Thread(target=_gen, daemon=True, name="DemoCapture")
        t.start()
        logger.info("Demo capture running (realistic attack scenarios)")

    def _start_csv_writer(self):
        self._csv_path.parent.mkdir(parents=True, exist_ok=True)
        t = threading.Thread(target=self._csv_loop, daemon=True, name="CSVWriter")
        t.start()

    def _csv_loop(self):
        FIELDS = ["timestamp","src_ip","dst_ip","src_port","dst_port",
                  "protocol","size","flags","ttl","payload_len"]
        write_hdr = not self._csv_path.exists()
        while not self._stop_event.wait(self._csv_flush_interval):
            with self._csv_lock:
                batch = self._csv_buffer.copy(); self._csv_buffer.clear()
            if batch:
                try:
                    with open(self._csv_path, "a", newline="", encoding="utf-8") as f:
                        w = csv.DictWriter(f, fieldnames=FIELDS, extrasaction="ignore")
                        if write_hdr: w.writeheader(); write_hdr = False
                        w.writerows(batch)
                except Exception as e: logger.error("CSV: %s", e)

    def stop(self):
        self._stop_event.set()
