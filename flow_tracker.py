"""
flow_tracker.py
Flow Tracker — maintains active network flows and calculates flow statistics.
Flows are defined by the 5-tuple: (src_ip, dst_ip, src_port, dst_port, protocol).
"""

import time
import threading
import logging
from typing import Dict, Any, List

logger = logging.getLogger("nids.flow_tracker")

class Flow:
    """Represents a single network flow."""
    def __init__(self, flow_id: str, src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: str):
        self.flow_id = flow_id
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        
        self.start_time = time.time()
        self.last_time = self.start_time
        
        self.packet_count = 0
        self.byte_count = 0
        
        self.sum_inter_arrival = 0.0
        self.syn_count = 0
        self.ack_count = 0
        
        # TCP-specific state
        self.state = "new"  # new, established, closed
        self.syn_seen = False
        self.fin_seen = False

    def update(self, packet_size: int, flags: str = ""):
        now = time.time()
        self.packet_count += 1
        self.byte_count += packet_size
        
        if self.packet_count > 1:
            self.sum_inter_arrival += (now - self.last_time)
            
        self.last_time = now
        
        if self.protocol == "TCP" and flags:
            flag_set = set(flags)
            if "S" in flag_set:
                self.syn_seen = True
                self.syn_count += 1
            if "A" in flag_set:
                self.ack_count += 1
                if self.syn_seen:
                    self.state = "established"
            if "F" in flag_set or "R" in flag_set:
                self.fin_seen = True
                self.state = "closed"

    @property
    def duration(self) -> float:
        return self.last_time - self.start_time

    @property
    def avg_packet_size(self) -> float:
        return self.byte_count / self.packet_count if self.packet_count > 0 else 0.0

    @property
    def mean_inter_arrival(self) -> float:
        return self.sum_inter_arrival / (self.packet_count - 1) if self.packet_count > 1 else 0.0

    @property
    def syn_ack_ratio(self) -> float:
        return self.syn_count / max(self.ack_count, 1) if self.protocol == "TCP" else 0.0

    def get_timeout_threshold(self) -> int:
        """Return the idle timeout (seconds) based on connection state and protocol."""
        # TCP Settings
        if self.protocol == "TCP":
            if self.state == "established":
                return 3600  # 1 hour for established
            elif self.state == "closed":
                return 5  # Quick timeout once FIN/RST seen
            else:
                return 60  # Initial timeout for half-open/SYN-sent
                
        # UDP Settings
        elif self.protocol == "UDP":
            return 60
            
        # ICMP Settings
        elif self.protocol == "ICMP":
            return 30
            
        return 60  # Default fallback

    def to_dict(self) -> Dict[str, Any]:
        return {
            "flow_id": self.flow_id,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "state": self.state if self.protocol == "TCP" else "N/A",
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "duration": self.duration,
            "avg_packet_size": round(self.avg_packet_size, 2),
            "mean_inter_arrival": round(self.mean_inter_arrival, 5),
            "syn_ack_ratio": round(self.syn_ack_ratio, 3),
            "start_time": self.start_time,
            "last_time": self.last_time,
        }

class FlowTracker:
    """Tracks active flows and expires idle or actively-long flows."""
    def __init__(self, active_timeout: int = 300):
        # Time to force-flush a very long running connection 
        # so we don't hold them in memory indefinitely without emitting stats
        self.active_timeout = active_timeout
        self.flows: Dict[str, Flow] = {}
        self._lock = threading.Lock()
        
    def _generate_flow_id(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: str) -> str:
        """Create a bidirectional flow ID."""
        # Sort IP and Port to combine both directions into a single flow ID
        if src_ip < dst_ip:
            s_ip, d_ip = src_ip, dst_ip
            s_port, d_port = src_port, dst_port
        elif src_ip > dst_ip:
            s_ip, d_ip = dst_ip, src_ip
            s_port, d_port = dst_port, src_port
        else:
            s_ip, d_ip = src_ip, dst_ip
            s_port, d_port = sorted([src_port, dst_port])

        return f"{s_ip}:{s_port}-{d_ip}:{d_port}-{protocol}"

    def process_packet(self, pkt: Dict[str, Any]):
        src_ip = pkt.get("src_ip")
        dst_ip = pkt.get("dst_ip")
        src_port = pkt.get("src_port", 0)
        dst_port = pkt.get("dst_port", 0)
        protocol = pkt.get("protocol", "UNKNOWN")
        size = pkt.get("size", 0)
        flags = pkt.get("flags", "")

        # We only track IP flows
        if not src_ip or not dst_ip:
            return

        flow_id = self._generate_flow_id(src_ip, dst_ip, src_port, dst_port, protocol)

        with self._lock:
            if flow_id not in self.flows:
                self.flows[flow_id] = Flow(flow_id, src_ip, dst_ip, src_port, dst_port, protocol)
            
            self.flows[flow_id].update(size, flags)

    def get_active_flows(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [f.to_dict() for f in self.flows.values()]

    def cleanup_flows(self) -> List[Dict[str, Any]]:
        """Remove flows that hit their idle timeout or hit the global active timeout."""
        now = time.time()
        expired_flows = []
        with self._lock:
            to_remove = []
            for flow_id, flow in self.flows.items():
                
                idle_duration = now - flow.last_time
                active_duration = now - flow.start_time
                
                # Check 1: Idle Timeout
                if idle_duration > flow.get_timeout_threshold():
                    to_remove.append(flow_id)
                    expired_flows.append(flow.to_dict())
                # Check 2: Active Timeout (long running flow flush)
                elif active_duration > self.active_timeout:
                    to_remove.append(flow_id)
                    expired_flows.append(flow.to_dict())
            
            for flow_id in to_remove:
                del self.flows[flow_id]
                
        return expired_flows
