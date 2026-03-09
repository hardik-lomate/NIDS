"""
storage/database.py
SQLite database manager for NIDS.
Handles persistent storage of packets, alerts, and statistics.
"""

import sqlite3
import json
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, List, Dict, Any
import logging

logger = logging.getLogger(__name__)


class DatabaseManager:
    """Thread-safe SQLite database manager."""

    def __init__(self, db_path: str = "data/nids.db"):
        self.db_path = db_path
        self._lock = threading.Lock()
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_schema(self):
        """Create tables if they don't exist."""
        with self._lock, self._get_conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS packets (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp   TEXT NOT NULL,
                    src_ip      TEXT,
                    dst_ip      TEXT,
                    src_port    INTEGER,
                    dst_port    INTEGER,
                    protocol    TEXT,
                    size        INTEGER,
                    flags       TEXT,
                    ttl         INTEGER,
                    payload_len INTEGER,
                    raw_summary TEXT
                );

                CREATE TABLE IF NOT EXISTS alerts (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp    TEXT NOT NULL,
                    alert_type   TEXT NOT NULL,
                    severity     TEXT NOT NULL,
                    src_ip       TEXT,
                    dst_ip       TEXT,
                    dst_port     INTEGER,
                    description  TEXT,
                    details      TEXT,
                    country      TEXT,
                    city         TEXT,
                    threat_score INTEGER DEFAULT 0,
                    acknowledged INTEGER DEFAULT 0,
                    blocked      INTEGER DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS ip_reputation (
                    ip           TEXT PRIMARY KEY,
                    threat_score INTEGER DEFAULT 0,
                    alert_count  INTEGER DEFAULT 0,
                    first_seen   TEXT,
                    last_seen    TEXT,
                    country      TEXT,
                    city         TEXT,
                    is_blocked   INTEGER DEFAULT 0,
                    tags         TEXT
                );

                CREATE TABLE IF NOT EXISTS traffic_stats (
                    id            INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp     TEXT NOT NULL,
                    packets_total INTEGER DEFAULT 0,
                    bytes_total   INTEGER DEFAULT 0,
                    tcp_count     INTEGER DEFAULT 0,
                    udp_count     INTEGER DEFAULT 0,
                    icmp_count    INTEGER DEFAULT 0,
                    other_count   INTEGER DEFAULT 0,
                    unique_ips    INTEGER DEFAULT 0,
                    alerts_count  INTEGER DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS blocked_ips (
                    ip           TEXT PRIMARY KEY,
                    reason       TEXT,
                    blocked_at   TEXT NOT NULL,
                    auto_blocked INTEGER DEFAULT 0,
                    iptables_cmd TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
                CREATE INDEX IF NOT EXISTS idx_alerts_src_ip    ON alerts(src_ip);
                CREATE INDEX IF NOT EXISTS idx_alerts_type      ON alerts(alert_type);
                CREATE INDEX IF NOT EXISTS idx_packets_src_ip   ON packets(src_ip);
                CREATE INDEX IF NOT EXISTS idx_packets_timestamp ON packets(timestamp);
            """)
        logger.info("Database schema initialized: %s", self.db_path)

    # ──────────────────────────────────────────────────────────────
    # Packets
    # ──────────────────────────────────────────────────────────────

    def insert_packet(self, pkt_data: Dict[str, Any]):
        with self._lock, self._get_conn() as conn:
            conn.execute("""
                INSERT INTO packets
                  (timestamp, src_ip, dst_ip, src_port, dst_port, protocol,
                   size, flags, ttl, payload_len, raw_summary)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)
            """, (
                pkt_data.get("timestamp", datetime.utcnow().isoformat()),
                pkt_data.get("src_ip"), pkt_data.get("dst_ip"),
                pkt_data.get("src_port"), pkt_data.get("dst_port"),
                pkt_data.get("protocol"), pkt_data.get("size", 0),
                pkt_data.get("flags"), pkt_data.get("ttl"),
                pkt_data.get("payload_len", 0), pkt_data.get("raw_summary"),
            ))

    def get_recent_packets(self, limit: int = 100) -> List[Dict]:
        with self._lock, self._get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM packets ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    # ──────────────────────────────────────────────────────────────
    # Alerts
    # ──────────────────────────────────────────────────────────────

    def insert_alert(self, alert: Dict[str, Any]) -> int:
        with self._lock, self._get_conn() as conn:
            cur = conn.execute("""
                INSERT INTO alerts
                  (timestamp, alert_type, severity, src_ip, dst_ip, dst_port,
                   description, details, country, city, threat_score)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)
            """, (
                alert.get("timestamp", datetime.utcnow().isoformat()),
                alert.get("alert_type"), alert.get("severity", "MEDIUM"),
                alert.get("src_ip"), alert.get("dst_ip"),
                alert.get("dst_port"),
                alert.get("description"), json.dumps(alert.get("details", {})),
                alert.get("country"), alert.get("city"),
                alert.get("threat_score", 0),
            ))
            self._update_ip_reputation(conn, alert)
            return cur.lastrowid

    def _update_ip_reputation(self, conn: sqlite3.Connection, alert: Dict):
        src_ip = alert.get("src_ip")
        if not src_ip:
            return
        now = datetime.utcnow().isoformat()
        score_delta = {"LOW": 5, "MEDIUM": 15, "HIGH": 30, "CRITICAL": 50}.get(
            alert.get("severity", "LOW"), 5
        )
        conn.execute("""
            INSERT INTO ip_reputation (ip, threat_score, alert_count, first_seen, last_seen, country, city)
            VALUES (?,?,1,?,?,?,?)
            ON CONFLICT(ip) DO UPDATE SET
                threat_score = MIN(100, threat_score + ?),
                alert_count  = alert_count + 1,
                last_seen    = ?,
                country      = COALESCE(EXCLUDED.country, country),
                city         = COALESCE(EXCLUDED.city, city)
        """, (
            src_ip, score_delta, now, now,
            alert.get("country"), alert.get("city"),
            score_delta, now,
        ))

    def get_recent_alerts(self, limit: int = 100, severity: Optional[str] = None) -> List[Dict]:
        with self._lock, self._get_conn() as conn:
            if severity:
                rows = conn.execute(
                    "SELECT * FROM alerts WHERE severity=? ORDER BY id DESC LIMIT ?",
                    (severity, limit)
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)
                ).fetchall()
        return [dict(r) for r in rows]

    def get_alert_counts_by_type(self) -> List[Dict]:
        with self._lock, self._get_conn() as conn:
            rows = conn.execute("""
                SELECT alert_type, COUNT(*) as count, MAX(timestamp) as last_seen
                FROM alerts GROUP BY alert_type ORDER BY count DESC
            """).fetchall()
        return [dict(r) for r in rows]

    def get_top_attackers(self, limit: int = 10) -> List[Dict]:
        with self._lock, self._get_conn() as conn:
            rows = conn.execute("""
                SELECT src_ip, COUNT(*) as alert_count,
                       MAX(threat_score) as max_score,
                       MAX(timestamp) as last_seen,
                       country, city
                FROM alerts
                WHERE src_ip IS NOT NULL
                GROUP BY src_ip
                ORDER BY alert_count DESC
                LIMIT ?
            """, (limit,)).fetchall()
        return [dict(r) for r in rows]

    def acknowledge_alert(self, alert_id: int):
        with self._lock, self._get_conn() as conn:
            conn.execute("UPDATE alerts SET acknowledged=1 WHERE id=?", (alert_id,))

    # ──────────────────────────────────────────────────────────────
    # Traffic Stats
    # ──────────────────────────────────────────────────────────────

    def insert_traffic_stat(self, stat: Dict[str, Any]):
        with self._lock, self._get_conn() as conn:
            conn.execute("""
                INSERT INTO traffic_stats
                  (timestamp, packets_total, bytes_total, tcp_count, udp_count,
                   icmp_count, other_count, unique_ips, alerts_count)
                VALUES (?,?,?,?,?,?,?,?,?)
            """, (
                stat.get("timestamp", datetime.utcnow().isoformat()),
                stat.get("packets_total", 0), stat.get("bytes_total", 0),
                stat.get("tcp_count", 0), stat.get("udp_count", 0),
                stat.get("icmp_count", 0), stat.get("other_count", 0),
                stat.get("unique_ips", 0), stat.get("alerts_count", 0),
            ))

    def get_traffic_history(self, minutes: int = 60) -> List[Dict]:
        since = (datetime.utcnow() - timedelta(minutes=minutes)).isoformat()
        with self._lock, self._get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM traffic_stats WHERE timestamp >= ? ORDER BY timestamp",
                (since,)
            ).fetchall()
        return [dict(r) for r in rows]

    # ──────────────────────────────────────────────────────────────
    # Blocked IPs
    # ──────────────────────────────────────────────────────────────

    def block_ip(self, ip: str, reason: str, auto: bool = False):
        cmd = f"iptables -A INPUT -s {ip} -j DROP"
        with self._lock, self._get_conn() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO blocked_ips (ip, reason, blocked_at, auto_blocked, iptables_cmd)
                VALUES (?,?,?,?,?)
            """, (ip, reason, datetime.utcnow().isoformat(), int(auto), cmd))
            conn.execute("UPDATE ip_reputation SET is_blocked=1 WHERE ip=?", (ip,))

    def get_blocked_ips(self) -> List[Dict]:
        with self._lock, self._get_conn() as conn:
            rows = conn.execute("SELECT * FROM blocked_ips ORDER BY blocked_at DESC").fetchall()
        return [dict(r) for r in rows]

    def is_blocked(self, ip: str) -> bool:
        with self._lock, self._get_conn() as conn:
            row = conn.execute("SELECT 1 FROM blocked_ips WHERE ip=?", (ip,)).fetchone()
        return row is not None

    # ──────────────────────────────────────────────────────────────
    # IP Reputation
    # ──────────────────────────────────────────────────────────────

    def get_ip_reputation(self, ip: str) -> Optional[Dict]:
        with self._lock, self._get_conn() as conn:
            row = conn.execute("SELECT * FROM ip_reputation WHERE ip=?", (ip,)).fetchone()
        return dict(row) if row else None

    def get_top_threat_ips(self, limit: int = 20) -> List[Dict]:
        with self._lock, self._get_conn() as conn:
            rows = conn.execute("""
                SELECT * FROM ip_reputation ORDER BY threat_score DESC LIMIT ?
            """, (limit,)).fetchall()
        return [dict(r) for r in rows]

    # ──────────────────────────────────────────────────────────────
    # Maintenance
    # ──────────────────────────────────────────────────────────────

    def purge_old_records(self, retention_days: int = 30):
        """Remove old packet and alert records."""
        cutoff = (datetime.utcnow() - timedelta(days=retention_days)).isoformat()
        with self._lock, self._get_conn() as conn:
            conn.execute("DELETE FROM packets WHERE timestamp < ?", (cutoff,))
            conn.execute("DELETE FROM traffic_stats WHERE timestamp < ?", (cutoff,))
        logger.info("Purged records older than %d days", retention_days)

    def get_summary_stats(self) -> Dict[str, Any]:
        with self._lock, self._get_conn() as conn:
            total_alerts = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            total_packets = conn.execute("SELECT COUNT(*) FROM packets").fetchone()[0]
            blocked_ips   = conn.execute("SELECT COUNT(*) FROM blocked_ips").fetchone()[0]
            critical      = conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE severity='CRITICAL'"
            ).fetchone()[0]
            unacked       = conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE acknowledged=0"
            ).fetchone()[0]
        return {
            "total_alerts": total_alerts,
            "total_packets": total_packets,
            "blocked_ips": blocked_ips,
            "critical_alerts": critical,
            "unacknowledged": unacked,
        }
