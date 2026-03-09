"""
storage/logger.py
Structured logging system with file rotation, JSON formatting,
and color-coded console output.
"""

import logging
import logging.handlers
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, Any


class JSONFormatter(logging.Formatter):
    """Emit log records as JSON lines for easy ingestion by SIEM tools."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level":     record.levelname,
            "logger":    record.name,
            "message":   record.getMessage(),
            "module":    record.module,
            "line":      record.lineno,
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        if hasattr(record, "extra"):
            payload.update(record.extra)
        return json.dumps(payload)


class AlertFormatter(logging.Formatter):
    """Human-readable formatter for the alert log file."""
    FMT = "[{asctime}] [{levelname:<8}] {message}"

    def __init__(self):
        super().__init__(fmt=self.FMT, style="{", datefmt="%Y-%m-%d %H:%M:%S")


class ColorConsoleFormatter(logging.Formatter):
    """ANSI color-coded formatter for terminal output."""
    COLORS = {
        "DEBUG":    "\033[37m",
        "INFO":     "\033[36m",
        "WARNING":  "\033[33m",
        "ERROR":    "\033[31m",
        "CRITICAL": "\033[1;31m",
    }
    RESET = "\033[0m"
    FMT   = "%(asctime)s  %(levelname)-8s  %(name)s  %(message)s"

    def format(self, record: logging.LogRecord) -> str:
        color   = self.COLORS.get(record.levelname, "")
        message = super().format(record)
        return f"{color}{message}{self.RESET}"


def setup_logging(config: Dict[str, Any]) -> logging.Logger:
    """
    Configure the root logger based on config dict.
    Returns the root NIDS logger.
    """
    log_cfg = config.get("logging", {})
    level_str = log_cfg.get("level", "INFO").upper()
    level     = getattr(logging, level_str, logging.INFO)

    log_file   = log_cfg.get("log_file",   "logs/nids.log")
    alert_file = log_cfg.get("alert_file", "logs/alerts.log")
    max_bytes  = log_cfg.get("max_file_size", 10 * 1024 * 1024)
    backups    = log_cfg.get("backup_count", 10)
    use_json   = log_cfg.get("json_format", True)

    Path(log_file).parent.mkdir(parents=True, exist_ok=True)
    Path(alert_file).parent.mkdir(parents=True, exist_ok=True)

    root = logging.getLogger()
    root.setLevel(level)
    root.handlers.clear()

    # ── Console handler ──────────────────────────────────────────
    console_h = logging.StreamHandler(sys.stdout)
    console_h.setLevel(level)
    console_h.setFormatter(ColorConsoleFormatter())
    root.addHandler(console_h)

    # ── Main rotating log ─────────────────────────────────────────
    file_h = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=max_bytes, backupCount=backups, encoding="utf-8"
    )
    file_h.setLevel(level)
    if use_json:
        file_h.setFormatter(JSONFormatter())
    else:
        file_h.setFormatter(AlertFormatter())
    root.addHandler(file_h)

    # ── Dedicated alert log ───────────────────────────────────────
    alert_h = logging.handlers.RotatingFileHandler(
        alert_file, maxBytes=max_bytes, backupCount=backups, encoding="utf-8"
    )
    alert_h.setLevel(logging.WARNING)
    alert_h.setFormatter(AlertFormatter())

    alert_logger = logging.getLogger("nids.alerts")
    alert_logger.addHandler(alert_h)
    alert_logger.propagate = True

    return logging.getLogger("nids")


def log_alert(alert_type: str, src_ip: str, description: str,
              severity: str = "MEDIUM", details: Dict = None):
    """Convenience function to emit a structured alert log entry."""
    logger = logging.getLogger("nids.alerts")
    extra  = {
        "alert_type": alert_type,
        "src_ip":     src_ip,
        "severity":   severity,
        "details":    details or {},
    }
    level_map = {
        "LOW":      logging.INFO,
        "MEDIUM":   logging.WARNING,
        "HIGH":     logging.ERROR,
        "CRITICAL": logging.CRITICAL,
    }
    level = level_map.get(severity.upper(), logging.WARNING)
    logger.log(level, "[%s] %s — %s", severity, alert_type, description, extra=extra)
