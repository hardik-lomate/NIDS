"""
alerting/slack_alert.py
Slack webhook alerter with rich Block Kit formatting.
"""

import json
import logging
import urllib.request
from typing import Dict, Any

logger = logging.getLogger("nids.slack")

SEVERITY_EMOJI = {
    "LOW":      ":information_source:",
    "MEDIUM":   ":warning:",
    "HIGH":     ":rotating_light:",
    "CRITICAL": ":skull_and_crossbones:",
}
SEVERITY_COLOR = {
    "LOW": "#3498db", "MEDIUM": "#f39c12",
    "HIGH": "#e67e22", "CRITICAL": "#e74c3c",
}


class SlackAlerter:
    def __init__(self, config: Dict[str, Any]):
        cfg             = config.get("alerting", {}).get("slack", {})
        self.webhook    = cfg.get("webhook_url", "")
        self.channel    = cfg.get("channel", "#security-alerts")

    def send(self, alert: Dict[str, Any]):
        if not self.webhook:
            return
        sev    = alert.get("severity", "MEDIUM")
        emoji  = SEVERITY_EMOJI.get(sev, ":warning:")
        color  = SEVERITY_COLOR.get(sev, "#7f8c8d")

        payload = {
            "channel": self.channel,
            "attachments": [{
                "color":   color,
                "pretext": f"{emoji} *NIDS ALERT — {sev}*",
                "title":   alert.get("alert_type", "UNKNOWN"),
                "text":    alert.get("description", ""),
                "fields": [
                    {"title": "Source IP",    "value": alert.get("src_ip", "N/A"), "short": True},
                    {"title": "Country",      "value": alert.get("country", "Unknown"), "short": True},
                    {"title": "Threat Score", "value": str(alert.get("threat_score", 0)) + "/100", "short": True},
                    {"title": "Time",         "value": alert.get("timestamp", ""), "short": True},
                ],
                "footer": "NIDS Monitor",
                "ts":      int(__import__("time").time()),
            }]
        }

        body = json.dumps(payload).encode("utf-8")
        req  = urllib.request.Request(
            self.webhook, data=body,
            headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, timeout=5):
                pass
            logger.info("Slack alert sent for %s", alert.get("alert_type"))
        except Exception as exc:
            logger.error("Slack webhook error: %s", exc)
