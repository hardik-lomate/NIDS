"""
alerting/email_alert.py
SMTP email alerter with HTML-formatted notifications.
"""

import smtplib
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime
from typing import Dict, Any

logger = logging.getLogger("nids.email")

SEVERITY_COLORS = {
    "LOW":      "#3498db",
    "MEDIUM":   "#f39c12",
    "HIGH":     "#e67e22",
    "CRITICAL": "#e74c3c",
}


class EmailAlerter:
    def __init__(self, config: Dict[str, Any]):
        cfg             = config.get("alerting", {}).get("email", {})
        self.smtp_host  = cfg.get("smtp_server", "smtp.gmail.com")
        self.smtp_port  = cfg.get("smtp_port", 587)
        self.use_tls    = cfg.get("use_tls", True)
        self.sender     = cfg.get("sender", "")
        self.password   = cfg.get("password", "")
        self.recipients = cfg.get("recipients", [])

    def send(self, alert: Dict[str, Any]):
        if not self.sender or not self.recipients:
            return
        sev   = alert.get("severity", "MEDIUM")
        color = SEVERITY_COLORS.get(sev, "#7f8c8d")
        subj  = f"[NIDS {sev}] {alert.get('alert_type')} — {alert.get('src_ip', 'N/A')}"

        html = f"""
        <html><body style="font-family:monospace;background:#0a0e1a;color:#e0e0e0;padding:20px">
          <div style="border-left:4px solid {color};padding:12px 20px;background:#111827">
            <h2 style="color:{color};margin:0">{alert.get('alert_type')}</h2>
            <p style="color:#9ca3af">{alert.get('timestamp')}</p>
          </div>
          <table style="width:100%;margin-top:16px;border-collapse:collapse">
            <tr><td style="color:#6b7280;padding:6px">Severity</td>
                <td style="color:{color};font-weight:bold">{sev}</td></tr>
            <tr><td style="color:#6b7280;padding:6px">Source IP</td>
                <td style="color:#e0e0e0">{alert.get('src_ip','N/A')}</td></tr>
            <tr><td style="color:#6b7280;padding:6px">Country</td>
                <td style="color:#e0e0e0">{alert.get('country','Unknown')}</td></tr>
            <tr><td style="color:#6b7280;padding:6px">Description</td>
                <td style="color:#e0e0e0">{alert.get('description','')}</td></tr>
            <tr><td style="color:#6b7280;padding:6px">Threat Score</td>
                <td style="color:{color}">{alert.get('threat_score',0)}/100</td></tr>
          </table>
          <p style="color:#4b5563;margin-top:20px;font-size:12px">
            NIDS — Network Intrusion Detection System
          </p>
        </body></html>
        """

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subj
        msg["From"]    = self.sender
        msg["To"]      = ", ".join(self.recipients)
        msg.attach(MIMEText(html, "html"))

        try:
            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=10) as s:
                if self.use_tls:
                    s.starttls()
                s.login(self.sender, self.password)
                s.sendmail(self.sender, self.recipients, msg.as_string())
            logger.info("Alert email sent for %s", alert.get("alert_type"))
        except Exception as exc:
            logger.error("Email error: %s", exc)
