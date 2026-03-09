"""
report_generator.py  — v1.0 (Phase 6)

Incident Report Generation:
  - HTML report (standalone, embeds all data)
  - JSON dump (SIEM-importable)
  - CEF format (ArcSight / Splunk compatible)
  - CSV export for forensic spreadsheet analysis

Reports include:
  - Executive summary (alert counts by severity)
  - Attack timeline with severity breakdown
  - Top attacker IPs with GeoIP
  - MITRE ATT&CK technique matrix
  - Full alert detail table
  - ML model evaluation results
  - Recommended iptables block commands
"""

import json
import csv
import io
import time
from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path

REPORT_DIR = Path("data/reports")


def _sev_color(sev: str) -> str:
    return {"CRITICAL": "#e53e4d", "HIGH": "#f5a142",
            "MEDIUM": "#f9ca4f", "LOW": "#3dd4a0"}.get(sev, "#8e9ab8")


class ReportGenerator:

    def __init__(self, db=None, threat_intel=None, ml_detector=None):
        self.db = db
        self.ti = threat_intel
        self.ml = ml_detector
        REPORT_DIR.mkdir(parents=True, exist_ok=True)

    # ─── JSON / SIEM Export ──────────────────────────────────────────────
    def export_json(self, alerts: List[Dict], limit: int = 1000) -> str:
        subset = alerts[:limit]
        return json.dumps({
            "export_time": datetime.utcnow().isoformat(),
            "total_alerts": len(subset),
            "source": "AI-NIDS v3.0",
            "alerts": subset,
        }, indent=2, default=str)

    def export_cef(self, alerts: List[Dict]) -> str:
        """
        CEF (Common Event Format) for ArcSight / Splunk Universal Forwarder.
        Format: CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extensions
        """
        lines = []
        sev_map = {"CRITICAL": "10", "HIGH": "7", "MEDIUM": "5", "LOW": "3"}
        for a in alerts:
            sig = (a.get("alert_type") or "UNKNOWN").replace("|", "|")
            name = (a.get("description") or "").replace("|", "|").replace("=", "=")[:100]
            sev  = sev_map.get(a.get("severity", "LOW"), "3")
            ext  = " ".join([
                f"src={a.get('src_ip','')}",
                f"dst={a.get('dst_ip','')}",
                f"dpt={a.get('dst_port','')}",
                f"cs1={a.get('mitre_technique','')}",
                f"cs1Label=MITRETechnique",
                f"cs2={a.get('mitre_tactic','')}",
                f"cs2Label=MITRETactic",
                f"cn1={a.get('confidence',0)}",
                f"cn1Label=Confidence",
                f"cn2={a.get('threat_score',0)}",
                f"cn2Label=ThreatScore",
                f"rt={a.get('timestamp','')}",
            ])
            lines.append(f"CEF:0|AI-NIDS|NetworkIDS|3.0|{sig}|{name}|{sev}|{ext}")
        return "\n".join(lines)

    def export_csv(self, alerts: List[Dict]) -> str:
        buf = io.StringIO()
        fields = ["timestamp", "alert_type", "severity", "confidence", "threat_score",
                  "src_ip", "dst_ip", "dst_port", "mitre_tactic", "mitre_technique",
                  "mitre_name", "description"]
        w = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(alerts)
        return buf.getvalue()

    # ─── HTML Report ─────────────────────────────────────────────────────
    def generate_html_report(self, alerts: List[Dict],
                             ml_info: Optional[Dict] = None,
                             ti_stats: Optional[Dict] = None) -> str:
        now      = datetime.utcnow().isoformat()
        total    = len(alerts)
        by_sev   = {}
        by_type  = {}
        by_mitre = {}
        top_ips: Dict[str, int] = {}

        for a in alerts:
            sev  = a.get("severity", "LOW")
            typ  = a.get("alert_type", "?")
            ip   = a.get("src_ip", "")
            tac  = a.get("mitre_tactic", "")
            by_sev[sev]   = by_sev.get(sev, 0) + 1
            by_type[typ]  = by_type.get(typ, 0) + 1
            if tac: by_mitre[tac] = by_mitre.get(tac, 0) + 1
            if ip: top_ips[ip] = top_ips.get(ip, 0) + 1

        top_ip_rows = sorted(top_ips.items(), key=lambda x: x[1], reverse=True)[:10]
        top_type_rows = sorted(by_type.items(), key=lambda x: x[1], reverse=True)[:15]
        block_cmds = [f"iptables -A INPUT -s {ip} -j DROP" for ip, _ in top_ip_rows[:5]]

        def sev_badge(sev):
            c = _sev_color(sev)
            return f'<span style="background:{c}22;color:{c};padding:2px 8px;border-radius:3px;font-size:10px;font-weight:600;font-family:monospace">{sev}</span>'

        alert_rows = "".join(
            f'<tr style="border-bottom:1px solid #1a2030">'
            f'<td style="padding:6px 10px;color:#8e9ab8;font-family:monospace;font-size:11px">{a.get("timestamp","")[:19]}</td>'
            f'<td style="padding:6px 10px">{sev_badge(a.get("severity","LOW"))}</td>'
            f'<td style="padding:6px 10px;color:#4da8e0;font-family:monospace">{a.get("src_ip","—")}</td>'
            f'<td style="padding:6px 10px;color:#dde3f5;font-family:monospace;font-size:11px">{a.get("alert_type","?")}</td>'
            f'<td style="padding:6px 10px;color:#8e9ab8;font-size:11px">{str(a.get("confidence",""))+"%" if a.get("confidence") else "—"}</td>'
            f'<td style="padding:6px 10px;color:#9b74e8;font-family:monospace;font-size:10px">{a.get("mitre_technique","—")}</td>'
            f'<td style="padding:6px 10px;color:#8e9ab8;font-size:11px;max-width:300px;overflow:hidden;text-overflow:ellipsis">{a.get("description","")[:100]}</td>'
            f'</tr>'
            for a in alerts[:200]
        )

        type_rows = "".join(
            f'<tr><td style="padding:5px 10px;color:#dde3f5;font-family:monospace;font-size:11px">{t}</td>'
            f'<td style="padding:5px 10px;color:#4da8e0;font-weight:600;font-family:monospace">{c}</td></tr>'
            for t, c in top_type_rows
        )
        ip_rows = "".join(
            f'<tr><td style="padding:5px 10px;color:#4da8e0;font-family:monospace">{ip}</td>'
            f'<td style="padding:5px 10px;color:#f5a142;font-weight:600;font-family:monospace">{cnt}</td>'
            f'<td style="padding:5px 10px;color:#3dd4a0;font-family:monospace;font-size:10px">iptables -A INPUT -s {ip} -j DROP</td></tr>'
            for ip, cnt in top_ip_rows
        )
        block_section = "\n".join(f"$ {cmd}" for cmd in block_cmds)
        mitre_rows = "".join(
            f'<tr><td style="padding:5px 10px;color:#22d3ee;font-family:monospace;font-size:11px">{t}</td>'
            f'<td style="padding:5px 10px;color:#f5a142;font-family:monospace">{c}</td></tr>'
            for t, c in sorted(by_mitre.items(), key=lambda x: x[1], reverse=True)
        )
        ml_section = ""
        if ml_info:
            ml_section = f"""
            <div style="background:#0c0e17;border:1px solid #1a2030;border-radius:4px;padding:16px;margin-bottom:16px">
              <h3 style="font-family:'Barlow Condensed',sans-serif;font-size:16px;margin-bottom:10px;color:#4da8e0">ML Model</h3>
              <p style="color:#8e9ab8;font-size:12px">Architecture: <span style="color:#dde3f5;font-family:monospace">{ml_info.get("models",["IF"])} ensemble</span></p>
              <p style="color:#8e9ab8;font-size:12px">Training samples: <span style="color:#3dd4a0;font-family:monospace">{ml_info.get("samples",0):,}</span></p>
              <p style="color:#8e9ab8;font-size:12px">Features: <span style="color:#dde3f5;font-family:monospace">{ml_info.get("features",18)}</span></p>
            </div>"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<title>AI-NIDS Incident Report — {now[:10]}</title>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600&family=IBM+Plex+Mono&family=Barlow+Condensed:wght@600;700&display=swap" rel="stylesheet"/>
<style>
body{{background:#07080e;color:#dde3f5;font-family:'IBM Plex Sans',sans-serif;margin:0;padding:24px;font-size:13px}}
.hdr{{background:#0c0e17;border:1px solid #1a2030;border-radius:6px;padding:20px 24px;margin-bottom:20px;display:flex;align-items:center;justify-content:space-between}}
.hdr-title{{font-family:'Barlow Condensed',sans-serif;font-size:26px;font-weight:700;letter-spacing:.3px}}
.hdr-meta{{font-size:11px;color:#4e5878;font-family:monospace}}
.kpis{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:20px}}
.kpi{{background:#0c0e17;border:1px solid #1a2030;border-radius:4px;padding:14px 16px}}
.kpi-n{{font-family:'Barlow Condensed',sans-serif;font-size:32px;font-weight:700;line-height:1}}
.kpi-l{{font-size:10px;color:#4e5878;text-transform:uppercase;letter-spacing:.7px;margin-top:4px}}
.card{{background:#0c0e17;border:1px solid #1a2030;border-radius:4px;margin-bottom:16px;overflow:hidden}}
.card-hd{{background:#10131e;border-bottom:1px solid #1a2030;padding:8px 14px;font-family:'Barlow Condensed',sans-serif;font-size:14px;font-weight:600;color:#dde3f5}}
table{{width:100%;border-collapse:collapse}}
th{{padding:7px 10px;text-align:left;font-size:9.5px;color:#4e5878;text-transform:uppercase;letter-spacing:.6px;border-bottom:1px solid #1a2030;background:#10131e}}
.block-pre{{background:#060710;border:1px solid #1a2030;border-radius:4px;padding:14px 16px;font-family:monospace;font-size:11px;color:#3dd4a0;white-space:pre;overflow-x:auto}}
@media print{{body{{background:white;color:black}}}}
</style>
</head>
<body>
<div class="hdr">
  <div>
    <div class="hdr-title">&#x1F6E1; AI-NIDS Incident Report</div>
    <div class="hdr-meta">Generated: {now} UTC | AI-NIDS v3.0 | Isolation Forest + OC-SVM + Autoencoder</div>
  </div>
  <div style="text-align:right">
    <div style="font-family:monospace;font-size:11px;color:#4e5878">CONFIDENTIAL — SECURITY OPERATIONS</div>
  </div>
</div>

<div class="kpis">
  <div class="kpi"><div class="kpi-n">{total}</div><div class="kpi-l">Total Alerts</div></div>
  <div class="kpi"><div class="kpi-n" style="color:#e53e4d">{by_sev.get("CRITICAL",0)}</div><div class="kpi-l">Critical</div></div>
  <div class="kpi"><div class="kpi-n" style="color:#f5a142">{by_sev.get("HIGH",0)}</div><div class="kpi-l">High</div></div>
  <div class="kpi"><div class="kpi-n" style="color:#3dd4a0">{len(top_ips)}</div><div class="kpi-l">Unique Attacker IPs</div></div>
</div>

<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px">
  <div class="card">
    <div class="card-hd">Attack Type Distribution</div>
    <table><thead><tr><th>Type</th><th>Count</th></tr></thead><tbody>{type_rows}</tbody></table>
  </div>
  <div class="card">
    <div class="card-hd">MITRE ATT&CK Tactics</div>
    <table><thead><tr><th>Tactic</th><th>Count</th></tr></thead><tbody>{mitre_rows}</tbody></table>
  </div>
</div>

<div class="card" style="margin-bottom:16px">
  <div class="card-hd">Top Attacker IPs</div>
  <table><thead><tr><th>IP Address</th><th>Alerts</th><th>Recommended Block Command</th></tr></thead>
  <tbody>{ip_rows}</tbody></table>
</div>

<div class="card" style="margin-bottom:16px">
  <div class="card-hd">Recommended iptables Block Commands</div>
  <div style="padding:14px"><pre class="block-pre">{block_section}</pre></div>
</div>

{ml_section}

<div class="card">
  <div class="card-hd">Alert Detail (first 200)</div>
  <table>
    <thead><tr><th>Time</th><th>Sev</th><th>Source IP</th><th>Type</th><th>Confidence</th><th>MITRE</th><th>Description</th></tr></thead>
    <tbody>{alert_rows}</tbody>
  </table>
</div>

<div style="margin-top:20px;padding:14px;color:#2a3252;font-size:10px;font-family:monospace;text-align:center">
  AI-NIDS v3.0 — Isolation Forest + One-Class SVM + Autoencoder ensemble — {total} alerts analyzed — {now} UTC
</div>
</body></html>"""
        return html

    def save_html_report(self, alerts: List[Dict], **kwargs) -> Path:
        content = self.generate_html_report(alerts, **kwargs)
        filename = REPORT_DIR / f"report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.html"
        filename.write_text(content, encoding="utf-8")
        return filename

    def list_reports(self) -> List[Dict]:
        reports = []
        for f in sorted(REPORT_DIR.glob("report_*.html"), key=lambda x: x.stat().st_mtime, reverse=True):
            stat = f.stat()
            reports.append({"filename": f.name, "path": str(f),
                           "size_bytes": stat.st_size,
                           "created": datetime.fromtimestamp(stat.st_mtime).isoformat()})
        return reports[:20]
