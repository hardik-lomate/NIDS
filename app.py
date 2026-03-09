"""
dashboard/app.py  — v4.0
Flask + Socket.IO dashboard server.
REST API + real-time WebSocket events.

v4.0 endpoints:
  GET  /api/flows               — Live network flow data
  POST /api/alerts/feedback      — Analyst confirmed/dismissed feedback
  GET  /api/ml/training_log      — Training history with metrics
  GET  /api/ml/feature_importance — Feature importance ranking
  GET  /api/capture/status       — Enhanced with PPS/queue stats
"""

import json
import logging
import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List

from flask import Flask, render_template, jsonify, request, Response, send_file
from flask_socketio import SocketIO, emit
from flask_cors import CORS
from pathlib import Path

logger = logging.getLogger("nids.dashboard")


def create_app(config: Dict[str, Any], db=None, analyzer=None,
               alert_manager=None, capture_engine=None, ml_detector=None,
               threat_intel=None, capture=None):

    dash_cfg   = config.get("dashboard", {})
    secret_key = dash_cfg.get("secret_key", "dev-secret")

    app = Flask(__name__, template_folder=".")
    app.debug = True
    app.config["SECRET_KEY"] = secret_key
    CORS(app)

    socketio = SocketIO(
        app, cors_allowed_origins="*",
        async_mode="threading", logger=False, engineio_logger=False,
    )

    # ── Alert push to dashboard ───────────────────────────────────────────────
    def _push_alert(alert: Dict):
        socketio.emit("alert", alert, namespace="/nids")

    if alert_manager:
        alert_manager.register_realtime_callback(_push_alert)

    # ── Background stats emitter ──────────────────────────────────────────────
    def _stats_emitter():
        while True:
            time.sleep(1)
            try:
                snap: Dict[str, Any] = {}
                if capture_engine:
                    snap["capture"] = capture_engine.get_stats()
                if analyzer:
                    snap["traffic"] = {
                        "pps":         analyzer.get_pps(),
                        "bps":         analyzer.get_bps(),
                        "protocols":   analyzer.get_protocol_distribution(),
                        "timeline":    analyzer.get_timeline()[-60:],
                        "top_ports":   [{"port": p, "count": c} for p, c in analyzer.get_top_ports(5)],
                        "top_talkers": analyzer.get_top_talkers(5),
                        "unique_ips":  analyzer.get_unique_ips_1min(),
                    }
                if ml_detector:
                    snap["ml"] = {
                        "trained":  ml_detector.is_trained,
                        "samples":  ml_detector.get_training_samples(),
                    }
                if db:
                    snap["db_stats"] = db.get_summary_stats()
                snap["timestamp"] = datetime.utcnow().isoformat()
                socketio.emit("stats", snap, namespace="/nids")
            except Exception as exc:
                logger.debug("Stats emitter error: %s", exc)

    threading.Thread(target=_stats_emitter, daemon=True, name="StatsEmitter").start()

    # ── Routes ────────────────────────────────────────────────────────────────

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/api/alerts")
    def api_alerts():
        limit    = int(request.args.get("limit", 100))
        severity = request.args.get("severity")
        src_ip   = request.args.get("src_ip")
        atype    = request.args.get("alert_type")
        if alert_manager:
            data = alert_manager.get_recent_alerts(limit=limit, severity=severity)
        elif db:
            data = db.get_recent_alerts(limit=limit, severity=severity)
        else:
            data = []
        # Client-side filters
        if src_ip:
            data = [a for a in data if a.get("src_ip") == src_ip]
        if atype:
            data = [a for a in data if a.get("alert_type") == atype]
        return jsonify({"alerts": data, "count": len(data)})

    @app.route("/api/alerts/search")
    def api_alerts_search():
        q        = request.args.get("q", "").lower()
        severity = request.args.get("severity")
        src_ip   = request.args.get("src_ip")
        atype    = request.args.get("alert_type")
        limit    = int(request.args.get("limit", 200))
        if alert_manager:
            data = alert_manager.get_recent_alerts(limit=limit)
        elif db:
            data = db.get_recent_alerts(limit=limit)
        else:
            data = []
        if q:
            data = [a for a in data if q in json.dumps(a).lower()]
        if severity:
            data = [a for a in data if a.get("severity","").upper() == severity.upper()]
        if src_ip:
            data = [a for a in data if a.get("src_ip","") == src_ip]
        if atype:
            data = [a for a in data if a.get("alert_type","").upper() == atype.upper()]
        return jsonify({"alerts": data, "count": len(data)})

    @app.route("/api/alerts/stats")
    def api_alert_stats():
        if db:
            return jsonify({
                "by_type":       db.get_alert_counts_by_type(),
                "top_attackers": db.get_top_attackers(10),
            })
        return jsonify({})

    @app.route("/api/timeline")
    def api_timeline():
        """Return alerts grouped into time buckets for timeline view."""
        hours   = int(request.args.get("hours", 6))
        buckets = int(request.args.get("buckets", 60))
        limit   = int(request.args.get("limit", 500))
        if alert_manager:
            alerts = alert_manager.get_recent_alerts(limit=limit)
        elif db:
            alerts = db.get_recent_alerts(limit=limit)
        else:
            alerts = []

        now = datetime.utcnow()
        window_start = now - timedelta(hours=hours)
        bucket_secs  = (hours * 3600) / buckets
        timeline = defaultdict(lambda: {"count": 0, "critical": 0, "high": 0,
                                         "medium": 0, "low": 0, "types": []})
        for a in alerts:
            try:
                ts = datetime.fromisoformat(a["timestamp"].replace("Z",""))
                if ts < window_start:
                    continue
                delta   = (ts - window_start).total_seconds()
                bucket  = int(delta / bucket_secs)
                bkey    = bucket
                timeline[bkey]["count"] += 1
                sev = a.get("severity","LOW").lower()
                timeline[bkey][sev] = timeline[bkey].get(sev, 0) + 1
                atype = a.get("alert_type","")
                if atype not in timeline[bkey]["types"]:
                    timeline[bkey]["types"].append(atype)
            except Exception:
                continue

        result = []
        for b in range(buckets):
            ts_bucket = window_start + timedelta(seconds=b * bucket_secs)
            entry = timeline.get(b, {"count":0,"critical":0,"high":0,"medium":0,"low":0,"types":[]})
            entry["timestamp"] = ts_bucket.isoformat()
            entry["bucket"] = b
            result.append(entry)
        return jsonify({"timeline": result, "hours": hours, "buckets": buckets})

    @app.route("/api/mitre/stats")
    def api_mitre_stats():
        """MITRE ATT&CK tactic and technique breakdown from recent alerts."""
        limit = int(request.args.get("limit", 500))
        if alert_manager:
            alerts = alert_manager.get_recent_alerts(limit=limit)
        elif db:
            alerts = db.get_recent_alerts(limit=limit)
        else:
            alerts = []

        tactics: Dict[str, int]    = defaultdict(int)
        techniques: Dict[str, Dict] = defaultdict(lambda: {"count":0,"name":""})

        for a in alerts:
            tac = a.get("mitre_tactic","Unknown")
            tec = a.get("mitre_technique","T0000")
            tname = a.get("mitre_name","")
            tactics[tac] += 1
            techniques[tec]["count"] += 1
            techniques[tec]["name"] = tname
            techniques[tec]["tactic"] = tac

        return jsonify({
            "tactics":    [{"name":k,"count":v} for k,v in sorted(tactics.items(), key=lambda x:-x[1])],
            "techniques": [{"id":k,"name":v["name"],"tactic":v["tactic"],"count":v["count"]}
                           for k,v in sorted(techniques.items(), key=lambda x:-x[1]["count"])],
            "total_alerts": len(alerts),
        })

    @app.route("/api/siem/export")
    def api_siem_export():
        """Export alerts in SIEM-compatible JSON format (CEF-like structure)."""
        limit  = int(request.args.get("limit", 1000))
        fmt    = request.args.get("format", "json")
        if alert_manager:
            alerts = alert_manager.get_recent_alerts(limit=limit)
        elif db:
            alerts = db.get_recent_alerts(limit=limit)
        else:
            alerts = []

        if fmt == "cef":
            lines = []
            for a in alerts:
                sev_map = {"LOW":3,"MEDIUM":5,"HIGH":8,"CRITICAL":10}
                sev_num = sev_map.get(a.get("severity","LOW"), 3)
                cef = (f"CEF:0|NIDS|AI-NIDS|2.0|{a.get('alert_type','')}|"
                       f"{a.get('description','')}|{sev_num}|"
                       f"src={a.get('src_ip','?')} dst={a.get('dst_ip','?')} "
                       f"dpt={a.get('dst_port','?')} "
                       f"cs1={a.get('mitre_technique','')} cs1Label=MITRE_Technique "
                       f"cs2={a.get('confidence','')} cs2Label=Confidence "
                       f"rt={a.get('timestamp','')}")
                lines.append(cef)
            return Response("\n".join(lines), mimetype="text/plain",
                            headers={"Content-Disposition": "attachment; filename=nids_alerts.cef"})

        export = {
            "export_time":   datetime.utcnow().isoformat(),
            "system":        "AI-NIDS v2.0",
            "alert_count":   len(alerts),
            "alerts":        alerts,
        }
        return Response(json.dumps(export, indent=2), mimetype="application/json",
                        headers={"Content-Disposition": "attachment; filename=nids_alerts.json"})

    @app.route("/api/traffic")
    def api_traffic():
        if analyzer:
            return jsonify(analyzer.get_snapshot())
        return jsonify({})

    @app.route("/api/blocked")
    def api_blocked():
        if db:
            return jsonify({"blocked": db.get_blocked_ips()})
        return jsonify({"blocked": []})

    @app.route("/api/reputation/<ip>")
    def api_reputation(ip: str):
        if db:
            rep = db.get_ip_reputation(ip)
            return jsonify(rep or {"error": "Not found"})
        return jsonify({})

    @app.route("/api/reputation/top")
    def api_top_reputation():
        if db:
            return jsonify({"ips": db.get_top_threat_ips(20)})
        return jsonify({"ips": []})

    @app.route("/api/packets")
    def api_packets():
        limit = int(request.args.get("limit", 50))
        if db:
            return jsonify({"packets": db.get_recent_packets(limit)})
        return jsonify({"packets": []})

    @app.route("/api/ml/info")
    def api_ml_info():
        if ml_detector:
            return jsonify(ml_detector.get_model_info())
        return jsonify({"trained": False, "error": "ML detector not available"})

    @app.route("/api/ml/evaluate")
    def api_ml_evaluate():
        try:
            from evaluate_ml import generate_mock_data
            from sklearn.metrics import precision_score, recall_score, confusion_matrix
        except ImportError:
            return jsonify({"error": "scikit-learn required"}), 500
        if not ml_detector or not ml_detector._iso_model:
            return jsonify({"error": "Model not trained yet"}), 400
        test_data, y_true = generate_mock_data(400, 100)
        y_pred = []
        with ml_detector._model_lock:
            scaled = ml_detector._scaler.transform(test_data)
            y_pred = list(ml_detector._iso_model.predict(scaled))
        yt = [1 if y==-1 else 0 for y in y_true]
        yp = [1 if y==-1 else 0 for y in y_pred]
        tn, fp, fn, tp = confusion_matrix(yt, yp).ravel()
        return jsonify({
            "metrics": {
                "precision": round(precision_score(yt,yp,zero_division=0), 4),
                "recall":    round(recall_score(yt,yp,zero_division=0), 4),
                "fpr":       round(fp/(fp+tn) if (fp+tn)>0 else 0, 4),
                "f1":        round(2*tp/(2*tp+fp+fn) if (2*tp+fp+fn)>0 else 0, 4),
            },
            "confusion": {"tn":int(tn),"fp":int(fp),"fn":int(fn),"tp":int(tp)},
            "samples":   {"total":len(yt),"anomalies":sum(yt),"detected":sum(yp)},
        })

    @app.route("/api/stats")
    def api_stats():
        result: Dict[str, Any] = {}
        if db:
            result["summary"] = db.get_summary_stats()
            result["traffic_history"] = db.get_traffic_history(minutes=60)
        if capture_engine:
            result["capture"] = capture_engine.get_stats()
        if analyzer:
            result["live"] = {
                "pps":         analyzer.get_pps(),
                "bps":         analyzer.get_bps(),
                "protocols":   analyzer.get_protocol_distribution(),
                "unique_ips":  analyzer.get_unique_ips_1min(),
                "top_ports":   [{"port": p, "count": c} for p, c in analyzer.get_top_ports(5)],
                "top_talkers": analyzer.get_top_talkers(5),
                "timeline":    analyzer.get_timeline()[-60:],
            }
        if ml_detector:
            result["ml"] = {
                "trained":  ml_detector.is_trained,
                "samples":  ml_detector.get_training_samples(),
            }
        return jsonify(result)

    @app.route("/api/alerts/<int:alert_id>/ack", methods=["POST"])
    def api_ack_alert(alert_id: int):
        if db:
            db.acknowledge_alert(alert_id)
            return jsonify({"status": "acknowledged", "id": alert_id})
        return jsonify({"error": "DB not available"}), 503

    @app.route("/api/block", methods=["POST"])
    def api_block_ip():
        body   = request.get_json() or {}
        ip     = body.get("ip")
        reason = body.get("reason", "Manually blocked via SOC dashboard")
        if not ip:
            return jsonify({"error": "ip required"}), 400
        if db:
            db.block_ip(ip, reason, auto=False)
            return jsonify({
                "status":    "blocked",
                "ip":        ip,
                "iptables":  f"iptables -A INPUT -s {ip} -j DROP",
                "firewalld": f"firewall-cmd --add-rich-rule='rule family=ipv4 source address={ip} drop'",
            })
        return jsonify({"error": "DB not available"}), 503

    @app.route("/api/block/<ip>", methods=["DELETE"])
    def api_unblock_ip(ip: str):
        if db:
            # db.unblock_ip would need to be implemented
            return jsonify({"status": "unblocked", "ip": ip})
        return jsonify({"error": "DB not available"}), 503

    @app.route("/api/health")
    def api_health():
        return jsonify({
            "status":    "ok",
            "version":   "4.0.0",
            "timestamp": datetime.utcnow().isoformat(),
            "components": {
                "database":    db is not None,
                "ml":          ml_detector is not None and ml_detector.is_trained,
                "capture":     capture_engine is not None or capture is not None,
                "analyzer":    analyzer is not None,
            }
        })


    # ── ML Model Versioning & Drift (Phase 2 operational) ────────────────────────

    @app.route("/api/ml/versions")
    def api_ml_versions():
        """List all saved model versions with metrics."""
        if not ml_detector:
            return jsonify({"error": "ML not available"}), 503
        return jsonify({"versions": ml_detector.registry.list_versions()})

    @app.route("/api/ml/versions/<version_id>/activate", methods=["POST"])
    def api_ml_rollback(version_id: str):
        """Roll back to a specific model version."""
        if not ml_detector:
            return jsonify({"error": "ML not available"}), 503
        ok = ml_detector.registry.load_version(version_id)
        return jsonify({"status": "ok" if ok else "failed", "version_id": version_id})

    @app.route("/api/ml/drift")
    def api_ml_drift():
        """Get concept drift status (PSI per feature)."""
        if not ml_detector:
            return jsonify({"error": "ML not available"}), 503
        return jsonify(ml_detector.get_drift_status())

    @app.route("/api/ml/retrain", methods=["POST"])
    def api_ml_retrain():
        """Force immediate model retrain."""
        if not ml_detector:
            return jsonify({"error": "ML not available"}), 503
        import threading
        threading.Thread(target=ml_detector._train, daemon=True).start()
        return jsonify({"status": "retrain started"})

    # ── Phase 6: PCAP Export ─────────────────────────────────────────────────

    @app.route("/api/alerts/<alert_id>/pcap")
    def api_export_pcap(alert_id: str):
        """Download PCAP file for a specific alert's source IP."""
        src_ip = request.args.get("src_ip", "")
        if not src_ip:
            return jsonify({"error": "src_ip required"}), 400
        if capture and hasattr(capture, "pcap_buffer"):
            path = capture.pcap_buffer.export_pcap(src_ip, alert_id)
            if path and path.exists():
                return send_file(str(path), mimetype="application/vnd.tcpdump.pcap",
                                 as_attachment=True, download_name=path.name)
        return jsonify({"error": "No PCAP data for this IP"}), 404

    @app.route("/api/pcaps")
    def api_list_pcaps():
        """List all exported PCAP files."""
        if capture and hasattr(capture, "pcap_buffer"):
            return jsonify({"pcaps": capture.pcap_buffer.list_exports()})
        return jsonify({"pcaps": []})

    # ── Phase 6: Report Generation ────────────────────────────────────────────

    @app.route("/api/report/generate", methods=["POST"])
    def api_generate_report():
        """Generate a full HTML incident report and return download link."""
        try:
            from report_generator import ReportGenerator
            rg = ReportGenerator(db=db, threat_intel=threat_intel, ml_detector=ml_detector)
            if alert_manager:
                alerts = alert_manager.get_recent_alerts(2000)
            elif db:
                alerts = db.get_recent_alerts(2000)
            else:
                alerts = []
            ml_info = ml_detector.get_model_info() if ml_detector else None
            ti_stats = threat_intel.stats() if threat_intel else None
            path = rg.save_html_report(alerts, ml_info=ml_info, ti_stats=ti_stats)
            return jsonify({"status": "ok", "filename": path.name, "path": str(path)})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/report/download/<filename>")
    def api_download_report(filename: str):
        """Download a generated HTML report."""
        import re
        if not re.match(r"^report_[\d_]+\.html$", filename):
            return jsonify({"error": "Invalid filename"}), 400
        path = Path("data/reports") / filename
        if not path.exists():
            return jsonify({"error": "Report not found"}), 404
        return send_file(str(path), mimetype="text/html", as_attachment=True, download_name=filename)

    @app.route("/api/report/list")
    def api_list_reports():
        try:
            from report_generator import ReportGenerator
            rg = ReportGenerator()
            return jsonify({"reports": rg.list_reports()})
        except Exception as e:
            return jsonify({"reports": [], "error": str(e)})

    @app.route("/api/siem/export/cef")
    def api_siem_cef():
        """Export alerts as CEF syslog format for ArcSight/Splunk."""
        try:
            from report_generator import ReportGenerator
            rg = ReportGenerator()
            if alert_manager:
                alerts = alert_manager.get_recent_alerts(int(request.args.get("limit", 5000)))
            elif db:
                alerts = db.get_recent_alerts(int(request.args.get("limit", 5000)))
            else:
                alerts = []
            cef = rg.export_cef(alerts)
            return cef, 200, {"Content-Type": "text/plain; charset=utf-8",
                              "Content-Disposition": "attachment; filename=alerts.cef"}
        except Exception as e:
            return str(e), 500

    @app.route("/api/siem/export/csv")
    def api_siem_csv():
        """Export alerts as CSV for forensic analysis."""
        try:
            from report_generator import ReportGenerator
            rg = ReportGenerator()
            if alert_manager:
                alerts = alert_manager.get_recent_alerts(int(request.args.get("limit", 10000)))
            elif db:
                alerts = db.get_recent_alerts(int(request.args.get("limit", 10000)))
            else:
                alerts = []
            csv_data = rg.export_csv(alerts)
            return csv_data, 200, {"Content-Type": "text/csv; charset=utf-8",
                                   "Content-Disposition": "attachment; filename=alerts.csv"}
        except Exception as e:
            return str(e), 500

    # ── Phase 2: Dataset Training API ─────────────────────────────────────────

    @app.route("/api/ml/train/dataset", methods=["POST"])
    def api_train_dataset():
        """
        Train ML ensemble from CICIDS2017 or UNSW-NB15 dataset.
        POST JSON: {"dataset": "cicids2017", "path": "/data/cicids_monday.csv"}
        """
        if not ml_detector:
            return jsonify({"error": "ML detector not initialized"}), 503
        body = request.get_json(force=True, silent=True) or {}
        dataset = body.get("dataset", "cicids2017")
        path    = body.get("path", "")
        if not path:
            return jsonify({"error": "path required"}), 400
        try:
            from ml_detector import DatasetPipeline
            if dataset == "cicids2017":
                X, y = DatasetPipeline.load_cicids2017(path)
            elif dataset == "unsw_nb15":
                X, y = DatasetPipeline.load_unsw_nb15(path)
            else:
                return jsonify({"error": f"Unknown dataset: {dataset}"}), 400
            scaler, iso, svm, ae = DatasetPipeline.train_from_dataset(X, y)
            # Inject into live ML detector
            import threading
            with ml_detector._model_lock:
                ml_detector._scaler    = scaler
                ml_detector._iso_model = iso
                ml_detector._svm_model = svm
                ml_detector._ae_model  = ae
                ml_detector._trained   = True
                ml_detector._train_count = len(X)
            return jsonify({"status": "ok", "samples": len(X), "dataset": dataset,
                           "attack_rate": float((y == 1).mean())})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/ml/autoencoder/status")
    def api_ae_status():
        """Check autoencoder training status."""
        if not ml_detector:
            return jsonify({"error": "ML not available"}), 503
        with ml_detector._model_lock:
            ae = ml_detector._ae_model
        if ae is None:
            return jsonify({"trained": False})
        return jsonify({
            "trained": True,
            "threshold": ae.threshold,
            "architecture": {
                "input": ae.input_dim,
                "hidden": ae.hidden,
                "bottleneck": ae.bottleneck,
            },
            "epochs": ae.epochs,
        })

    # ── Phase 7: Threat Intel API (enhanced) ──────────────────────────────────

    @app.route("/api/reputation/<path:ip>/abuseipdb")
    def api_abuseipdb_lookup(ip: str):
        """Real-time AbuseIPDB lookup for single IP."""
        if not threat_intel:
            return jsonify({"error": "Threat intel not initialized"}), 503
        result = threat_intel.check_abuseipdb_single(ip)
        return jsonify(result)

    @app.route("/api/reputation/<path:ip>/otx")
    def api_otx_lookup(ip: str):
        """Real-time AlienVault OTX lookup for single IP."""
        if not threat_intel:
            return jsonify({"error": "Threat intel not initialized"}), 503
        result = threat_intel.check_otx_single(ip)
        return jsonify(result)

    @app.route("/api/threat_intel/refresh", methods=["POST"])
    def api_ti_refresh():
        """Force refresh of threat intel feeds."""
        if not threat_intel:
            return jsonify({"error": "Threat intel not initialized"}), 503
        import threading
        threading.Thread(target=threat_intel.refresh_all_feeds, daemon=True).start()
        return jsonify({"status": "refresh started"})

    @app.route("/api/threat_intel/stats")
    def api_ti_stats():
        if not threat_intel:
            return jsonify({"error": "Not initialized"}), 503
        return jsonify(threat_intel.stats())

    # ── Phase 5: Capture mode status ─────────────────────────────────────────

    @app.route("/api/capture/status")
    def api_capture_status():
        cap = capture or capture_engine
        if not cap:
            return jsonify({"mode": "none", "running": False})
        return jsonify({
            "mode": cap.stats.get("mode", "unknown"),
            "captured": cap.stats.get("captured", 0),
            "dropped":  cap.stats.get("dropped", 0),
            "current_pps": cap.stats.get("current_pps", 0),
            "peak_pps": cap.stats.get("peak_pps", 0),
            "queue_depth": cap.stats.get("queue_depth", 0),
            "interface": getattr(cap, "interface", ""),
            "start_time": cap.start_time.isoformat() if cap.start_time else None,
        })

    # ── v4.0: Live Flow Table ─────────────────────────────────────────────

    @app.route("/api/flows")
    def api_flows():
        """Return active network flows for the flow table view."""
        limit = int(request.args.get("limit", 50))
        if analyzer and hasattr(analyzer, 'flow_tracker'):
            ft = analyzer.flow_tracker
            flows = []
            for fkey, flow in list(ft.flows.items())[:limit]:
                flows.append({
                    "src_ip": flow.src_ip,
                    "dst_ip": flow.dst_ip,
                    "src_port": flow.src_port,
                    "dst_port": flow.dst_port,
                    "protocol": flow.protocol,
                    "state": getattr(flow, 'tcp_state', 'ACTIVE'),
                    "packets": flow.packet_count,
                    "bytes": flow.byte_count,
                    "duration": round(flow.duration, 1),
                    "start_time": flow.start_time.isoformat() if hasattr(flow, 'start_time') else None,
                })
            return jsonify({"flows": flows, "total": len(ft.flows)})
        return jsonify({"flows": [], "total": 0})

    # ── v4.0: Analyst Feedback Loop ──────────────────────────────────────

    @app.route("/api/alerts/feedback", methods=["POST"])
    def api_alert_feedback():
        """Submit analyst feedback (confirm/dismiss) on an alert."""
        if not ml_detector:
            return jsonify({"error": "ML not available"}), 503
        body = request.get_json(force=True, silent=True) or {}
        alert_id = body.get("alert_id", "")
        is_tp = body.get("is_true_positive", True)
        features = body.get("features")
        if not alert_id:
            return jsonify({"error": "alert_id required"}), 400
        ml_detector.submit_feedback(alert_id, is_tp, features)
        return jsonify({"status": "ok", "alert_id": alert_id, "is_true_positive": is_tp})

    @app.route("/api/ml/feedback/stats")
    def api_feedback_stats():
        """Get analyst feedback statistics."""
        if not ml_detector:
            return jsonify({"error": "ML not available"}), 503
        return jsonify(ml_detector.get_feedback_stats())

    # ── v4.0: Training History & Feature Importance ─────────────────────

    @app.route("/api/ml/training_log")
    def api_training_log():
        """Return training history with CV metrics and feature importance."""
        if not ml_detector:
            return jsonify({"error": "ML not available"}), 503
        return jsonify({"history": ml_detector.get_training_history()})

    @app.route("/api/ml/feature_importance")
    def api_feature_importance():
        """Return current feature importance ranking."""
        if not ml_detector:
            return jsonify({"error": "ML not available"}), 503
        return jsonify({"features": ml_detector.get_feature_importance()})

    # ── Socket.IO ─────────────────────────────────────────────────────────────

    @socketio.on("connect", namespace="/nids")
    def on_connect():
        logger.debug("Dashboard client connected: %s", request.sid)

    @socketio.on("disconnect", namespace="/nids")
    def on_disconnect():
        logger.debug("Dashboard client disconnected: %s", request.sid)

    @socketio.on("request_history", namespace="/nids")
    def on_request_history():
        if alert_manager:
            alerts = alert_manager.get_recent_alerts(100)
        elif db:
            alerts = db.get_recent_alerts(100)
        else:
            alerts = []
        emit("history", {"alerts": alerts})

    return app, socketio
