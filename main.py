import sys
import os
import logging
import yaml
from database import DatabaseManager
from traffic_analyzer import TrafficAnalyzer
from ml_detector import MLDetector
from threat_intel import ThreatIntel
from alert_manager import AlertManager
from attack_detection import AttackDetector
from packet_capture import PacketCapture
from app import create_app

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

def main():
    config = {
        "network": {"interface": "eth0", "capture_filter": "", "promiscuous": True, "worker_threads": 2, "packet_buffer": 10000},
        "database": {"path": "data/nids.db"},
        "ml": {"enabled": True, "contamination": 0.05, "min_samples": 50, "n_estimators": 50},
        "dashboard": {"secret_key": "dev_secret"},
        "brute_force": {"enabled": True, "threshold": 5, "time_window": 60, "monitored_ports": {22: "SSH", 21: "FTP", 3389: "RDP", 3306: "MySQL"}},
        "syn_flood": {"enabled": True, "threshold": 100, "time_window": 10},
        "port_scan": {"enabled": True, "threshold": 20, "time_window": 10},
        "slow_scan": {"enabled": True, "threshold": 15, "time_window": 300},
        "dns_amp": {"enabled": True},
    }
    
    try:
        with open("config.yaml", "r") as f:
            file_config = yaml.safe_load(f)
            if file_config:
                config.update(file_config)
    except Exception:
        pass

    db_path = config.get("database", {}).get("path", "data/nids.db")
    db = DatabaseManager(db_path)
    intel = ThreatIntel()
    ml = MLDetector(config)
    traffic = TrafficAnalyzer(config)
    alert = AlertManager(config, db)
    detector = AttackDetector(config, threat_intel=intel)
    capture = PacketCapture(config)
    
    detector.add_callback(alert.receive)
    ml.add_callback(alert.receive)
    
    capture.add_callback(traffic.process)
    capture.add_callback(detector.process_packet)
    capture.add_callback(ml.process_packet)
    
    # Auto demo mode when: --demo flag, non-root (Linux), or on Windows
    is_root = False
    try:
        if os.name == "posix":
            is_root = os.geteuid() == 0
    except AttributeError:
        pass  # Windows — no geteuid

    demo_mode = "--demo" in sys.argv or not is_root
    if demo_mode:
        capture._start_demo()
        logging.info("Running in DEMO mode (synthetic traffic). Use sudo for live capture on Linux.")
    else:
        capture.start()
    
    app, socketio = create_app(
        config, db=db, analyzer=traffic, alert_manager=alert,
        capture_engine=capture, ml_detector=ml, threat_intel=intel, capture=capture
    )
    
    port = int(os.environ.get("NIDS_PORT", 5000))
    host = os.environ.get("NIDS_HOST", "0.0.0.0")
    logging.info(f"Starting NIDS Dashboard on http://{host}:{port}")
    socketio.run(app, host=host, port=port, allow_unsafe_werkzeug=True)

if __name__ == "__main__":
    main()
