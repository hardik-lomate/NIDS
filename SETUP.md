# NIDS — Network Intrusion Detection System
## Quick Setup & Run Guide

---

## 1. Install dependencies

```bash
pip install flask scikit-learn numpy pandas pyyaml python-dateutil
```

Optional (for live packet capture — requires root):
```bash
pip install scapy
```

---

## 2. Run the dashboard

```bash
cd NIDS
python3 main.py
```

Open **http://localhost:5000** in your browser.

> **Demo Mode** runs automatically when:
> - You're not running as root, OR
> - `scapy` is not installed
>
> Demo mode generates synthetic attack traffic so the UI is fully functional.

---

## 3. Run with live capture (Linux, root required)

```bash
sudo python3 main.py
```

Change the interface in `config.yaml` (default: `eth0`):
```yaml
network:
  interface: eth0      # or wlan0, ens3, etc.
  capture_filter: ""   # BPF filter, e.g. "tcp port 80"
```

---

## 4. What was fixed

| Issue | Fix |
|-------|-----|
| `flask-socketio` not installed | Replaced with polling stub (`flask_socketio.py`) |
| `flask-cors` not installed | Replaced with header stub (`flask_cors.py`) |
| `scapy` not installed | Auto-falls back to demo mode |
| Startup blocked on threat-intel feeds | Feed download moved to background thread |
| Socket.IO in frontend | Replaced with `/api/poll` polling (800ms interval) |
| `signal` error in non-main thread | Flask server uses `werkzeug.serving.make_server` |

---

## 5. API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /` | Dashboard UI |
| `GET /api/health` | Health check |
| `GET /api/alerts` | Recent alerts (add `?limit=N&severity=HIGH`) |
| `GET /api/stats` | Live traffic + ML + capture stats |
| `GET /api/traffic` | Traffic snapshot |
| `GET /api/packets` | Recent packets |
| `GET /api/blocked` | Blocked IPs |
| `GET /api/poll?ns=/nids&since=<epoch>` | Real-time event poll |
| `POST /api/block` | Block an IP `{"ip": "1.2.3.4"}` |
| `POST /api/alerts/<id>/ack` | Acknowledge alert |
| `GET /api/ml/evaluate` | ML model metrics |

---

## 6. Attack detection categories

- Port Scan (horizontal/vertical)
- Brute Force (SSH, FTP, RDP, MySQL)
- SYN Flood
- ICMP Flood
- UDP Flood
- ARP Spoofing
- DNS Amplification
- NULL/Xmas Stealth Scans
- ML Anomaly Detection (Isolation Forest)
