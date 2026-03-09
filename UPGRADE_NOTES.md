# AI-NIDS v3.0 — Full Upgrade Notes

## Phase 1 — Deeper Packet Analysis (attack_detection.py)

### New detectors added
| Detector | Trigger | MITRE |
|---|---|---|
| **SYN Flood** | >200 SYN/10s, tracks SYN:ACK ratio | T1499 |
| **RST Storm** | >50 RST/10s — indicates active port scanner | T1046 |
| **ICMP Flood** | >100 ICMP/10s with type classification | T1498 |
| **Fragment Flood** | >50 IP fragments/10s | T1498 |
| **Tiny Fragment Attack** | Offset>0, size<68 — firewall bypass | T1498 |
| **NULL Scan** | No TCP flags — stealth recon | T1046 |
| **XMAS Scan** | FIN+URG+PSH — stealth recon | T1046 |
| **SYN+RST** | Invalid combo — OS fingerprinting | T1046 |
| **HTTP Scanning** | >30 req/10s, scanner UA, path probing | T1190 |
| **DNS Tunneling** | Entropy >3.8 on subdomain, depth ≥3, len >40 | T1048 |
| **Packet Size Anomaly** | >85% packets in same size bin (covert channel) | T1001 |

### Packet-level fields now inspected
- **TCP flags**: SYN, ACK, RST, FIN, URG, PSH (all combinations)
- **IP fragmentation**: `is_fragment`, `frag_offset`, tiny-fragment attack
- **ICMP type**: 8=Echo, 13=Timestamp, 17=Address Mask, 30=Traceroute
- **HTTP**: URI, User-Agent, path enumeration, request rate
- **DNS**: QPS, subdomain entropy, TXT record abuse, domain repetition
- **TLS**: ClientHello detection, JA3 hash matching (Emotet, Cobalt Strike, TrickBot)
- **Packet size distribution**: Kolmogorov-Smirnov-style concentration test

## Phase 2 — Better ML System (ml_detector.py)

### Autoencoder (NEW)
Pure-numpy 3-layer autoencoder: **18 → 8 → 3 → 8 → 18**
- Trained via mini-batch gradient descent (MSE loss, Xavier init)
- Anomaly = reconstruction error exceeds 95th percentile of training data
- No PyTorch/TensorFlow dependency
- ~10s training on 10,000 samples

### Triple-model ensemble
| Model | Vote Weight | Strength |
|---|---|---|
| Isolation Forest | 40% | Fast, high-dimensional outliers |
| One-Class SVM | 30% | Tight RBF decision boundary |
| Autoencoder | 30% | Temporal/sequential pattern anomalies |

Alert fires if **ANY** model votes anomaly. Confidence = weighted score.

### Dataset Pipeline
```python
# Train on CICIDS2017
from ml_detector import DatasetPipeline
X, y = DatasetPipeline.load_cicids2017("/data/Monday-WorkingHours.pcap_ISCX.csv")
scaler, iso, svm, ae = DatasetPipeline.train_from_dataset(X, y)

# Or via REST API:
POST /api/ml/train/dataset
{"dataset": "cicids2017", "path": "/data/your_file.csv"}
```

### Model persistence
- Trained model saved to `data/ml_model.pkl` on every retrain
- Loaded automatically at startup
- Retrain every 60 minutes on live traffic (configurable)

## Phase 3 — Threat Intelligence (threat_intel.py)

### Live feeds (no API key required)
| Feed | IPs | Threat Score |
|---|---|---|
| Feodo Tracker | ~1,000 Botnet C2 | 90 |
| TOR Exit Nodes | ~1,500 TOR exits | 60 |
| ipsum Level-3 | ~50,000 aggregated | 75 |
| Spamhaus DROP | CIDR blocks | 85 |

### API feeds (optional, configure in config.yaml)
```yaml
threat_intel:
  abuseipdb_key: YOUR_KEY      # abuseipdb.com (free)
  alientvault_key: YOUR_KEY    # otx.alienvault.com (free)
```

### Per-IP reputation tracking
- Alert volume correlation (score bumped on active threats)
- GeoIP enrichment via ip-api.com (no key, 45 req/min)
- Real-time single-IP lookup: `GET /api/reputation/{ip}/abuseipdb`
- Real-time OTX lookup: `GET /api/reputation/{ip}/otx`

## Phase 5 — High-Performance Capture (packet_capture.py)

### Capture mode priority
1. **PyShark** (libpcap + Wireshark dissectors) — best accuracy
   - Install: `pip install pyshark && sudo apt install tshark`
   - Access to 700+ protocol dissectors
2. **AF_PACKET** (Linux raw socket) — fastest, zero-copy kernel path
   - No external dependencies (stdlib socket module)
   - Requires root/`CAP_NET_RAW`
3. **Scapy** (portable fallback) — full Python, cross-platform
4. **Demo** (no root, synthetic attack scenarios) — development/testing

### PCAP ring buffer
- Per-IP circular buffer of last 200 raw Ethernet frames
- Triggered on alert: `GET /api/alerts/{id}/pcap?src_ip=1.2.3.4`
- Valid PCAP binary (libpcap magic header + per-packet headers)
- Opens directly in Wireshark

## Phase 6 — Incident Investigation Tools (app.py + report_generator.py)

### PCAP export
```
GET /api/alerts/{alert_id}/pcap?src_ip=10.0.0.99
→ Downloads: alert_abc123_10_0_0_99.pcap
```

### Report generation
```
POST /api/report/generate
→ {"filename": "report_20250307_143022.html", ...}

GET /api/report/download/report_20250307_143022.html
→ Self-contained HTML report with full alert table

GET /api/report/list
→ List all generated reports
```

### Export formats
| Endpoint | Format | Use Case |
|---|---|---|
| `GET /api/siem/export` | JSON | Generic SIEM import |
| `GET /api/siem/export/cef` | CEF | ArcSight, Splunk Universal Forwarder |
| `GET /api/siem/export/csv` | CSV | Forensic spreadsheet analysis |

## Phase 7 — Professional Features (all modules)

### MITRE ATT&CK mapping
Every alert includes:
```json
{
  "mitre_tactic":    "Impact",
  "mitre_technique": "T1499",
  "mitre_name":      "Endpoint Denial of Service"
}
```

21 alert types fully mapped. Viewable in SOC dashboard MITRE Navigator.

### Alert schema v3.0
```json
{
  "id":              "10.0.0.99-SYN_FLOOD-1741234567",
  "timestamp":       "2025-03-07T14:30:22.123456",
  "alert_type":      "SYN_FLOOD",
  "severity":        "CRITICAL",
  "confidence":      91,
  "threat_score":    90,
  "src_ip":          "10.0.0.99",
  "dst_ip":          "192.168.1.10",
  "dst_port":        80,
  "description":     "SYN flood: 612 SYN/10s, SYN:ACK ratio 18.4:1",
  "mitre_tactic":    "Impact",
  "mitre_technique": "T1499",
  "mitre_name":      "Endpoint Denial of Service",
  "details": {
    "syn_rate": 612,
    "ack_rate": 33,
    "syn_ack_ratio": 18.4,
    "threshold": 200
  }
}
```

### REST API — complete endpoint list
| Method | Path | Description |
|---|---|---|
| GET | /api/alerts | Paginated alert list |
| GET | /api/alerts/search | Full-text + filter search |
| GET | /api/alert/{id}/pcap | Download PCAP for alert |
| GET | /api/stats | System health snapshot |
| GET | /api/timeline | Time-bucketed alert history |
| GET | /api/mitre/stats | ATT&CK tactic breakdown |
| GET | /api/reputation/{ip} | IP reputation lookup |
| GET | /api/reputation/{ip}/abuseipdb | AbuseIPDB real-time |
| GET | /api/reputation/{ip}/otx | OTX real-time |
| GET | /api/reputation/top | Top threat IPs |
| GET | /api/siem/export | JSON export |
| GET | /api/siem/export/cef | CEF export |
| GET | /api/siem/export/csv | CSV export |
| POST | /api/block | Block IP |
| DELETE | /api/block/{ip} | Unblock IP |
| GET | /api/blocked | List blocked IPs |
| GET | /api/ml/info | ML model info |
| GET | /api/ml/evaluate | ML evaluation metrics |
| GET | /api/ml/autoencoder/status | Autoencoder status |
| POST | /api/ml/train/dataset | Train from CICIDS/UNSW |
| POST | /api/report/generate | Generate HTML report |
| GET | /api/report/list | List reports |
| GET | /api/report/download/{file} | Download report |
| GET | /api/capture/status | Capture mode info |
| GET | /api/threat_intel/stats | Feed statistics |
| POST | /api/threat_intel/refresh | Force feed refresh |
| GET | /api/health | Component health check |

## Performance Notes

| Mode | Throughput | Root | Dependencies |
|---|---|---|---|
| PyShark | ~100k pps | Yes | pyshark, tshark |
| AF_PACKET | ~500k pps | Yes | None (stdlib) |
| Scapy | ~10k pps | Yes | scapy |
| Demo | 10–50 pps | No | None |

For production networks >1Gbps: use Suricata/Zeek + send alerts to this system via their JSON output.
