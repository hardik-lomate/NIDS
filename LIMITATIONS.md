# AI-NIDS v3.0 — Honest Limitations

## 1. Packet Capture Performance

**Current implementation:** Python userspace capture.

| Mode | Max throughput | CPU @ 100Mbps | Packet drop risk |
|---|---|---|---|
| PyShark (tshark) | ~50k pps | ~40% | Medium |
| AF_PACKET (stdlib socket) | ~150k pps | ~25% | Low |
| Scapy (fallback) | ~8k pps | ~80% | High |

**Why this matters:** At 1Gbps with 64-byte packets you get ~1.5M pps. Python cannot keep up. Every packet the OS kernel sees but your program hasn't read yet sits in a socket buffer — when that fills, the kernel drops silently.

**What production systems use:**
- **Suricata / Snort 3** — C engine, AF_PACKET with TPACKET_V3 ring buffer, multi-threaded, zero-copy
- **DPDK** — bypasses the kernel entirely, maps NIC memory directly to userspace. Requires dedicated CPU cores and a DPDK-compatible NIC
- **eBPF + XDP** — programs run inside the kernel before packet even hits the socket layer. Can process at line rate (10-100Gbps). Requires Linux 4.18+
- **Zeek (formerly Bro)** — event-based scripting engine in C++, commonly used for exactly this problem

**Recommended architecture for production:** Run Suricata or Zeek for raw capture and initial detection. Feed their JSON alert logs into this system's REST API for ML analysis, threat intel correlation, and SOC dashboard display. This system then handles the intelligence layer, not the wire capture layer.

**This project's position:** The AF_PACKET mode is suitable for low-volume networks (<100Mbps) and lab environments. It correctly demonstrates the concepts. For a portfolio project, this is appropriate — you would call it out honestly in an interview.

## 2. ML Detection — What's Real vs Academic

**What's implemented:**
- Isolation Forest: ✓ real scikit-learn, trains on live traffic
- One-Class SVM: ✓ real scikit-learn, ensemble vote
- Autoencoder: ✓ pure-numpy, MSE reconstruction error threshold
- 18 behavioral features: ✓ extracted from 5s per-IP windows
- Model persistence: ✓ saved to `data/ml_model.pkl`

**What's missing for operational ML:**
- **Dataset training**: The system trains on whatever traffic it sees at startup, which may include attacker traffic (concept poisoning). Production systems train on labeled datasets (CICIDS2017, UNSW-NB15) where clean/attack traffic is known.
- **Model versioning**: No rollback if a bad retrain degrades performance. Production systems keep N previous model versions and A/B test.
- **Concept drift detection**: Network behavior changes over time (new services, peak hours). The model should detect when its training distribution has diverged from current traffic.
- **Labeled ground truth**: Without labeled data, precision/recall metrics are estimates. The `/api/ml/evaluate` endpoint simulates this — in production you'd feed confirmed alerts as ground truth.

**Academic vs operational gap summary:** This system demonstrates all the correct techniques. The gap is in the operational plumbing — not the algorithms themselves.

## 3. Payload Inspection Depth

**What's actually inspected (per capture mode):**

| Field | Scapy | PyShark | AF_PACKET | Demo |
|---|---|---|---|---|
| TCP flags | ✓ | ✓ | ✓ | ✓ |
| DNS query name | ✓ | ✓ | Port only* | ✓ |
| HTTP URI + User-Agent | ✓ | ✓ | ✓ | ✓ |
| TLS ClientHello detection | ✓ | ✓ | ✓ | — |
| JA3 hash | Stub** | ✓ (tshark) | — | — |
| ICMP type | ✓ | ✓ | ✓ | ✓ |
| IP fragmentation | ✓ | ✓ | ✓ | — |
| Payload content (C2 patterns) | ✓ | Partial | Partial | ✓ |

*AF_PACKET sets `is_dns=True` from port 53 but does not parse the DNS wire format query name from raw bytes (requires UDP payload parsing of the DNS message format).

**JA3 hashing in Scapy mode: detects TLS ClientHello by byte pattern but does not compute a proper JA3 hash (requires parsing cipher suites, extensions, elliptic curves from the TLS handshake). PyShark/tshark computes real JA3.

**What would make inspection production-grade:**
- Full DNS wire format parser (implemented below for AF_PACKET)
- Real JA3 computation from TLS ClientHello fields
- HTTP response inspection (not just requests)
- SSL/TLS certificate subject/issuer inspection
- SMB/RDP protocol-level inspection

## 4. Dashboard — What's Missing

The investigation panel shows alert metadata. It does not show:
- Raw packet hex dump
- Full DNS query/response timeline
- HTTP request/response pair
- TLS certificate details

These are implemented below in the upgraded dashboard.
