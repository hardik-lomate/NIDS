# DeepSight NIDS Demo Script

This guide provides a step-by-step walkthrough for recording a demonstration of the NIDS capabilities.

## Prerequisites
1. Ensure Docker and Docker Compose are installed.
2. In the `docker-compose.yml`, uncomment the `network_mode: host` and `cap_add` blocks if you are running on a Linux host to allow real interface capture, or leave it as default to run in Demo/Synthetic Mode.
3. Open two terminal windows side-by-side.
4. Open a web browser to `http://localhost:5000`.

## 🎬 Section 1: Bootstrapping & The Dashboard (0:00 - 1:00)
**Action**: In Terminal 1, run `docker-compose up -d --build`.
**Narration**: "Welcome to the DeepSight NIDS demonstration. We'll start by launching the containerized stack. This brings up our multi-threaded capture engine, the flow intelligence layer, and the Isolation Forest ML detector."

**Action**: Switch to the Web Browser (`http://localhost:5000`). Scroll through the different components: Traffic Volume, Protocol Distribution, Geographic Threat Map, Alert Severity, and the Live Feed.
**Narration**: "Here is the SOC-style dashboard. Right away, you can see real-time packet processing throughput, protocol distribution, and the Isolation Forest training progress. The layout is designed for rapid incident response."

## 🎬 Section 2: Rule-based Attack Simulation (1:00 - 2:30)
**Action**: In Terminal 2, navigate to `attack_simulation/` and run `./run_simulations.sh 127.0.0.1` (or your host IP).
**Narration**: "We'll now dispatch a suite of simulated attacks against the host. This includes standard Nmap port scans, SYN floods, SSH Brute force, DNS Amplification, and C2 Server payloads."

**Action**: Switch back to the Web Dashboard. Highlight the Live Alert Feed as alerts stream in.
**Narration**: "Almost instantly, the Deep Packet Inspection rules flag the malicious anomalies. You can see CRITICAL alerts for Command and Control Powershell payloads, HIGH alerts for rapid port scanning, and MEDIUM alerts for the DNS anomalies."

## 🎬 Section 3: Stealth Attacks & ML Detection (2:30 - 3:30)
**Action**: Wait for the "Stealthy Slow Scan Simulation" to run from the script, or run `./slow_scan.sh 127.0.0.1` manually.
**Narration**: "Advanced attackers often lower their scan rates to evade threshold-based rules. DeepSight mitigates this using scikit-learn's Isolation Forest."

**Action**: Point to the ML Alerts in the feed, or navigate to the "Alerts" tab and filter by "ML_ANOMALY".
**Narration**: "Because the ML model tracks port entropy and flow inter-arrival times dynamically, it catches the slow scan and flags it as a statistical anomaly, without requiring a hardcoded threshold."

## 🎬 Section 4: Threat Intelligence & Mitigation (3:30 - 4:30)
**Action**: Navigate to the "Attackers" tab in the dashboard.
**Narration**: "The system correlates source IPs against live Cyber Threat Intelligence feeds like Feodo Tracker and Tor Exit Nodes. We prioritize threats visually by an aggregated Threat Score."

**Action**: Click the "Block" button next to a highly active attacker. Then navigate to the "Blocked IPs" tab to verify it was added.
**Narration**: "If a threat reaches a critical threshold or presents a severe risk, SOC analysts can instantaneously issue a block command right from the dashboard, executing the mitigation at the firewall level."

## 🎬 Conclusion (4:30 - 5:00)
**Narration**: "This concludes the demonstration of DeepSight NIDS: combining deterministic DPI rules with probabilistic machine learning and rich visualization to defend modern networks. Thank you for watching."
