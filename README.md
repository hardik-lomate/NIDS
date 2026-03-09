<p align="center">
  <h1 align="center">🛡️ DeepSight NIDS</h1>
  <p align="center">
    <strong>AI-Enhanced Network Intrusion Detection System</strong>
  </p>

  <p align="center">
    <img src="https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge">
    <img src="https://img.shields.io/badge/ML-IsolationForest-orange?style=for-the-badge">
    <img src="https://img.shields.io/badge/Docker-Supported-2496ED?style=for-the-badge&logo=docker">
    <img src="https://img.shields.io/badge/API-REST-green?style=for-the-badge">
    <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge">
  </p>
</p>

---

# DeepSight NIDS

**DeepSight** is a Python-based **Network Intrusion Detection System (NIDS)** that monitors network traffic, detects suspicious activity, and visualizes threats through a real-time dashboard.

The project combines:

- Packet capture
- Rule-based intrusion detection
- Machine learning anomaly detection
- Real-time monitoring dashboard

It is designed as a **cybersecurity research and learning project** demonstrating how modern intrusion detection systems work.

---

# Architecture

```mermaid
graph TD

A[Network Traffic] --> B(Packet Capture)

B --> C(Feature Extraction)

C --> D(Rule Based Detection)

C --> E(ML Anomaly Detection)

D --> F(Alert Manager)
E --> F

F --> G(Database)

G --> H(API Server)

H --> I(Web Dashboard)
