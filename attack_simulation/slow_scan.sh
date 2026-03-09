#!/bin/bash
TARGET=${1:-127.0.0.1}

echo "[Slow Scan] Running a stealthy port scan against $TARGET"
echo "Using nmap with Timing template T1 (Sneaky) to evade rapid port scan rules."

# T1 scans ports very slowly (15 seconds between probes by default).
# To make the simulation finish in a reasonable time, we'll use --scan-delay 1s
# and scan 25 ports. The standard NIDS rule looks for 20 ports in 10s.
# Scanning 25 ports at 1 port/sec will bypass the basic rule but might trigger ML or a dedicated slow scan rule.
nmap -sS --max-retries 0 --scan-delay 1.1s -p 1-25 $TARGET > /dev/null

echo "[+] Slow scan complete."
