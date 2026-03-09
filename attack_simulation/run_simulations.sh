#!/bin/bash
TARGET=${1:-127.0.0.1}

echo "======================================"
echo " NIDS Attack Simulation Runner"
echo " Target: $TARGET"
echo "======================================"

chmod +x nmap_scan.sh hping_flood.sh hydra_brute.sh

echo ""
echo "1. Port Scan Simulation"
./nmap_scan.sh $TARGET

echo ""
echo "2. SYN Flood Simulation (5 seconds)"
./hping_flood.sh $TARGET

echo ""
echo "3. Brute Force Simulation (SSH)"
./hydra_brute.sh $TARGET

echo ""
echo "4. DNS Anomaly / Tunneling Simulation"
RANDOM_STR=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 30)
dig @$TARGET "${RANDOM_STR}.example.com"
echo "[+] DNS request sent."

echo ""
echo "5. Malware C2 / HTTP User-Agent Simulation"
curl -A "sqlmap/1.5.8#dev (http://sqlmap.org)" http://$TARGET/ -m 2
echo ""
echo "[+] HTTP request sent."

echo ""
echo "6. DNS Amplification Simulation"
chmod +x dns_amp.sh
./dns_amp.sh 8.8.8.8

echo ""
echo "7. Stealthy Slow Scan Simulation"
chmod +x slow_scan.sh
./slow_scan.sh $TARGET

echo ""
echo "All simulations dispatched."
