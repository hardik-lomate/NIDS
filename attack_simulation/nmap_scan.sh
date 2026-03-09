#!/bin/bash
TARGET=${1:-127.0.0.1}
echo "[*] Simulating Port Scan against $TARGET..."
nmap -p 1-1000 -T4 $TARGET
echo "[+] Nmap scan finished."
