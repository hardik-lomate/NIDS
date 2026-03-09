#!/bin/bash
TARGET=${1:-8.8.8.8}

echo "[DNS Amplification] Sending ANY requests using dig to generate large responses."
echo "Targeting resolver: $TARGET"

# Sending multiple queries to trigger amplification detection.
# The NIDS rule triggers when sport=53 and response size > 512.
for i in {1..5}; do
  dig ANY microsoft.com @$TARGET +notcp +ignore > /dev/null &
  dig ANY google.com @$TARGET +notcp +ignore > /dev/null &
done

wait
echo "[+] DNS Amplification simulation complete."
