#!/bin/bash
# NIDS PCAP Replay Tool
# Replays standard datasets (e.g., CICIDS2017, UNSW-NB15) onto a local interface
# so the NIDS engine can detect real-world attack signatures.

PCAP_FILE=$1
INTERFACE=${2:-eth0}

if [ -z "$PCAP_FILE" ]; then
    echo "=========================================================="
    echo " NIDS PCAP Replay Testing"
    echo "=========================================================="
    echo "Usage: ./replay_pcap.sh <path_to_pcap_file> [interface]"
    echo ""
    echo "Instructions for testing with standard datasets:"
    echo "1. Download a dataset like CICIDS2017 or UNSW-NB15."
    echo "2. Extract the .pcap files."
    echo "3. Run this script passing the PCAP file as an argument."
    echo "4. The NIDS engine will observe the traffic on the specified interface"
    echo "   and generate alerts in the SOC Dashboard."
    echo ""
    echo "Example:"
    echo "  sudo ./replay_pcap.sh /path/to/CICIDS2017_Friday_PortScan.pcap eth0"
    echo "=========================================================="
    exit 1
fi

if ! command -v tcpreplay &> /dev/null; then
    echo "[-] tcpreplay is not installed."
    echo "    Please install it first (e.g., sudo apt-get install tcpreplay)"
    exit 1
fi

echo "[+] Replaying $PCAP_FILE on interface $INTERFACE..."
# --topspeed replays as fast as possible, --pps limits rate.
# Here we use a safe 1000 pps to not overwhelm generic Scapy captures.
sudo tcpreplay --intf1=$INTERFACE --mbps=10 $PCAP_FILE
echo "[+] Replay complete."
