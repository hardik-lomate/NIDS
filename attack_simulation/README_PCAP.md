# PCAP Replay Testing
This directory includes tools to test the NIDS against real-world, recorded attack traffic datasets like **CICIDS2017** and **UNSW-NB15**.

## Replaying a Dataset

Use the included `replay_pcap.sh` script to replay traffic onto your local interface. 

### 1. Install Dependencies
You need `tcpreplay` installed on your system.
```bash
# Ubuntu/Debian
sudo apt-get install tcpreplay

# CentOS/RHEL
sudo yum install tcpreplay
```

### 2. Download a Dataset
We recommend downloading PCAP files from recognized academic datasets. For example, testing against the **CICIDS2017** PortScan or DDoS days.
- [CICIDS2017 Dataset](https://www.unb.ca/cic/datasets/ids-2017.html)
- [UNSW-NB15 Dataset](https://research.unsw.edu.au/projects/unsw-nb15-dataset)

*Due to the large size of these datasets (often 10GB+), they are not included in this repository.*

### 3. Replay the Traffic
While your NIDS engine (`python app.py`) is running and listening on `eth0` (or your chosen interface), execute the replay script:

```bash
sudo ./replay_pcap.sh /path/to/downloaded/CICIDS2017_Friday_PortScan.pcap eth0
```

The NIDS will ingest the replayed packets in real-time. Navigate to the Web Dashboard at `http://localhost:5000` to observe the detected anomalies, ML alerts, and rule triggers just as if the attack was happening live.
