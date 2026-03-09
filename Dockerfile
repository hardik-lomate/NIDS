FROM python:3.11-slim

LABEL maintainer="NIDS"
LABEL description="Network Intrusion Detection System"

# Install libpcap for Scapy
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    net-tools \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p data logs

# Run as demo mode by default in Docker (override with --network=host + root for live)
EXPOSE 5000

CMD ["python", "app.py"]
