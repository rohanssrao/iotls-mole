FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      iproute2 iptables nftables conntrack openssl net-tools tcpdump libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY pyproject.toml README.md /app/
COPY trustfall /app/trustfall
RUN pip install --no-cache-dir .
ENTRYPOINT ["trustfall"]
