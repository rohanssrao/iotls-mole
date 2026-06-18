FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 iptables net-tools tcpdump && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY pyproject.toml README.md /app/
COPY iotls_mole /app/iotls_mole
RUN pip install --no-cache-dir .
ENTRYPOINT ["iotls-mole"]
