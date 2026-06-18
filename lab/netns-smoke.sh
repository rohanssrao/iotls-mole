#!/usr/bin/env bash
set -euo pipefail

# Non-destructive Linux network-namespace smoke test for IoTLS-Mole.
# Creates isolated namespaces: gw, target, mole on an isolated bridge.
# Requires: root, iproute2, iptables, python3, openssl, and Python deps
# cryptography+scapy installed either system-wide or in the active environment.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BR="iotls-br0"
GW_NS="iotls-gw"
TARGET_NS="iotls-target"
MOLE_NS="iotls-mole-ns"
NET="10.13.37"
SESSION="${ROOT}/lab/session-$(date +%s)"
PIDS=()

cleanup() {
  set +e
  for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
  ip netns pids "$GW_NS" 2>/dev/null | xargs -r kill 2>/dev/null || true
  ip netns pids "$TARGET_NS" 2>/dev/null | xargs -r kill 2>/dev/null || true
  ip netns pids "$MOLE_NS" 2>/dev/null | xargs -r kill 2>/dev/null || true
  ip link del "$BR" 2>/dev/null || true
  ip netns del "$GW_NS" 2>/dev/null || true
  ip netns del "$TARGET_NS" 2>/dev/null || true
  ip netns del "$MOLE_NS" 2>/dev/null || true
}
trap cleanup EXIT

need() { command -v "$1" >/dev/null || { echo "missing $1" >&2; exit 1; }; }
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
need ip; need iptables; need python3; need openssl
python3 - <<'PY' >/dev/null
import cryptography, scapy
PY

cleanup
mkdir -p "$SESSION"

ip netns add "$GW_NS"
ip netns add "$TARGET_NS"
ip netns add "$MOLE_NS"
ip link add "$BR" type bridge
ip link set "$BR" up

mkport() {
  local ns="$1" hostif="$2" nsif="$3" ipaddr="$4"
  ip link add "$hostif" type veth peer name "$nsif"
  ip link set "$hostif" master "$BR"
  ip link set "$hostif" up
  ip link set "$nsif" netns "$ns"
  ip -n "$ns" link set lo up
  ip -n "$ns" link set "$nsif" name eth0
  ip -n "$ns" addr add "$ipaddr/24" dev eth0
  ip -n "$ns" link set eth0 up
}

mkport "$GW_NS" vgw0 vgw1 "$NET.1"
mkport "$TARGET_NS" vtgt0 vtgt1 "$NET.10"
mkport "$MOLE_NS" vmole0 vmole1 "$NET.66"

ip -n "$TARGET_NS" route add default via "$NET.1" dev eth0
ip -n "$MOLE_NS" route add default via "$NET.1" dev eth0

# A tiny HTTPS server in the gateway namespace. It intentionally uses a self-signed
# cert because the upstream side is only for exercising forwarding/proxying.
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$SESSION/upstream.key" -out "$SESSION/upstream.crt" -days 1 \
  -subj "/CN=telemetry.example.test" \
  -addext "subjectAltName=DNS:telemetry.example.test" >/dev/null 2>&1
cat > "$SESSION/server.py" <<'PY'
import http.server, ssl
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.end_headers(); self.wfile.write(b'hello from upstream\n')
    def log_message(self, *a): pass
httpd = http.server.HTTPServer(('10.13.37.1', 443), H)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain('/SESSION/upstream.crt', '/SESSION/upstream.key')
httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
httpd.serve_forever()
PY
sed -i "s#/SESSION#${SESSION}#g" "$SESSION/server.py"
ip netns exec "$GW_NS" python3 "$SESSION/server.py" & PIDS+=("$!")
sleep 1

# Start IoTLS-Mole in the mole namespace. ARP spoofing and iptables happen only
# inside the isolated lab namespaces/bridge.
ip netns exec "$MOLE_NS" env PATH="$PATH" PYTHONPATH="$ROOT" python3 -m iotls_mole.cli "$NET.10" \
  --out "$SESSION/mole" --include-udp --retest wait --jsonl >"$SESSION/mole.log" 2>"$SESSION/mole.err" & PIDS+=("$!")
for i in $(seq 1 20); do
  if grep -q 'arp_spoofing started\|proxy listening' "$SESSION/mole.log" 2>/dev/null; then break; fi
  sleep 1
done
if ! grep -q 'proxy listening' "$SESSION/mole.log" 2>/dev/null; then
  echo "[-] Mole did not start in time" >&2
  cat "$SESSION/mole.err" >&2 || true
  exit 2
fi

cat > "$SESSION/client.py" <<'PY'
import socket, ssl, sys
verify = sys.argv[1] == 'verify'
ctx = ssl.create_default_context() if verify else ssl._create_unverified_context()
try:
    s = socket.create_connection(('10.13.37.1', 443), timeout=5)
    t = ctx.wrap_socket(s, server_hostname='telemetry.example.test')
    t.sendall(b'GET /device-checkin?id=smoke HTTP/1.1\r\nHost: telemetry.example.test\r\nConnection: close\r\n\r\n')
    print(t.recv(200).decode(errors='ignore'))
    t.close()
except Exception as e:
    print(type(e).__name__ + ': ' + str(e))
PY

# First connection should be rejected by a validating client.
echo "[+] target neighbor table before client attempts:"
ip -n "$TARGET_NS" neigh show || true
# Encourage the target namespace to learn the spoofed gateway MAC during the test window.
ip -n "$TARGET_NS" neigh flush all || true
sleep 3
echo "[+] target neighbor table after spoof window:"
ip -n "$TARGET_NS" neigh show || true

echo "[+] validating client attempt; expected cert failure"
ip netns exec "$TARGET_NS" python3 "$SESSION/client.py" verify || true
sleep 1

# Second connection accepts any cert, proving the transparent path/proxy works and payload capture occurs.
echo "[+] insecure client attempt; expected HTTP response through MITM"
ip netns exec "$TARGET_NS" python3 "$SESSION/client.py" insecure || true
sleep 2

echo "[+] Mole log: $SESSION/mole.log"
tail -n +1 "$SESSION/mole.log" || true

echo "[+] Payload files:"
find "$SESSION/mole" -type f -maxdepth 4 -print 2>/dev/null || true

if grep -q '"result": "accepted"' "$SESSION/mole.log" && find "$SESSION/mole" -name client.bin -size +0c | grep -q .; then
  echo "[+] smoke test passed"
else
  echo "[-] smoke test did not observe accepted MITM + payload; inspect $SESSION" >&2
  exit 2
fi
