# IoTLS-Mole

Linux-only transparent MITM harness for owned/lab IoT devices. It performs ARP gateway takeover, redirects target TCP flows to a local proxy, logs DNS/service metadata, and rotates TLS certificate-validation test strategies across successive reconnects.

> Use only on devices/networks you own or are authorized to test.

## Quick start

```bash
sudo uv run iotls-mole 192.168.1.42
# Ctrl-C when done
sudo uv run iotls-mole show sessions/<created-session-dir>
```

By default, stdout is curated and the full event stream is written to `events.jsonl` under the session directory. Captured plaintext/decrypted payloads are written as `client.txt`, `server.txt`, `client.bin`, and `server.bin` per session.

## Install / run

Python package mode is preferred:

```bash
uv tool install .
sudo env PATH="$PATH" iotls-mole 192.168.1.42
```

From the source tree:

```bash
sudo uv run iotls-mole 192.168.1.42 --out ./sessions/test-run
```

NixOS-style dependency shell if `ip`, `iptables`, or libpcap bits are missing:

```bash
nix develop
sudo -E env PATH="$PATH" LD_LIBRARY_PATH="$LD_LIBRARY_PATH" uv run iotls-mole 192.168.1.42
```

Docker is retained as a fallback for conventional Linux hosts, but is not expected to work for L2 ARP spoofing on Docker Desktop/macOS:

```bash
sudo docker build -t iotls-mole:latest .
sudo docker run --rm --privileged --net=host -v "$PWD/sessions:/sessions" iotls-mole:latest 192.168.1.42 --out /sessions/run1
```

Optional public cert/key for wrong-host testing:

```bash
sudo uv run iotls-mole 192.168.1.42 --cert fullchain.pem --key privkey.pem
```

Cleanup stale firewall rules:

```bash
sudo uv run iotls-mole 192.168.1.42 --cleanup-only
```

## Useful flags

```text
--out DIR                 output/session directory
--verbose                 show low-level TCP/TLS/DNS events on stdout
--quiet                   only print high-signal findings and summary
--jsonl                   emit full event stream on stdout
--redirect-ports 80,443   restrict active TCP redirection
--on-exhausted close      deterministic testing; default is passthrough
--no-payloads             collect metadata only
```

## Notes

- Linux IPv4 only for now.
- One certificate strategy is tested per TLS connection attempt. Re-testing requires natural reconnects or `--retest rst|auto`.
- Cert strategies each isolate one validation defect: `self-signed`, `private-ca` (unknown CA + wrong-host), `cn-only` (no SAN), `wildcard` (wildcard that can't match the host), `weak-key` (1024-bit RSA), `expired`, and `public-wrong-host` (needs `--cert/--key`). Select a subset with `--strategy`.
- Rejections are classified by the client's TLS alert (`unknown_ca` → validates chain, `certificate_expired` → checks validity, etc.). Endpoints that reject everything with only opaque alerts are flagged as **likely certificate pinning**.
- UDP is classified/logged only, not MITM'd. DNS and mDNS (`_service._proto.local`) names are decoded for device fingerprinting.
- Each intercepted ClientHello is fingerprinted with **JA3**; the *real* upstream certificate is captured (subject/issuer/SANs/validity) into `metadata.json` and an `UPSTREAM_CERT` event for ground-truth comparison.
- Decrypted/plaintext payloads are scanned for secrets (JWTs, Basic/Bearer auth, API keys, AWS keys, cookies, passwords, private keys); hits are emitted as `SECRET` events (masked) and written to per-session `secrets.json`.
- Each run writes `summary.txt` (human) and `summary.json` (machine-readable: per-endpoint findings, alerts, pinning, plus a device behavioral inventory of domains/endpoints/mDNS/protocols/JA3).
- `iotls-mole show <dir> --grep TOKEN [-i]` filters captured sessions whose payload contains a substring.
