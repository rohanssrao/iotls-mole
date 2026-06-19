# IoTLS-Mole

Transparent MITM harness for owned/lab IoT devices. It performs ARP gateway takeover, redirects target TCP flows to a local proxy, logs DNS/service metadata, and rotates TLS certificate-validation test strategies across successive reconnects.

Linux is the primary, fully-tested platform (iptables + `SO_ORIGINAL_DST`). **macOS support is recon-only:** discovery/the device picker and passive monitoring (SNI/ALPN/JA3, DNS/mDNS/CoAP) work natively, but **transparent TLS interception does not work on macOS.** This is a macOS platform limitation, not a tool bug — the kernel does not deliver pf-`rdr`'d *forwarded* (ARP-spoofed) packets to a local listener (connections stall at `SYN_SENT`; the rewritten packet is dropped, never reflected to the local socket). Verified directly at the packet/state level that **bettercap's `http.proxy`/`https.proxy` fail identically on the same machine** (same `SYN_SENT`, proxies receive nothing while the target actively sends traffic), across every rdr-target/bind/forwarding combination. Use **Linux** for interception. (The proper macOS fix would be a `utun`-based datapath instead of pf-rdr-to-local-socket — a separate, substantial effort.)

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
--funnel / --no-funnel    block QUIC/DoH/DoT + run DNS responder (default: on, active mode)
--dns-spoof-ip IP         answer all A queries with IP (full redirection)
--dns-spoof-domains a,b   limit --dns-spoof-ip to these domain suffixes
--dns-upstream IP         upstream resolver for passthrough (default: gateway)
```

## Traffic funnel

In active mode IoTLS-Mole funnels the target's traffic into the one channel it can fully decrypt (TCP + our TLS):

- **Blocks QUIC/HTTP3** (UDP 443) so apps fall back to TLS-over-TCP we intercept.
- **Blocks DoH/DoT** (TCP/UDP 853 + well-known DoH resolver IPs on 443) so DNS falls back to plaintext.
- **Runs an on-path DNS responder** that suppresses AAAA (forcing IPv4, where ARP spoofing works) and passes A queries through to a real resolver. `--dns-spoof-ip` switches it to full redirection.
- **Strips STARTTLS** on opportunistic-TLS ports (SMTP/IMAP/POP3/FTP/XMPP) to keep those sessions in cleartext.
- **Detects TLS fail-open**: if the device retries in cleartext after its TLS handshake is refused, that's flagged as a HIGH finding.

Disable the whole funnel with `--no-funnel`.

## Lab smoke test

A self-contained network-namespace smoke test exercises the full pipeline
(redirect → proxy → TLS interception → funnel → capture → summary → CoAP) on an
isolated bridge, without touching host networking:

```bash
sudo -E env PATH="$PATH" bash lab/netns-smoke.sh        # deterministic (routes target via mole)
MOLE_LAB_ARP=1 sudo -E env PATH="$PATH" bash lab/netns-smoke.sh   # exercise live ARP spoofing (racy by nature)
```

## Notes

- IPv4 only for now. **Linux is fully tested and is the platform for interception.** macOS is recon-only (discovery + passive monitoring); transparent interception is a confirmed macOS limitation — see the note at the top.
- One certificate strategy is tested per TLS connection attempt. Re-testing requires natural reconnects or `--retest rst|auto`.
- Cert strategies each isolate one validation defect: `self-signed`, `private-ca` (unknown CA + wrong-host), `cn-only` (no SAN), `wildcard` (wildcard that can't match the host), `weak-key` (1024-bit RSA), `expired`, and `public-wrong-host` (needs `--cert/--key`). Select a subset with `--strategy`.
- Rejections are classified by the client's TLS alert (`unknown_ca` → validates chain, `certificate_expired` → checks validity, etc.). Endpoints that reject everything with only opaque alerts are flagged as **likely certificate pinning**.
- UDP is classified/logged only, not MITM'd. DNS and mDNS (`_service._proto.local`) names are decoded for device fingerprinting.
- Plaintext **CoAP** (RFC 7252, :5683) is parsed passively (method/URI/payload) and logged as `COAP` events. Encrypted **CoAP/DTLS** (:5684) is detected and flagged (`DTLS_CLIENTHELLO`) but not decrypted.
- **IPv6 escape detection**: any IPv6 traffic from the target is flagged (`IPV6_ESCAPE`) since IPv4 ARP spoofing doesn't cover it. `--suppress-ipv6` RA-kills the real IPv6 router to force the target back onto IPv4 (aggressive, LAN-wide; opt-in).
- Each intercepted ClientHello is fingerprinted with **JA3**; the *real* upstream certificate is captured (subject/issuer/SANs/validity) into `metadata.json` and an `UPSTREAM_CERT` event for ground-truth comparison.
- Decrypted/plaintext payloads are scanned for secrets (JWTs, Basic/Bearer auth, API keys, AWS keys, cookies, passwords, private keys); hits are emitted as `SECRET` events (masked) and written to per-session `secrets.json`.
- Each run writes `summary.txt` (human) and `summary.json` (machine-readable: per-endpoint findings, alerts, pinning, plus a device behavioral inventory of domains/endpoints/mDNS/protocols/JA3).
- `iotls-mole show <dir> --grep TOKEN [-i]` filters captured sessions whose payload contains a substring.
