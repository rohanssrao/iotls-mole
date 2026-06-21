# Trustfall

A transparent MitM harness for sniffing and breaking TLS over a network. It ARP-spoofs the target, redirects its TCP flows through a local proxy, and tries several strategies to crack its TLS traffic. Outputs plaintext, findings by category, and a .pcap for analysis. Designed to be as easy as possible to use -- no configuration or preparation necessary.

## Usage

Run it, pick a target from the interactive LAN device picker, and Ctrl-C to stop and output a summary. You can also pass a target IP as the first argument to skip the picker.

```bash
sudo uv run trustfall
```

NixOS:

```bash
sudo nix run .
```

Docker:

```bash
sudo docker build -t trustfall .
sudo docker run --rm -it --privileged --net=host -v "$PWD/out:/out" trustfall --out /out
```

Each run creates a session directory (printed on exit) containing `summary.txt`/`summary.json`, `events.jsonl`, decrypted payloads, `capture.pcap`, and `sslkeys.log`.

## Inspecting results

Browse captured plaintext/decrypted payloads:

```bash
uv run trustfall show <session-dir>
```

Open the capture in Wireshark, decrypting the intercepted TLS with the key log:

```bash
wireshark -r <session-dir>/capture.pcap -o tls.keylog_file:<session-dir>/sslkeys.log
```

Or dump decrypted HTTP from the terminal:

```bash
tshark -nr <session-dir>/capture.pcap -o tls.keylog_file:<session-dir>/sslkeys.log -Y http
```

## Common options

```text
--out DIR                      session directory
--strategy NAME                test one cert strategy (default: all)
--cert/--key PEM               operator cert for public-wrong-host testing
--redirect-ports 80,443        restrict redirected TCP ports
--no-funnel                    don't block QUIC/DoH/DoT or run the DNS responder
--no-pcap                      don't write capture.pcap / sslkeys.log
--firewall auto|iptables|nft   Linux firewall backend (default: auto)
--verbose / --quiet / --jsonl  stdout verbosity
--cleanup-only                 remove leftover firewall rules and exit
```

## What it does

- **Cert strategies** — each isolates one defect: `self-signed`, `private-ca` (unknown CA + wrong host), `cn-only` (no SAN), `wildcard` (non-matching), `weak-key` (1024-bit RSA), `expired`, `public-wrong-host`. One strategy is tried per connection; reconnects rotate through the rest. Rejections are classified by the client's TLS alert, and endpoints that refuse everything opaquely are flagged as **likely certificate pinning**.
- **Traffic funnel** (on by default, active mode) — blocks QUIC/HTTP3, DoH/DoT, suppresses AAAA, and strips STARTTLS so traffic falls back into the interceptable TCP+TLS path. Flags **TLS fail-open** if a device retries in cleartext after its handshake is refused.
- **Passive recon** — decodes SNI/ALPN/**JA3**, DNS, mDNS service names, and plaintext **CoAP**; flags **CoAP/DTLS** and **IPv6 escape** (traffic outside IPv4 ARP scope). Captures the *real* upstream cert for ground-truth comparison and scans payloads for secrets.
- **Outputs** — `summary.json` (per-endpoint findings + a device inventory of domains/endpoints/protocols/JA3), `events.jsonl`, per-session payloads, and a Wireshark-decryptable pcap.

## Platform support

Linux is the fully-supported platform; the firewall backend (iptables or nftables) is auto-selected. On a host whose existing nftables forward chain has a `drop` policy, the target may need to be explicitly allowed to forward (`nft list ruleset`).

macOS is **recon-only**: discovery and passive monitoring work, but transparent interception does not — macOS does not deliver pf-`rdr`'d forwarded traffic to a local listener. Use Linux to intercept.
