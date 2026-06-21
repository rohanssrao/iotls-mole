#!/usr/bin/env python3
"""Safe macOS validation for Trustfall's platform layer.

Runs as root but is NON-DESTRUCTIVE:
  * discovery: sends ARP who-has on the default interface (like any LAN scanner)
  * pf: validates the generated ruleset with `pfctl -n -f` (parse only, NOT applied)

It does NOT ARP-spoof, enable forwarding, load pf rules, or touch any device.

Run from the repo root:
    sudo -E env "PATH=$PATH" uv run --no-sync python lab/macos_check.py
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace

from trustfall.discovery import HostTracker, Probe
from trustfall.netos import default_route, iface_cidr
from trustfall.pf import PacketFilter


def main() -> int:
    gw, iface = default_route()
    cidr = iface_cidr(iface)
    print(f"[*] platform: macOS   iface={iface}  cidr={cidr}  gateway={gw}")

    print("\n[*] discovery (6s ARP sweep + passive sniff)...")
    tracker = HostTracker()
    probe = Probe(iface, tracker)
    probe.start()
    time.sleep(6)
    probe.restore()
    hosts = tracker.snapshot()
    print(f"    found {len(hosts)} host(s):")
    for h in hosts:
        print(f"      {h.ip:15} {h.mac:18} {h.vendor or '?':22} {h.name or ''}")
    discovery_ok = len(hosts) > 0

    print("\n[*] pf ruleset parse-check (pfctl -n -f, NOT applied)...")
    target = hosts[1].ip if len(hosts) > 1 else "10.0.0.123"
    local_ip = cidr.split("/")[0] if cidr else ""
    env = SimpleNamespace(iface=iface, target_ip=target, gateway_ip=gw, local_ip=local_ip, old_forward="0")
    ruleset = PacketFilter(env, 9900, [80, 443, 8883], funnel=True, dns_port=9953).ruleset()
    with tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False) as f:
        f.write(ruleset)
        path = f.name
    r = subprocess.run(["pfctl", "-n", "-f", path], text=True, capture_output=True)
    Path(path).unlink(missing_ok=True)
    pf_ok = r.returncode == 0
    print(f"    pfctl parse exit={r.returncode}")
    if r.stderr.strip():
        print("    pfctl said:\n      " + r.stderr.strip().replace("\n", "\n      "))

    print("\n=== RESULT ===")
    print(f"  discovery: {'PASS' if discovery_ok else 'FAIL (no hosts seen)'}")
    print(f"  pf parse : {'PASS' if pf_ok else 'FAIL (ruleset rejected by pfctl)'}")
    return 0 if (discovery_ok and pf_ok) else 1


if __name__ == "__main__":
    sys.exit(main())
