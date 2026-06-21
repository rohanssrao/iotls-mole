from __future__ import annotations

import os
import re
import shutil
import socket
import struct
import subprocess
import sys
from pathlib import Path

IS_MACOS = sys.platform == "darwin"
LINUX_IP_FORWARD = Path("/proc/sys/net/ipv4/ip_forward")

# Well-known DNS-over-HTTPS resolver IPs. Dropping TCP/443 to these forces the
# device to fall back to plaintext :53 (which our DNS responder then owns).
DOH_IPS = [
    "1.1.1.1", "1.0.0.1", "1.1.1.2", "1.0.0.2",        # Cloudflare
    "8.8.8.8", "8.8.4.4",                                # Google
    "9.9.9.9", "149.112.112.112",                        # Quad9
    "94.140.14.14", "94.140.15.15",                      # AdGuard
    "208.67.222.222", "208.67.220.220",                  # OpenDNS
    "185.228.168.9",                                      # CleanBrowsing
]


def run(cmd: list[str], check: bool = True, input_text: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, text=True, input=input_text, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=check)


def detect_firewall(prefer: str = "auto") -> str:
    """Pick the firewall backend: 'pf' on macOS, else 'iptables' (preferred when
    present, most-tested) or native 'nft'. `prefer` forces a Linux backend."""
    if IS_MACOS:
        return "pf"
    if prefer in ("iptables", "nft"):
        return prefer
    if shutil.which("iptables"):
        return "iptables"
    if shutil.which("nft"):
        return "nft"
    raise SystemExit("no supported firewall backend found (need iptables or nft)")


def require_root():
    if os.geteuid() != 0:
        raise SystemExit("trustfall must run as root for ARP spoofing / packet redirection")


# --- default route / interface discovery -------------------------------------

def default_route() -> tuple[str, str]:
    """Return (gateway_ip, iface) for the default route."""
    if IS_MACOS:
        return parse_macos_default_route(run(["route", "-n", "get", "default"]).stdout)
    return parse_linux_default_route(run(["ip", "route", "show", "default"]).stdout)


def parse_linux_default_route(out: str) -> tuple[str, str]:
    line = out.strip().splitlines()[0]
    toks = line.split()
    return toks[toks.index("via") + 1], toks[toks.index("dev") + 1]


def parse_macos_default_route(out: str) -> tuple[str, str]:
    gw = iface = None
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("gateway:"):
            gw = line.split()[1]
        elif line.startswith("interface:"):
            iface = line.split()[1]
    if not gw or not iface:
        raise RuntimeError("could not determine default route")
    return gw, iface


def iface_cidr(iface: str) -> str | None:
    if IS_MACOS:
        return parse_macos_ifconfig_cidr(run(["ifconfig", iface], check=False).stdout)
    return parse_linux_ip_cidr(run(["ip", "-4", "addr", "show", "dev", iface], check=False).stdout)


def parse_linux_ip_cidr(out: str) -> str | None:
    m = re.search(r"inet (\d+\.\d+\.\d+\.\d+/\d+)", out)
    return m.group(1) if m else None


def parse_macos_ifconfig_cidr(out: str) -> str | None:
    # macOS prints the mask in hex, e.g. "inet 10.0.0.5 netmask 0xffffc000 ..."
    m = re.search(r"inet (\d+\.\d+\.\d+\.\d+) netmask (0x[0-9a-fA-F]+)", out)
    if not m:
        return None
    prefix = bin(int(m.group(2), 16)).count("1")
    return f"{m.group(1)}/{prefix}"


def iface_ip(iface: str) -> str:
    cidr = iface_cidr(iface)
    if not cidr:
        raise RuntimeError(f"no IPv4 address on {iface}")
    return cidr.split("/")[0]


# --- IP forwarding ------------------------------------------------------------

def read_forwarding() -> str:
    if IS_MACOS:
        return run(["sysctl", "-n", "net.inet.ip.forwarding"], check=False).stdout.strip() or "0"
    return LINUX_IP_FORWARD.read_text().strip()


def enable_forwarding():
    if IS_MACOS:
        run(["sysctl", "-w", "net.inet.ip.forwarding=1"])
    else:
        LINUX_IP_FORWARD.write_text("1\n")


def restore_forwarding(old: str):
    if IS_MACOS:
        run(["sysctl", "-w", f"net.inet.ip.forwarding={old or '0'}"], check=False)
    else:
        LINUX_IP_FORWARD.write_text((old or "0") + "\n")


# --- original destination recovery -------------------------------------------

SO_ORIGINAL_DST = 80  # Linux netfilter
_PF_STATE_PAREN = re.compile(r"\((\d+\.\d+\.\d+\.\d+):(\d+)\)")


def original_dst(sock: socket.socket) -> tuple[str, int]:
    if IS_MACOS:
        return _macos_original_dst(sock)
    data = sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
    return socket.inet_ntoa(data[4:8]), struct.unpack_from("!H", data, 2)[0]


def parse_pf_state(out: str, client_ip: str, proxy_port: int) -> tuple[str, int] | None:
    """Recover the original destination of an rdr'd connection from `pfctl -s state`.

    macOS renders a redirected state as e.g.
        en0 tcp 10.0.0.224:9900 (1.1.1.1:443) <- 10.0.0.169:54321  ESTABLISHED:...
    where the parenthesized address is the *original* destination. Some pf builds
    instead use a `src -> orig -> rdr` triple-arrow form (handled as a fallback).
    We match the line carrying the client IP and our proxy port.
    """
    needle_port = f":{proxy_port}"
    for line in out.splitlines():
        if client_ip not in line or needle_port not in line:
            continue
        m = _PF_STATE_PAREN.search(line)
        if m:
            return m.group(1), int(m.group(2))
        fields = line.split()
        arrows = [i for i, f in enumerate(fields) if f in ("->", "<-")]
        if len(arrows) >= 2:
            host, _, port = fields[arrows[0] + 1].rpartition(":")
            if host and port.isdigit():
                return host, int(port)
    return None


def _macos_original_dst(sock: socket.socket) -> tuple[str, int]:
    client_ip = sock.getpeername()[0]
    proxy_port = sock.getsockname()[1]
    out = run(["pfctl", "-s", "state"], check=False).stdout
    dst = parse_pf_state(out, client_ip, proxy_port)
    if dst is None:
        raise RuntimeError(f"no pf state for original dst of {client_ip} (proxy port {proxy_port})")
    return dst
