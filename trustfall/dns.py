from __future__ import annotations

import socket
import threading

from scapy.all import DNS, DNSQR, DNSRR, IP  # type: ignore  # noqa: F401

# DNS record type numbers we care about.
TYPE_A = 1
TYPE_AAAA = 28


def first_question(dns):
    """Return the first DNSQR regardless of scapy version (qd may be list-like)."""
    qd = dns.qd
    if qd is None:
        return None
    if isinstance(qd, list):
        return qd[0] if qd else None
    return qd


def query_info(query: bytes) -> tuple[str, int] | None:
    """(qname, qtype) for the first question, or None if not a query."""
    dns = DNS(query)
    if dns.qr != 0:
        return None
    q = first_question(dns)
    if q is None:
        return None
    name = q.qname.decode(errors="ignore").rstrip(".") if isinstance(q.qname, bytes) else str(q.qname).rstrip(".")
    return name, int(q.qtype)


def build_nodata(query: bytes) -> bytes:
    """A NOERROR/NODATA response (no answers) — used to suppress AAAA and force IPv4."""
    dns = DNS(query)
    dns.qr = 1
    dns.ra = 1
    dns.aa = 0
    dns.ancount = 0
    dns.an = []
    return bytes(dns)


def build_spoofed_a(query: bytes, ip: str, ttl: int = 60) -> bytes:
    """An A-record response pointing the queried name at `ip`."""
    dns = DNS(query)
    q = first_question(dns)
    name = q.qname if q is not None else b"."
    resp = DNS(id=dns.id, qr=1, ra=1, qd=dns.qd, an=DNSRR(rrname=name, type="A", ttl=ttl, rdata=ip))
    return bytes(resp)


def domain_matches(name: str, patterns: list[str] | None) -> bool:
    """True if no patterns (match all) or name endswith one of the suffixes."""
    if not patterns:
        return True
    name = name.lower().rstrip(".")
    return any(name == p or name.endswith("." + p) for p in (p.lower().lstrip(".") for p in patterns))


class DNSResponder:
    """On-path DNS responder.

    Default behavior funnels traffic onto IPv4 we can intercept: suppress AAAA
    (NODATA) so the device uses A records, and pass A queries through to a real
    upstream resolver. With spoof_ip set, A queries (optionally limited to
    spoof_domains) are answered with our address for full redirection.
    """

    def __init__(self, env, log, listen_port: int, upstream: str,
                 suppress_aaaa: bool = True, spoof_ip: str | None = None,
                 spoof_domains: list[str] | None = None, upstream_timeout: float = 3.0,
                 bind_host: str = "0.0.0.0"):
        self.env = env
        self.log = log
        self.listen_port = listen_port
        self.bind_host = bind_host
        self.upstream = upstream
        self.suppress_aaaa = suppress_aaaa
        self.spoof_ip = spoof_ip
        self.spoof_domains = spoof_domains
        self.upstream_timeout = upstream_timeout
        self.stop = threading.Event()
        self.sock: socket.socket | None = None
        self.thread: threading.Thread | None = None

    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.bind_host, self.listen_port))
        self.sock.settimeout(1)
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def restore(self):
        self.stop.set()
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass

    def _loop(self):
        while not self.stop.is_set():
            try:
                data, addr = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                reply = self.handle(data)
            except Exception as e:
                self.log.emit("WARN", msg="dns handler failed", error=str(e))
                reply = None
            if reply:
                try:
                    self.sock.sendto(reply, addr)
                except OSError:
                    pass

    def handle(self, data: bytes) -> bytes | None:
        info = query_info(data)
        if info is None:
            return self._forward(data)
        name, qtype = info
        if qtype == TYPE_AAAA and self.suppress_aaaa:
            self.log.emit("DNS_SPOOF", query=name, action="aaaa_suppressed")
            return build_nodata(data)
        if self.spoof_ip and qtype == TYPE_A and domain_matches(name, self.spoof_domains):
            self.log.emit("DNS_SPOOF", query=name, action="spoofed_a", answer=self.spoof_ip)
            return build_spoofed_a(data, self.spoof_ip)
        return self._forward(data)

    def _forward(self, data: bytes) -> bytes | None:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as up:
                up.settimeout(self.upstream_timeout)
                up.sendto(data, (self.upstream, 53))
                return up.recvfrom(4096)[0]
        except OSError as e:
            self.log.emit("WARN", msg="dns upstream failed", upstream=self.upstream, error=str(e))
            return None
