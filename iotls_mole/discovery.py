from __future__ import annotations

import ipaddress
import socket
import threading
import time
from dataclasses import dataclass, field

from scapy.all import ARP, IP, Ether, get_if_hwaddr, sendp, sniff, srp  # type: ignore

from .netos import iface_cidr

# Small curated OUI table for common consumer/IoT vendors so the picker shows
# useful labels out of the box; scapy's manuf DB (if present) fills in the rest.
OUI = {
    "00:17:88": "Philips Hue", "ec:fa:bc": "Espressif", "24:0a:c4": "Espressif",
    "30:ae:a4": "Espressif", "a0:20:a6": "Espressif", "dc:4f:22": "Espressif",
    "50:02:91": "Espressif", "10:52:1c": "Espressif", "84:0d:8e": "Espressif",
    "d8:f1:5b": "Espressif", "68:57:2d": "Tuya", "d8:1f:12": "Tuya", "10:d5:61": "Tuya",
    "50:8a:06": "Tuya", "84:e3:42": "Tuya", "b8:f0:09": "Shelly/Allterco",
    "c4:5b:be": "Shelly/Allterco", "3c:61:05": "Espressif", "ac:0b:fb": "Espressif",
    "fc:f5:c4": "Espressif", "b4:e6:2d": "Espressif", "44:65:0d": "Amazon",
    "fc:65:de": "Amazon", "68:37:e9": "Amazon", "ac:63:be": "Amazon", "f0:81:73": "Amazon",
    "44:00:49": "Amazon", "08:a6:f7": "Google", "f4:f5:d8": "Google", "1c:f2:9a": "Google",
    "54:60:09": "Google", "30:fd:38": "Google", "d4:f5:47": "Google Nest",
    "b0:09:da": "Ring", "00:62:6e": "Ring", "94:10:3e": "Belkin Wemo",
    "ec:1b:bd": "Wyze", "2c:aa:8e": "Wyze", "7c:78:b2": "Wyze",
    "b0:4e:26": "TP-Link", "50:c7:bf": "TP-Link", "ac:84:c6": "TP-Link",
    "f4:f2:6d": "TP-Link", "98:da:c4": "TP-Link Kasa", "78:11:dc": "Xiaomi",
    "64:09:80": "Xiaomi", "fc:64:ba": "Xiaomi", "28:6c:07": "Xiaomi",
    "b4:e6:2a": "Sonoff/Itead", "dc:a6:32": "Raspberry Pi", "b8:27:eb": "Raspberry Pi",
    "e4:5f:01": "Raspberry Pi", "28:cd:c1": "Raspberry Pi", "00:1a:11": "Google",
    "c8:3a:35": "Tenda", "00:12:fb": "Samsung", "package": "",
    "44:91:60": "Hangzhou Hikvision", "c0:56:e3": "Hangzhou Hikvision",
    "bc:ad:28": "Hangzhou Hikvision", "3c:ef:8c": "Dahua", "90:02:a9": "Dahua",
    "fc:fc:48": "Apple", "a4:83:e7": "Apple", "f0:18:98": "Apple", "dc:a9:04": "Apple",
    "78:8a:20": "Ubiquiti", "fc:ec:da": "Ubiquiti", "24:5a:4c": "Ubiquiti",
}


def vendor_for(mac: str | None, resolver=None) -> str:
    if not mac:
        return ""
    oui = mac.lower().replace("-", ":")[:8]
    if resolver is not None:           # injectable for tests
        v = resolver(oui) or ""
    elif oui in OUI:
        return OUI[oui]
    else:
        v = _scapy_vendor(mac)
    # scapy's manuf lookup (and some resolvers) echo the MAC back on a miss.
    return "" if v and str(v).count(":") >= 2 else (v or "")


def _scapy_vendor(mac: str) -> str:
    try:
        from scapy.all import conf  # type: ignore
        db = getattr(conf, "manufdb", None)
        if db is None:
            return ""
        for attr in ("_get_manuf", "lookup"):
            fn = getattr(db, attr, None)
            if fn:
                try:
                    v = fn(mac)
                    if isinstance(v, (tuple, list)):
                        v = v[-1]
                    if v:
                        return str(v)
                except Exception:
                    continue
    except Exception:
        pass
    return ""


@dataclass
class Host:
    ip: str
    mac: str
    vendor: str = ""
    name: str = ""
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)


class HostTracker:
    """Thread-safe live inventory of discovered hosts (ip -> Host)."""

    def __init__(self):
        self._hosts: dict[str, Host] = {}
        self._lock = threading.Lock()
        self._name_attempted: set[str] = set()

    def observe(self, ip: str, mac: str | None, name: str | None = None):
        now = time.time()
        with self._lock:
            host = self._hosts.get(ip)
            if host is None:
                self._hosts[ip] = Host(ip=ip, mac=mac or "", vendor=vendor_for(mac), name=name or "")
            else:
                host.last_seen = now
                if mac and not host.mac:
                    host.mac = mac
                    host.vendor = vendor_for(mac)
                if name and not host.name:
                    host.name = name

    def set_name(self, ip: str, name: str):
        with self._lock:
            if ip in self._hosts and name:
                self._hosts[ip].name = name

    def needs_name(self) -> list[str]:
        with self._lock:
            out = [ip for ip, h in self._hosts.items() if not h.name and ip not in self._name_attempted]
            self._name_attempted.update(out)
            return out

    def snapshot(self) -> list[Host]:
        with self._lock:
            return sorted((Host(**vars(h)) for h in self._hosts.values()),
                          key=lambda h: ipaddress.ip_address(h.ip))


def ip_in_scope(ip: str, net) -> bool:
    """True if `ip` is a usable host in `net` (filters 0.0.0.0, network/broadcast)."""
    if ip in ("0.0.0.0", "255.255.255.255"):
        return False
    if net is None:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr in net and addr not in (net.network_address, net.broadcast_address)


class Probe:
    """net.probe-style discovery: active ARP sweep + passive ARP/IP sniffing."""

    def __init__(self, iface: str, tracker: HostTracker, log=None, sweep_interval: float = 4.0,
                 resolve_names: bool = True):
        self.iface = iface
        self.tracker = tracker
        self.log = log
        self.sweep_interval = sweep_interval
        self.resolve_names = resolve_names
        self.cidr = iface_cidr(iface)
        self.our_mac = get_if_hwaddr(iface)
        self._net = None
        if self.cidr:
            try:
                self._net = ipaddress.ip_network(self.cidr, strict=False)
            except ValueError:
                self._net = None
        self.stop = threading.Event()
        self._threads: list[threading.Thread] = []

    def start(self):
        for target in (self._sweep_loop, self._sniff_loop, self._name_loop):
            t = threading.Thread(target=target, daemon=True)
            t.start()
            self._threads.append(t)

    def restore(self):
        self.stop.set()

    # --- active ---
    def _sweep_loop(self):
        if not self.cidr:
            return
        net = ipaddress.ip_network(self.cidr, strict=False)
        hosts = [str(h) for h in net.hosts()] if net.num_addresses <= 4096 else []
        while not self.stop.is_set():
            try:
                ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=hosts or str(net)),
                             timeout=2, iface=self.iface, verbose=False)
                for _, r in ans:
                    self.tracker.observe(r.psrc, r.hwsrc)
            except Exception as e:
                if self.log:
                    self.log.emit("WARN", msg="arp sweep failed", error=str(e))
            self.stop.wait(self.sweep_interval)

    def _in_scope(self, ip: str) -> bool:
        return ip_in_scope(ip, self._net)

    # --- passive ---
    def _sniff_loop(self):
        def cb(pkt):
            try:
                if ARP in pkt and pkt[ARP].op in (1, 2):
                    if self._in_scope(pkt[ARP].psrc):
                        self.tracker.observe(pkt[ARP].psrc, pkt[ARP].hwsrc)
                elif IP in pkt and Ether in pkt:
                    if self._in_scope(pkt[IP].src):
                        self.tracker.observe(pkt[IP].src, pkt[Ether].src)
            except Exception:
                pass
        try:
            sniff(iface=self.iface, filter="arp or ip", prn=cb, store=False,
                  stop_filter=lambda _: self.stop.is_set())
        except Exception as e:
            if self.log:
                self.log.emit("WARN", msg="probe sniff failed", error=str(e))

    # --- names ---
    def _name_loop(self):
        if not self.resolve_names:
            return
        while not self.stop.is_set():
            for ip in self.tracker.needs_name():
                try:
                    name = socket.gethostbyaddr(ip)[0]
                    self.tracker.set_name(ip, name)
                except Exception:
                    pass
            self.stop.wait(2.0)
