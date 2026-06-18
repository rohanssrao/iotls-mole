from __future__ import annotations

from scapy.all import ICMPv6ND_RA, IPv6, UDP, IP, Ether
from scapy.layers.dns import DNS, DNSQR

from iotls_mole.system import build_ra_kill, handle_packet, handle_udp


class FakeLog:
    def __init__(self):
        self.events = []

    def emit(self, kind, **fields):
        self.events.append((kind, fields))


class FakeEnv:
    target_ip = "10.0.0.50"
    target_mac = "aa:bb:cc:dd:ee:ff"


def test_build_ra_kill_deprecates_router():
    pkt = build_ra_kill("fe80::1", "11:22:33:44:55:66", prefixes=[("2001:db8::", 64)])
    assert pkt[IPv6].dst == "ff02::1"
    assert pkt[IPv6].src == "fe80::1"
    assert pkt[Ether].src == "11:22:33:44:55:66"
    ra = pkt[ICMPv6ND_RA]
    assert ra.routerlifetime == 0  # tells hosts to stop using this router


def test_ipv6_from_target_flagged_as_escape():
    pkt = Ether(src="aa:bb:cc:dd:ee:ff") / IPv6(src="2001:db8::50", dst="2606:4700::1") / UDP()
    log = FakeLog()
    handle_packet(pkt, FakeEnv(), log, include_udp=False)
    kinds = [k for k, _ in log.events]
    assert "IPV6_ESCAPE" in kinds


def test_coap_request_parsed_by_sniffer():
    # CON GET /status from the target
    coap = bytes([0x40, 0x01, 0x12, 0x34, (11 << 4) | 6]) + b"status"
    pkt = IP(src="10.0.0.50", dst="10.0.0.9") / UDP(sport=40000, dport=5683) / coap
    log = FakeLog()
    handle_packet(pkt, FakeEnv(), log, include_udp=False)
    coap_events = [f for k, f in log.events if k == "COAP"]
    assert coap_events and coap_events[0]["method"] == "GET"
    assert coap_events[0]["uri"] == "status"


def test_dtls_clienthello_flagged_by_sniffer():
    record = bytes([0x16, 0xFE, 0xFD]) + b"\x00" * 10 + bytes([0x01]) + b"\x00" * 4
    pkt = IP(src="10.0.0.50", dst="10.0.0.9") / UDP(sport=40000, dport=5684) / record
    log = FakeLog()
    handle_packet(pkt, FakeEnv(), log, include_udp=False)
    dtls = [f for k, f in log.events if k == "DTLS_CLIENTHELLO"]
    assert dtls and dtls[0]["version"] == "DTLSv1.2"


def test_dns_still_works_after_changes():
    pkt = IP(src="10.0.0.50", dst="10.0.0.1") / UDP(sport=5000, dport=53) / DNS(qd=DNSQR(qname="api.vendor.com"))
    log = FakeLog()
    handle_packet(pkt, FakeEnv(), log, include_udp=False)
    assert any(k == "DNS" for k, _ in log.events)
