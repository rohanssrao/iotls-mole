from __future__ import annotations

from scapy.all import DNS, DNSQR, DNSRR, IP, UDP

from trustfall.system import classify_udp, handle_packet


class FakeLog:
    def __init__(self):
        self.events = []

    def emit(self, kind, **fields):
        self.events.append((kind, fields))


class FakeEnv:
    target_ip = "10.0.0.50"


def test_mdns_query_emits_service_names():
    pkt = (
        IP(src="10.0.0.50", dst="224.0.0.251")
        / UDP(sport=5353, dport=5353)
        / DNS(qd=DNSQR(qname="_googlecast._tcp.local"))
    )
    log = FakeLog()
    handle_packet(pkt, FakeEnv(), log, include_udp=False)
    mdns = [f for k, f in log.events if k == "MDNS"]
    assert mdns and "_googlecast._tcp.local" in mdns[0]["services"]


def test_mdns_response_emits_service_names():
    pkt = (
        IP(src="10.0.0.50", dst="224.0.0.251")
        / UDP(sport=5353, dport=5353)
        / DNS(qr=1, an=DNSRR(rrname="_hap._tcp.local", type="PTR", rdata="MyDevice._hap._tcp.local"))
    )
    log = FakeLog()
    handle_packet(pkt, FakeEnv(), log, include_udp=False)
    mdns = [f for k, f in log.events if k == "MDNS"]
    assert mdns and "_hap._tcp.local" in mdns[0]["services"]


def test_non_target_packet_ignored():
    pkt = IP(src="10.0.0.99", dst="224.0.0.251") / UDP(sport=5353, dport=5353) / DNS(qd=DNSQR(qname="x.local"))
    log = FakeLog()
    handle_packet(pkt, FakeEnv(), log, include_udp=False)
    assert log.events == []


def test_classify_udp_unchanged():
    assert classify_udp(123, b"") == "ntp"
    assert classify_udp(5684, b"") == "coap-dtls"
