from __future__ import annotations

from scapy.all import DNS, DNSQR, DNSRR

from trustfall.dns import (
    DNSResponder,
    build_nodata,
    build_spoofed_a,
    domain_matches,
    query_info,
)


def _q(qname, qtype):
    return bytes(DNS(id=0x1234, rd=1, qd=DNSQR(qname=qname, qtype=qtype)))


def test_query_info():
    assert query_info(_q("api.vendor.com", "A")) == ("api.vendor.com", 1)
    assert query_info(_q("api.vendor.com", "AAAA")) == ("api.vendor.com", 28)
    # a response (qr=1) is not a query
    resp = bytes(DNS(id=1, qr=1, qd=DNSQR(qname="x.com", qtype="A")))
    assert query_info(resp) is None


def test_build_nodata_suppresses_answers():
    out = DNS(build_nodata(_q("api.vendor.com", "AAAA")))
    assert out.qr == 1
    assert (out.ancount or 0) == 0
    assert not out.an
    assert out.id == 0x1234  # preserves the query id


def test_build_spoofed_a_points_at_ip():
    out = DNS(build_spoofed_a(_q("api.vendor.com", "A"), "10.0.0.171"))
    assert out.qr == 1
    assert out.id == 0x1234
    answers = out.an if isinstance(out.an, list) else [out.an]
    assert any(getattr(a, "rdata", None) in ("10.0.0.171", b"10.0.0.171") for a in answers)


def test_domain_matches():
    assert domain_matches("anything.com", None) is True          # no filter -> all
    assert domain_matches("api.vendor.com", ["vendor.com"]) is True
    assert domain_matches("vendor.com", ["vendor.com"]) is True
    assert domain_matches("api.other.com", ["vendor.com"]) is False
    assert domain_matches("notvendor.com", ["vendor.com"]) is False  # suffix must be label-aligned


class _Log:
    def __init__(self):
        self.events = []

    def emit(self, kind, **f):
        self.events.append((kind, f))


def test_responder_suppresses_aaaa_and_spoofs_a():
    log = _Log()
    r = DNSResponder(env=None, log=log, listen_port=0, upstream="9.9.9.9",
                     suppress_aaaa=True, spoof_ip="10.0.0.171")
    aaaa = DNS(r.handle(_q("api.vendor.com", "AAAA")))
    assert (aaaa.ancount or 0) == 0  # NODATA -> forces IPv4
    a = DNS(r.handle(_q("api.vendor.com", "A")))
    assert a.qr == 1 and a.ancount >= 1
    actions = {f.get("action") for k, f in log.events if k == "DNS_SPOOF"}
    assert {"aaaa_suppressed", "spoofed_a"} <= actions


def test_responder_spoof_domain_filter():
    log = _Log()
    r = DNSResponder(env=None, log=log, listen_port=0, upstream="9.9.9.9",
                     suppress_aaaa=False, spoof_ip="10.0.0.171", spoof_domains=["vendor.com"])
    # in-scope domain is spoofed
    assert DNS(r.handle(_q("api.vendor.com", "A"))).ancount >= 1
    # out-of-scope would be forwarded upstream; assert we didn't emit a spoof for it
    actions = [(f.get("query"), f.get("action")) for k, f in log.events if k == "DNS_SPOOF"]
    assert ("api.vendor.com", "spoofed_a") in actions
