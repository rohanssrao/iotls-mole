from __future__ import annotations

from types import SimpleNamespace

from trustfall.netos import DOH_IPS
from trustfall.pf import PacketFilter


def _env():
    return SimpleNamespace(iface="en0", target_ip="10.0.0.50", gateway_ip="10.0.0.1",
                           local_ip="10.0.0.66", old_forward="0")


def test_ruleset_redirects_tcp_ports_to_proxy():
    rs = PacketFilter(_env(), 9900, [80, 443, 8883]).ruleset()
    assert "rdr pass on en0 inet proto tcp from 10.0.0.50 to any port { 80, 443, 8883 } -> 10.0.0.66 port 9900" in rs
    assert "com.apple" not in rs                  # minimal ruleset: don't import Apple's blocking anchors
    assert "block" not in rs                       # no funnel unless requested
    # No bare `pass`: pf defaults to pass, and an explicit stateful pass breaks rdr.
    assert not any(l.strip() == "pass" for l in rs.splitlines())


def test_ruleset_all_ports_when_empty():
    rs = PacketFilter(_env(), 9900, []).ruleset()
    assert "rdr pass on en0 inet proto tcp from 10.0.0.50 to any -> 10.0.0.66 port 9900" in rs


def test_ruleset_dns_redirect():
    rs = PacketFilter(_env(), 9900, [443], dns_port=9953).ruleset()
    assert "rdr pass on en0 inet proto udp from 10.0.0.50 to any port 53 -> 10.0.0.66 port 9953" in rs


def test_ruleset_funnel_blocks():
    rs = PacketFilter(_env(), 9900, [443], funnel=True, dns_port=9953).ruleset()
    assert "block drop quick on en0 inet proto udp from 10.0.0.50 to any port 443" in rs        # QUIC
    assert "block drop quick on en0 inet proto { tcp udp } from 10.0.0.50 to any port 853" in rs  # DoT/DoQ
    for ip in DOH_IPS:
        assert f"block drop quick on en0 inet proto tcp from 10.0.0.50 to {ip} port 443" in rs    # DoH


def test_ruleset_translation_before_filtering():
    # rdr (translation) rules must precede block (filtering) rules in pf.
    lines = PacketFilter(_env(), 9900, [443], funnel=True, dns_port=9953).ruleset().splitlines()
    first_rdr = next(i for i, l in enumerate(lines) if l.startswith("rdr "))
    first_block = next(i for i, l in enumerate(lines) if l.startswith("block "))
    assert first_rdr < first_block
    assert not any(l.strip() == "pass" for l in lines)   # no bare pass (breaks rdr)


def test_packetfilter_matches_netfilter_constructor():
    # Both backends must be drop-in for the CLI factory.
    from trustfall.system import Netfilter
    import inspect
    pf = set(inspect.signature(PacketFilter.__init__).parameters)
    nf = set(inspect.signature(Netfilter.__init__).parameters)
    assert pf == nf
    for method in ("install", "cleanup", "purge_stale", "enable_forwarding"):
        assert hasattr(PacketFilter, method) and hasattr(Netfilter, method)
