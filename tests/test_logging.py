from __future__ import annotations

from iotls_mole.logging import EventLogger, _BoundedSet


def _fmt(**fields) -> str:
    log = EventLogger(jsonl=False)
    record = {"ts": "T", "kind": fields.pop("kind", "TLS"), **fields}
    return log._format_human(record)


def test_bounded_set_basic():
    s = _BoundedSet(maxsize=2)
    s.add(("a",))
    assert ("a",) in s
    assert ("z",) not in s


def test_tls_reject_shows_reconnect_hint():
    line = _fmt(dest="1.1.1.1:443", sni="a.test", strategy="self_signed_match", result="rejected", remaining=2)
    assert "2 strategies left" in line
    assert "awaiting reconnect" in line


def test_tls_reject_singular_and_exhausted():
    one = _fmt(dest="1.1.1.1:443", sni="a.test", strategy="x", result="rejected", remaining=1)
    assert "1 strategy left" in one and "awaiting reconnect" in one
    done = _fmt(dest="1.1.1.1:443", sni="a.test", strategy="x", result="rejected", remaining=0)
    assert "0 strategies left" in done and "endpoint exhausted" in done


def test_tls_accept_has_no_reconnect_hint():
    line = _fmt(dest="1.1.1.1:443", sni="a.test", strategy="private_ca_match", result="accepted", finding="x")
    assert "left" not in line
    assert "finding=x" in line


def test_mdns_format():
    line = _fmt(kind="MDNS", services="_googlecast._tcp.local")
    assert line.endswith("MDNS _googlecast._tcp.local")
