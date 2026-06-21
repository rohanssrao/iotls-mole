from __future__ import annotations

from trustfall.logging import EventLogger, _BoundedSet


def _fmt(**fields) -> str:
    log = EventLogger(jsonl=False)
    record = {"ts": "2026-06-21T14:27:51Z", "kind": fields.pop("kind", "TLS"), **fields}
    return log._format_human(record)


def test_bounded_set_basic():
    s = _BoundedSet(maxsize=2)
    s.add(("a",))
    assert ("a",) in s
    assert ("z",) not in s


def test_short_timestamp():
    line = _fmt(kind="MDNS", services="_x._tcp.local")
    assert line.startswith("14:27:51  ")


def test_tls_reject_shows_alert_meaning_and_reconnect_hint():
    line = _fmt(dest="1.1.1.1:443", sni="a.test", strategy="self_signed_match", result="rejected",
                alert_meaning="validates the chain to a trusted CA", remaining=2)
    assert "REJECT" in line
    assert "rejected self-signed" in line
    assert "validates the chain to a trusted CA" in line
    assert "2 strategies left" in line and "awaiting reconnect" in line


def test_tls_reject_singular_and_exhausted():
    one = _fmt(dest="1.1.1.1:443", sni="a.test", strategy="x", result="rejected", remaining=1)
    assert "1 strategy left" in one and "awaiting reconnect" in one
    done = _fmt(dest="1.1.1.1:443", sni="a.test", strategy="x", result="rejected", remaining=0)
    assert "0 strategies left" in done and "endpoint exhausted" in done


def test_tls_accept_is_a_vuln_with_finding_phrase():
    line = _fmt(dest="1.1.1.1:443", sni="a.test", strategy="private_ca_match", result="accepted",
                finding="trusts_unknown_ca_or_missing_chain_validation")
    assert "VULN" in line
    assert "accepts private-ca" in line
    assert "accepts unknown/private CA" in line
    assert "left" not in line  # no reconnect hint on a finding


def test_mdns_format():
    line = _fmt(kind="MDNS", services="_googlecast._tcp.local")
    assert "MDNS" in line and line.rstrip().endswith("_googlecast._tcp.local")


def test_plaintext_capture_logged_by_default():
    log = EventLogger(jsonl=False)  # default: not verbose, not quiet
    assert log._should_print("PAYLOAD", {"proto": "tcp"}) is True
    line = _fmt(kind="PAYLOAD", dest="1.1.1.1:80", proto="tcp", path="out/x/0001")
    assert "CAPTURE" in line and "cleartext" in line and "out/x/0001" in line
    tls = _fmt(kind="PAYLOAD", dest="1.1.1.1:443", proto="tls", path="out/x/0002")
    assert "decrypted TLS" in tls


def test_secret_and_attack_tags():
    s = _fmt(kind="SECRET", secret="jwt", direction="client", dest="1.1.1.1:443", value="ey***")
    assert s.lstrip().split()[1] == "SECRET" and "jwt (client)" in s
    a = _fmt(kind="FAIL_OPEN", dest="1.1.1.1:443", tls_port=443, sni="a.test")
    assert "ATTACK" in a and "fail-open" in a


def test_ipv6_escape_is_informational_not_alarming():
    line = _fmt(kind="IPV6_ESCAPE", src="fe80::1", dst="ff02::1")
    assert "IPV6" in line
    assert "outside IPv4 ARP scope" in line
    assert "\u26a0" not in line and "\U0001f511" not in line  # no emoji


def test_header_block_for_startup_info():
    line = _fmt(kind="INFO", target="10.0.0.5", iface="en0", gateway="10.0.0.1",
                local_ip="10.0.0.9", session_dir="out/x")
    assert "trustfall" in line and "10.0.0.5" in line
    assert "via en0" in line and "session" in line
