from __future__ import annotations

from iotls_mole.proxy import PINNING_ALERTS, classify_tls_alert
from iotls_mole.tlshello import is_grease, parse_client_hello
from tests.test_tlshello import build_client_hello


def test_classify_tls_alert():
    assert classify_tls_alert("[SSL: TLSV1_ALERT_UNKNOWN_CA] tlsv1 alert unknown ca") == "unknown_ca"
    assert classify_tls_alert("[SSL: SSLV3_ALERT_CERTIFICATE_EXPIRED] ...") == "certificate_expired"
    assert classify_tls_alert("[SSL: SSLV3_ALERT_BAD_CERTIFICATE] ...") == "bad_certificate"
    assert classify_tls_alert("[SSL: TLSV1_ALERT_HANDSHAKE_FAILURE] ...") == "handshake_failure"
    assert classify_tls_alert("connection reset by peer") is None
    assert classify_tls_alert(None) is None


def test_pinning_alert_set():
    # CA-validation alerts are NOT pinning; opaque rejections are pinning candidates.
    assert "unknown_ca" not in PINNING_ALERTS
    assert "certificate_expired" not in PINNING_ALERTS
    assert {"bad_certificate", "certificate_unknown", "handshake_failure"} <= PINNING_ALERTS


def test_ja3_is_computed_and_stable():
    raw = build_client_hello(sni="x.test", alpn=["h2", "http/1.1"], versions=[0x0304, 0x0303])
    a = parse_client_hello(raw)
    b = parse_client_hello(raw)
    assert a.ja3 and a.ja3_hash
    assert len(a.ja3_hash) == 32  # md5 hex
    assert a.ja3_hash == b.ja3_hash  # deterministic
    # JA3 string is version,ciphers,extensions,groups,points
    assert a.ja3.startswith("771,")  # legacy version 0x0303 == 771
    assert a.ciphers == [4865]


def test_ja3_excludes_grease():
    assert is_grease(0x0A0A) and is_grease(0x1A1A) and is_grease(0x2A2A)
    assert not is_grease(0x1301) and not is_grease(0x0303)
