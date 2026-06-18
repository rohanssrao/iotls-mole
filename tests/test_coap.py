from __future__ import annotations

from iotls_mole.coap import is_coap, parse_coap
from iotls_mole.tlshello import dtls_version, looks_dtls_client_hello


def _build_coap(code=1, mtype=0, mid=0xBEEF, token=b"", path=(), query=(), payload=b"", cf=None):
    b0 = (1 << 6) | ((mtype & 3) << 4) | (len(token) & 0xF)
    out = bytes([b0, code]) + mid.to_bytes(2, "big") + token
    prev = 0

    def opt(num, val):
        nonlocal out, prev
        delta = num - prev
        assert 0 <= delta < 13 and len(val) < 13, "test helper only does short, ascending options"
        out += bytes([(delta << 4) | len(val)]) + val
        prev = num

    # options MUST be emitted in ascending option-number order: Uri-Path(11),
    # Content-Format(12), Uri-Query(15).
    for seg in path:
        opt(11, seg.encode())
    if cf is not None:
        opt(12, cf.to_bytes(1, "big"))
    for q in query:
        opt(15, q.encode())
    if payload:
        out += b"\xff" + payload
    return out


def test_parse_coap_get_request():
    raw = _build_coap(code=1, mtype=0, path=("sensors", "temp"), query=("unit=c",))
    msg = parse_coap(raw)
    assert msg.type == "CON"
    assert msg.method == "GET"
    assert msg.code == "0.01"
    assert msg.uri_path == "sensors/temp"
    assert msg.uri_query == "unit=c"
    assert msg.summary() == "CON GET /sensors/temp?unit=c"


def test_parse_coap_post_with_payload():
    raw = _build_coap(code=2, mtype=1, path=("actuators", "relay"), payload=b'{"on":true}', cf=50)
    msg = parse_coap(raw)
    assert msg.method == "POST" and msg.type == "NON"
    assert msg.uri_path == "actuators/relay"
    assert msg.payload == b'{"on":true}'
    assert msg.content_format == 50


def test_parse_coap_response_code():
    raw = _build_coap(code=(2 << 5) | 5, mtype=2)  # 2.05 Content
    msg = parse_coap(raw)
    assert msg.code == "2.05" and msg.method is None and msg.type == "ACK"


def test_is_coap_structural_check():
    # Heuristic + port-gated in practice: requires CoAP version bits == 1.
    assert not is_coap(b"\x00\x00\x00\x00")   # version 0
    assert not is_coap(b"\xff")               # too short
    assert is_coap(_build_coap())


def test_dtls_client_hello_detection():
    # DTLS 1.2 record: type=22, version=0xFEFD, epoch/seq/len, handshake type 1
    record = bytes([0x16, 0xFE, 0xFD]) + b"\x00" * 10 + bytes([0x01]) + b"\x00" * 5
    assert looks_dtls_client_hello(record)
    assert dtls_version(record) == "DTLSv1.2"
    record10 = bytes([0x16, 0xFE, 0xFF]) + b"\x00" * 10 + bytes([0x01])
    assert dtls_version(record10) == "DTLSv1.0"
    # a TLS (TCP) ClientHello must not be mistaken for DTLS
    assert not looks_dtls_client_hello(bytes([0x16, 0x03, 0x01]) + b"\x00" * 11)
