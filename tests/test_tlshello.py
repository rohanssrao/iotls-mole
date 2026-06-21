from __future__ import annotations

import struct

from trustfall.tlshello import looks_tls, parse_client_hello


def _ext(ext_type: int, body: bytes) -> bytes:
    return struct.pack("!HH", ext_type, len(body)) + body


def _sni_ext(host: str) -> bytes:
    name = host.encode()
    entry = bytes([0]) + struct.pack("!H", len(name)) + name  # name_type=host_name
    return _ext(0, struct.pack("!H", len(entry)) + entry)


def _alpn_ext(protocols: list[str]) -> bytes:
    body = b""
    for p in protocols:
        pb = p.encode()
        body += bytes([len(pb)]) + pb
    return _ext(16, struct.pack("!H", len(body)) + body)


def _supported_versions_ext(versions: list[int]) -> bytes:
    body = b"".join(struct.pack("!H", v) for v in versions)
    return _ext(43, bytes([len(body)]) + body)


def build_client_hello(sni=None, alpn=None, versions=None) -> bytes:
    exts = b""
    if sni is not None:
        exts += _sni_ext(sni)
    if alpn:
        exts += _alpn_ext(alpn)
    if versions:
        exts += _supported_versions_ext(versions)

    body = struct.pack("!H", 0x0303)          # legacy client_version TLS1.2
    body += b"\x00" * 32                        # random
    body += b"\x00"                             # session id length 0
    body += struct.pack("!H", 2) + b"\x13\x01"  # one cipher suite
    body += b"\x01\x00"                         # compression methods: 1 method (null)
    body += struct.pack("!H", len(exts)) + exts

    handshake = b"\x01" + struct.pack("!I", len(body))[1:] + body  # type + 3-byte len
    record = b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake
    return record


def test_looks_tls_does_not_raise_on_short_buffer():
    # Regression: a 5-byte buffer used to IndexError on buf[5].
    assert looks_tls(b"\x16\x03\x01\x00\x01") is False
    assert looks_tls(b"") is False
    assert looks_tls(b"\x16\x03\x01\x00\x10\x01") is True
    assert looks_tls(b"GET / HTTP/1.1\r\n") is False


def test_parse_full_client_hello():
    raw = build_client_hello(sni="telemetry.example.test", alpn=["h2", "http/1.1"], versions=[0x0304, 0x0303])
    assert looks_tls(raw)
    ch = parse_client_hello(raw)
    assert ch.sni == "telemetry.example.test"
    assert ch.alpn == ["h2", "http/1.1"]
    assert ch.offered_versions == ["TLSv1.3", "TLSv1.2"]
    assert ch.cipher_count == 1


def test_parse_no_sni():
    ch = parse_client_hello(build_client_hello(sni=None, versions=[0x0303]))
    assert ch.sni is None
    assert ch.offered_versions == ["TLSv1.2"]


def test_parse_garbage_is_safe():
    assert parse_client_hello(b"not tls at all").sni is None
    assert parse_client_hello(b"\x16\x03\x01").sni is None
