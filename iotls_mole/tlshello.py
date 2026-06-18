from __future__ import annotations

import hashlib
from dataclasses import dataclass, field


@dataclass
class ClientHello:
    sni: str | None = None
    alpn: list[str] = field(default_factory=list)
    offered_versions: list[str] = field(default_factory=list)
    cipher_count: int = 0
    legacy_version: int = 0
    ciphers: list[int] = field(default_factory=list)
    extensions: list[int] = field(default_factory=list)
    groups: list[int] = field(default_factory=list)
    point_formats: list[int] = field(default_factory=list)
    ja3: str | None = None
    ja3_hash: str | None = None


TLS_VERSION_MAP = {
    0x0300: "SSLv3", 0x0301: "TLSv1.0", 0x0302: "TLSv1.1", 0x0303: "TLSv1.2", 0x0304: "TLSv1.3",
}

# DTLS uses inverted version numbers (1's-complement-ish) and a different record layout.
DTLS_VERSION_MAP = {0xFEFF: "DTLSv1.0", 0xFEFD: "DTLSv1.2"}


def looks_dtls_client_hello(buf: bytes) -> bool:
    # DTLS record: type 22 (handshake), version 0xFE.., then epoch/seq/length,
    # then handshake type 1 (ClientHello) at offset 13.
    return len(buf) >= 14 and buf[0] == 0x16 and buf[1] == 0xFE and buf[13] == 0x01


def dtls_version(buf: bytes) -> str | None:
    if len(buf) < 3:
        return None
    return DTLS_VERSION_MAP.get(int.from_bytes(buf[1:3], "big"), hex(int.from_bytes(buf[1:3], "big")))


def is_grease(value: int) -> bool:
    # RFC 8701 GREASE values follow the pattern 0x?a?a with matching nibbles.
    return (value & 0x0F0F) == 0x0A0A and (value >> 8) == (value & 0xFF)


def looks_tls(buf: bytes) -> bool:
    # byte 0: handshake record (0x16), byte 1: major version 0x03,
    # byte 5: handshake type ClientHello (0x01). Need >= 6 bytes to read byte 5.
    return len(buf) >= 6 and buf[0] == 0x16 and buf[1] == 0x03 and buf[5] == 0x01


def parse_client_hello(data: bytes) -> ClientHello:
    ch = ClientHello()
    try:
        if not looks_tls(data):
            return ch
        rec_len = int.from_bytes(data[3:5], "big")
        body = data[5:5+rec_len]
        if len(body) < 42 or body[0] != 1:
            return ch
        p = 4
        legacy_ver = int.from_bytes(body[p:p+2], "big"); p += 2
        ch.legacy_version = legacy_ver
        ch.offered_versions.append(TLS_VERSION_MAP.get(legacy_ver, hex(legacy_ver)))
        p += 32
        sid_len = body[p]; p += 1 + sid_len
        cs_len = int.from_bytes(body[p:p+2], "big"); p += 2
        ch.ciphers = [int.from_bytes(body[p+i:p+i+2], "big") for i in range(0, cs_len, 2)]
        ch.cipher_count = len(ch.ciphers)
        p += cs_len
        comp_len = body[p]; p += 1 + comp_len
        if p + 2 > len(body):
            return _finalize_ja3(ch)
        ext_total = int.from_bytes(body[p:p+2], "big"); p += 2
        end = min(len(body), p + ext_total)
        while p + 4 <= end:
            et = int.from_bytes(body[p:p+2], "big")
            el = int.from_bytes(body[p+2:p+4], "big")
            ev = body[p+4:p+4+el]
            p += 4 + el
            ch.extensions.append(et)
            if et == 0:  # server_name
                q = 2
                while q + 3 <= len(ev):
                    nt = ev[q]; nl = int.from_bytes(ev[q+1:q+3], "big"); q += 3
                    name = ev[q:q+nl]; q += nl
                    if nt == 0:
                        # SNI host_name is ASCII on the wire (RFC 6066; IDNs are
                        # sent as A-labels). Keep the exact bytes so the forged
                        # cert SAN mirrors what the client asked for.
                        ch.sni = name.decode("ascii", "ignore")
                        break
            elif et == 16:  # ALPN
                q = 2
                while q < len(ev):
                    l = ev[q]; q += 1
                    ch.alpn.append(ev[q:q+l].decode("ascii", "ignore")); q += l
            elif et == 10:  # supported_groups
                glen = int.from_bytes(ev[0:2], "big") if len(ev) >= 2 else 0
                ch.groups = [int.from_bytes(ev[2+i:2+i+2], "big") for i in range(0, glen, 2)]
            elif et == 11:  # ec_point_formats
                plen = ev[0] if ev else 0
                ch.point_formats = list(ev[1:1+plen])
            elif et == 43:  # supported_versions
                q = 1
                versions = []
                while q + 2 <= len(ev):
                    v = int.from_bytes(ev[q:q+2], "big"); q += 2
                    versions.append(TLS_VERSION_MAP.get(v, hex(v)))
                if versions:
                    ch.offered_versions = versions
    except Exception:
        pass
    return _finalize_ja3(ch)


def _finalize_ja3(ch: ClientHello) -> ClientHello:
    """Compute the classic JA3 fingerprint (RFC-agnostic, de-facto standard)."""
    try:
        if not ch.ciphers and not ch.extensions:
            return ch
        ciphers = "-".join(str(c) for c in ch.ciphers if not is_grease(c))
        exts = "-".join(str(e) for e in ch.extensions if not is_grease(e))
        groups = "-".join(str(g) for g in ch.groups if not is_grease(g))
        points = "-".join(str(p) for p in ch.point_formats)
        ja3 = f"{ch.legacy_version},{ciphers},{exts},{groups},{points}"
        ch.ja3 = ja3
        ch.ja3_hash = hashlib.md5(ja3.encode()).hexdigest()
    except Exception:
        pass
    return ch
