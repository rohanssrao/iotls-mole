from __future__ import annotations

from dataclasses import dataclass, field

# RFC 7252 CoAP over UDP (plaintext, :5683). We observe these passively from our
# on-path position; no relay needed since we already forward the target's traffic.

TYPES = {0: "CON", 1: "NON", 2: "ACK", 3: "RST"}
METHODS = {1: "GET", 2: "POST", 3: "PUT", 4: "DELETE", 5: "FETCH", 6: "PATCH", 7: "iPATCH"}

OPT_URI_HOST = 3
OPT_URI_PATH = 11
OPT_CONTENT_FORMAT = 12
OPT_URI_QUERY = 15


@dataclass
class CoapMessage:
    type: str
    code: str                     # e.g. "0.01" (GET) or "2.05" (Content)
    method: str | None            # GET/POST/... for requests, else None
    mid: int
    token: str
    uri_host: str | None = None
    uri_path: str = ""
    uri_query: str = ""
    content_format: int | None = None
    payload: bytes = b""
    options: list[int] = field(default_factory=list)

    def summary(self) -> str:
        verb = self.method or self.code
        path = "/" + self.uri_path if self.uri_path else ""
        q = "?" + self.uri_query if self.uri_query else ""
        return f"{self.type} {verb} {path}{q}".strip()


def is_coap(data: bytes) -> bool:
    if len(data) < 4:
        return False
    return (data[0] >> 6) == 1 and (data[0] & 0x0F) <= 8


def _ext(base: int, data: bytes, p: int) -> tuple[int, int]:
    """Resolve a CoAP 4-bit option delta/length nibble, consuming extended bytes."""
    if base == 13:
        return (data[p] + 13, p + 1) if p < len(data) else (base, p)
    if base == 14:
        return (int.from_bytes(data[p:p + 2], "big") + 269, p + 2) if p + 2 <= len(data) else (base, p)
    return base, p  # 15 is reserved/payload-marker; caller guards 0xFF first


def parse_coap(data: bytes) -> CoapMessage | None:
    if not is_coap(data):
        return None
    b0 = data[0]
    typ = TYPES.get((b0 >> 4) & 0x3, "?")
    tkl = b0 & 0x0F
    code = data[1]
    mid = int.from_bytes(data[2:4], "big")
    p = 4
    token = data[p:p + tkl]
    p += tkl

    uri_path: list[str] = []
    uri_query: list[str] = []
    uri_host = None
    content_format = None
    options: list[int] = []
    payload = b""
    opt_num = 0
    try:
        while p < len(data):
            if data[p] == 0xFF:
                payload = data[p + 1:]
                break
            delta, length = data[p] >> 4, data[p] & 0x0F
            p += 1
            delta, p = _ext(delta, data, p)
            length, p = _ext(length, data, p)
            val = data[p:p + length]
            p += length
            opt_num += delta
            options.append(opt_num)
            if opt_num == OPT_URI_PATH:
                uri_path.append(val.decode("utf-8", "replace"))
            elif opt_num == OPT_URI_QUERY:
                uri_query.append(val.decode("utf-8", "replace"))
            elif opt_num == OPT_URI_HOST:
                uri_host = val.decode("utf-8", "replace")
            elif opt_num == OPT_CONTENT_FORMAT:
                content_format = int.from_bytes(val, "big") if val else 0
    except Exception:
        pass

    cls, detail = code >> 5, code & 0x1F
    return CoapMessage(
        type=typ,
        code=f"{cls}.{detail:02d}",
        method=METHODS.get(code) if cls == 0 else None,
        mid=mid,
        token=token.hex(),
        uri_host=uri_host,
        uri_path="/".join(uri_path),
        uri_query="&".join(uri_query),
        content_format=content_format,
        payload=payload,
        options=options,
    )
