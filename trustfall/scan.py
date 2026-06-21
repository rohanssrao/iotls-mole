from __future__ import annotations

import re
from dataclasses import dataclass

# Each pattern flags one class of sensitive material that should never traverse a
# link an operator can passively decrypt. Kept deliberately high-signal to avoid
# drowning real findings; tune in one place.
_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("jwt", re.compile(rb"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("authorization_basic", re.compile(rb"(?i)authorization:\s*basic\s+([A-Za-z0-9+/=]{8,})")),
    ("authorization_bearer", re.compile(rb"(?i)authorization:\s*bearer\s+([A-Za-z0-9._~+/=-]{10,})")),
    ("aws_access_key", re.compile(rb"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("google_api_key", re.compile(rb"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("slack_token", re.compile(rb"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("private_key_block", re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("set_cookie", re.compile(rb"(?i)set-cookie:\s*([^\r\n;]{1,120})")),
    ("api_key_kv", re.compile(rb"(?i)(?:api[_-]?key|x-api-key|access[_-]?token|client[_-]?secret)[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9._\-]{8,})")),
    ("password_kv", re.compile(rb"(?i)(?:password|passwd|pwd)[\"']?\s*[:=]\s*[\"']?([^&\"'\s]{3,64})")),
]

_MASK_KEEP = 4  # leading/trailing chars kept when masking a secret


@dataclass(frozen=True)
class Secret:
    kind: str
    direction: str          # "client" or "server"
    masked: str
    offset: int

    def as_dict(self) -> dict:
        return {"kind": self.kind, "direction": self.direction, "masked": self.masked, "offset": self.offset}


def _mask(raw: bytes) -> str:
    text = raw.decode("utf-8", "replace")
    if len(text) <= _MASK_KEEP * 2:
        return text[0] + "…" if text else "…"
    return f"{text[:_MASK_KEEP]}…{text[-_MASK_KEEP:]} ({len(text)} chars)"


def scan(data: bytes, direction: str) -> list[Secret]:
    """Find sensitive material in a (decrypted) payload buffer. De-duplicated by (kind, masked)."""
    if not data:
        return []
    found: dict[tuple[str, str], Secret] = {}
    for kind, pat in _PATTERNS:
        for m in pat.finditer(data):
            captured = m.group(m.lastindex) if m.lastindex else m.group(0)
            secret = Secret(kind=kind, direction=direction, masked=_mask(captured), offset=m.start())
            found.setdefault((kind, secret.masked), secret)
    return list(found.values())
