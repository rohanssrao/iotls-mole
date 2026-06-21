from __future__ import annotations

from trustfall.scan import scan


def test_scan_finds_common_secrets():
    payload = (
        b"POST /login HTTP/1.1\r\nHost: api.vendor.com\r\n"
        b"Authorization: Bearer eyJabc.def123456.ghi789xyz\r\n"
        b"Authorization: Basic dXNlcjpwYXNzd29yZA==\r\n"
        b"X-API-Key: sk_live_abcdef1234567890\r\n\r\n"
        b'{"password":"hunter2supersecret","aws":"AKIAIOSFODNN7EXAMPLE"}'
    )
    kinds = {s.kind for s in scan(payload, "client")}
    assert {"authorization_bearer", "authorization_basic", "api_key_kv", "password_kv", "aws_access_key"} <= kinds


def test_scan_jwt_and_private_key():
    jwt = b"token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NSJ9.abcDEF_hash-123"
    assert any(s.kind == "jwt" for s in scan(jwt, "server"))
    pem = b"-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----"
    assert any(s.kind == "private_key_block" for s in scan(pem, "server"))


def test_scan_empty_and_clean():
    assert scan(b"", "client") == []
    assert scan(b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\nOK", "server") == []


def test_scan_masks_value_and_records_direction():
    hits = scan(b"X-API-Key: supersecretvalue123456", "client")
    s = next(h for h in hits if h.kind == "api_key_kv")
    assert s.direction == "client"
    assert "supersecretvalue123456" not in s.masked  # masked, not raw
    assert s.masked.startswith("supe") and s.masked.endswith(("…", ")"))


def test_scan_dedupes_repeats():
    payload = b"X-API-Key: tokentokentoken\n" * 5
    api = [s for s in scan(payload, "client") if s.kind == "api_key_kv"]
    assert len(api) == 1
