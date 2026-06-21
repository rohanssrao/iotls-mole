#!/usr/bin/env python3
"""
Dependency-less Trustfall client test script for Termux/Android.

Run from Termux while Trustfall targets the phone's IPv4 address:

    python3 termux_client_tests.py

It uses raw IPv4 sockets rather than urllib/requests so Android proxy/VPN settings
are less likely to interfere. Disable VPN/Private DNS for the cleanest test.
"""
from __future__ import annotations

import argparse
import socket
import ssl
import sys
import time
import uuid


def resolve4(host: str) -> str:
    infos = socket.getaddrinfo(host, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
    if not infos:
        raise RuntimeError(f"no IPv4 address for {host}")
    return infos[0][4][0]


def http_get(host: str, port: int, path: str, token: str, timeout: float = 10) -> bytes:
    ip = resolve4(host)
    print(f"    resolving {host} -> {ip}:{port} HTTP", flush=True)
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: trustfall-termux-test/1.0\r\n"
        f"X-Trustfall-Test: {token}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((ip, port))
    s.sendall(req)
    data = recv_some(s)
    s.close()
    return data


def https_get(host: str, path: str, token: str, verify: bool, sni: bool = True, timeout: float = 10) -> bytes:
    ip = resolve4(host)
    print(f"    resolving {host} -> {ip}:443 HTTPS verify={verify} sni={sni}", flush=True)
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: trustfall-termux-test/1.0\r\n"
        f"X-Trustfall-Test: {token}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.settimeout(timeout)
    raw.connect((ip, 443))
    if verify:
        ctx = ssl.create_default_context()
        server_hostname = host if sni else None
    else:
        ctx = ssl._create_unverified_context()
        server_hostname = host if sni else None
    tls = ctx.wrap_socket(raw, server_hostname=server_hostname)
    tls.sendall(req)
    data = recv_some(tls)
    tls.close()
    return data


def recv_some(sock, max_bytes: int = 65536) -> bytes:
    chunks = []
    total = 0
    while total < max_bytes:
        try:
            b = sock.recv(min(8192, max_bytes - total))
        except socket.timeout:
            break
        if not b:
            break
        chunks.append(b)
        total += len(b)
        if b"\r\n\r\n" in b"".join(chunks) and total > 512:
            # enough to prove payload capture; avoid huge bodies
            break
    return b"".join(chunks)


def show_result(name: str, ok: bool, detail: str = ""):
    status = "PASS" if ok else "FAIL"
    print(f"[{status}] {name}: {detail}")


def first_line(data: bytes) -> str:
    if not data:
        return "<no data>"
    return data.splitlines()[0].decode("utf-8", "replace") if data.splitlines() else repr(data[:40])


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Trustfall Termux client tests")
    ap.add_argument("--http-host", default="example.com")
    ap.add_argument("--https-strict-host", default="example.com")
    ap.add_argument("--https-insecure-host", default="www.example.com")
    ap.add_argument("--rotation-host", default="example.org")
    ap.add_argument("--strict-attempts", type=int, default=4, help="strict HTTPS attempts to exercise strategy rotation")
    ap.add_argument("--timeout", type=float, default=10)
    args = ap.parse_args(argv)

    token = "trustfall-" + uuid.uuid4().hex[:12]
    path = f"/trustfall-test/{token}"
    print(f"Trustfall client test token: {token}")
    print("Search captured payloads with:")
    print(f"  grep -RIna {token!r} <session-dir>")
    print()

    # 1. Plaintext HTTP capture.
    try:
        data = http_get(args.http_host, 80, path + "/plaintext", token + "-plaintext", args.timeout)
        show_result("plaintext HTTP", bool(data), first_line(data))
    except Exception as e:
        show_result("plaintext HTTP", False, repr(e))

    time.sleep(0.5)

    # 2. Strict HTTPS should fail under Trustfall active MITM.
    try:
        data = https_get(args.https_strict_host, path + "/strict", token + "-strict", verify=True, sni=True, timeout=args.timeout)
        show_result("strict HTTPS rejection", False, "connection succeeded; MITM may not be active for this endpoint: " + first_line(data))
    except ssl.SSLError as e:
        show_result("strict HTTPS rejection", True, f"TLS failed as expected: {e.__class__.__name__}: {e}")
    except Exception as e:
        show_result("strict HTTPS rejection", True, f"failed as expected-ish: {e.__class__.__name__}: {e}")

    time.sleep(0.5)

    # 3. Insecure HTTPS should accept forged cert and produce decrypted payload.
    try:
        data = https_get(args.https_insecure_host, path + "/insecure", token + "-insecure", verify=False, sni=True, timeout=args.timeout)
        show_result("insecure HTTPS MITM", bool(data), first_line(data))
    except Exception as e:
        show_result("insecure HTTPS MITM", False, repr(e))

    time.sleep(0.5)

    # 4. No-SNI insecure TLS, useful for IoT-ish clients that connect by IP/no SNI.
    try:
        data = https_get(args.https_insecure_host, path + "/nosni", token + "-nosni", verify=False, sni=False, timeout=args.timeout)
        show_result("insecure HTTPS without SNI", bool(data), first_line(data))
    except Exception as e:
        show_result("insecure HTTPS without SNI", False, repr(e))

    time.sleep(0.5)

    # 5. Strategy rotation: repeated validating connects to a distinct endpoint.
    print()
    print(f"Rotation test against {args.rotation_host}: expected failures under MITM")
    for i in range(args.strict_attempts):
        try:
            data = https_get(args.rotation_host, path + f"/rotate-{i}", f"{token}-rotate-{i}", verify=True, sni=True, timeout=args.timeout)
            show_result(f"rotation strict attempt {i+1}", False, "unexpected success: " + first_line(data))
        except ssl.SSLError as e:
            show_result(f"rotation strict attempt {i+1}", True, e.__class__.__name__)
        except Exception as e:
            show_result(f"rotation strict attempt {i+1}", True, f"{e.__class__.__name__}: {e}")
        time.sleep(0.3)

    print()
    print("Done. On the Trustfall host, look for:")
    print(f"  grep -RIna {token!r} <session-dir>")
    print("Expected tokens in decrypted/plaintext captures:")
    print(f"  {token}-plaintext")
    print(f"  {token}-insecure")
    print(f"  {token}-nosni")
    print("Strict/rotation attempts should usually appear only as TLS rejection log events, not payloads.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
