from __future__ import annotations

import argparse
import io
from contextlib import redirect_stdout
from pathlib import Path

from iotls_mole.show import show_session


def _make_session(root: Path, name: str, client: bytes, server: bytes):
    d = root / name
    d.mkdir(parents=True)
    (d / "client.bin").write_bytes(client)
    (d / "server.bin").write_bytes(server)
    return d


def _args(**over):
    base = dict(only_text=False, grep=None, ignore_case=False, direction="both", limit=None, session=None, all=True)
    base.update(over)
    return argparse.Namespace(**base)


def _render(d, args) -> tuple[bool, str]:
    buf = io.StringIO()
    with redirect_stdout(buf):
        shown = show_session(d, args)
    return shown, buf.getvalue()


def test_grep_matches_payload(tmp_path):
    d = _make_session(tmp_path, "0001", b"GET /x?token=abc123 HTTP/1.1\r\n", b"HTTP/1.1 200 OK\r\n")
    shown, out = _render(d, _args(grep="abc123"))
    assert shown is True
    assert "token=abc123" in out


def test_grep_filters_out_nonmatching(tmp_path):
    d = _make_session(tmp_path, "0002", b"nothing interesting here", b"plain response")
    shown, _ = _render(d, _args(grep="abc123"))
    assert shown is False


def test_grep_ignore_case(tmp_path):
    d = _make_session(tmp_path, "0003", b"X-IoTLS-Mole-Test: TOKEN-XYZ", b"")
    assert _render(d, _args(grep="token-xyz", ignore_case=True))[0] is True
    assert _render(d, _args(grep="token-xyz", ignore_case=False))[0] is False
