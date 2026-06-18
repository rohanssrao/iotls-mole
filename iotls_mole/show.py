from __future__ import annotations

import argparse, json, string
from pathlib import Path

PRINTABLE = set(bytes(string.printable, "ascii"))

def is_mostly_text(data: bytes) -> bool:
    if not data: return False
    sample = data[:4096]
    return sum(b in PRINTABLE or b in b"\r\n\t" for b in sample) / max(1, len(sample)) > 0.75

def decode(data: bytes, limit: int | None = None) -> str:
    if limit is not None:
        data = data[:limit]
    return data.decode("utf-8", "replace")

def session_dirs(root: Path):
    payload_root = root / "payloads"
    if payload_root.exists():
        yield from sorted(p for p in payload_root.iterdir() if p.is_dir())
    yield from sorted(p for p in root.iterdir() if p.is_dir() and p.name[:4].isdigit())

def load_meta(d: Path) -> dict:
    p = d / "metadata.json"
    if p.exists():
        try: return json.loads(p.read_text())
        except Exception: return {}
    return {}

def show_session(d: Path, args) -> bool:
    meta = load_meta(d)
    cb = d / "client.bin"; sb = d / "server.bin"
    if not cb.exists() and not sb.exists():
        return False
    cdata = cb.read_bytes() if cb.exists() else b""
    sdata = sb.read_bytes() if sb.exists() else b""
    if args.only_text and not (is_mostly_text(cdata) or is_mostly_text(sdata)):
        return False
    if args.grep is not None:
        needle = args.grep.encode()
        hay_c, hay_s = (cdata.lower(), sdata.lower()) if args.ignore_case else (cdata, sdata)
        if args.ignore_case:
            needle = needle.lower()
        if needle not in hay_c and needle not in hay_s:
            return False
    title = f"Session {d.name}"
    if meta:
        title += f"  {meta.get('proto','?')}  {meta.get('upstream_sni') or meta.get('sni') or meta.get('dest_ip')}:{meta.get('dest_port','?')}"
    print("=" * len(title)); print(title); print("=" * len(title))
    uc = meta.get("upstream_cert")
    if uc:
        flags = ", ".join(f for f, on in (("self-signed", uc.get("self_signed")), ("expired", uc.get("expired"))) if on) or "no obvious defects"
        print(f"upstream cert: subject={uc.get('subject_cn')} issuer={uc.get('issuer_cn')} not_after={uc.get('not_after')} [{flags}]")
    if args.direction in ("both", "client") and cdata:
        print("\n--- client -> server ---")
        print(decode(cdata, args.limit))
    if args.direction in ("both", "server") and sdata:
        print("\n--- server -> client ---")
        print(decode(sdata, args.limit))
    print()
    return True

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="iotls-mole show", description="Show captured plaintext/decrypted payloads from a session directory")
    ap.add_argument("session_dir")
    ap.add_argument("--session", help="show one session id/name")
    ap.add_argument("--all", action="store_true", help="show binary-looking sessions too")
    ap.add_argument("--limit", type=int, default=20000, help="max bytes per direction; 0 means unlimited")
    ap.add_argument("--direction", choices=["both", "client", "server"], default="both")
    ap.add_argument("--grep", help="only show sessions whose payload contains this substring")
    ap.add_argument("-i", "--ignore-case", action="store_true", help="case-insensitive --grep")
    args = ap.parse_args(argv)
    args.only_text = not args.all
    if args.limit == 0: args.limit = None
    root = Path(args.session_dir)
    if not root.exists():
        raise SystemExit(f"session dir not found: {root}")
    dirs = list(session_dirs(root))
    if args.session:
        dirs = [d for d in dirs if d.name == args.session or d.name.startswith(args.session + "_")]
    count = 0
    for d in dirs:
        if show_session(d, args): count += 1
    if count == 0:
        hint = " matching --grep" if args.grep else ""
        print(f"No readable payload sessions found{hint}. Try --all or check events.jsonl/summary.txt.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
