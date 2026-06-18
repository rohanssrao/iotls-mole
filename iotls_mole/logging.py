from __future__ import annotations

import json, time
from collections import OrderedDict
from pathlib import Path


class _BoundedSet:
    """Membership set with an LRU cap, so long-running sessions don't leak memory."""

    def __init__(self, maxsize: int = 4096):
        self.maxsize = maxsize
        self._items: OrderedDict = OrderedDict()

    def __contains__(self, key) -> bool:
        if key in self._items:
            self._items.move_to_end(key)
            return True
        return False

    def add(self, key):
        self._items[key] = None
        self._items.move_to_end(key)
        while len(self._items) > self.maxsize:
            self._items.popitem(last=False)


class EventLogger:
    QUIET_KINDS = {"TCP_SYN", "TLS_CLIENTHELLO", "UDP"}

    def __init__(self, jsonl: bool = False, session_dir: str | None = None, verbose: bool = False, quiet: bool = False):
        self.jsonl = jsonl
        self.verbose = verbose
        self.quiet = quiet
        self.seen = _BoundedSet()
        self.events_file = None
        if session_dir:
            Path(session_dir).mkdir(parents=True, exist_ok=True)
            self.events_file = open(Path(session_dir) / "events.jsonl", "a", buffering=1)

    def emit(self, kind: str, **fields):
        fields = {k: v for k, v in fields.items() if v is not None}
        record = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "kind": kind, **fields}
        line = json.dumps(record, default=str)
        if self.events_file:
            self.events_file.write(line + "\n")
        if self.jsonl:
            print(line, flush=True); return
        if not self._should_print(kind, fields):
            return
        print(self._format_human(record), flush=True)

    def _should_print(self, kind: str, f: dict) -> bool:
        if self.verbose:
            return True
        if self.quiet:
            return kind in {"INFO", "WARN", "ERROR", "TLS", "UPSTREAM_CERT", "SECRET", "FAIL_OPEN", "STARTTLS_STRIP", "PLAINTEXT", "SUMMARY", "SUMMARY_TLS"} and (
                kind not in {"INFO"} or f.get("msg") in {"stopping", "cleanup_only_done"}
            )
        if kind in self.QUIET_KINDS:
            return False
        if kind == "DNS":
            key = (kind, f.get("query"), f.get("dest"))
            if key in self.seen: return False
            self.seen.add(key); return True
        if kind == "MDNS":
            key = (kind, f.get("services"))
            if key in self.seen: return False
            self.seen.add(key); return True
        if kind == "DNS_SPOOF":
            key = (kind, f.get("query"), f.get("action"))
            if key in self.seen: return False
            self.seen.add(key); return True
        if kind == "COAP":
            key = (kind, f.get("method") or f.get("code"), f.get("uri"))
            if key in self.seen: return False
            self.seen.add(key); return True
        if kind == "DTLS_CLIENTHELLO":
            key = (kind, f.get("dest"), f.get("version"))
            if key in self.seen: return False
            self.seen.add(key); return True
        if kind == "IPV6_ESCAPE":
            key = (kind, f.get("src"))
            if key in self.seen: return False
            self.seen.add(key); return True
        if kind == "PAYLOAD":
            return True
        if kind == "TLS":
            # Print accepted, exhausted, skipped, and completed-looking failures; suppress noisy raw repeats.
            key = (kind, f.get("dest"), f.get("sni"), f.get("strategy"), f.get("result"), f.get("action"))
            if key in self.seen: return False
            self.seen.add(key); return True
        return True

    def _format_human(self, record: dict) -> str:
        ts = record.pop("ts"); kind = record.pop("kind")
        if kind == "PAYLOAD":
            return f"[{ts}] CAPTURE session={record.get('session')} proto={record.get('proto')} dest={record.get('dest')} path={record.get('path')}"
        if kind == "TLS":
            base = f"[{ts}] TLS dest={record.get('dest')} sni={record.get('sni','none')} result={record.get('result')}"
            if record.get("strategy"): base += f" strategy={record.get('strategy')}"
            if record.get("finding"): base += f" finding={record.get('finding')}"
            if record.get("alert"): base += f" alert={record.get('alert')}"
            if record.get("alert_meaning"): base += f" ({record.get('alert_meaning')})"
            if record.get("action"): base += f" action={record.get('action')}"
            remaining = record.get("remaining")
            if record.get("result") == "rejected" and isinstance(remaining, int):
                base += f" | {remaining} strateg{'y' if remaining == 1 else 'ies'} left" + ("; awaiting reconnect" if remaining else "; endpoint exhausted")
            return base
        if kind == "SECRET":
            return f"[{ts}] \U0001f511 SECRET {record.get('secret')} ({record.get('direction')}) dest={record.get('dest')} value={record.get('value')}"
        if kind == "FAIL_OPEN":
            return f"[{ts}] \u26a0\ufe0f  FAIL_OPEN {record.get('dest')} (refused TLS on :{record.get('tls_port')}, retried cleartext) sni={record.get('sni')}"
        if kind == "STARTTLS_STRIP":
            return f"[{ts}] \u26a0\ufe0f  STARTTLS_STRIP {record.get('dest','')} {record.get('msg','')}".rstrip()
        if kind == "DNS":
            return f"[{ts}] DNS {record.get('query')} via {record.get('dest')}"
        if kind == "MDNS":
            return f"[{ts}] MDNS {record.get('services')}"
        if kind == "DNS_SPOOF":
            ans = f" -> {record.get('answer')}" if record.get("answer") else ""
            return f"[{ts}] DNS_SPOOF {record.get('query')} {record.get('action')}{ans}"
        if kind == "COAP":
            p = f" payload={record.get('payload')}" if record.get("payload") else ""
            return f"[{ts}] CoAP {record.get('dest')} {record.get('summary')}{p}"
        if kind == "DTLS_CLIENTHELLO":
            return f"[{ts}] DTLS_CLIENTHELLO {record.get('dest')} {record.get('version')} (encrypted CoAP; not decrypted)"
        if kind == "IPV6_ESCAPE":
            return f"[{ts}] \u26a0\ufe0f  IPV6_ESCAPE src={record.get('src')} dst={record.get('dst')} (outside IPv4 ARP scope)"
        if kind == "UPSTREAM_CERT":
            flags = ",".join(f for f, on in (("self-signed", record.get("self_signed")), ("expired", record.get("expired"))) if on) or "valid-ish"
            return f"[{ts}] UPSTREAM_CERT dest={record.get('dest')} subject={record.get('subject')} issuer={record.get('issuer')} [{flags}]"
        parts = [f"[{ts}]", kind]
        for k, v in record.items(): parts.append(f"{k}={v}")
        return " ".join(parts)

    def close(self):
        if self.events_file:
            self.events_file.close(); self.events_file = None
