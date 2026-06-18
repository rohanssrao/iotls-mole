from __future__ import annotations

import json
import time

from iotls_mole.cli import build_summary
from iotls_mole.proxy import FailOpenTracker, State, strip_starttls_caps


def test_strip_starttls_caps_equal_length():
    smtp = b"250-mail.example.com\r\n250-STARTTLS\r\n250 HELP\r\n"
    out, changed = strip_starttls_caps(smtp)
    assert changed
    assert b"STARTTLS" not in out
    assert len(out) == len(smtp)  # equal-length replacement preserves framing

    pop3 = b"+OK Capability list follows\r\nSTLS\r\nUSER\r\n.\r\n"
    out2, changed2 = strip_starttls_caps(pop3)
    assert changed2 and b"STLS" not in out2 and len(out2) == len(pop3)

    ftp = b"234 AUTH TLS OK"
    out3, changed3 = strip_starttls_caps(ftp)
    assert changed3 and b"AUTH TLS" not in out3


def test_strip_starttls_noop_on_plain_traffic():
    data = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"
    out, changed = strip_starttls_caps(data)
    assert not changed and out == data


def test_fail_open_tracker_flags_cleartext_retry():
    t = FailOpenTracker(window=30)
    assert t.check_plaintext("1.2.3.4", 80) is None          # no prior TLS reject
    t.record_tls_reject("1.2.3.4", 443, "api.vendor.com")
    hit = t.check_plaintext("1.2.3.4", 80)
    assert hit == {"tls_port": 443, "sni": "api.vendor.com", "cleartext_port": 80}
    # only flags once per ip
    assert t.check_plaintext("1.2.3.4", 80) is None


def test_fail_open_tracker_respects_window():
    t = FailOpenTracker(window=0.0)
    t.record_tls_reject("5.6.7.8", 8883, None)
    time.sleep(0.01)
    assert t.check_plaintext("5.6.7.8", 1883) is None        # outside window


def test_behavioral_findings_in_summary(tmp_path):
    events = [
        {"kind": "FAIL_OPEN", "dest": "1.2.3.4:80", "tls_port": 443, "sni": "api.vendor.com"},
        {"kind": "STARTTLS_STRIP", "dest": "1.2.3.4:25"},
    ]
    (tmp_path / "events.jsonl").write_text("\n".join(json.dumps(e) for e in events) + "\n")
    data = build_summary(State([], stop_on_success=True), tmp_path)
    bf = data["behavioral_findings"]
    assert bf["fail_open"] == [{"dest": "1.2.3.4:80", "tls_port": 443, "sni": "api.vendor.com"}]
    assert bf["starttls_stripped"] == [{"dest": "1.2.3.4:25"}]
