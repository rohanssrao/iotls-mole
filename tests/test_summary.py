from __future__ import annotations

import json

from trustfall.cli import build_inventory, build_summary
from trustfall.proxy import Attempt, State


def _state_with_finding(tmp_dir):
    state = State(["self_signed_match", "private_ca_match"], stop_on_success=True)
    # endpoint A: self-signed rejected, private-ca accepted -> finding
    state.record(("1.1.1.1", 443, "a.test"), Attempt("self_signed_match", "rejected", "unknown ca"))
    state.record(("1.1.1.1", 443, "a.test"), Attempt("private_ca_match", "accepted", session="0001"))
    # endpoint B: everything rejected -> no finding
    state.record(("2.2.2.2", 8883, None), Attempt("self_signed_match", "rejected", "unknown ca"))
    return state


def test_build_summary_structure(tmp_path):
    data = build_summary(_state_with_finding(tmp_path), tmp_path)
    assert data["findings"] == 1
    assert data["tls_endpoints"] == 2
    by_ep = {e["endpoint"]: e for e in data["endpoints"]}

    a = by_ep["1.1.1.1:443"]
    assert a["accepted_strategy"] == "private_ca_match"
    assert a["finding"] == "HIGH accepts unknown/private CA"
    assert [x["result"] for x in a["attempts"]] == ["rejected", "accepted"]
    assert a["attempts"][1]["session"] == "0001"

    b = by_ep["2.2.2.2:8883"]
    assert b["accepted_strategy"] is None
    assert b["finding"] is None

    # round-trips as JSON (what gets written to summary.json)
    assert json.loads(json.dumps(data))["findings"] == 1


def test_likely_pinning_classification(tmp_path):
    state = State(["self_signed_match", "private_ca_match"], stop_on_success=True)
    # Opaque rejections, never a CA-validation alert -> likely pinning.
    pin = ("3.3.3.3", 443, "pinned.test")
    state.record(pin, Attempt("self_signed_match", "rejected", alert="handshake_failure"))
    state.record(pin, Attempt("private_ca_match", "rejected", alert="bad_certificate"))
    # Normal PKI validation -> not pinning.
    val = ("4.4.4.4", 443, "normal.test")
    state.record(val, Attempt("self_signed_match", "rejected", alert="unknown_ca"))

    by_ep = {e["endpoint"]: e for e in build_summary(state, tmp_path)["endpoints"]}
    assert by_ep["3.3.3.3:443"]["likely_pinning"] is True
    assert by_ep["4.4.4.4:443"]["likely_pinning"] is False


def test_build_inventory_from_events(tmp_path):
    events = [
        {"kind": "DNS", "query": "api.vendor.com", "dest": "10.0.0.1"},
        {"kind": "TLS_CLIENTHELLO", "sni": "api.vendor.com", "dest": "1.2.3.4:443", "ja3": "abc123"},
        {"kind": "TLS_CLIENTHELLO", "sni": "none", "dest": "1.2.3.4:443"},
        {"kind": "MDNS", "services": "_googlecast._tcp.local,_hap._tcp.local"},
        {"kind": "PAYLOAD", "proto": "tls", "dest": "1.2.3.4:443"},
        {"kind": "SECRET", "kind2": "x", "value": "abcd…wxyz"},
    ]
    (tmp_path / "events.jsonl").write_text("\n".join(json.dumps(e) for e in events) + "\n")
    inv = build_inventory(tmp_path)
    assert inv["domains"] == ["api.vendor.com"]
    assert "1.2.3.4:443" in inv["endpoints"]
    assert inv["mdns_services"] == ["_googlecast._tcp.local", "_hap._tcp.local"]
    assert inv["ja3"] == ["abc123"]
    assert "tls" in inv["protocols"]


def test_build_inventory_missing_events(tmp_path):
    inv = build_inventory(tmp_path)  # no events.jsonl
    assert inv == {"domains": [], "endpoints": [], "mdns_services": [], "protocols": [], "ja3": [], "secrets_seen": 0}
