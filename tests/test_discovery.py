from __future__ import annotations

import ipaddress
import time

from trustfall.discovery import Host, HostTracker, ip_in_scope, vendor_for


def test_ip_in_scope_filters_noise():
    import ipaddress
    net = ipaddress.ip_network("10.0.0.224/24", strict=False)
    assert ip_in_scope("10.0.0.54", net) is True
    assert ip_in_scope("0.0.0.0", net) is False           # DHCP/no-address noise
    assert ip_in_scope("192.133.232.134", net) is False   # off-subnet (seen via gateway MAC)
    assert ip_in_scope("10.0.0.0", net) is False          # network address
    assert ip_in_scope("10.0.0.255", net) is False        # broadcast
    assert ip_in_scope("10.0.0.54", None) is True         # no subnet known -> allow


def test_vendor_for_bundled_and_injected():
    assert vendor_for("dc:a6:32:11:22:33") == "Raspberry Pi"
    assert vendor_for("EC:FA:BC:00:00:01") == "Espressif"  # case-insensitive
    assert vendor_for("") == ""
    assert vendor_for("aa:bb:cc:dd:ee:ff", resolver=lambda oui: "TestCorp") == "TestCorp"
    assert vendor_for("aa:bb:cc:dd:ee:ff", resolver=lambda oui: None) == ""


def test_vendor_for_ignores_mac_echoed_by_scapy(monkeypatch):
    # scapy's manuf lookup echoes the input MAC on a miss; that must not become a vendor.
    import trustfall.discovery as d
    monkeypatch.setattr(d, "_scapy_vendor", lambda mac: mac)
    assert d.vendor_for("16:52:1d:3d:17:ef") == ""


def test_tracker_observe_and_snapshot_sorted():
    t = HostTracker()
    t.observe("10.0.0.20", "dc:a6:32:00:00:01")
    t.observe("10.0.0.3", "ec:fa:bc:00:00:02")
    snap = t.snapshot()
    assert [h.ip for h in snap] == ["10.0.0.3", "10.0.0.20"]  # numeric IP order
    assert snap[0].vendor == "Espressif"
    assert snap[1].vendor == "Raspberry Pi"


def test_tracker_updates_last_seen_and_fills_mac():
    t = HostTracker()
    t.observe("10.0.0.5", None)
    first = t.snapshot()[0].last_seen
    time.sleep(0.01)
    t.observe("10.0.0.5", "dc:a6:32:aa:bb:cc")   # mac arrives later
    h = t.snapshot()[0]
    assert h.mac == "dc:a6:32:aa:bb:cc"
    assert h.vendor == "Raspberry Pi"
    assert h.last_seen >= first


def test_tracker_name_resolution_flow():
    t = HostTracker()
    t.observe("10.0.0.7", "aa:bb:cc:00:00:00")
    assert t.needs_name() == ["10.0.0.7"]
    assert t.needs_name() == []          # not retried until cleared
    t.set_name("10.0.0.7", "camera.local")
    assert t.snapshot()[0].name == "camera.local"


def test_snapshot_is_a_copy():
    t = HostTracker()
    t.observe("10.0.0.9", "aa:bb:cc:00:00:00")
    snap = t.snapshot()[0]
    snap.name = "mutated"
    assert t.snapshot()[0].name != "mutated"  # snapshot returns detached copies
