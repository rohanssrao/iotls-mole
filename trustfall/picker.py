from __future__ import annotations

import time

from .discovery import HostTracker, Probe
from .system import default_route, require_root


def _ago(ts: float) -> str:
    d = max(0, int(time.time() - ts))
    if d < 1:
        return "now"
    if d < 60:
        return f"{d}s"
    return f"{d // 60}m{d % 60}s"


def pick_target(log=None) -> str | None:
    """Launch the interactive device picker; return the chosen target IP or None.

    Discovers the local interface, runs net.probe-style discovery, and shows a
    live-refreshing Textual table. Enter targets the highlighted host.
    """
    require_root()
    _, iface = default_route()
    tracker = HostTracker()
    probe = Probe(iface, tracker, log=log)
    probe.start()
    try:
        from .picker_app import DevicePicker
        return DevicePicker(tracker, iface).run()
    finally:
        probe.restore()


def _build_app(tracker: HostTracker, iface: str = "eth0"):
    """Factory kept import-light so tests can construct the app without side effects."""
    from .picker_app import DevicePicker
    return DevicePicker(tracker, iface)
