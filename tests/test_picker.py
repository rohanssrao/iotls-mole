from __future__ import annotations

import asyncio

from trustfall.discovery import HostTracker
from trustfall.picker import _ago, _build_app


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def test_ago_formatting():
    import time
    now = time.time()
    assert _ago(now) in ("now", "0s")
    assert _ago(now - 5).endswith("s")
    assert "m" in _ago(now - 125)


def test_picker_enter_targets_highlighted_host():
    tracker = HostTracker()
    tracker.observe("10.0.0.3", "ec:fa:bc:00:00:01")
    tracker.observe("10.0.0.20", "dc:a6:32:00:00:02")
    app = _build_app(tracker, iface="eth0")

    async def drive():
        async with app.run_test() as pilot:
            await pilot.pause()             # mount + first refresh
            await pilot.press("down")       # move to second row (10.0.0.20)
            await pilot.press("enter")
        return app.return_value

    assert _run(drive()) == "10.0.0.20"


def test_picker_first_row_default_selection():
    tracker = HostTracker()
    tracker.observe("10.0.0.3", "ec:fa:bc:00:00:01")
    tracker.observe("10.0.0.20", "dc:a6:32:00:00:02")
    app = _build_app(tracker, iface="eth0")

    async def drive():
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("enter")      # take the highlighted (first) row
        return app.return_value

    assert _run(drive()) == "10.0.0.3"


def test_picker_quit_returns_none():
    tracker = HostTracker()
    tracker.observe("10.0.0.3", "ec:fa:bc:00:00:01")
    app = _build_app(tracker, iface="eth0")

    async def drive():
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("q")
        return app.return_value

    assert _run(drive()) is None


def test_picker_reflects_live_updates():
    tracker = HostTracker()
    tracker.observe("10.0.0.3", "ec:fa:bc:00:00:01")
    app = _build_app(tracker, iface="eth0")

    async def drive():
        async with app.run_test() as pilot:
            await pilot.pause()
            tracker.observe("10.0.0.50", "dc:a6:32:00:00:09")  # appears after launch
            app._refresh()
            from textual.widgets import DataTable
            return app.query_one(DataTable).row_count

    assert _run(drive()) == 2


if __name__ == "__main__":
    import pytest, sys
    sys.exit(pytest.main([__file__, "-q"]))
