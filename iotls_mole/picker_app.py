from __future__ import annotations

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.widgets import DataTable, Footer, Header

from .discovery import HostTracker
from .picker import _ago

COLUMNS = ("IP", "MAC", "Vendor", "Name", "Seen")


class DevicePicker(App):
    """Live-refreshing device picker. Enter targets the highlighted host."""

    CSS = "DataTable { height: 1fr; }"
    BINDINGS = [
        Binding("r", "rescan", "Rescan"),
        Binding("q,escape", "cancel", "Quit"),
    ]

    def __init__(self, tracker: HostTracker, iface: str = "", refresh_interval: float = 1.0):
        super().__init__()
        self.tracker = tracker
        self.iface = iface
        self.refresh_interval = refresh_interval
        self.selected: str | None = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield DataTable(cursor_type="row", zebra_stripes=True)
        yield Footer()

    def on_mount(self) -> None:
        self.title = "IoTLS-Mole"
        self.sub_title = f"select a target on {self.iface}  (\u2191\u2193 + Enter)"
        table = self.query_one(DataTable)
        for col in COLUMNS:
            table.add_column(col, key=col)
        self._refresh()
        self.set_interval(self.refresh_interval, self._refresh)

    def _refresh(self) -> None:
        table = self.query_one(DataTable)
        hosts = self.tracker.snapshot()
        # Preserve the highlighted IP across the rebuild.
        current = None
        if table.row_count and table.cursor_row is not None:
            try:
                current = table.coordinate_to_cell_key((table.cursor_row, 0)).row_key.value
            except Exception:
                current = None
        table.clear()
        for h in hosts:
            table.add_row(h.ip, h.mac or "?", h.vendor or "?", h.name or "?", _ago(h.last_seen), key=h.ip)
        self.sub_title = f"{len(hosts)} device(s) on {self.iface}  (\u2191\u2193 + Enter, r=rescan, q=quit)"
        if current is not None:
            try:
                table.move_cursor(row=table.get_row_index(current))
            except Exception:
                pass

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        # DataTable emits this on Enter for the highlighted row (cursor_type=row).
        ip = getattr(event.row_key, "value", None)
        if ip:
            self.selected = ip
            self.exit(ip)

    def action_rescan(self) -> None:
        self._refresh()

    def action_cancel(self) -> None:
        self.exit(None)
