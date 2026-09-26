import time
from collections.abc import Callable

from rich.text import Text
from textual import work
from textual.app import App, ComposeResult
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header

from network_snooker.conntrack_source import ConntrackError, Flow
from network_snooker.formatting import format_bytes, format_rate
from network_snooker.tracker import ROUTER_ID, HostStats, Tracker

HOST_COLUMNS = ("Host", "IP", "Rx/s", "Tx/s", "Rx total", "Tx total", "Flows")


def _selected_key(table: DataTable) -> str | None:
    if table.row_count == 0:
        return None
    return table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value


def _restore_cursor(table: DataTable, key: str | None) -> None:
    if key is not None and key in table.rows:
        table.move_cursor(row=table.get_row_index(key))


class HostScreen(Screen):
    AUTO_FOCUS = "#hosts"
    BINDINGS = [("q", "app.quit", "Quit")]

    def compose(self) -> ComposeResult:
        table = DataTable(id="hosts", cursor_type="row")
        table.add_columns(*HOST_COLUMNS)
        yield Header()
        yield table
        yield Footer()

    def on_mount(self) -> None:
        self.refresh_stats()

    def on_screen_resume(self) -> None:
        self.refresh_stats()

    def refresh_stats(self) -> None:
        table = self.query_one(DataTable)
        selected = _selected_key(table)
        table.clear()
        for host in self._ordered_hosts():
            table.add_row(*self._cells(host), key=host.host_id)
        _restore_cursor(table, selected)

    def _ordered_hosts(self) -> list[HostStats]:
        hosts = self.app.tracker.hosts
        others = sorted((host for host in hosts.values() if host.host_id != ROUTER_ID), key=lambda host: -(host.rx_rate + host.tx_rate))
        return ([hosts[ROUTER_ID]] if ROUTER_ID in hosts else []) + others

    def _cells(self, host: HostStats) -> list[Text]:
        values = (
            self.app.display_name(host),
            ", ".join(sorted(host.ips)),
            format_rate(host.rx_rate),
            format_rate(host.tx_rate),
            format_bytes(host.rx_total),
            format_bytes(host.tx_total),
            str(len(host.flows)),
        )
        return [Text(value, style="" if host.active else "dim") for value in values]


class SnookerApp(App):
    TITLE = "network-snooker"

    def __init__(self, tracker: Tracker, read_flows: Callable[[], list[Flow]], resolver, interval: float = 1.0) -> None:
        super().__init__()
        self.tracker = tracker
        self.resolver = resolver
        self._read_flows = read_flows
        self._interval = interval

    def get_default_screen(self) -> Screen:
        return HostScreen()

    def on_mount(self) -> None:
        self.poll()
        self.set_interval(self._interval, self.poll)

    def display_name(self, host: HostStats) -> str:
        return ROUTER_ID if host.host_id == ROUTER_ID else self.resolver.name(host.host_id)

    @work(thread=True, exclusive=True)
    def poll(self) -> None:
        try:
            flows = self._read_flows()
        except ConntrackError as error:
            self.call_from_thread(self._show_error, str(error))
            return
        self.call_from_thread(self._apply, flows, time.monotonic())

    def _show_error(self, message: str) -> None:
        self.sub_title = message

    def _apply(self, flows: list[Flow], now: float) -> None:
        self.tracker.update(flows, now)
        self.sub_title = ""
        self.screen.refresh_stats()
