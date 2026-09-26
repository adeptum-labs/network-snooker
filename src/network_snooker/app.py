import time
from collections.abc import Callable

from rich.text import Text
from textual import work
from textual.app import App, ComposeResult
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header, Input, Static

from network_snooker.conntrack_source import ConntrackError, Flow
from network_snooker.formatting import format_bytes, format_port, format_rate
from network_snooker.tracker import ROUTER_ID, HostStats, Tracker

HOST_COLUMNS = ("Host", "IP", "Rx/s", "Tx/s", "Rx total", "Tx total", "Flows")
FLOW_COLUMNS = ("Proto", "Remote", "Port", "Local port", "Rx/s", "Tx/s", "Bytes")
SORTS = ("rate", "name", "rx total", "tx total")


def _table(table_id: str, columns: tuple[str, ...]) -> DataTable:
    table = DataTable(id=table_id, cursor_type="row")
    table.add_columns(*columns)
    return table


def _selected_key(table: DataTable) -> str | None:
    if table.row_count == 0:
        return None
    return table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value


def _restore_cursor(table: DataTable, key: str | None) -> None:
    if key is not None and key in table.rows:
        table.move_cursor(row=table.get_row_index(key))


class HostScreen(Screen):
    AUTO_FOCUS = "#hosts"
    BINDINGS = [("s", "cycle_sort", "Sort"), ("slash", "filter", "Filter"), ("q", "app.quit", "Quit")]
    DEFAULT_CSS = """
    #filter { display: none; }
    #filter.visible { display: block; }
    """

    def __init__(self) -> None:
        super().__init__()
        self._sort = SORTS[0]
        self._filter = ""

    def compose(self) -> ComposeResult:
        yield Header()
        yield Input(placeholder="Filter by name or IP", id="filter")
        yield _table("hosts", HOST_COLUMNS)
        yield Footer()

    def on_mount(self) -> None:
        self.refresh_stats()

    def on_screen_resume(self) -> None:
        self.refresh_stats()

    def action_cycle_sort(self) -> None:
        self._sort = SORTS[(SORTS.index(self._sort) + 1) % len(SORTS)]
        self.notify(f"Sorted by {self._sort}")
        self.refresh_stats()

    def action_filter(self) -> None:
        field = self.query_one(Input)
        field.add_class("visible")
        field.focus()

    def on_input_changed(self, event: Input.Changed) -> None:
        self._filter = event.value.strip().lower()
        self.refresh_stats()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if not event.value:
            event.input.remove_class("visible")
        self.query_one(DataTable).focus()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        self.app.push_screen(DetailScreen(event.row_key.value))

    def refresh_stats(self) -> None:
        table = self.query_one(DataTable)
        selected = _selected_key(table)
        table.clear()
        for host in self._ordered_hosts():
            table.add_row(*self._cells(host), key=host.host_id)
        _restore_cursor(table, selected)

    def _ordered_hosts(self) -> list[HostStats]:
        hosts = [host for host in self.app.tracker.hosts.values() if self._matches(host)]
        router = [host for host in hosts if host.host_id == ROUTER_ID]
        others = [host for host in hosts if host.host_id != ROUTER_ID]
        return router + sorted(others, key=self._sort_key(), reverse=self._sort != "name")

    def _sort_key(self) -> Callable[[HostStats], object]:
        return {
            "rate": lambda host: host.rx_rate + host.tx_rate,
            "name": lambda host: self.app.display_name(host).lower(),
            "rx total": lambda host: host.rx_total,
            "tx total": lambda host: host.tx_total,
        }[self._sort]

    def _matches(self, host: HostStats) -> bool:
        haystack = " ".join([self.app.display_name(host), *host.ips]).lower()
        return self._filter in haystack

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


class DetailScreen(Screen):
    AUTO_FOCUS = "#flows"
    BINDINGS = [("escape", "app.pop_screen", "Back"), ("q", "app.quit", "Quit")]

    def __init__(self, host_id: str) -> None:
        super().__init__()
        self._host_id = host_id

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(id="summary")
        yield _table("flows", FLOW_COLUMNS)
        yield Footer()

    def on_mount(self) -> None:
        self.refresh_stats()

    def refresh_stats(self) -> None:
        host = self.app.tracker.hosts[self._host_id]
        self.query_one("#summary", Static).update(
            f"{self.app.display_name(host)}  {', '.join(sorted(host.ips))}  "
            f"rx {format_rate(host.rx_rate)} ({format_bytes(host.rx_total)})  "
            f"tx {format_rate(host.tx_rate)} ({format_bytes(host.tx_total)})"
        )
        table = self.query_one(DataTable)
        table.clear()
        for flow in sorted(host.flows, key=lambda flow: -(flow.rx_rate + flow.tx_rate)):
            table.add_row(
                flow.protocol,
                self.app.resolver.name(flow.remote_ip),
                format_port(flow.remote_port),
                format_port(flow.local_port),
                format_rate(flow.rx_rate),
                format_rate(flow.tx_rate),
                format_bytes(flow.rx_bytes + flow.tx_bytes),
            )


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
        if isinstance(self.screen, HostScreen | DetailScreen) and self.screen.is_mounted:
            self.screen.refresh_stats()
