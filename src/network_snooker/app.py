# Network Snooker is a live per-host traffic view for Linux routers.
# Copyright © 2026 Adam Waldenberg, Adeptum AB, Org.nr 559494-1824.
#
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along
# with this program. If not, see <https://www.gnu.org/licenses/>.
#
# Website: https://www.adeptum.se
# Contact: info@adeptum.se

import asyncio
import contextlib
import signal
from collections.abc import Callable

from rich.text import Text
from textual import work
from textual.app import App, ComposeResult
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header, Input, Static

from network_snooker.client import DaemonError, RequestRefused
from network_snooker.formatting import format_bytes, format_port, format_rate
from network_snooker.host_pane import HostPane
from network_snooker.policy import HostPolicy, Mode, Rule
from network_snooker.schedule_screen import ScheduleScreen
from network_snooker.tables import build_table as _table, refill as _refill, selected_key as _selected_key
from network_snooker.tracker import ROUTER_ID, FlowView, HostStats
from network_snooker.wire import Snapshot

HOST_COLUMNS = ("Host", "IP", "Rx/s", "Tx/s", "Rx total", "Tx total", "Flows", "Status")
PAUSED = "PAUSED"
SCHEDULE = "SCHEDULE"
EXIT_SIGNALS = (signal.SIGHUP, signal.SIGTERM)
FLOW_COLUMNS = ("Proto", "Remote", "Port", "Local port", "Rx/s", "Tx/s", "Bytes")
HOST_NAME_COLUMN = HOST_COLUMNS.index("Host")
FLOW_NAME_COLUMN = FLOW_COLUMNS.index("Remote")
SORTS = ("rx total", "tx total", "rate", "name")
STATUS_STYLE = {Mode.PAUSED: ("bold red", PAUSED), Mode.SCHEDULE: ("bold yellow", SCHEDULE)}


def _status_text(mode: Mode) -> Text:
    style, label = STATUS_STYLE.get(mode, ("", ""))
    return Text(label, style=style)


class HostScreen(Screen):
    AUTO_FOCUS = "#hosts"
    BINDINGS = [
        ("p", "toggle_pause", "Pause"),
        ("e", "edit_schedule", "Schedule"),
        ("s", "cycle_sort", "Sort"),
        ("slash", "filter", "Filter"),
        ("q", "app.quit", "Quit"),
    ]
    DEFAULT_CSS = """
    #filter { display: none; }
    #filter.visible { display: block; }
    #hosts { height: 1fr; }
    """

    def __init__(self) -> None:
        super().__init__()
        self._sort = SORTS[0]
        self._filter = ""

    def compose(self) -> ComposeResult:
        yield Header()
        yield Input(placeholder="Filter by name or IP", id="filter")
        yield _table("hosts", HOST_COLUMNS)
        yield HostPane()
        yield Footer()

    def on_mount(self) -> None:
        self.refresh_stats()

    # Column widths follow the table's width, which layout settles only
    # after the resize event has been handled.
    def on_resize(self) -> None:
        self.call_after_refresh(self.refresh_stats)

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

    # A refill queues a highlight for row 0 before the one for the restored
    # cursor, so the pane follows the cursor rather than the event's row.
    def on_data_table_row_highlighted(self) -> None:
        self._show_selected()

    def refresh_stats(self) -> None:
        _refill(self.query_one(DataTable), ((host.host_id, self._cells(host)) for host in self._ordered_hosts()), HOST_NAME_COLUMN)
        self._show_selected()

    def _show_selected(self) -> None:
        host_id = _selected_key(self.query_one(DataTable))
        self.query_one(HostPane).show(None if host_id is None else self.app.hosts[host_id])

    def _ordered_hosts(self) -> list[HostStats]:
        hosts = [host for host in self.app.hosts.values() if self._matches(host)]
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
        style = "" if host.active else "dim"
        return [*(Text(value, style=style) for value in values), _status_text(self.app.host_mode(host.host_id))]

    def action_toggle_pause(self) -> None:
        host_id = _selected_key(self.query_one(DataTable))
        if host_id is not None:
            self.app.request_toggle(host_id)

    def action_edit_schedule(self) -> None:
        host_id = _selected_key(self.query_one(DataTable))
        if host_id is not None:
            self.app.open_schedule(host_id)


class DetailScreen(Screen):
    AUTO_FOCUS = "#flows"
    BINDINGS = [
        ("p", "toggle_pause", "Pause"),
        ("e", "edit_schedule", "Schedule"),
        ("escape", "app.pop_screen", "Back"),
        ("q", "app.quit", "Quit"),
    ]

    def __init__(self, host_id: str) -> None:
        super().__init__()
        self._host_id = host_id

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(id="summary", markup=False)
        yield _table("flows", FLOW_COLUMNS)
        yield Footer()

    def on_mount(self) -> None:
        self.refresh_stats()

    def on_resize(self) -> None:
        self.call_after_refresh(self.refresh_stats)

    # A restarted daemon starts with no hosts until traffic shows them again.
    def refresh_stats(self) -> None:
        if (host := self.app.hosts.get(self._host_id)) is None:
            return
        status = _status_text(self.app.host_mode(self._host_id)).plain
        prefix = f"{status}  " if status else ""
        self.query_one("#summary", Static).update(
            f"{prefix}{self.app.display_name(host)}  {', '.join(sorted(host.ips))}  "
            f"rx {format_rate(host.rx_rate)} ({format_bytes(host.rx_total)})  "
            f"tx {format_rate(host.tx_rate)} ({format_bytes(host.tx_total)})"
        )
        flows = sorted(host.flows, key=lambda flow: -(flow.rx_rate + flow.tx_rate))
        _refill(self.query_one(DataTable), ((None, self._cells(flow)) for flow in flows), FLOW_NAME_COLUMN)

    def action_toggle_pause(self) -> None:
        self.app.request_toggle(self._host_id)

    def action_edit_schedule(self) -> None:
        self.app.open_schedule(self._host_id)

    def _cells(self, flow: FlowView) -> list[Text]:
        values = (
            flow.protocol,
            self.app.name_of(flow.remote_ip),
            format_port(flow.remote_port),
            format_port(flow.local_port),
            format_rate(flow.rx_rate),
            format_rate(flow.tx_rate),
            format_bytes(flow.rx_bytes + flow.tx_bytes),
        )
        return [Text(value) for value in values]


class SnookerApp(App):
    TITLE = "network-snooker"
    BINDINGS = [("Q", "quit_and_stop", "Quit + stop")]

    def __init__(self, client, catalog) -> None:
        super().__init__()
        self.client = client
        self.catalog = catalog
        self.snapshot = Snapshot()
        self._last_seq: int | None = None

    def get_default_screen(self) -> Screen:
        return HostScreen()

    @property
    def hosts(self) -> dict[str, HostStats]:
        return self.snapshot.hosts

    @property
    def interval(self) -> float:
        return self.snapshot.interval

    # Closing the SSH session sends SIGHUP; exiting through Textual instead of
    # dying lets the terminal be restored. The daemon keeps running regardless.
    def on_mount(self) -> None:
        loop = asyncio.get_running_loop()
        for signum in EXIT_SIGNALS:
            loop.add_signal_handler(signum, self.exit)
        self.poll()

    def on_unmount(self) -> None:
        loop = asyncio.get_running_loop()
        for signum in EXIT_SIGNALS:
            loop.remove_signal_handler(signum)

    def name_of(self, ip: str) -> str:
        return self.snapshot.names.get(ip, ip)

    def display_name(self, host: HostStats) -> str:
        return ROUTER_ID if host.host_id == ROUTER_ID else self.name_of(host.host_id)

    def mac_for(self, host_id: str) -> str | None:
        return self.snapshot.macs.get(host_id)

    def policy(self, mac: str) -> HostPolicy:
        mac = mac.lower()
        return self.snapshot.policies.get(mac, HostPolicy(mac, Mode.NONE))

    def host_mode(self, host_id: str) -> Mode:
        mac = self.mac_for(host_id)
        return Mode.NONE if mac is None else self.policy(mac).mode

    def blocked_now(self, host_id: str) -> tuple[str, ...]:
        return self.snapshot.blocked.get(host_id, ())

    # Scheduling the next poll only after this one finishes keeps requests
    # from piling up when the daemon is slow to answer.
    @work(thread=True)
    def poll(self) -> None:
        try:
            snapshot = self.client.snapshot(self._last_seq or 0)
        except DaemonError as error:
            self.call_from_thread(self._show_error, str(error))
        else:
            self.call_from_thread(self._apply, snapshot)
        finally:
            self.call_from_thread(self._schedule_poll)

    # A poll that finishes during shutdown would leave a timer pending
    # after the event loop is gone.
    def _schedule_poll(self) -> None:
        if self.is_running:
            self.set_timer(self.interval, self.poll)

    def _show_error(self, message: str) -> None:
        self.sub_title = message

    # Notices raised before this interface connected are old news, so the
    # first snapshot only sets the point from which to show them.
    def _apply(self, snapshot: Snapshot) -> None:
        if self._last_seq is not None:
            for notice in snapshot.notices:
                self.notify(notice.message, severity=notice.severity)
        self._last_seq = snapshot.last_seq
        self.snapshot = snapshot
        self.sub_title = snapshot.error
        self._refresh_screen()

    def _refresh_now(self) -> None:
        try:
            self._apply(self.client.snapshot(self._last_seq or 0))
        except DaemonError as error:
            self._show_error(str(error))

    # A poll can finish while the app shuts down and removes its screens;
    # is_running turns false before the first screen goes.
    def _refresh_screen(self) -> None:
        if self.is_running and isinstance(self.screen, HostScreen | DetailScreen) and self.screen.is_mounted:
            self.screen.refresh_stats()

    def request_toggle(self, host_id: str) -> None:
        self._change(self.client.toggle_pause, host_id)

    def set_mode(self, mac: str, mode: Mode) -> None:
        self._change(self.client.set_mode, mac, mode)

    def replace_rules(self, mac: str, rules: tuple[Rule, ...]) -> None:
        self._change(self.client.replace_rules, mac, rules)

    # The daemon has applied the change by the time the call returns, so the
    # fresh snapshot fetched here already shows it.
    def _change(self, request, *arguments) -> None:
        try:
            request(*arguments)
        except RequestRefused as error:
            self.notify(str(error), severity="warning")
            return
        except DaemonError as error:
            self._show_error(str(error))
            return
        self._refresh_now()

    def action_quit_and_stop(self) -> None:
        with contextlib.suppress(DaemonError):
            self.client.stop()
        self.exit()

    def open_schedule(self, host_id: str) -> None:
        if host_id == ROUTER_ID:
            self.notify("The router has no schedule", severity="warning")
        elif (mac := self.mac_for(host_id)) is None:
            self.notify("Unknown MAC address; host has no schedule", severity="warning")
        else:
            self.push_screen(ScheduleScreen(host_id, mac))
