import os
import signal
import tempfile
import time
from dataclasses import replace
from datetime import datetime
from pathlib import Path

from textual.geometry import Region
from textual.widgets import DataTable, Input, Sparkline, Static

from network_snooker.app import DetailScreen, HostScreen, SnookerApp
from network_snooker.catalog import Catalog, PortRange, Service
from network_snooker.conntrack_source import ConntrackError, Endpoints, Flow
from network_snooker.firewall import FirewallError, Ruleset
from network_snooker.host_pane import HostPane
from network_snooker.neighbors import Neighbors
from network_snooker.policy import PolicyStore, Rule
from network_snooker.tracker import Tracker

WEB = Flow(
    "tcp",
    Endpoints("192.168.1.10", "93.184.216.34", 51234, 443),
    Endpoints("93.184.216.34", "203.0.113.5", 443, 51234),
    1200,
    10,
    9000,
    8,
)
PING = Flow("icmp", Endpoints("203.0.113.5", "8.8.8.8"), Endpoints("8.8.8.8", "203.0.113.5"), 84, 1, 84, 1, 7)
HOST_MAC = "aa:bb:cc:dd:ee:01"
OTHER_MAC = "aa:bb:cc:dd:ee:02"
NEIGHBOR_MAP = {"192.168.1.10": HOST_MAC, "192.168.1.20": OTHER_MAC}
MONDAY_NOON = datetime(2026, 9, 28, 12, 0)
TEST_CATALOG = Catalog({"minecraft": Service("minecraft", "Minecraft", "game", ports=(PortRange("tcp", 25565, 25565),))})


class FakeResolver:
    def __init__(self, names=None):
        self.names = names or {"192.168.1.10": "laptop"}

    def name(self, ip):
        return self.names.get(ip, ip)


class FakeFirewall:
    def __init__(self, available=True, failing=False):
        self.available = available
        self.unavailable_reason = "nft not found; pausing unavailable"
        self.failing = failing
        self.ruleset = Ruleset()
        self.restore_pending = False

    def ensure(self):
        restored, self.restore_pending = self.restore_pending, False
        return restored

    def apply(self, ruleset):
        if self.failing:
            raise FirewallError("nft failed: boom")
        self.ruleset = ruleset


class FakeDomainSets:
    def mark_active(self, keys):
        pass

    def addresses(self, key):
        return frozenset(), frozenset()


def fresh_store() -> PolicyStore:
    return PolicyStore(Path(tempfile.mkdtemp()) / "policies.json")


def make_neighbors(mapping=NEIGHBOR_MAP) -> Neighbors:
    return Neighbors(read=lambda: mapping)


def make_app(topology, read_flows, firewall=None, resolver=None, store=None, neighbors=None, catalog=None, domain_sets=None, interval=0.05, clock=None):
    return SnookerApp(
        Tracker(topology),
        read_flows,
        resolver or FakeResolver(),
        firewall or FakeFirewall(),
        store or fresh_store(),
        catalog or TEST_CATALOG,
        neighbors or make_neighbors(),
        domain_sets or FakeDomainSets(),
        interval=interval,
        clock=clock or (lambda: MONDAY_NOON),
    )


async def test_hosts_appear_with_router_first(topology):
    app = make_app(topology, lambda: [WEB, PING])
    async with app.run_test() as pilot:
        await pilot.pause(0.2)
        assert isinstance(app.screen, HostScreen)
        table = app.screen.query_one("#hosts", DataTable)
        assert [key.value for key in table.rows] == ["router", "192.168.1.10"]
        assert str(table.get_row("192.168.1.10")[0]) == "laptop"


async def test_conntrack_error_shown_then_cleared(topology):
    failing = True

    def read_flows():
        if failing:
            raise ConntrackError("conntrack failed: boom")
        return [WEB]

    app = make_app(topology, read_flows)
    async with app.run_test() as pilot:
        await pilot.pause(0.2)
        assert "boom" in app.sub_title
        failing = False
        await pilot.pause(0.2)
        assert app.sub_title == ""
        assert app.screen.query_one("#hosts", DataTable).row_count == 1


LAN_PEER = Flow(
    "tcp",
    Endpoints("192.168.1.20", "1.1.1.1", 40000, 443),
    Endpoints("1.1.1.1", "203.0.113.5", 443, 40000),
)


async def test_enter_opens_detail_and_escape_returns(topology):
    app = make_app(topology, lambda: [WEB])
    async with app.run_test() as pilot:
        await pilot.pause(0.2)
        await pilot.press("enter")
        await pilot.pause(0.1)
        assert isinstance(app.screen, DetailScreen)
        flows = app.screen.query_one("#flows", DataTable)
        assert flows.row_count == 1
        assert [str(cell) for cell in flows.get_row_at(0)[:3]] == ["tcp", "93.184.216.34", "443"]
        await pilot.press("escape")
        assert isinstance(app.screen, HostScreen)


async def test_detail_summary_shows_name_verbatim(topology):
    app = make_app(topology, lambda: [WEB], resolver=FakeResolver({"192.168.1.10": "[TV] Samsung"}))
    async with app.run_test() as pilot:
        await pilot.pause(0.2)
        await pilot.press("enter")
        await pilot.pause(0.1)
        assert str(app.screen.query_one("#summary", Static).render()).startswith("[TV] Samsung  192.168.1.10")


async def test_detail_flows_show_remote_name_verbatim(topology):
    app = make_app(topology, lambda: [WEB], resolver=FakeResolver({"93.184.216.34": "[b]cdn[/b]"}))
    async with app.run_test() as pilot:
        await pilot.pause(0.2)
        await pilot.press("enter")
        await pilot.pause(0.1)
        assert "[b]cdn[/b]" in app.screen.query_one("#flows", DataTable).render_line(1).text


WEB_LATER = replace(WEB, orig_bytes=WEB.orig_bytes + 512, reply_bytes=WEB.reply_bytes + 1024)


def pane_title(app):
    pane = app.screen.query_one(HostPane)
    return pane.render_lines(Region(0, 0, pane.outer_size.width, 1))[0].text


def app_with_history(topology):
    tracker = Tracker(topology)
    tracker.update([WEB], now=0.0)
    tracker.update([WEB_LATER], now=1.0)
    resolver = FakeResolver({"192.168.1.10": "laptop", "93.184.216.34": "example.org"})
    return SnookerApp(
        tracker, lambda: [WEB_LATER], resolver, FakeFirewall(), fresh_store(), TEST_CATALOG, make_neighbors(), FakeDomainSets(), interval=60, clock=lambda: MONDAY_NOON
    )


async def test_host_pane_follows_cursor(topology):
    app = make_app(topology, lambda: [WEB, PING], interval=60)
    async with app.run_test() as pilot:
        await pilot.pause(0.2)
        assert "router · 203.0.113.5" in pane_title(app)
        await pilot.press("down")
        assert "laptop · 192.168.1.10" in pane_title(app)


async def test_host_pane_graphs_rate_history(topology):
    app = app_with_history(topology)
    async with app.run_test() as pilot:
        await pilot.pause(0.2)
        pane = app.screen.query_one(HostPane)
        rx = pane.query_one("#rx", Sparkline)
        assert str(pane.query_one("#rx-label", Static).render()) == "rx 0 B/s  peak 1.0 KiB/s"
        assert rx.data[-3:] == [0.0, 1024.0, 0.0]
        assert len(rx.data) == rx.size.width
        assert str(pane.query_one("#tx-label", Static).render()) == "tx 0 B/s  peak 512 B/s"
        assert pane.query_one("#tx", Sparkline).data[-3:] == [0.0, 512.0, 0.0]


def failing_read():
    raise ConntrackError("conntrack failed: boom")


async def test_host_pane_labels_stay_on_one_line(topology):
    tracker = Tracker(topology)
    for second, received in enumerate((0, 922_522, 1_547_572)):
        tracker.update([replace(WEB, reply_bytes=WEB.reply_bytes + received)], now=float(second))
    app = SnookerApp(
        tracker, failing_read, FakeResolver(), FakeFirewall(), fresh_store(), TEST_CATALOG, make_neighbors(), FakeDomainSets(), interval=60, clock=lambda: MONDAY_NOON
    )
    async with app.run_test() as pilot:
        await pilot.pause(0.2)
        label = app.screen.query_one(HostPane).query_one("#rx-label", Static)
        assert str(label.render()) == "rx 610.4 KiB/s  peak 900.9 KiB/s"
        assert label.size.height == 1


async def test_host_pane_divider_spans_pane(topology):
    app = make_app(topology, lambda: [WEB], interval=60)
    async with app.run_test() as pilot:
        await pilot.pause(0.2)
        pane = app.screen.query_one(HostPane)
        assert pane.query_one("#peers", Static).size.height == pane.query_one("#graphs").size.height


async def test_host_pane_window_label_matches_graph_width(topology):
    app = app_with_history(topology)
    async with app.run_test() as pilot:
        await pilot.pause(0.2)
        pane = app.screen.query_one(HostPane)
        columns = pane.query_one("#rx", Sparkline).size.width
        bottom = pane.render_lines(Region(0, pane.outer_size.height - 1, pane.outer_size.width, 1))[0].text
        assert f"last {columns - 1} min" in bottom


async def test_host_pane_graph_fills_width_after_resize(topology):
    app = app_with_history(topology)
    async with app.run_test() as pilot:
        await pilot.pause(0.2)
        rx = app.screen.query_one(HostPane).query_one("#rx", Sparkline)
        narrow = rx.size.width
        await pilot.resize_terminal(120, 24)
        await pilot.pause(0.1)
        assert rx.size.width > narrow
        assert len(rx.data) == rx.size.width


async def test_host_pane_summarises_flows(topology):
    app = app_with_history(topology)
    async with app.run_test() as pilot:
        await pilot.pause(0.2)
        assert str(app.screen.query_one(HostPane).query_one("#peers", Static).render()).splitlines() == [
            "flows  tcp 1",
            "example.org       tcp/443        0 B/s ↓       0 B/s ↑",
        ]


async def test_host_pane_shows_names_verbatim(topology):
    resolver = FakeResolver({"192.168.1.10": "[TV] Samsung", "93.184.216.34": "[b]cdn[/b]"})
    app = make_app(topology, lambda: [WEB], resolver=resolver, interval=60)
    async with app.run_test() as pilot:
        await pilot.pause(0.2)
        assert "[TV] Samsung · 192.168.1.10" in pane_title(app)
        assert "[b]cdn[/b]" in str(app.screen.query_one(HostPane).query_one("#peers", Static).render())


async def test_host_pane_hides_without_selection(topology):
    app = make_app(topology, lambda: [WEB], interval=60)
    async with app.run_test() as pilot:
        await pilot.pause(0.2)
        await pilot.press("slash", *"zzz")
        await pilot.pause(0.1)
        assert not app.screen.query_one(HostPane).display


async def test_host_pane_shows_blocked_services(topology):
    store = fresh_store()
    store.replace_rules(HOST_MAC, (Rule("minecraft", frozenset({0}), ()),))  # never allowed
    app = make_app(topology, lambda: [WEB], store=store, interval=60)
    async with app.run_test() as pilot:
        await pilot.pause(0.2)
        peers = str(app.screen.query_one(HostPane).query_one("#peers", Static).render())
        assert "Blocked now: Minecraft" in peers


def column_widths(table):
    return [column.width for column in table.columns.values()]


def fills_width(table):
    return table.virtual_size.width == table.scrollable_content_region.width


async def test_host_list_gives_spare_width_to_names(topology):
    app = make_app(topology, lambda: [WEB, PING], interval=60)
    async with app.run_test(size=(160, 30)) as pilot:
        await pilot.pause(0.2)
        table = app.screen.query_one("#hosts", DataTable)
        assert fills_width(table)
        assert column_widths(table)[1] == len("192.168.1.10")


async def test_host_list_never_squeezes_names(topology):
    app = make_app(topology, lambda: [WEB, PING], interval=60)
    async with app.run_test(size=(60, 24)) as pilot:
        await pilot.pause(0.2)
        assert column_widths(app.screen.query_one("#hosts", DataTable))[0] == len("laptop")


async def test_host_list_refits_after_resize(topology):
    app = make_app(topology, lambda: [WEB, PING], interval=60)
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause(0.2)
        await pilot.resize_terminal(160, 30)
        await pilot.pause(0.2)
        assert fills_width(app.screen.query_one("#hosts", DataTable))


async def test_detail_flows_give_spare_width_to_remote(topology):
    app = make_app(topology, lambda: [WEB], interval=60)
    async with app.run_test(size=(160, 30)) as pilot:
        await pilot.pause(0.2)
        await pilot.press("enter")
        await pilot.pause(0.2)
        flows = app.screen.query_one("#flows", DataTable)
        assert fills_width(flows)
        assert column_widths(flows)[0] == len("Proto")


async def test_host_pane_peer_names_use_spare_width(topology):
    resolver = FakeResolver({"192.168.1.10": "laptop", "93.184.216.34": "cdn.example-content-delivery.net"})
    app = make_app(topology, lambda: [WEB], resolver=resolver, interval=60)
    async with app.run_test(size=(160, 30)) as pilot:
        await pilot.pause(0.2)
        peers = app.screen.query_one(HostPane).query_one("#peers", Static)
        line = str(peers.render()).splitlines()[1]
        assert line.startswith("cdn.example-content-delivery.net ")
        assert len(line) == peers.size.width


async def test_poll_finishing_after_shutdown_is_ignored(topology):
    app = make_app(topology, lambda: [WEB], interval=60)
    async with app.run_test() as pilot:
        await pilot.pause(0.2)
    app._apply([WEB], time.monotonic())


async def test_filter_limits_hosts(topology):
    app = make_app(topology, lambda: [WEB, LAN_PEER])
    async with app.run_test() as pilot:
        await pilot.pause(0.2)
        await pilot.press("slash")
        await pilot.press(*"lapt")
        await pilot.pause(0.1)
        assert app.screen.query_one(Input).value == "lapt"
        assert [key.value for key in app.screen.query_one("#hosts", DataTable).rows] == ["192.168.1.10"]


async def test_sorts_by_rx_total_by_default(topology):
    polls = 0

    def burst_then_trickle():
        nonlocal polls
        polls += 1
        return [
            Flow("tcp", WEB.orig, WEB.reply, reply_bytes=polls * 1_000),
            Flow("tcp", LAN_PEER.orig, LAN_PEER.reply, reply_bytes=min(polls, 2) * 1_000_000),
        ]

    app = make_app(topology, burst_then_trickle)
    async with app.run_test() as pilot:
        await pilot.pause(0.4)
        rows = [key.value for key in app.screen.query_one("#hosts", DataTable).rows]
        assert rows == ["192.168.1.20", "192.168.1.10"]


async def test_sort_cycles_to_name(topology):
    app = make_app(topology, lambda: [LAN_PEER, WEB])
    async with app.run_test() as pilot:
        await pilot.pause(0.2)
        await pilot.press("s", "s", "s")
        await pilot.pause(0.1)
        rows = [key.value for key in app.screen.query_one("#hosts", DataTable).rows]
        assert rows == ["192.168.1.20", "192.168.1.10"]


async def test_slow_reads_never_overlap(topology):
    running = 0
    peak = 0

    def slow_read():
        nonlocal running, peak
        running += 1
        peak = max(peak, running)
        time.sleep(0.15)
        running -= 1
        return [WEB]

    app = make_app(topology, slow_read)
    async with app.run_test() as pilot:
        await pilot.pause(0.6)
    assert peak == 1


async def test_detail_cursor_survives_refresh(topology):
    flows = [
        Flow("tcp", Endpoints("192.168.1.10", "93.184.216.34", port, 443), Endpoints("93.184.216.34", "203.0.113.5", 443, port))
        for port in (50001, 50002, 50003)
    ]
    app = make_app(topology, lambda: flows)
    async with app.run_test() as pilot:
        await pilot.pause(0.2)
        await pilot.press("enter")
        await pilot.pause(0.1)
        await pilot.press("down", "down")
        await pilot.pause(0.2)
        assert app.screen.query_one("#flows", DataTable).cursor_row == 2


def status(app, host_id):
    return str(app.screen.query_one("#hosts", DataTable).get_row(host_id)[-1])


async def test_p_pauses_and_resumes_host(topology):
    firewall = FakeFirewall()
    app = make_app(topology, lambda: [WEB], firewall=firewall)
    async with app.run_test() as pilot:
        await pilot.pause(0.2)
        await pilot.press("p")
        await pilot.pause(0.2)
        assert firewall.ruleset.paused_macs == frozenset({HOST_MAC})
        assert status(app, "192.168.1.10") == "PAUSED"
        await pilot.press("p")
        await pilot.pause(0.2)
        assert firewall.ruleset.paused_macs == frozenset()
        assert status(app, "192.168.1.10") == ""


async def test_router_cannot_be_paused(topology):
    firewall = FakeFirewall()
    app = make_app(topology, lambda: [PING], firewall=firewall)
    async with app.run_test() as pilot:
        await pilot.pause(0.2)
        await pilot.press("p")
        await pilot.pause(0.2)
        assert firewall.ruleset.paused_macs == frozenset()


async def test_pause_with_unknown_mac_is_notified(topology):
    firewall = FakeFirewall()
    app = make_app(topology, lambda: [WEB], firewall=firewall, neighbors=make_neighbors({}))
    messages = record_notifications(app)
    async with app.run_test() as pilot:
        await pilot.pause(0.2)
        await pilot.press("p")
        await pilot.pause(0.2)
        assert firewall.ruleset.paused_macs == frozenset()
        assert any("Unknown MAC address" in message for message, _ in messages)


async def test_schedule_status_and_pane_line_reflect_active_block(topology):
    store = fresh_store()
    store.replace_rules(HOST_MAC, (Rule("minecraft", frozenset({0}), ()),))
    app = make_app(topology, lambda: [WEB], store=store)
    async with app.run_test() as pilot:
        await pilot.pause(0.2)
        assert status(app, "192.168.1.10") == "SCHEDULE"


def record_notifications(app):
    messages = []
    app.notify = lambda message, **kwargs: messages.append((message, kwargs.get("severity")))
    return messages


async def test_firewall_error_is_notified_and_keeps_state(topology):
    firewall = FakeFirewall(failing=True)
    app = make_app(topology, lambda: [WEB], firewall=firewall)
    messages = record_notifications(app)
    async with app.run_test() as pilot:
        await pilot.pause(0.2)
        await pilot.press("p")
        await pilot.pause(0.2)
        assert ("nft failed: boom", "error") in messages
        assert firewall.ruleset == Ruleset()


async def test_restored_firewall_table_is_notified(topology):
    firewall = FakeFirewall()
    firewall.restore_pending = True
    app = make_app(topology, lambda: [WEB], firewall=firewall)
    messages = record_notifications(app)
    async with app.run_test() as pilot:
        await pilot.pause(0.2)
    assert [message for message, severity in messages if "restored" in message and severity == "warning"]


async def test_sigterm_exits_app(topology):
    previous = signal.signal(signal.SIGTERM, lambda *args: None)
    try:
        app = make_app(topology, lambda: [WEB])
        async with app.run_test() as pilot:
            await pilot.pause(0.2)
            os.kill(os.getpid(), signal.SIGTERM)
            await pilot.pause(0.2)
            assert not app.is_running
    finally:
        signal.signal(signal.SIGTERM, previous)


async def test_unavailable_firewall_is_not_called(topology):
    firewall = FakeFirewall(available=False, failing=True)
    app = make_app(topology, lambda: [WEB], firewall=firewall)
    async with app.run_test() as pilot:
        await pilot.pause(0.2)
        await pilot.press("p")
        await pilot.pause(0.2)
        assert "boom" not in app.sub_title


async def test_p_on_empty_table_does_nothing(topology):
    firewall = FakeFirewall()
    app = make_app(topology, lambda: [], firewall=firewall)
    async with app.run_test() as pilot:
        await pilot.pause(0.2)
        await pilot.press("p")
        await pilot.pause(0.1)
        assert firewall.ruleset.paused_macs == frozenset()


async def test_p_on_detail_screen(topology):
    firewall = FakeFirewall()
    app = make_app(topology, lambda: [WEB], firewall=firewall)
    async with app.run_test() as pilot:
        await pilot.pause(0.2)
        await pilot.press("enter")
        await pilot.pause(0.1)
        await pilot.press("p")
        await pilot.pause(0.2)
        assert firewall.ruleset.paused_macs == frozenset({HOST_MAC})
        assert "PAUSED" in str(app.screen.query_one("#summary", Static).render())


async def test_no_poll_is_scheduled_after_shutdown(topology):
    app = make_app(topology, lambda: [WEB], interval=60)
    async with app.run_test() as pilot:
        await pilot.pause(0.2)
    scheduled = []
    app.set_timer = lambda *arguments, **options: scheduled.append(arguments)
    app._schedule_poll()
    assert scheduled == []
