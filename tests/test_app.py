import os
import signal
import time

from textual.widgets import DataTable, Input, Static

from network_snooker.app import DetailScreen, HostScreen, SnookerApp
from network_snooker.conntrack_source import ConntrackError, Endpoints, Flow
from network_snooker.firewall import FirewallError
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
        self.paused = frozenset()
        self.restore_pending = False

    def ensure(self):
        restored, self.restore_pending = self.restore_pending, False
        return restored

    def toggle(self, ip):
        if self.failing:
            raise FirewallError("nft failed: boom")
        pausing = ip not in self.paused
        self.paused = self.paused | {ip} if pausing else self.paused - {ip}
        return pausing


def make_app(topology, read_flows, firewall=None, resolver=None):
    return SnookerApp(Tracker(topology), read_flows, resolver or FakeResolver(), firewall or FakeFirewall(), interval=0.05)


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
    app = make_app(topology, lambda: [WEB], firewall)
    async with app.run_test() as pilot:
        await pilot.pause(0.2)
        await pilot.press("p")
        await pilot.pause(0.2)
        assert firewall.paused == {"192.168.1.10"}
        assert status(app, "192.168.1.10") == "PAUSED"
        await pilot.press("p")
        await pilot.pause(0.2)
        assert firewall.paused == frozenset()
        assert status(app, "192.168.1.10") == ""


async def test_router_cannot_be_paused(topology):
    firewall = FakeFirewall()
    app = make_app(topology, lambda: [PING], firewall)
    async with app.run_test() as pilot:
        await pilot.pause(0.2)
        await pilot.press("p")
        await pilot.pause(0.2)
        assert firewall.paused == frozenset()


def record_notifications(app):
    messages = []
    app.notify = lambda message, **kwargs: messages.append((message, kwargs.get("severity")))
    return messages


async def test_firewall_error_is_notified_and_keeps_state(topology):
    firewall = FakeFirewall(failing=True)
    app = make_app(topology, lambda: [WEB], firewall)
    messages = record_notifications(app)
    async with app.run_test() as pilot:
        await pilot.pause(0.2)
        await pilot.press("p")
        await pilot.pause(0.2)
        assert ("nft failed: boom", "error") in messages
        assert firewall.paused == frozenset()


async def test_restored_firewall_table_is_notified(topology):
    firewall = FakeFirewall()
    firewall.restore_pending = True
    app = make_app(topology, lambda: [WEB], firewall)
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
    app = make_app(topology, lambda: [WEB], firewall)
    async with app.run_test() as pilot:
        await pilot.pause(0.2)
        await pilot.press("p")
        await pilot.pause(0.2)
        assert "boom" not in app.sub_title


async def test_p_on_empty_table_does_nothing(topology):
    firewall = FakeFirewall()
    app = make_app(topology, lambda: [], firewall)
    async with app.run_test() as pilot:
        await pilot.pause(0.2)
        await pilot.press("p")
        await pilot.pause(0.1)
        assert firewall.paused == frozenset()


async def test_p_on_detail_screen(topology):
    firewall = FakeFirewall()
    app = make_app(topology, lambda: [WEB], firewall)
    async with app.run_test() as pilot:
        await pilot.pause(0.2)
        await pilot.press("enter")
        await pilot.pause(0.1)
        await pilot.press("p")
        await pilot.pause(0.2)
        assert firewall.paused == {"192.168.1.10"}
        assert "PAUSED" in str(app.screen.query_one("#summary", Static).render())
