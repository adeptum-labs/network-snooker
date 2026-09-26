from textual.widgets import DataTable

from network_snooker.app import HostScreen, SnookerApp
from network_snooker.conntrack_source import ConntrackError, Endpoints, Flow
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
    def name(self, ip):
        return {"192.168.1.10": "laptop"}.get(ip, ip)


def make_app(topology, read_flows):
    return SnookerApp(Tracker(topology), read_flows, FakeResolver(), interval=0.05)


async def test_hosts_appear_with_router_first(topology):
    app = make_app(topology, lambda: [WEB, PING])
    async with app.run_test() as pilot:
        await pilot.pause(0.2)
        assert isinstance(app.screen, HostScreen)
        table = app.screen.query_one("#hosts", DataTable)
        assert [key.value for key in table.rows] == ["router", "192.168.1.10"]
        assert str(table.get_row("192.168.1.10")[0]) == "laptop"


async def test_conntrack_error_shown_then_cleared(topology):
    results = iter([ConntrackError("conntrack failed: boom")])

    def read_flows():
        result = next(results, None)
        if isinstance(result, Exception):
            raise result
        return [WEB]

    app = make_app(topology, read_flows)
    async with app.run_test() as pilot:
        await pilot.pause(0.02)
        assert "boom" in app.sub_title
        await pilot.pause(0.2)
        assert app.sub_title == ""
        assert app.screen.query_one("#hosts", DataTable).row_count == 1
