import pytest

from network_snooker.conntrack_source import Endpoints, Flow
from network_snooker.tracker import ROUTER_ID, FlowView, Tracker


def flow(src, dst, responder, orig_bytes=0, reply_bytes=0, sport=51234, dport=443, reply_dst="203.0.113.5"):
    return Flow(
        protocol="tcp",
        orig=Endpoints(src, dst, sport, dport),
        reply=Endpoints(responder, reply_dst, dport, sport),
        orig_bytes=orig_bytes,
        reply_bytes=reply_bytes,
    )


def web(orig_bytes, reply_bytes):
    return flow("192.168.1.10", "93.184.216.34", "93.184.216.34", orig_bytes, reply_bytes)


@pytest.fixture
def tracker(topology):
    return Tracker(topology)


def test_first_snapshot_is_baseline(tracker):
    tracker.update([web(1000, 5000)], now=0.0)
    host = tracker.hosts["192.168.1.10"]
    assert (host.rx_total, host.tx_total, host.rx_rate, host.tx_rate) == (0, 0, 0.0, 0.0)
    assert host.active


def test_deltas_and_rates(tracker):
    tracker.update([web(1000, 5000)], now=0.0)
    tracker.update([web(1400, 9000)], now=2.0)
    host = tracker.hosts["192.168.1.10"]
    assert (host.tx_total, host.rx_total) == (400, 4000)
    assert (host.tx_rate, host.rx_rate) == (200.0, 2000.0)
    assert host.flows == [
        FlowView("tcp", "192.168.1.10", 51234, "93.184.216.34", 443, 9000, 1400, 2000.0, 200.0)
    ]


def test_new_flow_after_baseline_counts_fully(tracker):
    tracker.update([], now=0.0)
    tracker.update([web(100, 300)], now=1.0)
    host = tracker.hosts["192.168.1.10"]
    assert (host.tx_total, host.rx_total) == (100, 300)


def test_counter_reset_counts_current_value(tracker):
    tracker.update([web(1000, 5000)], now=0.0)
    tracker.update([web(10, 20)], now=1.0)
    assert (tracker.hosts["192.168.1.10"].tx_total, tracker.hosts["192.168.1.10"].rx_total) == (10, 20)


def test_disappeared_flow_keeps_totals(tracker):
    tracker.update([web(0, 0)], now=0.0)
    tracker.update([web(100, 200)], now=1.0)
    tracker.update([], now=2.0)
    host = tracker.hosts["192.168.1.10"]
    assert (host.tx_total, host.rx_total, host.rx_rate, host.tx_rate) == (100, 200, 0.0, 0.0)
    assert not host.active


def test_dnat_flow_belongs_to_internal_host(tracker):
    dnat = Flow(
        "tcp",
        Endpoints("198.51.100.7", "203.0.113.5", 60000, 8080),
        Endpoints("192.168.1.30", "198.51.100.7", 80, 60000),
        orig_bytes=500,
        reply_bytes=4000,
    )
    tracker.update([], now=0.0)
    tracker.update([dnat], now=1.0)
    host = tracker.hosts["192.168.1.30"]
    assert (host.tx_total, host.rx_total) == (4000, 500)
    assert host.flows[0].local_port == 80
    assert (host.flows[0].remote_ip, host.flows[0].remote_port) == ("198.51.100.7", 60000)
    assert ROUTER_ID not in tracker.hosts


def test_lan_to_router_counts_for_both(tracker):
    dns = flow("192.168.1.20", "192.168.1.1", "192.168.1.1", 60, 120, sport=40000, dport=53, reply_dst="192.168.1.20")
    tracker.update([], now=0.0)
    tracker.update([dns], now=1.0)
    assert (tracker.hosts["192.168.1.20"].tx_total, tracker.hosts["192.168.1.20"].rx_total) == (60, 120)
    assert (tracker.hosts[ROUTER_ID].tx_total, tracker.hosts[ROUTER_ID].rx_total) == (120, 60)


def test_router_local_flow_uses_router_id(tracker):
    tracker.update([], now=0.0)
    tracker.update([flow("203.0.113.5", "8.8.8.8", "8.8.8.8", 84, 84)], now=1.0)
    assert tracker.hosts[ROUTER_ID].ips == {"203.0.113.5"}


def test_foreign_and_loopback_flows_are_ignored(tracker):
    tracker.update([], now=0.0)
    tracker.update(
        [flow("10.9.9.9", "8.8.8.8", "8.8.8.8", 1, 1), flow("127.0.0.1", "127.0.0.1", "127.0.0.1", 1, 1)],
        now=1.0,
    )
    assert tracker.hosts == {}


def test_hairpin_to_same_host_counts_once(tracker):
    tracker.update([], now=0.0)
    tracker.update([flow("192.168.1.1", "203.0.113.5", "203.0.113.5", 10, 20)], now=1.0)
    assert (tracker.hosts[ROUTER_ID].tx_total, tracker.hosts[ROUTER_ID].rx_total) == (10, 20)
