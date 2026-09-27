import subprocess

import pytest

from network_snooker.neighbors import Neighbors, read_neighbors

NEIGH_JSON = """
[
    {"dst": "192.168.1.10", "dev": "br-lan", "lladdr": "aa:bb:cc:dd:ee:01", "state": ["REACHABLE"]},
    {"dst": "192.168.1.11", "dev": "br-lan", "lladdr": "aa:bb:cc:dd:ee:02", "state": ["STALE"]},
    {"dst": "192.168.1.12", "dev": "br-lan", "lladdr": "aa:bb:cc:dd:ee:03", "state": ["FAILED"]},
    {"dst": "192.168.1.13", "dev": "br-lan", "state": ["INCOMPLETE"]}
]
"""


def fake_run(command, **kwargs):
    assert command == ("ip", "-j", "neigh", "show")
    return subprocess.CompletedProcess(command, 0, NEIGH_JSON, "")


def test_read_neighbors_skips_failed_and_incomplete():
    assert read_neighbors(run=fake_run) == {
        "192.168.1.10": "aa:bb:cc:dd:ee:01",
        "192.168.1.11": "aa:bb:cc:dd:ee:02",
    }


def test_read_neighbors_returns_empty_on_command_failure():
    def failing(command, **kwargs):
        raise subprocess.CalledProcessError(1, command)

    assert read_neighbors(run=failing) == {}


def test_read_neighbors_returns_empty_on_bad_json():
    def garbled(command, **kwargs):
        return subprocess.CompletedProcess(command, 0, "not json", "")

    assert read_neighbors(run=garbled) == {}


@pytest.fixture
def neighbors():
    return Neighbors(read=lambda: {"192.168.1.10": "aa:bb:cc:dd:ee:01"})


def test_refresh_populates_lookups(neighbors):
    neighbors.refresh()
    assert neighbors.mac("192.168.1.10") == "aa:bb:cc:dd:ee:01"
    assert neighbors.ips("aa:bb:cc:dd:ee:01") == frozenset({"192.168.1.10"})


def test_mac_is_none_for_unknown_ip(neighbors):
    neighbors.refresh()
    assert neighbors.mac("192.168.1.99") is None


def test_stale_mapping_survives_until_replaced():
    calls = [{"192.168.1.10": "aa:bb:cc:dd:ee:01"}, {}]
    neighbors = Neighbors(read=lambda: calls.pop(0))
    neighbors.refresh()
    neighbors.refresh()
    assert neighbors.mac("192.168.1.10") == "aa:bb:cc:dd:ee:01"


def test_new_mac_replaces_old_for_same_ip():
    calls = [{"192.168.1.10": "aa:bb:cc:dd:ee:01"}, {"192.168.1.10": "aa:bb:cc:dd:ee:02"}]
    neighbors = Neighbors(read=lambda: calls.pop(0))
    neighbors.refresh()
    neighbors.refresh()
    assert neighbors.mac("192.168.1.10") == "aa:bb:cc:dd:ee:02"
    assert neighbors.ips("aa:bb:cc:dd:ee:01") == frozenset()
