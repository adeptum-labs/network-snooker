from datetime import datetime, time

import pytest

from network_snooker.catalog import Catalog, PortRange, Service
from network_snooker.enforcement import blocked_now, build_ruleset, host_mode
from network_snooker.neighbors import Neighbors
from network_snooker.policy import Mode, PolicyStore, Rule

MAC = "aa:bb:cc:dd:ee:01"
OTHER_MAC = "aa:bb:cc:dd:ee:02"
MON_16_19 = Rule("minecraft", frozenset({0, 1, 2, 3, 4}), ((time(16, 0), time(19, 0)),))
MONDAY_17 = datetime(2026, 9, 28, 17, 0)
MONDAY_20 = datetime(2026, 9, 28, 20, 0)


def catalog():
    return Catalog(
        {
            "minecraft": Service("minecraft", "Minecraft", "game", ports=(PortRange("tcp", 25565, 25565),), domains=("minecraft.net",)),
            "tiktok": Service("tiktok", "TikTok", "social", domains=("tiktok.com",), cidrs=("1.2.3.0/24",)),
        }
    )


class FakeDomainSets:
    def __init__(self):
        self.marked = None

    def mark_active(self, keys):
        self.marked = keys

    def addresses(self, key):
        return (frozenset({"93.184.216.34"}), frozenset())


@pytest.fixture
def store(tmp_path):
    return PolicyStore(tmp_path / "policies.json")


@pytest.fixture
def neighbors():
    neighbors = Neighbors(read=lambda: {"192.168.1.10": MAC})
    neighbors.refresh()
    return neighbors


def test_ruleset_is_empty_with_no_policies(store, neighbors):
    ruleset = build_ruleset(store, neighbors, catalog(), FakeDomainSets(), MONDAY_17)
    assert ruleset.paused_macs == frozenset()
    assert ruleset.blocks == ()


def test_paused_host_produces_paused_mac_and_ips(store, neighbors):
    store.toggle_paused(MAC)
    ruleset = build_ruleset(store, neighbors, catalog(), FakeDomainSets(), MONDAY_17)
    assert ruleset.paused_macs == frozenset({MAC})
    assert ruleset.paused_ips == frozenset({"192.168.1.10"})
    assert ruleset.mac_ips[MAC] == frozenset({"192.168.1.10"})


def test_scheduled_host_blocks_service_outside_its_window(store, neighbors):
    store.replace_rules(MAC, (MON_16_19,))
    ruleset = build_ruleset(store, neighbors, catalog(), FakeDomainSets(), MONDAY_20)
    assert [b.service_key for b in ruleset.blocks] == ["minecraft"]
    assert ruleset.blocks[0].mac == MAC
    assert ruleset.blocks[0].ports == (PortRange("tcp", 25565, 25565),)
    assert ruleset.blocks[0].v4 == frozenset({"93.184.216.34"})


def test_scheduled_host_allows_service_inside_its_window(store, neighbors):
    store.replace_rules(MAC, (MON_16_19,))
    ruleset = build_ruleset(store, neighbors, catalog(), FakeDomainSets(), MONDAY_17)
    assert ruleset.blocks == ()


def test_domain_sets_are_marked_active_for_currently_blocked_services(store, neighbors):
    store.replace_rules(MAC, (MON_16_19,))
    domain_sets = FakeDomainSets()
    build_ruleset(store, neighbors, catalog(), domain_sets, MONDAY_20)
    assert domain_sets.marked == frozenset({"minecraft"})


def test_host_with_unknown_ip_still_gets_ether_based_blocks(store):
    neighbors = Neighbors(read=lambda: {})
    store.replace_rules(MAC, (MON_16_19,))
    ruleset = build_ruleset(store, neighbors, catalog(), FakeDomainSets(), MONDAY_20)
    assert ruleset.blocks[0].mac == MAC
    assert ruleset.mac_ips[MAC] == frozenset()


def test_removed_catalog_service_is_skipped(store, neighbors):
    store.replace_rules(MAC, (Rule("ghost", frozenset({0}), ()),))
    ruleset = build_ruleset(store, neighbors, catalog(), FakeDomainSets(), MONDAY_17)
    assert ruleset.blocks == ()


def test_blocked_now_names_come_from_catalog(store):
    store.replace_rules(MAC, (MON_16_19,))
    assert blocked_now(store, catalog(), MAC, MONDAY_20) == ("Minecraft",)
    assert blocked_now(store, catalog(), MAC, MONDAY_17) == ()


def test_blocked_now_with_unknown_mac_is_empty(store):
    assert blocked_now(store, catalog(), None, MONDAY_17) == ()


def test_host_mode_reads_policy_by_mac(store):
    assert host_mode(store, None) is Mode.NONE
    assert host_mode(store, MAC) is Mode.NONE
    store.toggle_paused(MAC)
    assert host_mode(store, MAC) is Mode.PAUSED
