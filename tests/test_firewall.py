import subprocess
import threading
import time

import pytest

from network_snooker.catalog import PortRange
from network_snooker.firewall import BASE_SCRIPT, NFT_MISSING, EMPTY_RULESET, Firewall, FirewallError, Ruleset, ServiceBlock, _table_script

NFT = "/usr/sbin/nft"
MAC = "aa:bb:cc:dd:ee:01"
OTHER_MAC = "aa:bb:cc:dd:ee:02"


class FakeNft:
    def __init__(self, failing=False):
        self.scripts = []
        self.commands = []
        self.failing = failing
        self.table_missing = False
        self.delay = 0.0

    def __call__(self, command, **kwargs):
        if command[0] != NFT:
            self.commands.append(command)
            return subprocess.CompletedProcess(command, 1, "", "0 flow entries have been deleted.")
        assert command == (NFT, "-f", "-")
        time.sleep(self.delay)
        script = kwargs["input"]
        self.scripts.append(script)
        failed = self.failing or (self.table_missing and script.startswith("list table"))
        return subprocess.CompletedProcess(command, int(failed), "", "Error: boom" if failed else "")


@pytest.fixture
def nft():
    return FakeNft()


@pytest.fixture
def firewall(nft):
    firewall = Firewall(NFT, run=nft)
    firewall.setup()
    return firewall


def test_setup_replaces_table_atomically(firewall, nft):
    assert firewall.available
    assert nft.scripts == [_table_script(EMPTY_RULESET)]
    assert BASE_SCRIPT == "table inet network_snooker\ndelete table inet network_snooker\n"
    for rule in ("ip daddr @paused4 drop", "ip6 daddr @paused6 drop"):
        assert rule in nft.scripts[0]
    assert "hook forward priority -10; policy accept;" in nft.scripts[0]


def test_apply_pauses_mac_and_blocks_inbound_by_ip(firewall, nft):
    ruleset = Ruleset(paused_macs=frozenset({MAC}), paused_ips=frozenset({"192.168.1.10"}), mac_ips={MAC: frozenset({"192.168.1.10"})})
    firewall.apply(ruleset)
    assert firewall.ruleset == ruleset
    assert nft.scripts[-1] == _table_script(ruleset)
    assert f"ether saddr {MAC} drop" in nft.scripts[-1]
    assert "add element inet network_snooker paused4 { 192.168.1.10 }" in nft.scripts[-1]


def test_apply_is_a_noop_when_ruleset_is_unchanged(firewall, nft):
    ruleset = Ruleset(paused_macs=frozenset({MAC}), mac_ips={MAC: frozenset()})
    firewall.apply(ruleset)
    firewall.apply(ruleset)
    assert len(nft.scripts) == 2  # setup + one apply


def test_apply_drops_connections_only_for_newly_paused_mac(firewall, nft):
    ruleset = Ruleset(paused_macs=frozenset({MAC}), mac_ips={MAC: frozenset({"192.168.1.10"})})
    firewall.apply(ruleset)
    assert nft.commands == [
        ("conntrack", "-D", "-s", "192.168.1.10"),
        ("conntrack", "-D", "-d", "192.168.1.10"),
        ("conntrack", "-D", "--reply-src", "192.168.1.10"),
    ]
    both = Ruleset(paused_macs=frozenset({MAC, OTHER_MAC}), mac_ips={MAC: frozenset({"192.168.1.10"}), OTHER_MAC: frozenset({"192.168.1.20"})})
    firewall.apply(both)
    assert len(nft.commands) == 6
    assert nft.commands[3:] == [
        ("conntrack", "-D", "-s", "192.168.1.20"),
        ("conntrack", "-D", "-d", "192.168.1.20"),
        ("conntrack", "-D", "--reply-src", "192.168.1.20"),
    ]


def test_unpausing_does_not_drop_connections_again(firewall, nft):
    firewall.apply(Ruleset(paused_macs=frozenset({MAC}), mac_ips={MAC: frozenset({"192.168.1.10"})}))
    firewall.apply(EMPTY_RULESET)
    assert len(nft.commands) == 3


def test_service_block_renders_ports_and_site_sets(firewall, nft):
    block = ServiceBlock(
        mac=MAC,
        service_key="minecraft",
        ports=(PortRange("tcp", 25565, 25565), PortRange("udp", 19132, 19133)),
        v4=frozenset({"93.184.216.34"}),
        v6=frozenset({"2001:db8::1"}),
    )
    ruleset = Ruleset(blocks=(block,), mac_ips={MAC: frozenset({"192.168.1.10"})})
    firewall.apply(ruleset)
    script = nft.scripts[-1]
    assert "set svc_minecraft4 { type ipv4_addr; flags interval; }" in script
    assert "set svc_minecraft6 { type ipv6_addr; flags interval; }" in script
    assert f"ether saddr {MAC} tcp dport 25565 drop" in script
    assert f"ether saddr {MAC} udp dport 19132-19133 drop" in script
    assert f"ether saddr {MAC} ip daddr @svc_minecraft4 drop" in script
    assert f"ether saddr {MAC} ip6 daddr @svc_minecraft6 drop" in script
    assert "add element inet network_snooker svc_minecraft4 { 93.184.216.34 }" in script
    assert "add element inet network_snooker svc_minecraft6 { 2001:db8::1 }" in script


def test_pause_and_service_block_can_combine_for_different_hosts(firewall, nft):
    block = ServiceBlock(mac=OTHER_MAC, service_key="tiktok", v4=frozenset({"1.2.3.4"}))
    ruleset = Ruleset(paused_macs=frozenset({MAC}), blocks=(block,), mac_ips={MAC: frozenset(), OTHER_MAC: frozenset()})
    firewall.apply(ruleset)
    script = nft.scripts[-1]
    assert f"ether saddr {MAC} drop" in script
    assert f"ether saddr {OTHER_MAC} ip daddr @svc_tiktok4 drop" in script


def test_newly_blocked_service_drops_connections(firewall, nft):
    unblocked = Ruleset(mac_ips={MAC: frozenset({"192.168.1.10"})})
    firewall.apply(unblocked)
    block = ServiceBlock(mac=MAC, service_key="tiktok", v4=frozenset({"1.2.3.4"}))
    firewall.apply(Ruleset(blocks=(block,), mac_ips={MAC: frozenset({"192.168.1.10"})}))
    assert nft.commands == [
        ("conntrack", "-D", "-s", "192.168.1.10"),
        ("conntrack", "-D", "-d", "192.168.1.10"),
        ("conntrack", "-D", "--reply-src", "192.168.1.10"),
    ]


def test_apply_raises_when_unavailable():
    firewall = Firewall(None)
    firewall.setup()
    with pytest.raises(FirewallError, match="nft not found"):
        firewall.apply(EMPTY_RULESET)


def test_failed_apply_keeps_previous_ruleset(firewall, nft):
    nft.failing = True
    with pytest.raises(FirewallError, match="boom"):
        firewall.apply(Ruleset(paused_macs=frozenset({MAC}), mac_ips={MAC: frozenset()}))
    assert firewall.ruleset == EMPTY_RULESET
    assert nft.commands == []


def test_concurrent_applies_are_serialised(firewall, nft):
    nft.delay = 0.05
    a = Ruleset(paused_macs=frozenset({MAC}), mac_ips={MAC: frozenset()})
    b = Ruleset(paused_macs=frozenset({OTHER_MAC}), mac_ips={OTHER_MAC: frozenset()})
    threads = [threading.Thread(target=firewall.apply, args=(ruleset,)) for ruleset in (a, b)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert firewall.ruleset in (a, b)
    assert len(nft.scripts) == 3


def test_ensure_restores_externally_removed_table(firewall, nft):
    firewall.apply(Ruleset(paused_macs=frozenset({MAC}), mac_ips={MAC: frozenset()}))
    nft.table_missing = True
    assert firewall.ensure() is True
    assert nft.scripts[-1] == _table_script(firewall.ruleset)


def test_ensure_leaves_present_table_alone(firewall, nft):
    firewall.apply(Ruleset(paused_macs=frozenset({MAC}), mac_ips={MAC: frozenset()}))
    assert firewall.ensure() is False
    assert nft.scripts[-1] == "list table inet network_snooker\n"


def test_ensure_skips_check_when_ruleset_is_empty(firewall, nft):
    assert firewall.ensure() is False
    assert nft.scripts == [_table_script(EMPTY_RULESET)]


def test_teardown_deletes_table_and_resets_ruleset(firewall, nft):
    firewall.apply(Ruleset(paused_macs=frozenset({MAC}), mac_ips={MAC: frozenset()}))
    firewall.teardown()
    assert nft.scripts[-1] == "delete table inet network_snooker\n"
    assert firewall.ruleset == EMPTY_RULESET
    assert not firewall.available


def test_teardown_ignores_failure(firewall, nft):
    nft.failing = True
    firewall.teardown()
    assert not firewall.available


def test_missing_nft_is_unavailable():
    firewall = Firewall(None)
    firewall.setup()
    assert not firewall.available
    assert firewall.unavailable_reason == NFT_MISSING
    assert firewall.ensure() is False
    firewall.teardown()


def test_failed_setup_is_unavailable():
    firewall = Firewall(NFT, run=FakeNft(failing=True))
    firewall.setup()
    assert not firewall.available
    assert "boom" in firewall.unavailable_reason
