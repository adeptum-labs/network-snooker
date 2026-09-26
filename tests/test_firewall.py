import subprocess
import threading
import time

import pytest

from network_snooker.firewall import NFT_MISSING, SETUP_SCRIPT, Firewall, FirewallError

NFT = "/usr/sbin/nft"


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


def element(set_name, ip):
    return f"add element inet network_snooker {set_name} {{ {ip} }}\n"


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
    assert nft.scripts == [SETUP_SCRIPT]
    assert SETUP_SCRIPT.startswith("table inet network_snooker\ndelete table inet network_snooker\n")
    for rule in ("ip saddr @paused4 drop", "ip daddr @paused4 drop", "ip6 saddr @paused6 drop", "ip6 daddr @paused6 drop"):
        assert rule in SETUP_SCRIPT
    assert "hook forward priority -10; policy accept;" in SETUP_SCRIPT


def test_toggle_rewrites_table_with_all_paused_hosts(firewall, nft):
    assert firewall.toggle("192.168.1.10") is True
    assert firewall.toggle("2001:db8:1::10") is True
    assert firewall.paused == frozenset({"192.168.1.10", "2001:db8:1::10"})
    assert firewall.toggle("192.168.1.10") is False
    assert firewall.paused == frozenset({"2001:db8:1::10"})
    assert nft.scripts[1:] == [
        SETUP_SCRIPT + element("paused4", "192.168.1.10"),
        SETUP_SCRIPT + element("paused4", "192.168.1.10") + element("paused6", "2001:db8:1::10"),
        SETUP_SCRIPT + element("paused6", "2001:db8:1::10"),
    ]


def test_pause_drops_host_connections(firewall, nft):
    firewall.toggle("192.168.1.10")
    assert nft.commands == [
        ("conntrack", "-D", "-s", "192.168.1.10"),
        ("conntrack", "-D", "-d", "192.168.1.10"),
        ("conntrack", "-D", "--reply-src", "192.168.1.10"),
    ]
    firewall.toggle("192.168.1.10")
    assert len(nft.commands) == 3


def test_concurrent_toggles_are_serialised(firewall, nft):
    nft.delay = 0.05
    threads = [threading.Thread(target=firewall.toggle, args=("192.168.1.10",)) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert firewall.paused == frozenset()
    assert nft.scripts[1:] == [SETUP_SCRIPT + element("paused4", "192.168.1.10"), SETUP_SCRIPT]


def test_failed_toggle_keeps_state(firewall, nft):
    nft.failing = True
    with pytest.raises(FirewallError, match="boom"):
        firewall.toggle("192.168.1.10")
    assert firewall.paused == frozenset()
    assert nft.commands == []


def test_timeout_raises_firewall_error(firewall):
    def hang(command, **kwargs):
        raise subprocess.TimeoutExpired(command, kwargs["timeout"])

    firewall._run = hang
    with pytest.raises(FirewallError):
        firewall.toggle("192.168.1.10")


def test_ensure_restores_externally_removed_table(firewall, nft):
    firewall.toggle("192.168.1.10")
    nft.table_missing = True
    assert firewall.ensure() is True
    assert nft.scripts[-1] == SETUP_SCRIPT + element("paused4", "192.168.1.10")


def test_ensure_leaves_present_table_alone(firewall, nft):
    firewall.toggle("192.168.1.10")
    assert firewall.ensure() is False
    assert nft.scripts[-1] == "list table inet network_snooker\n"


def test_ensure_skips_check_when_nothing_paused(firewall, nft):
    assert firewall.ensure() is False
    assert nft.scripts == [SETUP_SCRIPT]


def test_teardown_deletes_table(firewall, nft):
    firewall.toggle("192.168.1.10")
    firewall.teardown()
    assert nft.scripts[-1] == "delete table inet network_snooker\n"
    assert firewall.paused == frozenset()
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
    with pytest.raises(FirewallError, match="nft not found"):
        firewall.toggle("192.168.1.10")
    assert firewall.ensure() is False
    firewall.teardown()


def test_failed_setup_is_unavailable():
    firewall = Firewall(NFT, run=FakeNft(failing=True))
    firewall.setup()
    assert not firewall.available
    assert "boom" in firewall.unavailable_reason
