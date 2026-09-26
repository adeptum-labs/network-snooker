import subprocess

import pytest

from network_snooker.firewall import NFT_MISSING, SETUP_SCRIPT, Firewall, FirewallError


class FakeNft:
    def __init__(self, failing=False):
        self.scripts = []
        self.failing = failing

    def __call__(self, command, **kwargs):
        assert command == ("/usr/sbin/nft", "-f", "-")
        self.scripts.append(kwargs["input"])
        return subprocess.CompletedProcess(command, 1 if self.failing else 0, "", "Error: boom" if self.failing else "")


@pytest.fixture
def nft():
    return FakeNft()


@pytest.fixture
def firewall(nft):
    firewall = Firewall("/usr/sbin/nft", run=nft)
    firewall.setup()
    return firewall


def test_setup_replaces_table_atomically(firewall, nft):
    assert firewall.available
    assert nft.scripts == [SETUP_SCRIPT]
    assert SETUP_SCRIPT.startswith("table inet network_snooker\ndelete table inet network_snooker\n")
    for rule in ("ip saddr @paused4 drop", "ip daddr @paused4 drop", "ip6 saddr @paused6 drop", "ip6 daddr @paused6 drop"):
        assert rule in SETUP_SCRIPT
    assert "hook forward priority -10; policy accept;" in SETUP_SCRIPT


def test_toggle_ipv4(firewall, nft):
    assert firewall.toggle("192.168.1.10") is True
    assert firewall.paused == frozenset({"192.168.1.10"})
    assert firewall.toggle("192.168.1.10") is False
    assert firewall.paused == frozenset()
    assert nft.scripts[1:] == [
        "add element inet network_snooker paused4 { 192.168.1.10 }\n",
        "delete element inet network_snooker paused4 { 192.168.1.10 }\n",
    ]


def test_toggle_ipv6(firewall, nft):
    firewall.toggle("2001:db8:1::10")
    assert nft.scripts[-1] == "add element inet network_snooker paused6 { 2001:db8:1::10 }\n"


def test_failed_toggle_keeps_state(firewall, nft):
    nft.failing = True
    with pytest.raises(FirewallError, match="boom"):
        firewall.toggle("192.168.1.10")
    assert firewall.paused == frozenset()


def test_timeout_raises_firewall_error(firewall):
    def hang(command, **kwargs):
        raise subprocess.TimeoutExpired(command, kwargs["timeout"])

    firewall._run = hang
    with pytest.raises(FirewallError):
        firewall.toggle("192.168.1.10")


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
    firewall.teardown()


def test_failed_setup_is_unavailable():
    firewall = Firewall("/usr/sbin/nft", run=FakeNft(failing=True))
    firewall.setup()
    assert not firewall.available
    assert "boom" in firewall.unavailable_reason
