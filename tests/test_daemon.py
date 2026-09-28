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


import pytest
from fakes import HOST_MAC, WEB, FakeFirewall, fresh_store, make_engine

from network_snooker.conntrack_source import ConntrackError
from network_snooker.daemon import TABLE_RESTORED, RequestError
from network_snooker.policy import ALL_DAYS, Mode, Rule

HOST = "192.168.1.10"
NEVER_ALLOWED = Rule("minecraft", ALL_DAYS, ())


def test_poll_tracks_flows(topology):
    engine = make_engine(topology)
    engine.poll()
    assert list(engine.snapshot().hosts) == [HOST]


def test_snapshot_names_hosts_and_remote_peers(topology):
    engine = make_engine(topology)
    engine.poll()
    assert engine.snapshot().names == {HOST: "laptop", "93.184.216.34": "93.184.216.34"}


def test_snapshot_maps_hosts_to_macs(topology):
    engine = make_engine(topology)
    engine.poll()
    assert engine.snapshot().macs == {HOST: HOST_MAC}


def test_conntrack_error_is_reported_then_cleared(topology):
    failing = True

    def read_flows():
        if failing:
            raise ConntrackError("conntrack failed: boom")
        return [WEB]

    engine = make_engine(topology, read_flows)
    engine.poll()
    assert "boom" in engine.snapshot().error
    failing = False
    engine.poll()
    assert engine.snapshot().error == ""


def test_poll_enforces_stored_policies(topology):
    store = fresh_store()
    store.set_mode(HOST_MAC, Mode.PAUSED)
    firewall = FakeFirewall()
    make_engine(topology, firewall=firewall, store=store).poll()
    assert firewall.ruleset.paused_macs == {HOST_MAC}


def test_toggle_pause_takes_effect_without_waiting_for_a_poll(topology):
    firewall = FakeFirewall()
    engine = make_engine(topology, firewall=firewall)
    engine.poll()
    engine.toggle_pause(HOST)
    assert firewall.ruleset.paused_macs == {HOST_MAC}
    assert engine.snapshot().policies[HOST_MAC].mode is Mode.PAUSED


@pytest.mark.parametrize(
    ("host_id", "reason"),
    [("router", "The router cannot be paused"), ("192.168.1.99", "Unknown MAC address; host cannot be paused")],
)
def test_toggle_pause_refuses_hosts_it_cannot_pause(topology, host_id, reason):
    engine = make_engine(topology)
    engine.poll()
    with pytest.raises(RequestError, match=reason):
        engine.toggle_pause(host_id)


def test_toggle_pause_refuses_when_the_firewall_is_unavailable(topology):
    engine = make_engine(topology, firewall=FakeFirewall(available=False))
    engine.poll()
    with pytest.raises(RequestError, match="pausing unavailable"):
        engine.toggle_pause(HOST)


def test_replace_rules_blocks_at_once_and_reports_what_is_blocked(topology):
    firewall = FakeFirewall()
    engine = make_engine(topology, firewall=firewall)
    engine.poll()
    engine.replace_rules(HOST_MAC, (NEVER_ALLOWED,))
    assert [block.service_key for block in firewall.ruleset.blocks] == ["minecraft"]
    assert engine.snapshot().blocked == {HOST: ("Minecraft",)}


def test_set_mode_lifts_blocks_at_once(topology):
    firewall = FakeFirewall()
    engine = make_engine(topology, firewall=firewall)
    engine.poll()
    engine.replace_rules(HOST_MAC, (NEVER_ALLOWED,))
    engine.set_mode(HOST_MAC, Mode.NONE)
    assert firewall.ruleset.blocks == ()


def test_firewall_failure_is_noticed_once_until_it_recovers(topology):
    store = fresh_store()
    store.set_mode(HOST_MAC, Mode.PAUSED)
    firewall = FakeFirewall(failing=True)
    engine = make_engine(topology, firewall=firewall, store=store)
    engine.poll()
    engine.poll()
    assert [(n.severity, n.message) for n in engine.snapshot().notices] == [("error", "nft failed: boom")]
    firewall.failing = False
    engine.poll()
    firewall.failing = True
    engine.poll()
    assert len(engine.snapshot().notices) == 2


def test_restored_firewall_table_is_noticed(topology):
    firewall = FakeFirewall()
    firewall.restore_pending = True
    engine = make_engine(topology, firewall=firewall)
    engine.poll()
    assert [(n.severity, n.message) for n in engine.snapshot().notices] == [("warning", TABLE_RESTORED)]


def test_snapshot_only_carries_notices_after_the_given_sequence(topology):
    firewall = FakeFirewall()
    engine = make_engine(topology, firewall=firewall)
    firewall.restore_pending = True
    engine.poll()
    firewall.restore_pending = True
    engine.poll()
    snapshot = engine.snapshot(since=1)
    assert [notice.seq for notice in snapshot.notices] == [2]
    assert snapshot.last_seq == 2


def test_snapshot_is_not_changed_by_later_polls(topology):
    engine = make_engine(topology)
    engine.poll()
    snapshot = engine.snapshot()
    engine.poll()
    assert snapshot.hosts[HOST] is not engine.snapshot().hosts[HOST]
    assert len(snapshot.hosts[HOST].history) == 1


def test_run_polls_until_stopped(topology):
    polls = []

    def read_flows():
        polls.append(1)
        if len(polls) == 3:
            engine.stop()
        return [WEB]

    engine = make_engine(topology, read_flows)
    engine.run()
    assert len(polls) == 3
