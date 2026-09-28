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

import subprocess

import pytest

import network_snooker.__main__ as entry
from network_snooker.__main__ import accounting_enabled, ensure_accounting, parse_args, preflight_errors
from network_snooker.catalog import CatalogError
from network_snooker.client import DaemonError
from network_snooker.policy import PolicyError
from network_snooker.topology import TopologyError


def test_defaults():
    args = parse_args([])
    assert (args.interval, args.lan) == (1.0, None)


def test_lan_is_repeatable():
    assert parse_args(["--lan", "10.0.0.0/8", "--lan", "fd00::/8"]).lan == ["10.0.0.0/8", "fd00::/8"]


@pytest.mark.parametrize("argv", [["--interval", "0"], ["--interval", "-1"], ["--interval", "x"], ["--lan", "nonsense"]])
def test_bad_arguments_exit_with_usage(argv, capsys):
    with pytest.raises(SystemExit) as exit_info:
        parse_args(argv)
    assert exit_info.value.code == 2
    assert "error:" in capsys.readouterr().err


def test_preflight_errors():
    assert preflight_errors(0, "/usr/sbin/conntrack") == []
    errors = preflight_errors(1000, None)
    assert len(errors) == 2
    assert "root" in errors[0]
    assert "conntrack" in errors[1]


def test_accounting_enabled(tmp_path):
    path = tmp_path / "acct"
    path.write_text("1\n")
    assert accounting_enabled(path)
    path.write_text("0\n")
    assert not accounting_enabled(path)
    assert not accounting_enabled(tmp_path / "absent")


def test_ensure_accounting_declined(tmp_path):
    path = tmp_path / "acct"
    path.write_text("0\n")
    calls = []
    assert not ensure_accounting(ask=lambda prompt: "n", run=lambda *a, **k: calls.append(a), path=path)
    assert calls == []


def test_ensure_accounting_enables(tmp_path):
    path = tmp_path / "acct"
    path.write_text("0\n")
    commands = []

    def run(command, **kwargs):
        commands.append(command)
        return subprocess.CompletedProcess(command, 0)

    assert ensure_accounting(ask=lambda prompt: "y", run=run, path=path)
    assert commands == [("sysctl", "-w", "net.netfilter.nf_conntrack_acct=1")]


def test_main_reports_topology_failure(monkeypatch, capsys):
    def fail(lan_override):
        raise TopologyError("cannot read 'ip -j addr'")

    monkeypatch.setattr(entry, "preflight_errors", lambda euid, path: [])
    monkeypatch.setattr(entry, "ensure_accounting", lambda: True)
    monkeypatch.setattr(entry, "detect_topology", fail)
    assert entry.main([]) == 1
    assert "cannot read 'ip -j addr'" in capsys.readouterr().err


def test_main_reports_catalog_failure(monkeypatch, capsys):
    monkeypatch.setattr(entry, "preflight_errors", lambda euid, path: [])
    monkeypatch.setattr(entry, "ensure_accounting", lambda: True)
    monkeypatch.setattr(entry, "detect_topology", lambda lan_override: None)

    def fail():
        raise CatalogError("bad catalog")

    monkeypatch.setattr(entry, "load_catalog", fail)
    assert entry.main([]) == 1
    assert "bad catalog" in capsys.readouterr().err


def test_main_reports_policy_store_failure(monkeypatch, capsys):
    monkeypatch.setattr(entry, "preflight_errors", lambda euid, path: [])
    monkeypatch.setattr(entry, "ensure_accounting", lambda: True)
    monkeypatch.setattr(entry, "detect_topology", lambda lan_override: None)
    monkeypatch.setattr(entry, "load_catalog", lambda: object())

    def fail():
        raise PolicyError("bad policy file")

    monkeypatch.setattr(entry, "PolicyStore", fail)
    assert entry.main([]) == 1
    assert "bad policy file" in capsys.readouterr().err


def test_main_tears_down_firewall_when_app_crashes(monkeypatch):
    events = []

    class FakeFirewall:
        def __init__(self, nft_path):
            pass

        def setup(self):
            events.append("setup")

        def teardown(self):
            events.append("teardown")

    class FakeDiscovery:
        def __init__(self, topology):
            pass

        def start(self):
            events.append("discovery started")

        def close(self):
            events.append("discovery closed")

    class FakeDomainSets:
        def __init__(self, catalog):
            pass

        def start(self):
            events.append("domain sets started")

        def close(self):
            events.append("domain sets closed")

    class CrashingApp:
        def __init__(self, *args):
            pass

        def run(self):
            raise RuntimeError("crash")

    monkeypatch.setattr(entry, "preflight_errors", lambda euid, path: [])
    monkeypatch.setattr(entry, "ensure_accounting", lambda: True)
    monkeypatch.setattr(entry, "detect_topology", lambda lan_override: None)
    monkeypatch.setattr(entry, "load_catalog", lambda: object())
    monkeypatch.setattr(entry, "PolicyStore", lambda: object())
    monkeypatch.setattr(entry, "Firewall", FakeFirewall)
    monkeypatch.setattr(entry, "ServiceDiscovery", FakeDiscovery)
    monkeypatch.setattr(entry, "DomainSets", FakeDomainSets)
    monkeypatch.setattr(entry, "SnookerApp", CrashingApp)
    with pytest.raises(RuntimeError, match="crash"):
        entry.main([])
    assert events == ["setup", "discovery started", "domain sets started", "teardown", "discovery closed", "domain sets closed"]


def test_daemon_command_and_its_options():
    args = parse_args(["daemon", "--interval", "2", "--lan", "10.0.0.0/8"])
    assert (args.command, args.interval, args.lan) == ("daemon", 2.0, ["10.0.0.0/8"])


def test_options_before_the_daemon_command_are_kept():
    args = parse_args(["--interval", "2", "daemon"])
    assert (args.command, args.interval) == ("daemon", 2.0)


def test_no_command_starts_the_interface():
    assert parse_args([]).command is None


def test_stop_command():
    assert parse_args(["stop"]).command == "stop"


def test_main_stop_asks_the_daemon_to_stop(monkeypatch):
    stopped = []
    monkeypatch.setattr(entry.os, "geteuid", lambda: 0)
    monkeypatch.setattr(entry, "DaemonClient", lambda: "client")
    monkeypatch.setattr(entry, "stop_daemon", lambda client: stopped.append(client) or 0)
    assert entry.main(["stop"]) == 0
    assert stopped == ["client"]


def test_main_stop_needs_root(monkeypatch, capsys):
    monkeypatch.setattr(entry.os, "geteuid", lambda: 1000)
    assert entry.main(["stop"]) == 1
    assert "root" in capsys.readouterr().err


class FakeClient:
    def __init__(self, running=True):
        self.running = running
        self.stops = 0

    def stop(self):
        if not self.running:
            raise DaemonError("daemon unreachable")
        self.stops += 1


def test_stop_daemon_waits_for_the_daemon_to_exit():
    client = FakeClient()
    waits = []
    assert entry.stop_daemon(client, wait_for_exit=lambda timeout: waits.append(timeout) or True) == 0
    assert (client.stops, waits) == (1, [entry.STOP_TIMEOUT])


def test_stop_daemon_reports_a_daemon_that_does_not_exit(capsys):
    assert entry.stop_daemon(FakeClient(), wait_for_exit=lambda timeout: False) == 1
    assert "did not stop" in capsys.readouterr().err


def test_stop_daemon_without_a_daemon_is_not_an_error(capsys):
    assert entry.stop_daemon(FakeClient(running=False), wait_for_exit=lambda timeout: True) == 0
    assert "not running" in capsys.readouterr().out


def test_main_daemon_needs_byte_counters(monkeypatch, capsys):
    monkeypatch.setattr(entry, "preflight_errors", lambda euid, path: [])
    monkeypatch.setattr(entry, "accounting_enabled", lambda: False)
    assert entry.main(["daemon"]) == 1
    assert "nf_conntrack_acct=1" in capsys.readouterr().err


def test_main_daemon_runs_the_daemon(monkeypatch):
    calls = []
    monkeypatch.setattr(entry, "preflight_errors", lambda euid, path: [])
    monkeypatch.setattr(entry, "accounting_enabled", lambda: True)
    monkeypatch.setattr(entry, "run_daemon", lambda interval, lan: calls.append((interval, lan)) or 0)
    assert entry.main(["daemon", "--interval", "2"]) == 0
    assert calls == [(2.0, None)]
