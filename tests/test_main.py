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
