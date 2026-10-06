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

import importlib.metadata
import subprocess
import sys

import pytest

import network_snooker
import network_snooker.__main__ as entry
from network_snooker.__main__ import accounting_enabled, ensure_accounting, parse_args, preflight_errors
from network_snooker.catalog import CatalogError
from network_snooker.client import DaemonError


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


@pytest.fixture
def interface_prerequisites(monkeypatch):
    monkeypatch.setattr(entry, "preflight_errors", lambda euid, path: [])
    monkeypatch.setattr(entry, "ensure_accounting", lambda: True)


def test_main_reports_catalog_failure(monkeypatch, interface_prerequisites, capsys):
    def fail():
        raise CatalogError("bad catalog")

    monkeypatch.setattr(entry, "load_catalog", fail)
    assert entry.main([]) == 1
    assert "bad catalog" in capsys.readouterr().err


def test_main_reports_a_daemon_that_fails_to_start(monkeypatch, interface_prerequisites, capsys):
    monkeypatch.setattr(entry, "load_catalog", lambda: object())
    monkeypatch.setattr(entry, "ensure_daemon", lambda client, args: False)
    assert entry.main([]) == 1
    assert str(entry.LOG_PATH) in capsys.readouterr().err


def test_main_reports_a_daemon_that_fails_to_restart(monkeypatch, interface_prerequisites, capsys):
    monkeypatch.setattr(entry, "load_catalog", lambda: object())
    monkeypatch.setattr(entry, "DaemonClient", FakeClient)
    monkeypatch.setattr(entry, "ensure_daemon", lambda client, args: True)
    monkeypatch.setattr(entry, "ensure_current_daemon", lambda client, args: False)
    assert entry.main([]) == 1
    assert str(entry.LOG_PATH) in capsys.readouterr().err


def test_main_runs_the_interface_against_the_daemon(monkeypatch, interface_prerequisites):
    started = []

    class FakeApp:
        def __init__(self, client, catalog):
            started.append((client, catalog))

        def run(self):
            started.append("run")

    client = FakeClient()
    monkeypatch.setattr(entry, "load_catalog", lambda: "catalog")
    monkeypatch.setattr(entry, "DaemonClient", lambda: client)
    monkeypatch.setattr(entry, "ensure_daemon", lambda client, args: True)
    monkeypatch.setattr(entry, "SnookerApp", FakeApp)
    assert entry.main([]) == 0
    assert started == [(client, "catalog"), "run"]


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
    def __init__(self, running=True, version=None):
        self.running = running
        self.daemon_version = version or network_snooker.package_version()
        self.stops = 0

    def is_running(self):
        return self.running

    def version(self):
        return self.daemon_version

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


def test_main_daemon_runs_the_daemon_with_timestamped_logging(monkeypatch):
    calls = []
    monkeypatch.setattr(entry, "preflight_errors", lambda euid, path: [])
    monkeypatch.setattr(entry, "accounting_enabled", lambda: True)
    monkeypatch.setattr(entry.logging, "basicConfig", lambda **options: calls.append(options))
    monkeypatch.setattr(entry, "run_daemon", lambda interval, lan: calls.append((interval, lan)) or 0)
    assert entry.main(["daemon", "--interval", "2"]) == 0
    assert calls == [{"format": entry.DAEMON_LOG_FORMAT}, (2.0, None)]
    assert "%(asctime)s" in entry.DAEMON_LOG_FORMAT


class StartingClient:
    def __init__(self, starts_after_checks):
        self.remaining = starts_after_checks

    def is_running(self):
        self.remaining -= 1
        return self.remaining < 0


class SpawnedProcess:
    def __init__(self, exit_code=None):
        self.exit_code = exit_code

    def poll(self):
        return self.exit_code


class Spawner:
    def __init__(self, process=None):
        self.process = process or SpawnedProcess()
        self.calls = []

    def __call__(self, command, **options):
        self.calls.append((command, options))
        return self.process


def daemon_args(*argv):
    return parse_args(list(argv))


def test_daemon_command_repeats_the_options():
    command = entry.daemon_command(daemon_args("--interval", "2", "--lan", "10.0.0.0/8", "--lan", "fd00::/8"))
    assert command == [sys.executable, "-m", "network_snooker", "daemon", "--interval", "2.0", "--lan", "10.0.0.0/8", "--lan", "fd00::/8"]


def test_a_running_daemon_is_not_started_again(tmp_path):
    spawner = Spawner()
    assert entry.ensure_daemon(FakeClient(), daemon_args(), spawn=spawner, log_path=tmp_path / "log")
    assert spawner.calls == []


def test_options_are_reported_as_ignored_by_a_running_daemon(tmp_path, capsys):
    entry.ensure_daemon(FakeClient(), daemon_args("--lan", "10.0.0.0/8"), spawn=Spawner(), log_path=tmp_path / "log")
    assert "already running" in capsys.readouterr().err


def test_a_missing_daemon_is_started_detached_and_awaited(tmp_path):
    spawner = Spawner()
    assert entry.ensure_daemon(StartingClient(3), daemon_args(), spawn=spawner, log_path=tmp_path / "log", sleep=lambda seconds: None)
    (command, options), = spawner.calls
    assert command == entry.daemon_command(daemon_args())
    assert options["start_new_session"] is True
    assert options["stdin"] == subprocess.DEVNULL


def test_the_daemon_writes_to_the_log(tmp_path):
    spawner = Spawner()
    entry.ensure_daemon(StartingClient(1), daemon_args(), spawn=spawner, log_path=tmp_path / "log", sleep=lambda seconds: None)
    assert (tmp_path / "log").exists()
    assert spawner.calls[0][1]["stdout"] is spawner.calls[0][1]["stderr"]


def test_a_daemon_that_exits_at_once_is_a_failure(tmp_path):
    spawner = Spawner(SpawnedProcess(exit_code=1))
    assert not entry.ensure_daemon(StartingClient(10**6), daemon_args(), spawn=spawner, log_path=tmp_path / "log", sleep=lambda seconds: None)


def test_a_daemon_that_never_answers_is_a_failure(tmp_path):
    assert not entry.ensure_daemon(StartingClient(10**9), daemon_args(), spawn=Spawner(), log_path=tmp_path / "log", timeout=0.05, sleep=lambda seconds: None)


def test_a_frozen_executable_starts_the_daemon_without_a_module_flag(monkeypatch):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    command = entry.daemon_command(daemon_args("--interval", "2"))
    assert command == [sys.executable, "daemon", "--interval", "2.0"]


def test_a_frozen_daemon_gets_its_own_unpacked_copy_of_the_bundle(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    spawner = Spawner()
    entry.ensure_daemon(StartingClient(1), daemon_args(), spawn=spawner, log_path=tmp_path / "log", sleep=lambda seconds: None)
    assert spawner.calls[0][1]["env"]["PYINSTALLER_RESET_ENVIRONMENT"] == "1"


def test_a_daemon_from_source_keeps_the_environment_it_inherits(tmp_path, monkeypatch):
    monkeypatch.delattr(sys, "frozen", raising=False)
    spawner = Spawner()
    entry.ensure_daemon(StartingClient(1), daemon_args(), spawn=spawner, log_path=tmp_path / "log", sleep=lambda seconds: None)
    assert spawner.calls[0][1]["env"] is None


@pytest.mark.parametrize("flag", ["--version", "-V"])
def test_version_flags_print_the_package_version_and_exit(flag, capsys):
    with pytest.raises(SystemExit) as exit_info:
        parse_args([flag])
    assert exit_info.value.code == 0
    assert capsys.readouterr().out == f"network-snooker {importlib.metadata.version('network-snooker')}\n"


def test_version_needs_no_root(monkeypatch, capsys):
    monkeypatch.setattr(entry.os, "geteuid", lambda: 1000)
    with pytest.raises(SystemExit) as exit_info:
        entry.main(["--version"])
    assert exit_info.value.code == 0
    assert "network-snooker " in capsys.readouterr().out


def test_version_is_unknown_without_installed_metadata(monkeypatch):
    def missing(name):
        raise importlib.metadata.PackageNotFoundError(name)

    monkeypatch.setattr(network_snooker.importlib.metadata, "version", missing)
    assert network_snooker.package_version() == "unknown"


class Restarter:
    def __init__(self, stop_code=0, started=True):
        self.stop_code = stop_code
        self.started = started
        self.calls = []

    def stop(self, client):
        self.calls.append("stop")
        return self.stop_code

    def start(self, client, args):
        self.calls.append("start")
        return self.started


def ensure_current(client, answer, restarter):
    prompts = []
    result = entry.ensure_current_daemon(client, daemon_args(), ask=lambda prompt: prompts.append(prompt) or answer, stop=restarter.stop, start=restarter.start)
    return result, prompts


def test_a_daemon_of_the_same_version_is_kept_without_asking():
    restarter = Restarter()
    assert ensure_current(FakeClient(), "y", restarter) == (True, [])
    assert restarter.calls == []


def test_a_daemon_of_another_version_is_kept_when_restarting_is_declined():
    restarter = Restarter()
    result, (prompt,) = ensure_current(FakeClient(version="0.0.1"), "n", restarter)
    assert result is True
    assert "0.0.1" in prompt and network_snooker.package_version() in prompt
    assert restarter.calls == []


def test_a_daemon_of_another_version_is_restarted_when_asked():
    restarter = Restarter()
    assert ensure_current(FakeClient(version="0.0.1"), "y", restarter)[0] is True
    assert restarter.calls == ["stop", "start"]


@pytest.mark.parametrize(("stop_code", "started", "calls"), [(1, True, ["stop"]), (0, False, ["stop", "start"])])
def test_a_failed_restart_is_a_failure(stop_code, started, calls):
    restarter = Restarter(stop_code, started)
    assert ensure_current(FakeClient(version="0.0.1"), "y", restarter)[0] is False
    assert restarter.calls == calls


def test_help_says_what_the_tool_is_and_does(capsys):
    with pytest.raises(SystemExit):
        parse_args(["--help"])
    text = " ".join(capsys.readouterr().out.split())
    assert "Terminal monitor" in text
    assert "connection tracking" in text
    assert "block services" in text
    assert "nftables" in text
    assert "background daemon" in text


def help_lines(capsys, monkeypatch, columns, *argv):
    monkeypatch.setenv("COLUMNS", str(columns))
    with pytest.raises(SystemExit):
        parse_args([*argv, "--help"])
    return capsys.readouterr().out.splitlines()


@pytest.mark.parametrize("argv", [[], ["daemon"], ["stop"]])
def test_help_is_never_wider_than_80_columns(capsys, monkeypatch, argv):
    assert max(map(len, help_lines(capsys, monkeypatch, 200, *argv))) <= 80


def test_help_still_fits_a_narrow_terminal(capsys, monkeypatch):
    assert max(map(len, help_lines(capsys, monkeypatch, 60))) <= 60


def test_help_uses_the_80_columns_it_is_allowed(capsys, monkeypatch):
    assert max(map(len, help_lines(capsys, monkeypatch, 200))) >= 70
