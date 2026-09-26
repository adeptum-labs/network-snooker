import subprocess

import pytest

from network_snooker.__main__ import accounting_enabled, ensure_accounting, parse_args, preflight_errors


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
