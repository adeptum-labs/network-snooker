import argparse
import ipaddress
import os
import shutil
import subprocess
import sys
from pathlib import Path

from network_snooker.app import SnookerApp
from network_snooker.conntrack_source import read_flows
from network_snooker.firewall import Firewall
from network_snooker.names import NameResolver
from network_snooker.topology import TopologyError, detect_topology
from network_snooker.tracker import Tracker

ACCOUNTING_PATH = Path("/proc/sys/net/netfilter/nf_conntrack_acct")
ENABLE_ACCOUNTING = ("sysctl", "-w", "net.netfilter.nf_conntrack_acct=1")


def _positive_float(value: str) -> float:
    try:
        number = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a number: {value}") from None
    if number <= 0:
        raise argparse.ArgumentTypeError(f"must be greater than 0: {value}")
    return number


def _network(value: str) -> str:
    try:
        ipaddress.ip_network(value, strict=False)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a subnet: {value}") from None
    return value


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="network-snooker", description="Live per-host traffic on a Linux router.")
    parser.add_argument("--interval", type=_positive_float, default=1.0, help="poll interval in seconds (default 1)")
    parser.add_argument("--lan", type=_network, action="append", metavar="CIDR", help="LAN subnet, repeatable; overrides detection")
    return parser.parse_args(argv)


def preflight_errors(euid: int, conntrack_path: str | None) -> list[str]:
    errors = []
    if euid != 0:
        errors.append("network-snooker must run as root.")
    if conntrack_path is None:
        errors.append("conntrack not found; install the 'conntrack' package.")
    return errors


def accounting_enabled(path: Path = ACCOUNTING_PATH) -> bool:
    try:
        return path.read_text().strip() == "1"
    except OSError:
        return False


def ensure_accounting(ask=input, run=subprocess.run, path: Path = ACCOUNTING_PATH) -> bool:
    if accounting_enabled(path):
        return True
    answer = ask("Byte counters are off (nf_conntrack_acct=0). Enable them now? [y/N] ")
    if answer.strip().lower() != "y":
        return False
    return run(ENABLE_ACCOUNTING, check=False).returncode == 0


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    errors = preflight_errors(os.geteuid(), shutil.which("conntrack"))
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    if not ensure_accounting():
        print("Byte counters are required; exiting.", file=sys.stderr)
        return 1
    try:
        topology = detect_topology(args.lan)
    except TopologyError as error:
        print(error, file=sys.stderr)
        return 1
    firewall = Firewall(shutil.which("nft"))
    firewall.setup()
    resolver = NameResolver()
    try:
        SnookerApp(Tracker(topology), read_flows, resolver, firewall, args.interval).run()
    finally:
        firewall.teardown()
        resolver.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
