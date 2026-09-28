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

import argparse
import ipaddress
import os
import shutil
import subprocess
import sys
from pathlib import Path

from network_snooker.app import SnookerApp
from network_snooker.catalog import CatalogError, load_catalog
from network_snooker.client import DaemonClient, DaemonError
from network_snooker.conntrack_source import read_flows
from network_snooker.discovery import ServiceDiscovery
from network_snooker.domain_sets import DomainSets
from network_snooker.firewall import Firewall
from network_snooker.names import NameResolver
from network_snooker.neighbors import Neighbors
from network_snooker.policy import PolicyError, PolicyStore
from network_snooker.service import run_daemon, wait_until_unlocked
from network_snooker.topology import TopologyError, detect_topology
from network_snooker.tracker import Tracker

ACCOUNTING_PATH = Path("/proc/sys/net/netfilter/nf_conntrack_acct")
ENABLE_ACCOUNTING = ("sysctl", "-w", "net.netfilter.nf_conntrack_acct=1")
NOT_ROOT = "network-snooker must run as root."
STOP_TIMEOUT = 10


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


def _add_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--interval", type=_positive_float, help="poll interval in seconds (default 1)")
    parser.add_argument("--lan", type=_network, action="append", metavar="CIDR", help="LAN subnet, repeatable; overrides detection")


# The daemon subcommand suppresses its own defaults so that options given
# before it are not overwritten by the defaults set on the main parser.
def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="network-snooker", description="Live per-host traffic on a Linux router.")
    _add_options(parser)
    parser.set_defaults(interval=1.0)
    commands = parser.add_subparsers(dest="command", metavar="{daemon,stop}")
    _add_options(commands.add_parser("daemon", help="run the background daemon in the foreground", argument_default=argparse.SUPPRESS))
    commands.add_parser("stop", help="stop the background daemon and lift its blocks")
    return parser.parse_args(argv)


def preflight_errors(euid: int, conntrack_path: str | None) -> list[str]:
    errors = []
    if euid != 0:
        errors.append(NOT_ROOT)
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


def stop_daemon(client: DaemonClient, wait_for_exit=wait_until_unlocked) -> int:
    try:
        client.stop()
    except DaemonError:
        print("network-snooker daemon is not running")
        return 0
    if not wait_for_exit(STOP_TIMEOUT):
        print("network-snooker daemon did not stop", file=sys.stderr)
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.command == "stop":
        if os.geteuid() != 0:
            print(NOT_ROOT, file=sys.stderr)
            return 1
        return stop_daemon(DaemonClient())
    errors = preflight_errors(os.geteuid(), shutil.which("conntrack"))
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    if args.command == "daemon":
        if not accounting_enabled():
            print(f"Byte counters are off; run: {' '.join(ENABLE_ACCOUNTING)}", file=sys.stderr)
            return 1
        return run_daemon(args.interval, args.lan)
    if not ensure_accounting():
        print("Byte counters are required; exiting.", file=sys.stderr)
        return 1
    try:
        topology = detect_topology(args.lan)
    except TopologyError as error:
        print(error, file=sys.stderr)
        return 1
    try:
        catalog = load_catalog()
    except CatalogError as error:
        print(error, file=sys.stderr)
        return 1
    try:
        store = PolicyStore()
    except PolicyError as error:
        print(error, file=sys.stderr)
        return 1
    firewall = Firewall(shutil.which("nft"))
    firewall.setup()
    discovery = ServiceDiscovery(topology)
    discovery.start()
    resolver = NameResolver(discovery=discovery)
    domain_sets = DomainSets(catalog)
    domain_sets.start()
    try:
        SnookerApp(Tracker(topology), read_flows, resolver, firewall, store, catalog, Neighbors(), domain_sets, args.interval).run()
    finally:
        firewall.teardown()
        resolver.close()
        discovery.close()
        domain_sets.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
