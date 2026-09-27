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

import ipaddress
import subprocess
import threading
from dataclasses import dataclass, field

from network_snooker.catalog import PortRange

TABLE = "inet network_snooker"
NFT_MISSING = "nft not found; pausing unavailable"
BASE_SCRIPT = f"table {TABLE}\ndelete table {TABLE}\n"
CONNTRACK_MATCHES = ("-s", "-d", "--reply-src")
COMMAND_TIMEOUT = 5


class FirewallError(RuntimeError):
    pass


@dataclass(frozen=True)
class ServiceBlock:
    mac: str
    service_key: str
    ports: tuple[PortRange, ...] = ()
    v4: frozenset[str] = frozenset()
    v6: frozenset[str] = frozenset()


@dataclass(frozen=True)
class Ruleset:
    paused_macs: frozenset[str] = frozenset()
    paused_ips: frozenset[str] = frozenset()
    blocks: tuple[ServiceBlock, ...] = ()
    mac_ips: dict[str, frozenset[str]] = field(default_factory=dict)


EMPTY_RULESET = Ruleset()


def _set_name(service_key: str, version: int) -> str:
    return f"svc_{service_key}{version}"


def _port_expr(port: PortRange) -> str:
    span = str(port.start) if port.start == port.end else f"{port.start}-{port.end}"
    return f"{port.protocol} dport {span}"


def _service_addresses(ruleset: Ruleset) -> dict[str, tuple[frozenset[str], frozenset[str]]]:
    return {block.service_key: (block.v4, block.v6) for block in ruleset.blocks}


def _block_keys(ruleset: Ruleset) -> frozenset[tuple[str, str]]:
    return frozenset((block.mac, block.service_key) for block in ruleset.blocks)


# A host loses network access the moment it becomes paused or gains a new
# blocked service; without this, an already-offloaded flow would keep
# bypassing the forward hook until it ended on its own.
def _newly_affected_macs(old: Ruleset, new: Ruleset) -> frozenset[str]:
    newly_paused = new.paused_macs - old.paused_macs
    newly_blocked = {mac for mac, _ in _block_keys(new) - _block_keys(old)}
    return newly_paused | newly_blocked


def _forward_rules(ruleset: Ruleset) -> str:
    lines = ["ip daddr @paused4 drop", "ip6 daddr @paused6 drop"]
    lines += [f"ether saddr {mac} drop" for mac in sorted(ruleset.paused_macs)]
    for block in sorted(ruleset.blocks, key=lambda b: (b.mac, b.service_key)):
        lines += [f"ether saddr {block.mac} {_port_expr(port)} drop" for port in block.ports]
        if block.v4:
            lines.append(f"ether saddr {block.mac} ip daddr @{_set_name(block.service_key, 4)} drop")
        if block.v6:
            lines.append(f"ether saddr {block.mac} ip6 daddr @{_set_name(block.service_key, 6)} drop")
    return "".join(f"        {line}\n" for line in lines)


def _set_declarations(ruleset: Ruleset) -> str:
    keys = sorted(_service_addresses(ruleset))
    declarations = [f"    set {_set_name(key, version)} {{ type {kind}; flags interval; }}\n" for key in keys for version, kind in ((4, "ipv4_addr"), (6, "ipv6_addr"))]
    return "".join(declarations)


def _elements(ruleset: Ruleset) -> str:
    lines = [f"add element {TABLE} {'paused6' if ipaddress.ip_address(ip).version == 6 else 'paused4'} {{ {ip} }}\n" for ip in sorted(ruleset.paused_ips)]
    for key, (v4, v6) in sorted(_service_addresses(ruleset).items()):
        for version, addresses in ((4, v4), (6, v6)):
            if addresses:
                lines.append(f"add element {TABLE} {_set_name(key, version)} {{ {', '.join(sorted(addresses))} }}\n")
    return "".join(lines)


def _table_script(ruleset: Ruleset) -> str:
    return (
        BASE_SCRIPT
        + f"table {TABLE} {{\n"
        + "    set paused4 { type ipv4_addr; }\n"
        + "    set paused6 { type ipv6_addr; }\n"
        + _set_declarations(ruleset)
        + "    chain forward {\n        type filter hook forward priority -10; policy accept;\n"
        + _forward_rules(ruleset)
        + "    }\n}\n"
        + _elements(ruleset)
    )


class Firewall:
    def __init__(self, nft_path: str | None, run=subprocess.run) -> None:
        self._nft_path = nft_path
        self._run = run
        self._lock = threading.Lock()
        self.available = False
        self.unavailable_reason = NFT_MISSING
        self.ruleset = EMPTY_RULESET

    def setup(self) -> None:
        if self._nft_path is None:
            return
        try:
            self._run_script(_table_script(EMPTY_RULESET))
        except FirewallError as error:
            self.unavailable_reason = f"pausing unavailable: {error}"
            return
        self.available = True

    def apply(self, ruleset: Ruleset) -> None:
        with self._lock:
            if not self.available:
                raise FirewallError(self.unavailable_reason)
            if ruleset == self.ruleset:
                return
            self._run_script(_table_script(ruleset))
            newly_affected = _newly_affected_macs(self.ruleset, ruleset)
            self.ruleset = ruleset
        for mac in newly_affected:
            for ip in ruleset.mac_ips.get(mac, ()):
                self._drop_connections(ip)

    def ensure(self) -> bool:
        with self._lock:
            if not (self.available and self.ruleset != EMPTY_RULESET):
                return False
            try:
                self._run_script(f"list table {TABLE}\n")
                return False
            except FirewallError:
                self._run_script(_table_script(self.ruleset))
                return True

    def teardown(self) -> None:
        if not self.available:
            return
        # Exiting must not fail just because the table is already gone.
        try:
            self._run_script(f"delete table {TABLE}\n")
        except FirewallError:
            pass
        self.available = False
        self.ruleset = EMPTY_RULESET

    # Offloaded flows (flowtables) skip the forward hook; deleting their
    # conntrack entries forces the host's packets back through the drop rules.
    def _drop_connections(self, ip: str) -> None:
        for match in CONNTRACK_MATCHES:
            try:
                self._run(("conntrack", "-D", match, ip), capture_output=True, text=True, timeout=COMMAND_TIMEOUT, check=False)
            except (OSError, subprocess.TimeoutExpired):
                pass

    def _run_script(self, script: str) -> None:
        try:
            result = self._run((self._nft_path, "-f", "-"), input=script, capture_output=True, text=True, timeout=COMMAND_TIMEOUT, check=False)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise FirewallError(f"nft failed: {error}") from error
        if result.returncode != 0:
            raise FirewallError(f"nft failed: {result.stderr.strip()}")
