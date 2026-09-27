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
import tomllib
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path

BUNDLED_SERVICES = resources.files("network_snooker").joinpath("services.toml")
OVERRIDE_SERVICES = Path("/etc/network-snooker/services.toml")
CATEGORIES = frozenset({"game", "social"})
PORT_PROTOCOLS = frozenset({"tcp", "udp"})


class CatalogError(RuntimeError):
    pass


@dataclass(frozen=True)
class PortRange:
    protocol: str
    start: int
    end: int


@dataclass(frozen=True)
class Service:
    key: str
    name: str
    category: str
    ports: tuple[PortRange, ...] = ()
    domains: tuple[str, ...] = ()
    cidrs: tuple[str, ...] = ()


@dataclass(frozen=True)
class Catalog:
    services: dict[str, Service] = field(default_factory=dict)

    def __getitem__(self, key: str) -> Service:
        return self.services[key]

    def __iter__(self):
        return iter(self.services.values())

    def __contains__(self, key: str) -> bool:
        return key in self.services


def _parse_port(source: str, spec: str) -> PortRange:
    try:
        protocol, ports = spec.split("/", 1)
        start, _, end = ports.partition("-")
        start_port, end_port = int(start), int(end or start)
    except ValueError:
        raise CatalogError(f"{source}: bad port '{spec}', expected 'tcp/1234' or 'udp/1000-2000'") from None
    if protocol not in PORT_PROTOCOLS:
        raise CatalogError(f"{source}: bad protocol '{protocol}' in '{spec}', expected tcp or udp")
    if not (1 <= start_port <= end_port <= 65535):
        raise CatalogError(f"{source}: bad port range '{spec}'")
    return PortRange(protocol, start_port, end_port)


def _parse_cidr(source: str, cidr: str) -> str:
    try:
        ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        raise CatalogError(f"{source}: bad CIDR '{cidr}'") from None
    return cidr


def _parse_service(source: str, key: str, entry: dict) -> Service:
    name = entry.get("name")
    category = entry.get("category")
    if not name:
        raise CatalogError(f"{source}: service '{key}' is missing 'name'")
    if category not in CATEGORIES:
        raise CatalogError(f"{source}: service '{key}' has bad category {category!r}, expected one of {sorted(CATEGORIES)}")
    return Service(
        key=key,
        name=name,
        category=category,
        ports=tuple(_parse_port(f"{source} [{key}]", spec) for spec in entry.get("ports", [])),
        domains=tuple(entry.get("domains", [])),
        cidrs=tuple(_parse_cidr(f"{source} [{key}]", cidr) for cidr in entry.get("cidrs", [])),
    )


def _load_file(path) -> dict[str, dict]:
    try:
        with path.open("rb") as handle:
            return tomllib.load(handle)
    except tomllib.TOMLDecodeError as error:
        raise CatalogError(f"{path}: invalid TOML: {error}") from error


def load_catalog(bundled=BUNDLED_SERVICES, override: Path = OVERRIDE_SERVICES) -> Catalog:
    services = {key: _parse_service(str(bundled), key, entry) for key, entry in _load_file(bundled).items()}
    if override.exists():
        overrides = _load_file(override)
        services.update({key: _parse_service(str(override), key, entry) for key, entry in overrides.items()})
    return Catalog(services)
