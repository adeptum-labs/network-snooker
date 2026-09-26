import ipaddress
import json
import subprocess
from dataclasses import dataclass

Address = ipaddress.IPv4Address | ipaddress.IPv6Address
Network = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass(frozen=True)
class Topology:
    router_ips: frozenset[Address]
    lan_networks: tuple[Network, ...]

    def is_router(self, ip: str) -> bool:
        return _address(ip) in self.router_ips

    def is_local(self, ip: str) -> bool:
        address = _address(ip)
        return address in self.router_ips or any(address in network for network in self.lan_networks)


def _address(ip: str) -> Address:
    return ipaddress.ip_address(ip.split("%")[0])


def _is_loopback(interface: dict) -> bool:
    return "LOOPBACK" in interface.get("flags", [])


def build_topology(addresses: list[dict], default_routes: list[dict], lan_override: list[str] | None = None) -> Topology:
    wan_devices = {route["dev"] for route in default_routes if "dev" in route}
    interfaces = [interface for interface in addresses if not _is_loopback(interface)]
    router_ips = frozenset(_address(info["local"]) for interface in interfaces for info in interface.get("addr_info", []))
    if lan_override:
        networks = tuple(ipaddress.ip_network(cidr, strict=False) for cidr in lan_override)
    else:
        networks = tuple(
            ipaddress.ip_interface(f"{info['local']}/{info['prefixlen']}").network
            for interface in interfaces
            if interface["ifname"] not in wan_devices
            for info in interface.get("addr_info", [])
            if info.get("scope") == "global"
        )
    return Topology(router_ips, networks)


def _ip_json(*arguments: str, run) -> list[dict]:
    result = run(("ip", "-j", *arguments), capture_output=True, text=True, check=True)
    return json.loads(result.stdout or "[]")


def detect_topology(lan_override: list[str] | None = None, run=subprocess.run) -> Topology:
    routes = _ip_json("-4", "route", "show", "default", run=run) + _ip_json("-6", "route", "show", "default", run=run)
    return build_topology(_ip_json("addr", run=run), routes, lan_override)
