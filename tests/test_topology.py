import json
import subprocess
from ipaddress import ip_network

from conftest import ADDRESSES, DEFAULT_ROUTES
from network_snooker.topology import build_topology, detect_topology


def test_lan_networks_exclude_wan_loopback_and_link_local(topology):
    assert topology.lan_networks == (ip_network("192.168.1.0/24"), ip_network("2001:db8:1::/64"))


def test_router_ips_exclude_loopback(topology):
    assert topology.is_router("203.0.113.5")
    assert topology.is_router("192.168.1.1")
    assert topology.is_router("fe80::1")
    assert not topology.is_router("127.0.0.1")


def test_is_local(topology):
    assert topology.is_local("192.168.1.10")
    assert topology.is_local("2001:db8:1::10")
    assert topology.is_local("203.0.113.5")
    assert not topology.is_local("93.184.216.34")
    assert not topology.is_local("127.0.0.1")
    assert not topology.is_local("fe80::99%br-lan")


def test_lan_override():
    topology = build_topology(ADDRESSES, DEFAULT_ROUTES, ["10.0.0.0/8"])
    assert topology.lan_networks == (ip_network("10.0.0.0/8"),)
    assert topology.is_local("10.2.3.4")
    assert not topology.is_local("192.168.1.10")


def test_detect_topology_runs_ip_json():
    outputs = {
        ("ip", "-j", "addr"): ADDRESSES,
        ("ip", "-j", "-4", "route", "show", "default"): DEFAULT_ROUTES,
        ("ip", "-j", "-6", "route", "show", "default"): [],
    }

    def run(command, **kwargs):
        return subprocess.CompletedProcess(command, 0, json.dumps(outputs[tuple(command)]), "")

    assert detect_topology(run=run).lan_networks == (ip_network("192.168.1.0/24"), ip_network("2001:db8:1::/64"))
