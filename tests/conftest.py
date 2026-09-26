import pytest

from network_snooker.topology import build_topology

ADDRESSES = [
    {
        "ifname": "lo",
        "flags": ["LOOPBACK", "UP"],
        "addr_info": [
            {"family": "inet", "local": "127.0.0.1", "prefixlen": 8, "scope": "host"},
            {"family": "inet6", "local": "::1", "prefixlen": 128, "scope": "host"},
        ],
    },
    {
        "ifname": "eth0",
        "flags": ["BROADCAST", "UP"],
        "addr_info": [{"family": "inet", "local": "203.0.113.5", "prefixlen": 24, "scope": "global"}],
    },
    {
        "ifname": "br-lan",
        "flags": ["BROADCAST", "UP"],
        "addr_info": [
            {"family": "inet", "local": "192.168.1.1", "prefixlen": 24, "scope": "global"},
            {"family": "inet6", "local": "2001:db8:1::1", "prefixlen": 64, "scope": "global"},
            {"family": "inet6", "local": "fe80::1", "prefixlen": 64, "scope": "link"},
        ],
    },
]
DEFAULT_ROUTES = [{"dst": "default", "gateway": "203.0.113.1", "dev": "eth0", "flags": []}]


@pytest.fixture
def topology():
    return build_topology(ADDRESSES, DEFAULT_ROUTES)
