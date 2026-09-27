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
