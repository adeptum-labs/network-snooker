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

import json
import subprocess

STALE_STATES = frozenset({"FAILED", "INCOMPLETE"})


def read_neighbors(run=subprocess.run) -> dict[str, str]:
    try:
        result = run(("ip", "-j", "neigh", "show"), capture_output=True, text=True, check=True)
        entries = json.loads(result.stdout or "[]")
    except (OSError, subprocess.CalledProcessError, ValueError):
        return {}
    return {
        entry["dst"]: entry["lladdr"]
        for entry in entries
        if "lladdr" in entry and entry.get("state", ["FAILED"])[0] not in STALE_STATES
    }


# DHCP leases and ARP entries age out well before a device stops being
# relevant to a schedule, so a MAC once seen for an IP is kept until another
# MAC claims that IP, rather than being dropped when the neighbour entry does.
class Neighbors:
    def __init__(self, read=read_neighbors) -> None:
        self._read = read
        self._mac_by_ip: dict[str, str] = {}

    def refresh(self) -> None:
        self._mac_by_ip.update(self._read())

    def mac(self, ip: str) -> str | None:
        return self._mac_by_ip.get(ip)

    def ips(self, mac: str) -> frozenset[str]:
        return frozenset(ip for ip, host_mac in self._mac_by_ip.items() if host_mac == mac)
