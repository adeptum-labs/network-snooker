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

from datetime import datetime

from network_snooker.catalog import Catalog
from network_snooker.domain_sets import DomainSets
from network_snooker.firewall import Ruleset, ServiceBlock
from network_snooker.neighbors import Neighbors
from network_snooker.policy import Mode, PolicyStore, blocked_services


# Every stored policy contributes its MAC's known IPs, even when nothing of
# it is currently enforced, so the firewall always has an address to drop
# connections for once that policy starts pausing or blocking something.
def build_ruleset(store: PolicyStore, neighbors: Neighbors, catalog: Catalog, domain_sets: DomainSets, now: datetime) -> Ruleset:
    paused_macs, blocks, mac_ips, active_services = set(), [], {}, set()
    for policy in store.all():
        mac_ips[policy.mac] = neighbors.ips(policy.mac)
        if policy.mode is Mode.PAUSED:
            paused_macs.add(policy.mac)
        for key in blocked_services(policy, now):
            if key not in catalog:
                continue
            active_services.add(key)
            v4, v6 = domain_sets.addresses(key)
            blocks.append(ServiceBlock(policy.mac, key, catalog[key].ports, v4, v6))
    domain_sets.mark_active(frozenset(active_services))
    paused_ips = frozenset(ip for mac in paused_macs for ip in mac_ips.get(mac, ()))
    return Ruleset(frozenset(paused_macs), paused_ips, tuple(blocks), mac_ips)


def blocked_now(store: PolicyStore, catalog: Catalog, mac: str | None, now: datetime) -> tuple[str, ...]:
    if mac is None:
        return ()
    keys = blocked_services(store.get(mac), now)
    return tuple(sorted(catalog[key].name for key in keys if key in catalog))


def host_mode(store: PolicyStore, mac: str | None) -> Mode:
    return Mode.NONE if mac is None else store.get(mac).mode
