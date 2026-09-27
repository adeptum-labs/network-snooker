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

import socket
import time

from network_snooker.catalog import Catalog, Service
from network_snooker.domain_sets import DomainSets


def catalog():
    return Catalog(
        {
            "minecraft": Service("minecraft", "Minecraft", "game", domains=("minecraft.net",)),
            "tiktok": Service("tiktok", "TikTok", "social", domains=("tiktok.com",), cidrs=("1.2.3.0/24", "2001:db8::/32")),
        }
    )


def addrinfo(*addresses):
    return [(socket.AF_INET6 if ":" in a else socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, 443)) for a in addresses]


def wait_for(condition, timeout=2.0):
    deadline = time.monotonic() + timeout
    while not condition() and time.monotonic() < deadline:
        time.sleep(0.01)
    return condition()


def test_addresses_include_bundled_cidrs_even_when_unresolved():
    sets = DomainSets(catalog(), resolve=lambda domain, port: [])
    v4, v6 = sets.addresses("tiktok")
    assert v4 == frozenset({"1.2.3.0/24"})
    assert v6 == frozenset({"2001:db8::/32"})


def test_marking_active_triggers_resolution():
    sets = DomainSets(catalog(), resolve=lambda domain, port: addrinfo("93.184.216.34"))
    sets.start()
    sets.mark_active(frozenset({"minecraft"}))
    assert wait_for(lambda: sets.addresses("minecraft")[0] == frozenset({"93.184.216.34"}))
    sets.close()


def test_resolved_addresses_split_by_family():
    sets = DomainSets(catalog(), resolve=lambda domain, port: addrinfo("93.184.216.34", "2001:db8:1::10"))
    sets.start()
    sets.mark_active(frozenset({"minecraft"}))
    assert wait_for(lambda: sets.addresses("minecraft") == (frozenset({"93.184.216.34"}), frozenset({"2001:db8:1::10"})))
    sets.close()


def test_resolution_failure_leaves_addresses_unresolved():
    def failing(domain, port):
        raise socket.gaierror("nope")

    sets = DomainSets(catalog(), resolve=failing)
    sets.start()
    sets.mark_active(frozenset({"minecraft"}))
    time.sleep(0.05)
    assert sets.addresses("minecraft") == (frozenset(), frozenset())
    sets.close()


def test_inactive_service_is_never_resolved():
    calls = []

    def resolve(domain, port):
        calls.append(domain)
        return addrinfo("93.184.216.34")

    sets = DomainSets(catalog(), resolve=resolve)
    sets.start()
    time.sleep(0.05)
    sets.close()
    assert calls == []


def test_marking_already_active_does_not_re_resolve():
    calls = []

    def resolve(domain, port):
        calls.append(domain)
        return addrinfo("93.184.216.34")

    sets = DomainSets(catalog(), resolve=resolve)
    sets.start()
    sets.mark_active(frozenset({"minecraft"}))
    assert wait_for(lambda: len(calls) == 1)
    sets.mark_active(frozenset({"minecraft"}))
    time.sleep(0.05)
    sets.close()
    assert calls == ["minecraft.net"]


# A service that goes inactive stops being re-resolved, so its stale
# addresses age out on the next sweeps rather than sticking around forever.
def test_expired_addresses_are_dropped_once_service_goes_inactive():
    sets = DomainSets(catalog(), resolve=lambda domain, port: addrinfo("93.184.216.34"), resolve_interval=0.05, address_ttl=0.05)
    sets.start()
    sets.mark_active(frozenset({"minecraft"}))
    assert wait_for(lambda: sets.addresses("minecraft")[0] == frozenset({"93.184.216.34"}))
    sets.mark_active(frozenset())
    assert wait_for(lambda: sets.addresses("minecraft")[0] == frozenset(), timeout=1.0)
    sets.close()


def test_close_stops_thread():
    sets = DomainSets(catalog(), resolve=lambda domain, port: [])
    sets.start()
    sets.close()
    sets._thread.join(2)
    assert not sets._thread.is_alive()
