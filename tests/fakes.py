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


import tempfile
from datetime import datetime
from pathlib import Path

from network_snooker.catalog import Catalog, PortRange, Service
from network_snooker.client import RequestRefused
from network_snooker.conntrack_source import Endpoints, Flow
from network_snooker.daemon import Engine, RequestError
from network_snooker.firewall import FirewallError, Ruleset
from network_snooker.neighbors import Neighbors
from network_snooker.policy import PolicyStore
from network_snooker.tracker import Tracker

WEB = Flow(
    "tcp",
    Endpoints("192.168.1.10", "93.184.216.34", 51234, 443),
    Endpoints("93.184.216.34", "203.0.113.5", 443, 51234),
    1200,
    10,
    9000,
    8,
)
PING = Flow("icmp", Endpoints("203.0.113.5", "8.8.8.8"), Endpoints("8.8.8.8", "203.0.113.5"), 84, 1, 84, 1, 7)
HOST_MAC = "aa:bb:cc:dd:ee:01"
OTHER_MAC = "aa:bb:cc:dd:ee:02"
NEIGHBOR_MAP = {"192.168.1.10": HOST_MAC, "192.168.1.20": OTHER_MAC}
MONDAY_NOON = datetime(2026, 9, 28, 12, 0)
TEST_CATALOG = Catalog({"minecraft": Service("minecraft", "Minecraft", "game", ports=(PortRange("tcp", 25565, 25565),))})


class FakeResolver:
    def __init__(self, names=None):
        self.names = names or {"192.168.1.10": "laptop"}

    def name(self, ip):
        return self.names.get(ip, ip)


class FakeFirewall:
    def __init__(self, available=True, failing=False):
        self.available = available
        self.unavailable_reason = "nft not found; pausing unavailable"
        self.failing = failing
        self.ruleset = Ruleset()
        self.restore_pending = False

    def ensure(self):
        restored, self.restore_pending = self.restore_pending, False
        return restored

    def apply(self, ruleset):
        if self.failing:
            raise FirewallError("nft failed: boom")
        self.ruleset = ruleset


class FakeDomainSets:
    def mark_active(self, keys):
        pass

    def addresses(self, key):
        return frozenset(), frozenset()


def fresh_store() -> PolicyStore:
    return PolicyStore(Path(tempfile.mkdtemp()) / "policies.json")


def make_neighbors(mapping=NEIGHBOR_MAP) -> Neighbors:
    return Neighbors(read=lambda: mapping)


def make_engine(topology, read_flows=lambda: [WEB], firewall=None, store=None, neighbors=None, resolver=None, tracker=None, interval=0.01, clock=None):
    return Engine(
        tracker or Tracker(topology),
        read_flows,
        resolver or FakeResolver(),
        firewall or FakeFirewall(),
        store or fresh_store(),
        TEST_CATALOG,
        neighbors or make_neighbors(),
        FakeDomainSets(),
        interval=interval,
        clock=clock or (lambda: MONDAY_NOON),
    )


# Stands in for the daemon's own polling thread: each snapshot the interface
# asks for first lets the engine poll, so tests need no timing of their own.
class InProcessClient:
    def __init__(self, engine):
        self.engine = engine
        self.stopped = False

    def snapshot(self, since=0):
        self.engine.poll()
        return self.engine.snapshot(since)

    def toggle_pause(self, host_id):
        self._call(self.engine.toggle_pause, host_id)

    def set_mode(self, mac, mode):
        self._call(self.engine.set_mode, mac, mode)

    def replace_rules(self, mac, rules):
        self._call(self.engine.replace_rules, mac, rules)

    def stop(self):
        self.stopped = True

    @staticmethod
    def _call(action, *arguments):
        try:
            action(*arguments)
        except RequestError as error:
            raise RequestRefused(str(error)) from error
