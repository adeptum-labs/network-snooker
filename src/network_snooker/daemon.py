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


import logging
import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import replace
from datetime import datetime

from network_snooker.conntrack_source import ConntrackError, Flow
from network_snooker.enforcement import blocked_now, build_ruleset
from network_snooker.firewall import FirewallError
from network_snooker.policy import Mode, Rule
from network_snooker.tracker import ROUTER_ID, HostStats, Tracker
from network_snooker.wire import Notice, Snapshot

log = logging.getLogger(__name__)

TABLE_RESTORED = "Firewall table was removed externally; pauses restored"
NOT_ENFORCED = "Saved but not enforced: {}"
NOTICE_LIMIT = 50


class RequestError(RuntimeError):
    pass


def _copy(host: HostStats) -> HostStats:
    return replace(host, ips=set(host.ips), flows=list(host.flows), history=deque(host.history, maxlen=host.history.maxlen))


# Owns everything that outlives the terminal UI: capture, enforcement and the
# policies. One lock serialises the poll thread and the request threads; the
# slow conntrack read stays outside it so a snapshot never waits for it.
class Engine:
    def __init__(
        self,
        tracker: Tracker,
        read_flows: Callable[[], list[Flow]],
        resolver,
        firewall,
        store,
        catalog,
        neighbors,
        domain_sets,
        interval: float = 1.0,
        clock: Callable[[], datetime] = datetime.now,
    ) -> None:
        self.tracker = tracker
        self.resolver = resolver
        self.firewall = firewall
        self.store = store
        self.catalog = catalog
        self.neighbors = neighbors
        self.domain_sets = domain_sets
        self.interval = interval
        self.clock = clock
        self._read_flows = read_flows
        self._lock = threading.Lock()
        self._stopped = threading.Event()
        self._notices: deque[Notice] = deque(maxlen=NOTICE_LIMIT)
        self._last_seq = 0
        self._error = ""
        self._enforce_error = ""

    # Waiting only after a poll finishes keeps snapshots in order; overlapping
    # reads would make older counters look like resets.
    def run(self) -> None:
        while not self._stopped.is_set():
            try:
                self.poll()
            except Exception:
                log.exception("poll failed")
            self._stopped.wait(self.interval)

    def stop(self) -> None:
        self._stopped.set()

    def poll(self) -> None:
        with self._lock:
            self.neighbors.refresh()
            self._check_firewall()
            self._enforce()
        try:
            flows = self._read_flows()
        except ConntrackError as error:
            self._error = str(error)
        else:
            with self._lock:
                self.tracker.update(flows, time.monotonic())
                self._error = ""

    def toggle_pause(self, host_id: str) -> None:
        with self._lock:
            if host_id == ROUTER_ID:
                raise RequestError("The router cannot be paused")
            if not self.firewall.available:
                raise RequestError(self.firewall.unavailable_reason)
            if (mac := self.neighbors.mac(host_id)) is None:
                raise RequestError("Unknown MAC address; host cannot be paused")
            self.store.toggle_paused(mac)
            self._enforce(after_change=True)

    def set_mode(self, mac: str, mode: Mode) -> None:
        with self._lock:
            self.store.set_mode(mac, mode)
            self._enforce(after_change=True)

    def replace_rules(self, mac: str, rules: tuple[Rule, ...]) -> None:
        with self._lock:
            self.store.replace_rules(mac, rules)
            self._enforce(after_change=True)

    def snapshot(self, since: int = 0) -> Snapshot:
        with self._lock:
            hosts = {host_id: _copy(host) for host_id, host in self.tracker.hosts.items()}
            macs = {host_id: mac for host_id in hosts if (mac := self.neighbors.mac(host_id))}
            now = self.clock()
            blocked = {host_id: names for host_id, mac in macs.items() if (names := blocked_now(self.store, self.catalog, mac, now))}
            return Snapshot(
                hosts=hosts,
                macs=macs,
                blocked=blocked,
                names=self._names(hosts),
                policies={policy.mac: policy for policy in self.store.all()},
                interval=self.interval,
                error=self._error,
                notices=tuple(notice for notice in self._notices if notice.seq > since),
                last_seq=self._last_seq,
            )

    def _names(self, hosts: dict[str, HostStats]) -> dict[str, str]:
        ips = {host_id for host_id in hosts if host_id != ROUTER_ID}
        ips.update(flow.remote_ip for host in hosts.values() for flow in host.flows)
        return {ip: self.resolver.name(ip) for ip in ips}

    def _notify(self, severity: str, message: str) -> None:
        self._last_seq += 1
        self._notices.append(Notice(self._last_seq, severity, message))

    def _check_firewall(self) -> None:
        try:
            restored = self.firewall.ensure()
        except FirewallError as error:
            self._notify("error", str(error))
            return
        if restored:
            self._notify("warning", TABLE_RESTORED)

    # Firewall unavailability is noticed only when a change asked for
    # enforcement; renotifying it on every poll would bury other notices. A
    # failing apply is noticed once, until an apply succeeds again, except
    # when a change asked for it: whoever made that change needs to hear it.
    def _enforce(self, after_change: bool = False) -> None:
        if not self.firewall.available:
            if after_change:
                self._notify("error", NOT_ENFORCED.format(self.firewall.unavailable_reason))
            return
        ruleset = build_ruleset(self.store, self.neighbors, self.catalog, self.domain_sets, self.clock())
        try:
            self.firewall.apply(ruleset)
        except FirewallError as error:
            if after_change or str(error) != self._enforce_error:
                self._notify("error", str(error))
                log.error("enforcement failed: %s", error)
            self._enforce_error = str(error)
        else:
            self._enforce_error = ""
