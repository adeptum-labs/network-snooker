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

from collections import deque
from dataclasses import dataclass, field

from network_snooker.conntrack_source import Flow
from network_snooker.topology import Topology

ROUTER_ID = "router"
# A poll starts only after the previous one has finished, so at the default
# 1 s interval these samples cover at least the last five minutes.
HISTORY_SAMPLES = 300


@dataclass(frozen=True)
class FlowView:
    protocol: str
    local_ip: str
    local_port: int | None
    remote_ip: str
    remote_port: int | None
    rx_bytes: int
    tx_bytes: int
    rx_rate: float
    tx_rate: float
    service_port: int | None


@dataclass
class HostStats:
    host_id: str
    ips: set[str] = field(default_factory=set)
    rx_rate: float = 0.0
    tx_rate: float = 0.0
    rx_total: int = 0
    tx_total: int = 0
    flows: list[FlowView] = field(default_factory=list)
    history: deque[tuple[float, float]] = field(default_factory=lambda: deque(maxlen=HISTORY_SAMPLES), repr=False)

    @property
    def active(self) -> bool:
        return bool(self.flows)


def _delta(current: tuple[int, int], previous: tuple[int, int] | None) -> tuple[int, int]:
    if previous is None:
        return current
    return tuple(now if now < before else now - before for now, before in zip(current, previous))


def _view(flow: Flow, is_originator: bool, rx_rate: float, tx_rate: float) -> FlowView:
    local, remote = (flow.orig, flow.reply) if is_originator else (flow.reply, flow.orig)
    tx_bytes, rx_bytes = (flow.orig_bytes, flow.reply_bytes) if is_originator else (flow.reply_bytes, flow.orig_bytes)
    return FlowView(flow.protocol, local.src, local.sport, remote.src, remote.sport, rx_bytes, tx_bytes, rx_rate, tx_rate, flow.reply.sport)


class Tracker:
    def __init__(self, topology: Topology) -> None:
        self._topology = topology
        self._previous: dict[tuple, tuple[int, int]] = {}
        self._last_time: float | None = None
        self.hosts: dict[str, HostStats] = {}

    def update(self, flows: list[Flow], now: float) -> None:
        elapsed = None if self._last_time is None else max(now - self._last_time, 1e-9)
        for host in self.hosts.values():
            host.rx_rate = host.tx_rate = 0.0
            host.flows = []
        current = {}
        for flow in flows:
            counters = (flow.orig_bytes, flow.reply_bytes)
            current[flow.key] = counters
            deltas = (0, 0) if elapsed is None else _delta(counters, self._previous.get(flow.key))
            self._attribute(flow, deltas, elapsed)
        for host in self.hosts.values():
            host.history.append((host.rx_rate, host.tx_rate))
        self._previous = current
        self._last_time = now

    def _attribute(self, flow: Flow, deltas: tuple[int, int], elapsed: float | None) -> None:
        counted = set()
        for local_ip, is_originator in ((flow.orig.src, True), (flow.reply.src, False)):
            if not self._topology.is_local(local_ip):
                continue
            host = self._host(local_ip)
            if host.host_id in counted:
                continue
            counted.add(host.host_id)
            tx_delta, rx_delta = deltas if is_originator else deltas[::-1]
            rx_rate, tx_rate = (0.0, 0.0) if elapsed is None else (rx_delta / elapsed, tx_delta / elapsed)
            host.ips.add(local_ip)
            host.rx_total += rx_delta
            host.tx_total += tx_delta
            host.rx_rate += rx_rate
            host.tx_rate += tx_rate
            host.flows.append(_view(flow, is_originator, rx_rate, tx_rate))

    def _host(self, ip: str) -> HostStats:
        host_id = ROUTER_ID if self._topology.is_router(ip) else ip
        return self.hosts.setdefault(host_id, HostStats(host_id))
