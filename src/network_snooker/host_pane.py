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

from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Sparkline, Static

from network_snooker.formatting import format_duration, format_rate
from network_snooker.tracker import FlowView, HostStats

TOP_PEERS = 5
NAME_WIDTH = 16


@dataclass(frozen=True)
class Peer:
    remote_ip: str
    protocol: str
    service_port: int | None
    rx_rate: float
    tx_rate: float
    bytes: int


def protocol_mix(flows: Iterable[FlowView]) -> str:
    counts = Counter(flow.protocol for flow in flows).most_common()
    return " · ".join(f"{protocol} {count}" for protocol, count in counts) or "none"


def top_peers(flows: Iterable[FlowView], count: int = TOP_PEERS) -> list[Peer]:
    totals: dict[tuple[str, str, int | None], tuple[float, float, int]] = {}
    for flow in flows:
        service = (flow.remote_ip, flow.protocol, flow.service_port)
        rx_rate, tx_rate, transferred = totals.get(service, (0.0, 0.0, 0))
        totals[service] = (rx_rate + flow.rx_rate, tx_rate + flow.tx_rate, transferred + flow.rx_bytes + flow.tx_bytes)
    peers = [Peer(*service, *sums) for service, sums in totals.items()]
    return sorted(peers, key=lambda peer: (peer.rx_rate + peer.tx_rate, peer.bytes), reverse=True)[:count]


def format_peer(peer: Peer, name: str, width: int) -> str:
    service = peer.protocol if peer.service_port is None else f"{peer.protocol}/{peer.service_port}"
    tail = f"  {service:<8}  {format_rate(peer.rx_rate):>10} ↓  {format_rate(peer.tx_rate):>10} ↑"
    name_width = max(NAME_WIDTH, width - len(tail))
    if len(name) > name_width:
        name = name[: name_width - 1] + "…"
    return f"{name:<{name_width}}{tail}"


# One value per column makes the graph scroll one column per poll. Sparkline
# scales its bars from the smallest to the largest value, so the leading zero
# stops a steady rate from drawing as a flat, idle-looking line.
def rate_series(samples: Sequence[float], columns: int) -> list[float]:
    recent = list(samples)[max(len(samples) - columns + 1, 0) :]
    return [0.0] * (columns - len(recent)) + recent


class HostPane(Horizontal):
    DEFAULT_CSS = """
    HostPane {
        height: 8;
        border: round $primary;
        border-subtitle-align: left;
    }
    HostPane #graphs { width: 2fr; }
    HostPane #graphs Static { text-wrap: nowrap; text-overflow: ellipsis; }
    HostPane #peers { width: 3fr; height: 1fr; border-left: solid $primary; padding-left: 1; text-wrap: nowrap; text-overflow: ellipsis; }
    HostPane Sparkline { height: 2; }
    """
    _host: HostStats | None = None

    # Host and peer names come from LAN devices and DNS, so no text in the
    # pane is parsed as markup.
    def compose(self) -> ComposeResult:
        with Vertical(id="graphs"):
            yield Static(id="rx-label", markup=False)
            yield Sparkline(id="rx")
            yield Static(id="tx-label", markup=False)
            yield Sparkline(id="tx")
        yield Static(id="peers", markup=False)

    # The graphs only get their width from layout, which runs after the pane
    # first shows a host, so a resize fits them again.
    def on_resize(self) -> None:
        self.show(self._host)

    def show(self, host: HostStats | None) -> None:
        self._host = host
        self.display = host is not None
        if host is None:
            return
        columns = self.query_one("#rx", Sparkline).size.width
        self.border_title = Text(f"{self.app.display_name(host)} · {', '.join(sorted(host.ips))}")
        self.border_subtitle = f"last {format_duration(max(columns - 1, 0) * self.app.interval)}"
        rx_samples, tx_samples = zip(*host.history)
        self._graph("rx", host.rx_rate, rate_series(rx_samples, columns))
        self._graph("tx", host.tx_rate, rate_series(tx_samples, columns))
        peers = self.query_one("#peers", Static)
        header = [f"flows  {protocol_mix(host.flows)}"]
        if blocked := self.app.blocked_now(host.host_id):
            header.append(f"Blocked now: {', '.join(blocked)}")
        lines = [format_peer(peer, self.app.name_of(peer.remote_ip), peers.size.width) for peer in top_peers(host.flows)]
        peers.update("\n".join([*header, *lines]))

    def _graph(self, direction: str, current: float, series: list[float]) -> None:
        self.query_one(f"#{direction}-label", Static).update(f"{direction} {format_rate(current)}  peak {format_rate(max(series, default=0.0))}")
        self.query_one(f"#{direction}", Sparkline).data = series
