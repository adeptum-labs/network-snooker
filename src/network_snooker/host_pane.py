from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Sparkline, Static

from network_snooker.formatting import format_duration, format_rate
from network_snooker.tracker import HISTORY_SAMPLES, FlowView, HostStats

TOP_PEERS = 5
NAME_WIDTH = 16


@dataclass(frozen=True)
class Peer:
    remote_ip: str
    protocol: str
    remote_port: int | None
    rx_rate: float
    tx_rate: float
    bytes: int


def protocol_mix(flows: Iterable[FlowView]) -> str:
    counts = Counter(flow.protocol for flow in flows).most_common()
    return " · ".join(f"{protocol} {count}" for protocol, count in counts) or "none"


def top_peers(flows: Iterable[FlowView], count: int = TOP_PEERS) -> list[Peer]:
    totals: dict[tuple[str, str, int | None], tuple[float, float, int]] = {}
    for flow in flows:
        service = (flow.remote_ip, flow.protocol, flow.remote_port)
        rx_rate, tx_rate, transferred = totals.get(service, (0.0, 0.0, 0))
        totals[service] = (rx_rate + flow.rx_rate, tx_rate + flow.tx_rate, transferred + flow.rx_bytes + flow.tx_bytes)
    peers = [Peer(*service, *sums) for service, sums in totals.items()]
    return sorted(peers, key=lambda peer: (peer.rx_rate + peer.tx_rate, peer.bytes), reverse=True)[:count]


def format_peer(peer: Peer, name: str) -> str:
    if len(name) > NAME_WIDTH:
        name = name[: NAME_WIDTH - 1] + "…"
    service = peer.protocol if peer.remote_port is None else f"{peer.protocol}/{peer.remote_port}"
    return f"{name:<{NAME_WIDTH}}  {service:<8}  {format_rate(peer.rx_rate):>10} ↓  {format_rate(peer.tx_rate):>10} ↑"


# Sparkline scales its bars from the smallest to the largest value. Leading
# zeros keep "now" at the right edge for hosts seen only recently, and the
# extra zero stops a steady rate from drawing as a flat, idle-looking line.
def rate_series(samples: Sequence[float]) -> list[float]:
    return [0.0] * (HISTORY_SAMPLES + 1 - len(samples)) + list(samples)


class HostPane(Horizontal):
    DEFAULT_CSS = """
    HostPane {
        height: 8;
        border: round $primary;
        border-subtitle-align: left;
    }
    HostPane #graphs { width: 2fr; }
    HostPane #peers { width: 3fr; border-left: solid $primary; padding-left: 1; text-wrap: nowrap; text-overflow: ellipsis; }
    HostPane Sparkline { height: 2; }
    """

    # Host and peer names come from LAN devices and DNS, so no text in the
    # pane is parsed as markup.
    def compose(self) -> ComposeResult:
        with Vertical(id="graphs"):
            yield Static(id="rx-label", markup=False)
            yield Sparkline(id="rx")
            yield Static(id="tx-label", markup=False)
            yield Sparkline(id="tx")
        yield Static(id="peers", markup=False)

    def on_mount(self) -> None:
        self.border_subtitle = f"last {format_duration(HISTORY_SAMPLES * self.app.interval)}"

    def show(self, host: HostStats | None) -> None:
        self.display = host is not None
        if host is None:
            return
        self.border_title = Text(f"{self.app.display_name(host)} · {', '.join(sorted(host.ips))}")
        rx_samples, tx_samples = zip(*host.history)
        self._graph("rx", host.rx_rate, rx_samples)
        self._graph("tx", host.tx_rate, tx_samples)
        peers = [format_peer(peer, self.app.resolver.name(peer.remote_ip)) for peer in top_peers(host.flows)]
        self.query_one("#peers", Static).update("\n".join([f"flows  {protocol_mix(host.flows)}", *peers]))

    def _graph(self, direction: str, current: float, samples: Sequence[float]) -> None:
        self.query_one(f"#{direction}-label", Static).update(f"{direction} {format_rate(current)}  peak {format_rate(max(samples))}")
        self.query_one(f"#{direction}", Sparkline).data = rate_series(samples)
