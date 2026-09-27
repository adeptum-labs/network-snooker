from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from network_snooker.formatting import format_rate
from network_snooker.tracker import HISTORY_SAMPLES, FlowView

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
