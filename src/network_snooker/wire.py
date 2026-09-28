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
from collections import deque
from dataclasses import asdict, dataclass, field

from network_snooker.policy import HostPolicy, policy_from_dict, policy_to_dict
from network_snooker.tracker import HISTORY_SAMPLES, FlowView, HostStats


class WireError(RuntimeError):
    pass


@dataclass(frozen=True)
class Notice:
    seq: int
    severity: str
    message: str


@dataclass(frozen=True)
class Snapshot:
    hosts: dict[str, HostStats] = field(default_factory=dict)
    macs: dict[str, str | None] = field(default_factory=dict)
    blocked: dict[str, tuple[str, ...]] = field(default_factory=dict)
    names: dict[str, str] = field(default_factory=dict)
    policies: dict[str, HostPolicy] = field(default_factory=dict)
    interval: float = 1.0
    error: str = ""
    notices: tuple[Notice, ...] = ()
    last_seq: int = 0


def encode(message: dict) -> bytes:
    return json.dumps(message).encode() + b"\n"


def decode(line: bytes) -> dict:
    try:
        message = json.loads(line)
    except ValueError as error:
        raise WireError(f"bad message: {error}") from error
    if not isinstance(message, dict):
        raise WireError("bad message: expected a JSON object")
    return message


def _host_to_dict(host: HostStats) -> dict:
    return {**asdict(host), "ips": sorted(host.ips), "history": [list(sample) for sample in host.history]}


def _host_from_dict(entry: dict) -> HostStats:
    return HostStats(
        **{
            **entry,
            "ips": set(entry["ips"]),
            "flows": [FlowView(**flow) for flow in entry["flows"]],
            "history": deque(map(tuple, entry["history"]), maxlen=HISTORY_SAMPLES),
        }
    )


def snapshot_to_dict(snapshot: Snapshot) -> dict:
    return {
        "hosts": {host_id: _host_to_dict(host) for host_id, host in snapshot.hosts.items()},
        "macs": snapshot.macs,
        "blocked": snapshot.blocked,
        "names": snapshot.names,
        "policies": {mac: policy_to_dict(policy) for mac, policy in snapshot.policies.items()},
        "interval": snapshot.interval,
        "error": snapshot.error,
        "notices": [asdict(notice) for notice in snapshot.notices],
        "last_seq": snapshot.last_seq,
    }


def snapshot_from_dict(entry: dict) -> Snapshot:
    try:
        return Snapshot(
            hosts={host_id: _host_from_dict(host) for host_id, host in entry["hosts"].items()},
            macs=entry["macs"],
            blocked={host_id: tuple(names) for host_id, names in entry["blocked"].items()},
            names=entry["names"],
            policies={mac: policy_from_dict(mac, policy) for mac, policy in entry["policies"].items()},
            interval=entry["interval"],
            error=entry["error"],
            notices=tuple(Notice(**notice) for notice in entry["notices"]),
            last_seq=entry["last_seq"],
        )
    except (KeyError, TypeError, ValueError, AttributeError) as error:
        raise WireError(f"bad snapshot: {error}") from error
