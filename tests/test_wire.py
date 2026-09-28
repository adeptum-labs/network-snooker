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
from datetime import time

import pytest

from network_snooker.policy import HostPolicy, Mode, Rule
from network_snooker.tracker import HISTORY_SAMPLES, FlowView, HostStats
from network_snooker.wire import (
    Notice,
    Snapshot,
    WireError,
    decode,
    encode,
    snapshot_from_dict,
    snapshot_to_dict,
)

MAC = "aa:bb:cc:dd:ee:01"


def host():
    return HostStats(
        host_id="192.168.1.10",
        ips={"192.168.1.10", "2001:db8:1::10"},
        rx_rate=1.5,
        tx_rate=2.5,
        rx_total=100,
        tx_total=200,
        flows=[FlowView("tcp", "192.168.1.10", 51234, "93.184.216.34", 443, 10, 20, 1.5, 2.5, 443)],
        history=deque([(1.0, 2.0), (1.5, 2.5)], maxlen=HISTORY_SAMPLES),
    )


def snapshot():
    policy = HostPolicy(MAC, Mode.SCHEDULE, (Rule("youtube", frozenset({0, 1}), ((time(16, 0), time(19, 0)),)),))
    return Snapshot(
        hosts={"192.168.1.10": host()},
        macs={"192.168.1.10": MAC},
        blocked={"192.168.1.10": ("YouTube",)},
        names={"192.168.1.10": "laptop", "93.184.216.34": "example.com"},
        policies={MAC: policy},
        interval=1.0,
        error="",
        notices=(Notice(3, "warning", "Firewall table was removed externally"),),
        last_seq=3,
    )


def test_encode_is_one_newline_terminated_json_line():
    assert encode({"op": "snapshot", "since": 0}) == b'{"op": "snapshot", "since": 0}\n'


def test_decode_round_trips_encode():
    assert decode(encode({"op": "stop"})) == {"op": "stop"}


@pytest.mark.parametrize("line", [b"not json\n", b"[1, 2]\n", b"\xff\n", b""])
def test_decode_rejects_anything_but_a_json_object(line):
    with pytest.raises(WireError):
        decode(line)


def test_snapshot_survives_a_json_round_trip():
    original = snapshot()
    restored = snapshot_from_dict(decode(encode(snapshot_to_dict(original))))
    assert restored == original


def test_restored_history_keeps_its_length_limit():
    restored = snapshot_from_dict(decode(encode(snapshot_to_dict(snapshot()))))
    assert restored.hosts["192.168.1.10"].history.maxlen == HISTORY_SAMPLES


def test_a_malformed_snapshot_is_a_wire_error():
    with pytest.raises(WireError):
        snapshot_from_dict({"hosts": "nope"})
