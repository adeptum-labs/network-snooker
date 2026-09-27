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

import struct
import time

import pytest

from network_snooker import discovery
from network_snooker.discovery import (
    NBSTAT,
    NETBIOS_ENTRY,
    NETBIOS_WILDCARD,
    PTR,
    ServiceDiscovery,
    _encode_name,
    collect_locations,
    friendly_name,
    lan_interface_ips,
    mdns_name,
    netbios_name,
)


def answer(record_type, rdata):
    return struct.pack("!2HIH", record_type, 1, 120, len(rdata)) + rdata


def mdns_reply(request, hostname_labels):
    header = request[:2] + struct.pack("!5H", 0x8400, 1, 1, 0, 0)
    return header + request[12:] + b"\xc0\x0c" + answer(PTR, _encode_name(hostname_labels))


def netbios_reply(request, entries):
    header = request[:2] + struct.pack("!5H", 0x8400, 0, 1, 0, 0)
    table = bytes([len(entries)]) + b"".join(NETBIOS_ENTRY.pack(name.ljust(15), suffix, flags) for name, suffix, flags in entries)
    return header + NETBIOS_WILDCARD + answer(NBSTAT, table + bytes(46))


@pytest.fixture
def exchanges(monkeypatch):
    sent = []

    def use(reply):
        def exchange(ip, port, request, timeout):
            sent.append((ip, port, request))
            return reply(request)

        monkeypatch.setattr(discovery, "_exchange", exchange)
        return sent

    return use


def test_mdns_asks_reverse_name_and_strips_local(exchanges):
    sent = exchanges(lambda request: mdns_reply(request, [b"laptop", b"local"]))
    assert mdns_name("192.168.1.10") == "laptop"
    ip, port, request = sent[0]
    assert (ip, port) == ("192.168.1.10", 5353)
    assert _encode_name([b"10", b"1", b"168", b"192", b"in-addr", b"arpa"]) in request


def test_mdns_ignores_other_transaction(exchanges):
    exchanges(lambda request: mdns_reply(bytes([request[0] ^ 1]) + request[1:], [b"laptop", b"local"]))
    assert mdns_name("192.168.1.10") is None


@pytest.mark.parametrize(
    "reply",
    [
        lambda request: None,
        lambda request: mdns_reply(request, [b"laptop", b"local"])[:-5],
        lambda request: request[:2] + struct.pack("!5H", 0x8400, 0, 1, 0, 0) + b"\xc0\x0c",
    ],
    ids=["silent", "truncated", "pointer loop"],
)
def test_mdns_bad_replies_give_none(exchanges, reply):
    exchanges(reply)
    assert mdns_name("192.168.1.10") is None


def test_netbios_picks_unique_workstation_name(exchanges):
    sent = exchanges(lambda request: netbios_reply(request, [(b"WORKGROUP", 0x00, 0x8000), (b"DESKTOP-1", 0x20, 0x0400), (b"DESKTOP-1", 0x00, 0x0400)]))
    assert netbios_name("192.168.1.30") == "DESKTOP-1"
    assert sent[0][1] == 137


def test_netbios_skips_ipv6(exchanges):
    sent = exchanges(lambda request: None)
    assert netbios_name("2001:db8:1::10") is None
    assert sent == []


def ssdp_response(location):
    return f"HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nLocation: {location}\r\n\r\n".encode()


def test_collect_locations_trusts_only_the_answering_device():
    responses = [
        (ssdp_response("http://192.168.1.40:49152/desc.xml"), "192.168.1.40"),
        (ssdp_response("http://192.168.1.40:8080/other.xml"), "192.168.1.40"),
        (ssdp_response("http://203.0.113.9/desc.xml"), "192.168.1.41"),
        (ssdp_response("file:///etc/passwd"), "192.168.1.42"),
        (b"HTTP/1.1 200 OK\r\n\r\n", "192.168.1.43"),
    ]
    assert collect_locations(responses) == {"192.168.1.40": "http://192.168.1.40:49152/desc.xml"}


def test_friendly_name_from_namespaced_description():
    description = b"""<?xml version="1.0"?>
    <root xmlns="urn:schemas-upnp-org:device-1-0"><device><friendlyName> Living Room TV </friendlyName></device></root>"""
    assert friendly_name(description) == "Living Room TV"


@pytest.mark.parametrize("description", [b"<root><device/></root>", b"<root><friendlyName>", b""])
def test_friendly_name_missing_or_malformed(description):
    assert friendly_name(description) is None


def test_lan_interface_ips(topology):
    assert lan_interface_ips(topology) == ("192.168.1.1",)


def wait_for(condition, timeout=2.0):
    deadline = time.monotonic() + timeout
    while not condition() and time.monotonic() < deadline:
        time.sleep(0.01)
    return condition()


def test_discovery_probes_lan_hosts_in_order(topology):
    probed = []
    probes = (lambda ip: probed.append(("mdns", ip)), lambda ip: probed.append(("netbios", ip)) or "DESKTOP-1")
    service = ServiceDiscovery(topology, probes=probes, sweep=lambda interfaces: {})
    service.start()
    for ip in ("93.184.216.34", "192.168.1.1", "192.168.1.30", "192.168.1.30"):
        service.request(ip)
    assert wait_for(lambda: service.name("192.168.1.30") == "DESKTOP-1")
    service.close()
    assert probed == [("mdns", "192.168.1.30"), ("netbios", "192.168.1.30")]


def test_probed_name_beats_swept_name(topology):
    swept = {"192.168.1.30": "Living Room TV", "192.168.1.40": "Printer"}
    service = ServiceDiscovery(topology, probes=(lambda ip: "tv-host" if ip == "192.168.1.30" else None,), sweep=lambda interfaces: swept)
    service.start()
    service.request("192.168.1.30")
    assert wait_for(lambda: service.name("192.168.1.30") == "tv-host")
    assert service.name("192.168.1.40") == "Printer"
    service.close()


def test_sweep_retries_silent_hosts(topology):
    answers = iter([None, "woke-up"])
    service = ServiceDiscovery(topology, probes=(lambda ip: next(answers, None),), sweep=lambda interfaces: {}, sweep_interval=0.05)
    service.start()
    service.request("192.168.1.30")
    assert wait_for(lambda: service.name("192.168.1.30") == "woke-up")
    service.close()


def test_close_stops_thread(topology):
    service = ServiceDiscovery(topology, probes=(), sweep=lambda interfaces: {})
    service.start()
    service.close()
    service._thread.join(2)
    assert not service._thread.is_alive()
