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

import http.client
import ipaddress
import queue
import random
import socket
import struct
import threading
import time
import xml.etree.ElementTree as ElementTree
from collections.abc import Callable, Iterable
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, build_opener

from network_snooker.topology import Topology

MDNS_PORT = 5353
NETBIOS_PORT = 137
SSDP_GROUP = ("239.255.255.250", 1900)
PTR = 12
NBSTAT = 0x21
INTERNET_CLASS = 1
NETBIOS_ENTRY = struct.Struct("!15sBH")
WORKSTATION_SUFFIX = 0x00
GROUP_NAME_FLAG = 0x8000
MAX_NAME_POINTERS = 64
MAX_DATAGRAM = 4096
MAX_DESCRIPTION_BYTES = 64 * 1024
PROBE_TIMEOUT = 1.0
SSDP_WAIT = 3.0
FETCH_TIMEOUT = 2.0
SWEEP_INTERVAL = 300.0
M_SEARCH = (
    b"M-SEARCH * HTTP/1.1\r\n"
    b"HOST: 239.255.255.250:1900\r\n"
    b'MAN: "ssdp:discover"\r\n'
    b"MX: 2\r\n"
    b"ST: ssdp:all\r\n\r\n"
)
MALFORMED = (IndexError, ValueError, struct.error)


def _encode_name(labels: Iterable[bytes]) -> bytes:
    return b"".join(bytes([len(label)]) + label for label in labels) + b"\0"


def _netbios_label(name: bytes) -> bytes:
    return bytes(ord("A") + nibble for byte in name.ljust(16, b"\0") for nibble in (byte >> 4, byte & 0xF))


NETBIOS_WILDCARD = _encode_name([_netbios_label(b"*")])


def _query(transaction_id: int, name: bytes, record_type: int) -> bytes:
    return struct.pack("!6H", transaction_id, 0, 1, 0, 0, 0) + name + struct.pack("!2H", record_type, INTERNET_CLASS)


def _read_name(packet: bytes, offset: int) -> tuple[list[bytes], int]:
    labels, end = [], None
    for _ in range(MAX_NAME_POINTERS):
        length = packet[offset]
        if length & 0xC0 == 0xC0:
            end = offset + 2 if end is None else end
            offset = struct.unpack_from("!H", packet, offset)[0] & 0x3FFF
        elif length == 0:
            return labels, offset + 1 if end is None else end
        else:
            labels.append(packet[offset + 1 : offset + 1 + length])
            offset += 1 + length
    raise ValueError("name compression loop")


def _answers(packet: bytes, transaction_id: int) -> Iterable[tuple[int, int]]:
    ident, _, questions, answers = struct.unpack_from("!4H", packet)
    if ident != transaction_id:
        return
    offset = 12
    for _ in range(questions):
        offset = _read_name(packet, offset)[1] + 4
    for _ in range(answers):
        offset = _read_name(packet, offset)[1]
        record_type, _, _, length = struct.unpack_from("!2HIH", packet, offset)
        yield record_type, offset + 10
        offset += 10 + length


def _exchange(ip: str, port: int, request: bytes, timeout: float) -> bytes | None:
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.connect((ip, port))
            sock.send(request)
            return sock.recv(MAX_DATAGRAM)
        except OSError:
            return None


def _ask(ip: str, port: int, name: bytes, record_type: int, parse: Callable[[bytes, int], str | None], timeout: float) -> str | None:
    transaction_id = random.getrandbits(16)
    reply = _exchange(ip, port, _query(transaction_id, name, record_type), timeout)
    if reply is None:
        return None
    try:
        return next((parse(reply, offset) for kind, offset in _answers(reply, transaction_id) if kind == record_type), None)
    except MALFORMED:
        return None


def _ptr_hostname(packet: bytes, offset: int) -> str | None:
    labels = _read_name(packet, offset)[0]
    return ".".join(label.decode(errors="replace") for label in labels).removesuffix(".local") or None


def _workstation_name(packet: bytes, offset: int) -> str | None:
    for index in range(packet[offset]):
        name, suffix, flags = NETBIOS_ENTRY.unpack_from(packet, offset + 1 + index * NETBIOS_ENTRY.size)
        if suffix == WORKSTATION_SUFFIX and not flags & GROUP_NAME_FLAG:
            return name.decode("latin-1").strip() or None
    return None


# Responders answer a unicast query from an ephemeral port straight back to
# the sender (RFC 6762 legacy unicast), so no multicast socket is needed.
def mdns_name(ip: str, timeout: float = PROBE_TIMEOUT) -> str | None:
    reverse = ipaddress.ip_address(ip.split("%")[0]).reverse_pointer
    return _ask(ip, MDNS_PORT, _encode_name(label.encode() for label in reverse.split(".")), PTR, _ptr_hostname, timeout)


def netbios_name(ip: str, timeout: float = PROBE_TIMEOUT) -> str | None:
    if ":" in ip:
        return None
    return _ask(ip, NETBIOS_PORT, NETBIOS_WILDCARD, NBSTAT, _workstation_name, timeout)


def _location(response: bytes) -> str | None:
    for line in response.decode("latin-1").split("\r\n")[1:]:
        key, _, value = line.partition(":")
        if key.strip().lower() == "location":
            return value.strip()
    return None


# Only descriptions served by the answering device itself are fetched, so a
# LAN device cannot make the router request URLs elsewhere.
def collect_locations(responses: Iterable[tuple[bytes, str]]) -> dict[str, str]:
    locations = {}
    for response, ip in responses:
        location = _location(response)
        if location and urlsplit(location).scheme == "http" and urlsplit(location).hostname == ip:
            locations.setdefault(ip, location)
    return locations


def _ssdp_responses(interface_ips: Iterable[str], wait: float) -> Iterable[tuple[bytes, str]]:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        for address in interface_ips:
            try:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(address))
                sock.sendto(M_SEARCH, SSDP_GROUP)
            except OSError:
                continue
        deadline = time.monotonic() + wait
        while (remaining := deadline - time.monotonic()) > 0:
            sock.settimeout(remaining)
            try:
                response, (ip, _) = sock.recvfrom(MAX_DATAGRAM)
            except OSError:
                return
            yield response, ip


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *arguments):
        return None


_OPENER = build_opener(ProxyHandler({}), _NoRedirect)


def friendly_name(description: bytes) -> str | None:
    try:
        root = ElementTree.fromstring(description)
    except ElementTree.ParseError:
        return None
    names = (element.text.strip() for element in root.iter() if element.tag.endswith("friendlyName") and element.text)
    return next(filter(None, names), None)


def _fetch_friendly_name(url: str) -> str | None:
    try:
        with _OPENER.open(url, timeout=FETCH_TIMEOUT) as response:
            return friendly_name(response.read(MAX_DESCRIPTION_BYTES))
    except (OSError, ValueError, http.client.HTTPException):
        return None


def ssdp_names(interface_ips: Iterable[str], wait: float = SSDP_WAIT) -> dict[str, str]:
    locations = collect_locations(_ssdp_responses(interface_ips, wait))
    return {ip: name for ip, location in locations.items() if (name := _fetch_friendly_name(location))}


def lan_interface_ips(topology: Topology) -> tuple[str, ...]:
    return tuple(
        str(ip) for ip in topology.router_ips if ip.version == 4 and any(ip in network for network in topology.lan_networks)
    )


class ServiceDiscovery:
    def __init__(self, topology: Topology, probes=(mdns_name, netbios_name), sweep=ssdp_names, sweep_interval: float = SWEEP_INTERVAL) -> None:
        self._topology = topology
        self._probes = probes
        self._sweep = sweep
        self._sweep_interval = sweep_interval
        self._requested: set[str] = set()
        self._probed: dict[str, str] = {}
        self._swept: dict[str, str] = {}
        self._pending: queue.SimpleQueue[str | None] = queue.SimpleQueue()
        self._stopping = threading.Event()
        self._thread = threading.Thread(target=self._run, name="service-discovery", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def close(self) -> None:
        self._stopping.set()
        self._pending.put(None)

    def request(self, ip: str) -> None:
        if ip not in self._requested and self._topology.is_local(ip) and not self._topology.is_router(ip):
            self._requested.add(ip)
            self._pending.put(ip)

    def name(self, ip: str) -> str | None:
        return self._probed.get(ip) or self._swept.get(ip)

    def _run(self) -> None:
        next_sweep = time.monotonic()
        while not self._stopping.is_set():
            if time.monotonic() >= next_sweep:
                self._sweep_and_retry()
                next_sweep = time.monotonic() + self._sweep_interval
            try:
                ip = self._pending.get(timeout=max(next_sweep - time.monotonic(), 0))
            except queue.Empty:
                continue
            if ip is not None and not self._stopping.is_set():
                self._probe(ip)

    # Hosts that were asleep or silent get another chance on every sweep.
    def _sweep_and_retry(self) -> None:
        self._swept = self._sweep(lan_interface_ips(self._topology))
        for ip in set(self._requested) - self._probed.keys():
            self._pending.put(ip)

    def _probe(self, ip: str) -> None:
        found = next(filter(None, (probe(ip) for probe in self._probes)), None)
        if found:
            self._probed[ip] = found
