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

import os
import threading
from concurrent.futures import ThreadPoolExecutor

from network_snooker.names import NameResolver, read_dhcpd_leases, read_dnsmasq_leases

DNSMASQ_LEASES = (
    "1790000000 aa:bb:cc:dd:ee:01 192.168.1.10 laptop 01:aa:bb:cc:dd:ee:01\n"
    "1790000000 aa:bb:cc:dd:ee:02 192.168.1.11 * *\n"
)

DHCPD_LEASES = """\
# The format of this file is documented in the dhcpd.leases(5) manual page.
# This lease file was written by isc-dhcp-4.4.3-P1

# authoring-byte-order entry is generated, DO NOT DELETE
authoring-byte-order little-endian;

lease 192.168.1.20 {
  starts 0 2026/09/27 06:40:07;
  ends 0 2026/09/27 12:40:07;
  cltt 0 2026/09/27 06:40:07;
  binding state active;
  next binding state free;
  rewind binding state free;
  hardware ethernet d6:2d:dc:66:3a:90;
  uid "\\001\\326-\\334f:\\220";
  set vendor-class-identifier = "android-dhcp-15";
  client-hostname "phone";
}
lease 192.168.1.21 {
  starts 6 2026/09/26 06:40:07;
  ends 6 2026/09/26 12:40:07;
  tstp 6 2026/09/26 12:40:07;
  cltt 6 2026/09/26 06:40:07;
  binding state free;
  rewind binding state active;
  hardware ethernet 14:c1:4e:09:81:16;
  client-hostname "speaker";
}
lease 192.168.1.22 {
  starts 0 2026/09/27 06:54:53;
  ends 0 2026/09/27 12:54:53;
  cltt 0 2026/09/27 06:54:53;
  binding state active;
  next binding state free;
  rewind binding state free;
  hardware ethernet 70:f0:88:73:e1:01;
}
"""

DHCPD_JOURNAL = """\
lease 192.168.1.30 {
  binding state active;
  client-hostname "old-name";
}
lease 192.168.1.31 {
  binding state active;
  client-hostname "tablet";
}
lease 192.168.1.30 {
  binding state active;
  client-hostname "new-name";
}
lease 192.168.1.31 {
  binding state free;
  client-hostname "tablet";
}
"""


class DeferredExecutor:
    def __init__(self):
        self.tasks = []

    def submit(self, function, *arguments):
        self.tasks.append((function, arguments))

    def run_all(self):
        for function, arguments in self.tasks:
            function(*arguments)
        self.tasks.clear()


def test_read_dnsmasq_leases_skips_unnamed(tmp_path):
    path = tmp_path / "leases"
    path.write_text(DNSMASQ_LEASES)
    assert read_dnsmasq_leases(path) == {"192.168.1.10": "laptop"}


def test_read_dnsmasq_leases_missing_file(tmp_path):
    assert read_dnsmasq_leases(tmp_path / "absent") == {}


def test_read_dhcpd_leases_keeps_active_named(tmp_path):
    path = tmp_path / "dhcpd.leases"
    path.write_text(DHCPD_LEASES)
    assert read_dhcpd_leases(path) == {"192.168.1.20": "phone"}


def test_read_dhcpd_leases_latest_block_wins(tmp_path):
    path = tmp_path / "dhcpd.leases"
    path.write_text(DHCPD_JOURNAL)
    assert read_dhcpd_leases(path) == {"192.168.1.30": "new-name"}


def test_read_dhcpd_leases_missing_file(tmp_path):
    assert read_dhcpd_leases(tmp_path / "absent") == {}


def test_lease_name_wins(tmp_path):
    path = tmp_path / "leases"
    path.write_text(DNSMASQ_LEASES)
    resolver = NameResolver([(path, read_dnsmasq_leases)], lookup=lambda ip: "dns-name", executor=DeferredExecutor())
    assert resolver.name("192.168.1.10") == "laptop"


def test_resolver_reads_every_lease_file(tmp_path):
    dnsmasq, dhcpd = tmp_path / "dnsmasq.leases", tmp_path / "dhcpd.leases"
    dnsmasq.write_text(DNSMASQ_LEASES)
    dhcpd.write_text(DHCPD_LEASES)
    lease_files = [(tmp_path / "absent", read_dhcpd_leases), (dnsmasq, read_dnsmasq_leases), (dhcpd, read_dhcpd_leases)]
    resolver = NameResolver(lease_files, lookup=lambda ip: None, executor=DeferredExecutor())
    assert resolver.name("192.168.1.10") == "laptop"
    assert resolver.name("192.168.1.20") == "phone"


def test_reverse_lookup_never_blocks():
    executor = DeferredExecutor()
    resolver = NameResolver((), lookup=lambda ip: "example.org", executor=executor)
    assert resolver.name("93.184.216.34") == "93.184.216.34"
    assert resolver.name("93.184.216.34") == "93.184.216.34"
    assert len(executor.tasks) == 1
    executor.run_all()
    assert resolver.name("93.184.216.34") == "example.org"


def test_failed_lookup_shows_ip():
    executor = DeferredExecutor()
    resolver = NameResolver((), lookup=lambda ip: None, executor=executor)
    resolver.name("198.51.100.7")
    executor.run_all()
    assert resolver.name("198.51.100.7") == "198.51.100.7"


class FakeDiscovery:
    def __init__(self, names):
        self.names = names
        self.requested = []

    def request(self, ip):
        self.requested.append(ip)

    def name(self, ip):
        return self.names.get(ip)


def test_discovered_name_beats_reverse_lookup():
    executor = DeferredExecutor()
    discovery = FakeDiscovery({"192.168.1.20": "printer"})
    resolver = NameResolver((), lookup=lambda ip: "dns-name", executor=executor, discovery=discovery)
    resolver.name("192.168.1.20")
    executor.run_all()
    assert resolver.name("192.168.1.20") == "printer"
    assert discovery.requested == ["192.168.1.20", "192.168.1.20"]


def test_lease_name_skips_discovery(tmp_path):
    path = tmp_path / "leases"
    path.write_text(DNSMASQ_LEASES)
    discovery = FakeDiscovery({"192.168.1.10": "printer"})
    resolver = NameResolver([(path, read_dnsmasq_leases)], lookup=lambda ip: None, executor=DeferredExecutor(), discovery=discovery)
    assert resolver.name("192.168.1.10") == "laptop"
    assert discovery.requested == []


def test_leases_reload_when_file_changes(tmp_path):
    dnsmasq, dhcpd = tmp_path / "dnsmasq.leases", tmp_path / "dhcpd.leases"
    dnsmasq.write_text(DNSMASQ_LEASES)
    dhcpd.write_text("")
    lease_files = [(dnsmasq, read_dnsmasq_leases), (dhcpd, read_dhcpd_leases)]
    resolver = NameResolver(lease_files, lookup=lambda ip: None, executor=DeferredExecutor())
    assert resolver.name("192.168.1.20") == "192.168.1.20"
    dhcpd.write_text(DHCPD_LEASES)
    os.utime(dhcpd, (1, 1))
    assert resolver.name("192.168.1.20") == "phone"


def test_close_drops_queued_lookups():
    started = threading.Event()
    release = threading.Event()
    looked_up = []

    def blocking_lookup(ip):
        looked_up.append(ip)
        started.set()
        release.wait(5)
        return None

    executor = ThreadPoolExecutor(max_workers=1)
    resolver = NameResolver((), lookup=blocking_lookup, executor=executor)
    for ip in ("198.51.100.1", "198.51.100.2", "198.51.100.3"):
        resolver.name(ip)
    started.wait(5)
    resolver.close()
    release.set()
    executor.shutdown(wait=True)
    assert looked_up == ["198.51.100.1"]


def test_control_characters_never_reach_the_terminal():
    discovery = FakeDiscovery({"192.168.1.20": "tv\x1b]0;owned\x07"})
    resolver = NameResolver((), lookup=lambda ip: None, executor=DeferredExecutor(), discovery=discovery)
    assert resolver.name("192.168.1.20") == "tv?]0;owned?"
