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
import signal
import tempfile
import threading
import time
from pathlib import Path

import pytest
from fakes import TEST_CATALOG, FakeDomainSets, FakeFirewall, FakeResolver, fresh_store, make_neighbors

import network_snooker.service as service
from network_snooker.client import DaemonClient
from network_snooker.topology import TopologyError


class RecordingFirewall(FakeFirewall):
    def __init__(self, events):
        super().__init__()
        self.events = events

    def setup(self):
        self.events.append("firewall set up")

    def teardown(self):
        self.events.append("firewall torn down")


class Recording:
    def __init__(self, events, name):
        self.events = events
        self.name = name

    def start(self):
        self.events.append(f"{self.name} started")

    def close(self):
        self.events.append(f"{self.name} closed")


class RecordingDomainSets(Recording, FakeDomainSets):
    pass


class RecordingResolver(Recording, FakeResolver):
    pass


@pytest.fixture
def paths():
    # Unix socket paths are limited to about 100 bytes, which pytest's tmp_path can exceed.
    directory = Path(tempfile.mkdtemp(prefix="ns-"))
    return directory / "daemon.sock", directory / "daemon.lock"


@pytest.fixture
def events(monkeypatch, topology):
    events = []
    monkeypatch.setattr(service, "detect_topology", lambda lan: topology)
    monkeypatch.setattr(service, "load_catalog", lambda: TEST_CATALOG)
    monkeypatch.setattr(service, "PolicyStore", fresh_store)
    monkeypatch.setattr(service, "Firewall", lambda nft_path: RecordingFirewall(events))
    monkeypatch.setattr(service, "ServiceDiscovery", lambda topology: Recording(events, "discovery"))
    monkeypatch.setattr(service, "NameResolver", lambda discovery: RecordingResolver(events, "resolver"))
    monkeypatch.setattr(service, "DomainSets", lambda catalog: RecordingDomainSets(events, "domain sets"))
    monkeypatch.setattr(service, "Neighbors", make_neighbors)
    monkeypatch.setattr(service, "read_flows", lambda: [])
    return events


def once_serving(socket_path, action):
    def act():
        client = DaemonClient(socket_path)
        deadline = time.monotonic() + 5
        while not client.is_running() and time.monotonic() < deadline:
            time.sleep(0.01)
        action(client)

    threading.Thread(target=act, daemon=True).start()


TORN_DOWN = [
    "discovery started",
    "domain sets started",
    "firewall set up",
    "firewall torn down",
    "domain sets closed",
    "resolver closed",
    "discovery closed",
]


def test_sigterm_stops_the_daemon_and_lifts_every_block(events, paths):
    socket_path, lock_path = paths
    socket_path.write_text("stale")
    handlers = {signum: signal.getsignal(signum) for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)}
    once_serving(socket_path, lambda client: os.kill(os.getpid(), signal.SIGTERM))
    assert service.run_daemon(1.0, None, socket_path, lock_path) == 0
    assert events == TORN_DOWN
    assert not socket_path.exists()
    assert handlers == {signum: signal.getsignal(signum) for signum in handlers}


def test_a_stop_request_stops_the_daemon(events, paths):
    socket_path, lock_path = paths
    once_serving(socket_path, DaemonClient.stop)
    assert service.run_daemon(1.0, None, socket_path, lock_path) == 0
    assert events == TORN_DOWN


def test_sighup_does_not_stop_the_daemon(events, paths):
    socket_path, lock_path = paths

    def hang_up_then_stop(client):
        os.kill(os.getpid(), signal.SIGHUP)
        time.sleep(0.1)
        assert client.is_running()
        client.stop()

    once_serving(socket_path, hang_up_then_stop)
    assert service.run_daemon(1.0, None, socket_path, lock_path) == 0


def test_a_second_daemon_is_refused(events, paths, capsys):
    socket_path, lock_path = paths
    with service.acquire_lock(lock_path):
        assert service.run_daemon(1.0, None, socket_path, lock_path) == 1
    assert "already running" in capsys.readouterr().err
    assert events == []


def test_startup_failure_is_reported_and_releases_the_lock(monkeypatch, events, paths, capsys):
    socket_path, lock_path = paths

    def fail(lan):
        raise TopologyError("cannot read 'ip -j addr'")

    monkeypatch.setattr(service, "detect_topology", fail)
    assert service.run_daemon(1.0, None, socket_path, lock_path) == 1
    assert "cannot read 'ip -j addr'" in capsys.readouterr().err
    assert not service.is_locked(lock_path)


def test_components_are_released_when_the_socket_cannot_be_bound(events, paths):
    socket_path, lock_path = paths
    with pytest.raises(OSError):
        service.run_daemon(1.0, None, socket_path.parent / "missing" / "daemon.sock", lock_path)
    assert events == TORN_DOWN


def test_is_locked_follows_the_lock(paths):
    _, lock_path = paths
    assert not service.is_locked(lock_path)
    with service.acquire_lock(lock_path):
        assert service.is_locked(lock_path)
    assert not service.is_locked(lock_path)


def test_wait_until_unlocked_reports_whether_the_daemon_exited(paths):
    _, lock_path = paths
    assert service.wait_until_unlocked(0.1, lock_path)
    with service.acquire_lock(lock_path):
        assert not service.wait_until_unlocked(0.1, lock_path)


def test_wait_until_unlocked_sees_a_daemon_that_exits_meanwhile(paths):
    _, lock_path = paths
    lock = service.acquire_lock(lock_path)
    threading.Timer(0.1, lock.close).start()
    assert service.wait_until_unlocked(2, lock_path)
