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


import shutil
import socket
import stat
import tempfile
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest
from fakes import HOST_MAC, FakeFirewall
from test_daemon import HOST, NEVER_ALLOWED, make_engine

from network_snooker.client import DaemonClient, DaemonError, RequestRefused
from network_snooker.policy import Mode
from network_snooker.server import DaemonServer
from network_snooker.wire import decode


@pytest.fixture
def daemon(topology):
    # Unix socket paths are limited to about 100 bytes, which pytest's tmp_path can exceed.
    directory = Path(tempfile.mkdtemp(prefix="ns-"))
    firewall = FakeFirewall()
    engine = make_engine(topology, firewall=firewall)
    engine.poll()
    server = DaemonServer(directory / "daemon.sock", engine)
    thread = threading.Thread(target=server.serve_forever, args=(0.02,), daemon=True)
    thread.start()
    yield SimpleNamespace(engine=engine, firewall=firewall, server=server, thread=thread, path=directory / "daemon.sock", client=DaemonClient(directory / "daemon.sock"))
    server.shutdown()
    server.server_close()
    shutil.rmtree(directory)


def raw_request(path, payload: bytes) -> dict:
    with socket.socket(socket.AF_UNIX) as connection:
        connection.connect(str(path))
        connection.sendall(payload)
        return decode(connection.makefile("rb").readline())


def test_snapshot_reaches_the_client(daemon):
    assert list(daemon.client.snapshot().hosts) == [HOST]


def test_snapshot_only_carries_notices_after_the_given_sequence(daemon):
    daemon.firewall.restore_pending = True
    daemon.engine.poll()
    assert len(daemon.client.snapshot().notices) == 1
    assert daemon.client.snapshot(since=1).notices == ()


def test_toggle_pause_pauses_the_host(daemon):
    daemon.client.toggle_pause(HOST)
    assert daemon.firewall.ruleset.paused_macs == {HOST_MAC}


def test_a_refused_request_carries_the_reason(daemon):
    with pytest.raises(RequestRefused, match="The router cannot be paused"):
        daemon.client.toggle_pause("router")


def test_replace_rules_and_set_mode_reach_the_engine(daemon):
    daemon.client.replace_rules(HOST_MAC, (NEVER_ALLOWED,))
    assert [block.service_key for block in daemon.firewall.ruleset.blocks] == ["minecraft"]
    daemon.client.set_mode(HOST_MAC, Mode.NONE)
    assert daemon.firewall.ruleset.blocks == ()


@pytest.mark.parametrize(
    "payload",
    [
        b"not json\n",
        b'{"op": "nope"}\n',
        b'{"op": "toggle_pause"}\n',
        b'{"op": "set_mode", "mac": "aa", "mode": "sideways"}\n',
        b'{"op": "replace_rules", "mac": "aa", "rules": [{"service": "x"}]}\n',
    ],
)
def test_bad_requests_get_an_error_response(daemon, payload):
    response = raw_request(daemon.path, payload)
    assert response["ok"] is False
    assert response["error"]


def test_a_stop_request_ends_the_serve_loop(daemon):
    daemon.client.stop()
    daemon.thread.join(timeout=2)
    assert not daemon.thread.is_alive()


def test_the_socket_is_private_to_its_owner_and_removed_on_close(daemon):
    assert stat.S_IMODE(daemon.path.stat().st_mode) == 0o600
    daemon.server.shutdown()
    daemon.server.server_close()
    assert not daemon.path.exists()


def test_an_unreachable_daemon_is_a_daemon_error(tmp_path):
    with pytest.raises(DaemonError):
        DaemonClient(tmp_path / "missing.sock").snapshot()


def test_is_running_follows_the_server(daemon, tmp_path):
    assert daemon.client.is_running()
    assert not DaemonClient(tmp_path / "missing.sock").is_running()
    daemon.server.shutdown()
    daemon.server.server_close()
    assert not daemon.client.is_running()
