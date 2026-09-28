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


import contextlib
import fcntl
import shutil
import signal
import sys
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import IO

from network_snooker.catalog import CatalogError, load_catalog
from network_snooker.client import SOCKET_PATH
from network_snooker.conntrack_source import read_flows
from network_snooker.daemon import Engine
from network_snooker.discovery import ServiceDiscovery
from network_snooker.domain_sets import DomainSets
from network_snooker.firewall import Firewall
from network_snooker.names import NameResolver
from network_snooker.neighbors import Neighbors
from network_snooker.policy import PolicyError, PolicyStore
from network_snooker.server import DaemonServer
from network_snooker.topology import TopologyError, detect_topology
from network_snooker.tracker import Tracker

LOCK_PATH = SOCKET_PATH.with_name("daemon.lock")
POLLER_TIMEOUT = 10
STARTUP_ERRORS = (TopologyError, CatalogError, PolicyError)


class AlreadyRunning(RuntimeError):
    pass


# The lock is held for the daemon's whole life and released only when the
# process has finished tearing down, so it also tells `stop` when that is.
def acquire_lock(path: Path = LOCK_PATH) -> IO[str]:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    handle = path.open("w")
    try:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        handle.close()
        raise AlreadyRunning("network-snooker daemon is already running") from None
    return handle


def is_locked(path: Path = LOCK_PATH) -> bool:
    try:
        acquire_lock(path).close()
    except AlreadyRunning:
        return True
    return False


# Only SIGHUP is ignored: the daemon must outlive the terminal that started it.
@contextlib.contextmanager
def _exit_on_signals(server: DaemonServer) -> Iterator[None]:
    # shutdown() waits for the serve loop, which runs on the thread that
    # receives the signal, so it has to be called from another thread.
    def stop(signum, frame) -> None:
        threading.Thread(target=server.shutdown).start()

    handlers = {signal.SIGTERM: stop, signal.SIGINT: stop, signal.SIGHUP: signal.SIG_IGN}
    previous = {signum: signal.signal(signum, handler) for signum, handler in handlers.items()}
    try:
        yield
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def _stop_poller(engine: Engine, poller: threading.Thread) -> None:
    engine.stop()
    poller.join(timeout=POLLER_TIMEOUT)


def run_daemon(interval: float, lan: list[str] | None, socket_path: Path = SOCKET_PATH, lock_path: Path = LOCK_PATH) -> int:
    try:
        lock = acquire_lock(lock_path)
    except AlreadyRunning as error:
        print(error, file=sys.stderr)
        return 1
    with lock:
        try:
            topology, catalog, store = detect_topology(lan), load_catalog(), PolicyStore()
        except STARTUP_ERRORS as error:
            print(error, file=sys.stderr)
            return 1
        _serve(topology, catalog, store, interval, socket_path)
    return 0


# Callbacks run last-registered first: the poller stops, then the socket
# closes, then the firewall table goes, then the helper threads.
def _serve(topology, catalog, store: PolicyStore, interval: float, socket_path: Path) -> None:
    with contextlib.ExitStack() as cleanup:
        discovery = ServiceDiscovery(topology)
        discovery.start()
        cleanup.callback(discovery.close)
        resolver = NameResolver(discovery=discovery)
        cleanup.callback(resolver.close)
        domain_sets = DomainSets(catalog)
        domain_sets.start()
        cleanup.callback(domain_sets.close)
        firewall = Firewall(shutil.which("nft"))
        firewall.setup()
        cleanup.callback(firewall.teardown)
        engine = Engine(Tracker(topology), read_flows, resolver, firewall, store, catalog, Neighbors(), domain_sets, interval)
        socket_path.unlink(missing_ok=True)
        server = DaemonServer(socket_path, engine)
        cleanup.callback(server.server_close)
        poller = threading.Thread(target=engine.run, name="poller")
        poller.start()
        cleanup.callback(_stop_poller, engine, poller)
        cleanup.enter_context(_exit_on_signals(server))
        server.serve_forever()
