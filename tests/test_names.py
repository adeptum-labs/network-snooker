import os
import threading
from concurrent.futures import ThreadPoolExecutor

from network_snooker.names import NameResolver, read_leases

LEASES = (
    "1790000000 aa:bb:cc:dd:ee:01 192.168.1.10 laptop 01:aa:bb:cc:dd:ee:01\n"
    "1790000000 aa:bb:cc:dd:ee:02 192.168.1.11 * *\n"
)


class DeferredExecutor:
    def __init__(self):
        self.tasks = []

    def submit(self, function, *arguments):
        self.tasks.append((function, arguments))

    def run_all(self):
        for function, arguments in self.tasks:
            function(*arguments)
        self.tasks.clear()


def test_read_leases_skips_unnamed(tmp_path):
    path = tmp_path / "leases"
    path.write_text(LEASES)
    assert read_leases(path) == {"192.168.1.10": "laptop"}


def test_read_leases_missing_file(tmp_path):
    assert read_leases(tmp_path / "absent") == {}


def test_lease_name_wins(tmp_path):
    path = tmp_path / "leases"
    path.write_text(LEASES)
    resolver = NameResolver(path, lookup=lambda ip: "dns-name", executor=DeferredExecutor())
    assert resolver.name("192.168.1.10") == "laptop"


def test_reverse_lookup_never_blocks(tmp_path):
    executor = DeferredExecutor()
    resolver = NameResolver(tmp_path / "absent", lookup=lambda ip: "example.org", executor=executor)
    assert resolver.name("93.184.216.34") == "93.184.216.34"
    assert resolver.name("93.184.216.34") == "93.184.216.34"
    assert len(executor.tasks) == 1
    executor.run_all()
    assert resolver.name("93.184.216.34") == "example.org"


def test_failed_lookup_shows_ip(tmp_path):
    executor = DeferredExecutor()
    resolver = NameResolver(tmp_path / "absent", lookup=lambda ip: None, executor=executor)
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


def test_discovered_name_beats_reverse_lookup(tmp_path):
    executor = DeferredExecutor()
    discovery = FakeDiscovery({"192.168.1.20": "printer"})
    resolver = NameResolver(tmp_path / "absent", lookup=lambda ip: "dns-name", executor=executor, discovery=discovery)
    resolver.name("192.168.1.20")
    executor.run_all()
    assert resolver.name("192.168.1.20") == "printer"
    assert discovery.requested == ["192.168.1.20", "192.168.1.20"]


def test_lease_name_skips_discovery(tmp_path):
    path = tmp_path / "leases"
    path.write_text(LEASES)
    discovery = FakeDiscovery({"192.168.1.10": "printer"})
    resolver = NameResolver(path, lookup=lambda ip: None, executor=DeferredExecutor(), discovery=discovery)
    assert resolver.name("192.168.1.10") == "laptop"
    assert discovery.requested == []


def test_leases_reload_when_file_changes(tmp_path):
    path = tmp_path / "leases"
    path.write_text("")
    resolver = NameResolver(path, lookup=lambda ip: None, executor=DeferredExecutor())
    assert resolver.name("192.168.1.10") == "192.168.1.10"
    path.write_text(LEASES)
    os.utime(path, (1, 1))
    assert resolver.name("192.168.1.10") == "laptop"


def test_close_drops_queued_lookups(tmp_path):
    started = threading.Event()
    release = threading.Event()
    looked_up = []

    def blocking_lookup(ip):
        looked_up.append(ip)
        started.set()
        release.wait(5)
        return None

    executor = ThreadPoolExecutor(max_workers=1)
    resolver = NameResolver(tmp_path / "absent", lookup=blocking_lookup, executor=executor)
    for ip in ("198.51.100.1", "198.51.100.2", "198.51.100.3"):
        resolver.name(ip)
    started.wait(5)
    resolver.close()
    release.set()
    executor.shutdown(wait=True)
    assert looked_up == ["198.51.100.1"]
