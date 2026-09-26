import os

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


def test_leases_reload_when_file_changes(tmp_path):
    path = tmp_path / "leases"
    path.write_text("")
    resolver = NameResolver(path, lookup=lambda ip: None, executor=DeferredExecutor())
    assert resolver.name("192.168.1.10") == "192.168.1.10"
    path.write_text(LEASES)
    os.utime(path, (1, 1))
    assert resolver.name("192.168.1.10") == "laptop"
