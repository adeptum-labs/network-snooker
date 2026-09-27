import re
import socket
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

DNSMASQ_LEASES = Path("/var/lib/misc/dnsmasq.leases")
DHCPD_LEASES = Path("/var/lib/dhcp/dhcpd.leases")
UNNAMED_LEASE = "*"
DHCPD_LEASE = re.compile(r"^lease (\S+) \{(.*?)^\}", re.MULTILINE | re.DOTALL)
ACTIVE_BINDING = re.compile(r"^\s*binding state active;", re.MULTILINE)
CLIENT_HOSTNAME = re.compile(r'^\s*client-hostname "([^"]+)";', re.MULTILINE)


def _read_text(path: Path) -> str:
    try:
        return path.read_text()
    except OSError:
        return ""


def read_dnsmasq_leases(path: Path) -> dict[str, str]:
    lines = _read_text(path).splitlines()
    return {parts[2]: parts[3] for parts in map(str.split, lines) if len(parts) >= 4 and parts[3] != UNNAMED_LEASE}


# dhcpd appends a block on every lease change and compacts the file only now
# and then, so the last block for an address is the current one.
def read_dhcpd_leases(path: Path) -> dict[str, str]:
    latest = dict(DHCPD_LEASE.findall(_read_text(path)))
    hostnames = {ip: CLIENT_HOSTNAME.search(block) for ip, block in latest.items() if ACTIVE_BINDING.search(block)}
    return {ip: match[1] for ip, match in hostnames.items() if match}


LEASE_FILES = ((DNSMASQ_LEASES, read_dnsmasq_leases), (DHCPD_LEASES, read_dhcpd_leases))


def reverse_lookup(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return None


class _LeaseFile:
    def __init__(self, path: Path, read: Callable[[Path], dict[str, str]]) -> None:
        self._path = path
        self._read = read
        self._mtime: float | None = None
        self._names: dict[str, str] = {}

    def names(self) -> dict[str, str]:
        try:
            mtime = self._path.stat().st_mtime
        except OSError:
            mtime = None
        if mtime != self._mtime:
            self._mtime = mtime
            self._names = self._read(self._path)
        return self._names


class NameResolver:
    def __init__(self, lease_files=LEASE_FILES, lookup=reverse_lookup, executor=None, discovery=None) -> None:
        self._lease_files = [_LeaseFile(path, read) for path, read in lease_files]
        self._lookup = lookup
        self._executor = executor or ThreadPoolExecutor(max_workers=4)
        self._discovery = discovery
        self._resolved: dict[str, str | None] = {}

    def name(self, ip: str) -> str:
        if lease_name := self._lease_name(ip):
            return lease_name
        if ip not in self._resolved:
            self._resolved[ip] = None
            self._executor.submit(self._resolve, ip)
        return self._discovered(ip) or self._resolved[ip] or ip

    def close(self) -> None:
        self._executor.shutdown(wait=False, cancel_futures=True)

    def _lease_name(self, ip: str) -> str | None:
        return next(filter(None, (lease_file.names().get(ip) for lease_file in self._lease_files)), None)

    def _discovered(self, ip: str) -> str | None:
        if self._discovery is None:
            return None
        self._discovery.request(ip)
        return self._discovery.name(ip)

    def _resolve(self, ip: str) -> None:
        self._resolved[ip] = self._lookup(ip)
