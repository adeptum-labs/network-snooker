import socket
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

DEFAULT_LEASES = Path("/var/lib/misc/dnsmasq.leases")
UNNAMED_LEASE = "*"


def read_leases(path: Path) -> dict[str, str]:
    try:
        lines = path.read_text().splitlines()
    except OSError:
        return {}
    return {parts[2]: parts[3] for parts in map(str.split, lines) if len(parts) >= 4 and parts[3] != UNNAMED_LEASE}


def reverse_lookup(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return None


class NameResolver:
    def __init__(self, leases_path: Path = DEFAULT_LEASES, lookup=reverse_lookup, executor=None) -> None:
        self._leases_path = leases_path
        self._lookup = lookup
        self._executor = executor or ThreadPoolExecutor(max_workers=4)
        self._leases: dict[str, str] = {}
        self._leases_mtime: float | None = None
        self._resolved: dict[str, str | None] = {}

    def name(self, ip: str) -> str:
        self._refresh_leases()
        if ip in self._leases:
            return self._leases[ip]
        if ip not in self._resolved:
            self._resolved[ip] = None
            self._executor.submit(self._resolve, ip)
        return self._resolved[ip] or ip

    def _resolve(self, ip: str) -> None:
        self._resolved[ip] = self._lookup(ip)

    def _refresh_leases(self) -> None:
        try:
            mtime = self._leases_path.stat().st_mtime
        except OSError:
            mtime = None
        if mtime != self._leases_mtime:
            self._leases_mtime = mtime
            self._leases = read_leases(self._leases_path)
