import queue
import socket
import threading
import time
from collections.abc import Callable

from network_snooker.catalog import Catalog

RESOLVE_INTERVAL = 300.0
ADDRESS_TTL = 3600.0


def _resolve_domain(resolve: Callable, domain: str) -> set[str]:
    try:
        results = resolve(domain, None)
    except OSError:
        return set()
    return {info[4][0] for info in results}


def _is_v6(address: str) -> bool:
    return ":" in address


# A service's site-blocking set is the union of its bundled CIDRs (always
# present) and whatever its domains last resolved to, so a resolver outage
# degrades to CIDR-only coverage rather than to no blocking at all.
class DomainSets:
    def __init__(self, catalog: Catalog, resolve=socket.getaddrinfo, resolve_interval: float = RESOLVE_INTERVAL, address_ttl: float = ADDRESS_TTL) -> None:
        self._catalog = catalog
        self._resolve = resolve
        self._resolve_interval = resolve_interval
        self._address_ttl = address_ttl
        self._active: frozenset[str] = frozenset()
        self._resolved: dict[str, dict[str, float]] = {}
        self._lock = threading.Lock()
        self._pending: queue.SimpleQueue[str | None] = queue.SimpleQueue()
        self._stopping = threading.Event()
        self._thread = threading.Thread(target=self._run, name="domain-sets", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def close(self) -> None:
        self._stopping.set()
        self._pending.put(None)

    def mark_active(self, service_keys: frozenset[str]) -> None:
        with self._lock:
            newly_active = service_keys - self._active
            self._active = service_keys
        for key in newly_active:
            self._pending.put(key)

    def addresses(self, service_key: str) -> tuple[frozenset[str], frozenset[str]]:
        service = self._catalog[service_key]
        with self._lock:
            resolved = frozenset(self._resolved.get(service_key, {}))
        combined = frozenset(service.cidrs) | resolved
        return frozenset(a for a in combined if not _is_v6(a)), frozenset(a for a in combined if _is_v6(a))

    def _run(self) -> None:
        next_sweep = time.monotonic()
        while not self._stopping.is_set():
            if time.monotonic() >= next_sweep:
                self._resolve_active()
                next_sweep = time.monotonic() + self._resolve_interval
            try:
                key = self._pending.get(timeout=max(next_sweep - time.monotonic(), 0))
            except queue.Empty:
                continue
            if key is not None and not self._stopping.is_set():
                self._resolve_service(key)

    def _resolve_active(self) -> None:
        with self._lock:
            active = self._active
        for key in active:
            self._resolve_service(key)
        self._expire()

    def _resolve_service(self, key: str) -> None:
        now = time.monotonic()
        found = {ip: now for domain in self._catalog[key].domains for ip in _resolve_domain(self._resolve, domain)}
        with self._lock:
            self._resolved.setdefault(key, {}).update(found)

    def _expire(self) -> None:
        cutoff = time.monotonic() - self._address_ttl
        with self._lock:
            for entries in self._resolved.values():
                for ip, last_seen in list(entries.items()):
                    if last_seen < cutoff:
                        del entries[ip]
