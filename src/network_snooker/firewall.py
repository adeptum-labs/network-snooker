import ipaddress
import subprocess
import threading

TABLE = "inet network_snooker"
NFT_MISSING = "nft not found; pausing unavailable"
# Declaring the table before deleting it makes the delete succeed whether or
# not a previous run, or an external flush, left one behind; nft applies the
# whole script atomically, so the kernel never runs without the table.
SETUP_SCRIPT = f"""table {TABLE}
delete table {TABLE}
table {TABLE} {{
    set paused4 {{ type ipv4_addr; }}
    set paused6 {{ type ipv6_addr; }}
    chain forward {{
        type filter hook forward priority -10; policy accept;
        ip saddr @paused4 drop
        ip daddr @paused4 drop
        ip6 saddr @paused6 drop
        ip6 daddr @paused6 drop
    }}
}}
"""
CONNTRACK_MATCHES = ("-s", "-d", "--reply-src")
COMMAND_TIMEOUT = 5


class FirewallError(RuntimeError):
    pass


def _set_name(ip: str) -> str:
    return "paused6" if ipaddress.ip_address(ip).version == 6 else "paused4"


def _table_script(paused: frozenset[str]) -> str:
    return SETUP_SCRIPT + "".join(f"add element {TABLE} {_set_name(ip)} {{ {ip} }}\n" for ip in sorted(paused))


class Firewall:
    def __init__(self, nft_path: str | None, run=subprocess.run) -> None:
        self._nft_path = nft_path
        self._run = run
        self._lock = threading.Lock()
        self.available = False
        self.unavailable_reason = NFT_MISSING
        self.paused: frozenset[str] = frozenset()

    def setup(self) -> None:
        if self._nft_path is None:
            return
        try:
            self._apply(_table_script(frozenset()))
        except FirewallError as error:
            self.unavailable_reason = f"pausing unavailable: {error}"
            return
        self.available = True

    def toggle(self, ip: str) -> bool:
        with self._lock:
            if not self.available:
                raise FirewallError(self.unavailable_reason)
            pausing = ip not in self.paused
            target = self.paused | {ip} if pausing else self.paused - {ip}
            self._apply(_table_script(target))
            self.paused = target
        if pausing:
            self._drop_connections(ip)
        return pausing

    def ensure(self) -> bool:
        with self._lock:
            if not (self.available and self.paused):
                return False
            try:
                self._apply(f"list table {TABLE}\n")
                return False
            except FirewallError:
                self._apply(_table_script(self.paused))
                return True

    def teardown(self) -> None:
        if not self.available:
            return
        # Exiting must not fail just because the table is already gone.
        try:
            self._apply(f"delete table {TABLE}\n")
        except FirewallError:
            pass
        self.available = False
        self.paused = frozenset()

    # Offloaded flows (flowtables) skip the forward hook; deleting their
    # conntrack entries forces the host's packets back through the drop rules.
    def _drop_connections(self, ip: str) -> None:
        for match in CONNTRACK_MATCHES:
            try:
                self._run(("conntrack", "-D", match, ip), capture_output=True, text=True, timeout=COMMAND_TIMEOUT, check=False)
            except (OSError, subprocess.TimeoutExpired):
                pass

    def _apply(self, script: str) -> None:
        try:
            result = self._run((self._nft_path, "-f", "-"), input=script, capture_output=True, text=True, timeout=COMMAND_TIMEOUT, check=False)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise FirewallError(f"nft failed: {error}") from error
        if result.returncode != 0:
            raise FirewallError(f"nft failed: {result.stderr.strip()}")
