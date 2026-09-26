import ipaddress
import subprocess

TABLE = "inet network_snooker"
NFT_MISSING = "nft not found; pausing unavailable"
# Declaring the table before deleting it makes the delete succeed whether or
# not a previous run left one behind; nft applies the whole script atomically.
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


class FirewallError(RuntimeError):
    pass


def _set_name(ip: str) -> str:
    return "paused6" if ipaddress.ip_address(ip).version == 6 else "paused4"


class Firewall:
    def __init__(self, nft_path: str | None, run=subprocess.run) -> None:
        self._nft_path = nft_path
        self._run = run
        self.available = False
        self.unavailable_reason = NFT_MISSING
        self.paused: frozenset[str] = frozenset()

    def setup(self) -> None:
        if self._nft_path is None:
            return
        try:
            self._apply(SETUP_SCRIPT)
        except FirewallError as error:
            self.unavailable_reason = f"pausing unavailable: {error}"
            return
        self.available = True

    def toggle(self, ip: str) -> bool:
        if not self.available:
            raise FirewallError(self.unavailable_reason)
        pausing = ip not in self.paused
        self._apply(f"{'add' if pausing else 'delete'} element {TABLE} {_set_name(ip)} {{ {ip} }}\n")
        self.paused = self.paused | {ip} if pausing else self.paused - {ip}
        return pausing

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

    def _apply(self, script: str) -> None:
        try:
            result = self._run((self._nft_path, "-f", "-"), input=script, capture_output=True, text=True, timeout=5, check=False)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise FirewallError(f"nft failed: {error}") from error
        if result.returncode != 0:
            raise FirewallError(f"nft failed: {result.stderr.strip()}")
