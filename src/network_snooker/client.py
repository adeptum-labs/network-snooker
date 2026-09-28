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


import socket
from pathlib import Path

from network_snooker.policy import Mode, Rule, rule_to_dict
from network_snooker.wire import Snapshot, WireError, decode, encode, snapshot_from_dict

SOCKET_PATH = Path("/run/network-snooker/daemon.sock")
TIMEOUT = 2.0


class DaemonError(RuntimeError):
    pass


class RequestRefused(DaemonError):
    pass


# One short connection per request: a restarted daemon needs no reconnect
# logic, and a UI left open while the daemon is down recovers on its own.
class DaemonClient:
    def __init__(self, path: Path = SOCKET_PATH, timeout: float = TIMEOUT) -> None:
        self._path = path
        self._timeout = timeout

    def snapshot(self, since: int = 0) -> Snapshot:
        try:
            return snapshot_from_dict(self._request({"op": "snapshot", "since": since}).get("snapshot", {}))
        except WireError as error:
            raise DaemonError(str(error)) from error

    def toggle_pause(self, host_id: str) -> None:
        self._request({"op": "toggle_pause", "host_id": host_id})

    def set_mode(self, mac: str, mode: Mode) -> None:
        self._request({"op": "set_mode", "mac": mac, "mode": mode.value})

    def replace_rules(self, mac: str, rules: tuple[Rule, ...]) -> None:
        self._request({"op": "replace_rules", "mac": mac, "rules": [rule_to_dict(rule) for rule in rules]})

    def stop(self) -> None:
        self._request({"op": "stop"})

    def is_running(self) -> bool:
        try:
            with socket.socket(socket.AF_UNIX) as connection:
                connection.settimeout(self._timeout)
                connection.connect(str(self._path))
        except OSError:
            return False
        return True

    def _request(self, message: dict) -> dict:
        try:
            with socket.socket(socket.AF_UNIX) as connection:
                connection.settimeout(self._timeout)
                connection.connect(str(self._path))
                connection.sendall(encode(message))
                line = connection.makefile("rb").readline()
            response = decode(line)
        except (OSError, WireError) as error:
            raise DaemonError(f"daemon unreachable: {error}") from error
        if not response.get("ok"):
            raise RequestRefused(response.get("error", "request refused"))
        return response
