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
import logging
import os
import socketserver
from pathlib import Path

from network_snooker import package_version
from network_snooker.daemon import Engine, RequestError
from network_snooker.policy import Mode, PolicyError, rule_from_dict
from network_snooker.wire import WireError, decode, encode, snapshot_to_dict

log = logging.getLogger(__name__)

MAX_REQUEST_BYTES = 1 << 20
OWNER_ONLY = 0o177


class _Handler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        line = self.rfile.readline(MAX_REQUEST_BYTES)
        if not line:
            return
        try:
            response = {"ok": True, **self.server.dispatch(decode(line))}
        except (WireError, RequestError) as error:
            response = {"ok": False, "error": str(error)}
        except Exception as error:
            log.exception("request failed")
            response = {"ok": False, "error": f"request failed: {error}"}
        with contextlib.suppress(ConnectionError):
            self.wfile.write(encode(response))
            self.wfile.flush()
        if self.server.stop_requested:
            self.server.shutdown()


# The socket is created under a restrictive umask so that no other user can
# connect to it, not even for the instant between bind and chmod.
class DaemonServer(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True

    def __init__(self, path: Path, engine: Engine) -> None:
        self.engine = engine
        self.stop_requested = False
        self._path = path
        previous = os.umask(OWNER_ONLY)
        try:
            super().__init__(str(path), _Handler)
        finally:
            os.umask(previous)

    def server_close(self) -> None:
        super().server_close()
        with contextlib.suppress(FileNotFoundError):
            self._path.unlink()

    def dispatch(self, request: dict) -> dict:
        try:
            return self._dispatch(request)
        except (KeyError, TypeError, ValueError, PolicyError) as error:
            raise WireError(f"bad request: {error!r}") from error

    def _dispatch(self, request: dict) -> dict:
        match request.get("op"):
            case "snapshot":
                return {"snapshot": snapshot_to_dict(self.engine.snapshot(int(request.get("since", 0))))}
            case "toggle_pause":
                self.engine.toggle_pause(request["host_id"])
            case "set_mode":
                self.engine.set_mode(request["mac"], Mode(request["mode"]))
            case "replace_rules":
                self.engine.replace_rules(request["mac"], tuple(rule_from_dict(rule) for rule in request["rules"]))
            case "version":
                return {"version": package_version()}
            case "stop":
                self.stop_requested = True
            case op:
                raise WireError(f"unknown op: {op}")
        return {}
