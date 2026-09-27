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

import subprocess
from dataclasses import dataclass

COMMAND = ("conntrack", "-L", "-o", "extended")
# conntrack lists only IPv4 unless a family is given.
FAMILIES = ("ipv4", "ipv6")


class ConntrackError(RuntimeError):
    pass


@dataclass(frozen=True)
class Endpoints:
    src: str
    dst: str
    sport: int | None = None
    dport: int | None = None


@dataclass(frozen=True)
class Flow:
    protocol: str
    orig: Endpoints
    reply: Endpoints
    orig_bytes: int = 0
    orig_packets: int = 0
    reply_bytes: int = 0
    reply_packets: int = 0
    ident: int | None = None

    @property
    def key(self) -> tuple[str, Endpoints, int | None]:
        return self.protocol, self.orig, self.ident


def _split_directions(tokens: list[str]) -> tuple[dict[str, str], dict[str, str]]:
    directions: tuple[dict[str, str], dict[str, str]] = ({}, {})
    index = -1
    for token in tokens:
        name, separator, value = token.partition("=")
        if not separator:
            continue
        if name == "src":
            index += 1
        if 0 <= index < 2:
            directions[index].setdefault(name, value)
    return directions


def _optional_int(value: str | None) -> int | None:
    return None if value is None else int(value)


def _endpoints(fields: dict[str, str]) -> Endpoints:
    return Endpoints(fields["src"], fields["dst"], _optional_int(fields.get("sport")), _optional_int(fields.get("dport")))


def parse_line(line: str) -> Flow | None:
    tokens = line.split()
    if len(tokens) < 3:
        return None
    orig, reply = _split_directions(tokens)
    if not ({"src", "dst"} <= orig.keys() and {"src", "dst"} <= reply.keys()):
        return None
    return Flow(
        protocol=tokens[2],
        orig=_endpoints(orig),
        reply=_endpoints(reply),
        orig_bytes=int(orig.get("bytes", 0)),
        orig_packets=int(orig.get("packets", 0)),
        reply_bytes=int(reply.get("bytes", 0)),
        reply_packets=int(reply.get("packets", 0)),
        ident=_optional_int(orig.get("id")),
    )


def parse_output(text: str) -> list[Flow]:
    return [flow for line in text.splitlines() if (flow := parse_line(line))]


def read_flows(run=subprocess.run, timeout: float = 5.0) -> list[Flow]:
    return [flow for family in FAMILIES for flow in _read_family(family, run, timeout)]


def _read_family(family: str, run, timeout: float) -> list[Flow]:
    try:
        result = run((*COMMAND, "-f", family), capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ConntrackError(f"conntrack failed: {error}") from error
    if result.returncode != 0:
        raise ConntrackError(f"conntrack failed: {result.stderr.strip()}")
    return parse_output(result.stdout)
