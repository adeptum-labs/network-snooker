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

import json
import os
import re
from dataclasses import dataclass, replace
from datetime import datetime, time
from enum import StrEnum
from pathlib import Path

DEFAULT_POLICY_PATH = Path("/var/lib/network-snooker/policies.json")
DAY_NAMES = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
ALL_DAYS = frozenset(range(7))
WINDOW_PATTERN = re.compile(r"^(\d{1,2}:\d{2})-(\d{1,2}:\d{2})$")


class Mode(StrEnum):
    NONE = "none"
    SCHEDULE = "schedule"
    PAUSED = "paused"


class PolicyError(RuntimeError):
    pass


@dataclass(frozen=True)
class Rule:
    service: str
    days: frozenset[int]
    windows: tuple[tuple[time, time], ...]


@dataclass(frozen=True)
class HostPolicy:
    mac: str
    mode: Mode
    rules: tuple[Rule, ...] = ()


def _window_covers(window: tuple[time, time], days: frozenset[int], weekday: int, now: time) -> bool:
    start, end = window
    if start <= end:
        return weekday in days and start <= now <= end
    previous_day = (weekday - 1) % 7
    return (weekday in days and now >= start) or (previous_day in days and now <= end)


def _rule_allows(rule: Rule, weekday: int, now: time) -> bool:
    return any(_window_covers(window, rule.days, weekday, now) for window in rule.windows)


# A service is blocked unless some rule for it allows the current moment;
# several rules for the same service therefore combine as an "any of these".
def blocked_services(policy: HostPolicy, now: datetime) -> frozenset[str]:
    if policy.mode is not Mode.SCHEDULE:
        return frozenset()
    weekday, current = now.weekday(), now.time()
    services = {rule.service for rule in policy.rules}
    allowed = {rule.service for rule in policy.rules if _rule_allows(rule, weekday, current)}
    return frozenset(services - allowed)


def parse_windows(text: str) -> tuple[tuple[time, time], ...]:
    text = text.strip()
    if not text or text.lower() == "never":
        return ()
    return tuple(_parse_window(part.strip()) for part in text.split(","))


def _parse_window(part: str) -> tuple[time, time]:
    match = WINDOW_PATTERN.match(part)
    if not match:
        raise PolicyError(f"bad time window '{part}', expected 'HH:MM-HH:MM'")
    return _parse_time(match[1]), _parse_time(match[2])


def _parse_time(text: str) -> time:
    hour, minute = text.split(":")
    try:
        return time(int(hour), int(minute))
    except ValueError:
        raise PolicyError(f"bad time '{text}'") from None


def format_windows(windows: tuple[tuple[time, time], ...]) -> str:
    if not windows:
        return "never"
    return ", ".join(f"{start:%H:%M}-{end:%H:%M}" for start, end in windows)


def format_days(days: frozenset[int]) -> str:
    if not days:
        return "never"
    if days == ALL_DAYS:
        return "every day"
    ranges, ordered = [], sorted(days)
    start = previous = ordered[0]
    for day in ordered[1:]:
        if day == previous + 1:
            previous = day
            continue
        ranges.append((start, previous))
        start = previous = day
    ranges.append((start, previous))
    return ", ".join(DAY_NAMES[a] if a == b else f"{DAY_NAMES[a]}-{DAY_NAMES[b]}" for a, b in ranges)


def rule_to_dict(rule: Rule) -> dict:
    return {
        "service": rule.service,
        "days": sorted(rule.days),
        "windows": [[f"{start:%H:%M}", f"{end:%H:%M}"] for start, end in rule.windows],
    }


def rule_from_dict(entry: dict) -> Rule:
    return Rule(
        service=entry["service"],
        days=frozenset(entry["days"]),
        windows=tuple((_parse_time(start), _parse_time(end)) for start, end in entry["windows"]),
    )


def policy_to_dict(policy: HostPolicy) -> dict:
    return {"mode": policy.mode.value, "rules": [rule_to_dict(rule) for rule in policy.rules]}


def policy_from_dict(mac: str, entry: dict) -> HostPolicy:
    return HostPolicy(mac=mac, mode=Mode(entry["mode"]), rules=tuple(rule_from_dict(rule) for rule in entry.get("rules", [])))


class PolicyStore:
    def __init__(self, path: Path = DEFAULT_POLICY_PATH) -> None:
        self._path = path
        self._policies: dict[str, HostPolicy] = {}
        self.load()

    def load(self) -> None:
        try:
            text = self._path.read_text()
        except FileNotFoundError:
            self._policies = {}
            return
        except OSError as error:
            raise PolicyError(f"cannot read {self._path}: {error}") from error
        try:
            raw = json.loads(text)
            self._policies = {mac: policy_from_dict(mac, entry) for mac, entry in raw.items()}
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
            raise PolicyError(f"cannot parse {self._path}: {error}") from error

    def get(self, mac: str) -> HostPolicy:
        mac = mac.lower()
        return self._policies.get(mac, HostPolicy(mac, Mode.NONE, ()))

    def all(self) -> tuple[HostPolicy, ...]:
        return tuple(self._policies.values())

    def set_mode(self, mac: str, mode: Mode) -> HostPolicy:
        return self._save_policy(replace(self.get(mac), mode=mode))

    # Unpausing lands back on SCHEDULE when there are rules to enforce again,
    # otherwise on NONE; scheduling and clearing the last rule mirror that.
    def toggle_paused(self, mac: str) -> HostPolicy:
        policy = self.get(mac)
        if policy.mode is Mode.PAUSED:
            mode = Mode.SCHEDULE if policy.rules else Mode.NONE
        else:
            mode = Mode.PAUSED
        return self._save_policy(replace(policy, mode=mode))

    def replace_rules(self, mac: str, rules: tuple[Rule, ...]) -> HostPolicy:
        policy = self.get(mac)
        mode = policy.mode
        if mode is Mode.NONE and rules:
            mode = Mode.SCHEDULE
        elif mode is Mode.SCHEDULE and not rules:
            mode = Mode.NONE
        return self._save_policy(replace(policy, mode=mode, rules=rules))

    def _save_policy(self, policy: HostPolicy) -> HostPolicy:
        mac = policy.mac.lower()
        if policy.mode is Mode.NONE and not policy.rules:
            self._policies.pop(mac, None)
        else:
            self._policies[mac] = policy
        self._write()
        return policy

    def _write(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(".tmp")
        tmp.write_text(json.dumps({mac: policy_to_dict(policy) for mac, policy in self._policies.items()}, indent=2))
        os.replace(tmp, self._path)
