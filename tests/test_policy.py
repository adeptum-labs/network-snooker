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

from datetime import datetime, time

import pytest

from network_snooker.policy import (
    HostPolicy,
    Mode,
    PolicyError,
    PolicyStore,
    Rule,
    blocked_services,
    format_days,
    format_windows,
    parse_windows,
)

MON_16_19 = Rule("minecraft", frozenset({0, 1, 2, 3, 4}), ((time(16, 0), time(19, 0)),))
WEEKEND_MORNING = Rule("minecraft", frozenset({5, 6}), ((time(22, 0), time(2, 0)),))
NEVER_TIKTOK = Rule("tiktok", frozenset({0, 1, 2, 3, 4, 5, 6}), ())


def at(weekday_date: str, hour: int, minute: int = 0) -> datetime:
    return datetime.fromisoformat(weekday_date).replace(hour=hour, minute=minute)


def test_blocked_when_mode_is_not_schedule():
    policy = HostPolicy("aa:bb", Mode.NONE, (MON_16_19,))
    assert blocked_services(policy, at("2026-09-28", 17)) == frozenset()  # Monday
    policy = HostPolicy("aa:bb", Mode.PAUSED, (MON_16_19,))
    assert blocked_services(policy, at("2026-09-28", 17)) == frozenset()


def test_service_allowed_inside_window():
    policy = HostPolicy("aa:bb", Mode.SCHEDULE, (MON_16_19,))
    assert blocked_services(policy, at("2026-09-28", 17)) == frozenset()


def test_service_blocked_outside_window():
    policy = HostPolicy("aa:bb", Mode.SCHEDULE, (MON_16_19,))
    assert blocked_services(policy, at("2026-09-28", 20)) == frozenset({"minecraft"})


def test_service_blocked_on_day_not_in_rule():
    policy = HostPolicy("aa:bb", Mode.SCHEDULE, (MON_16_19,))
    assert blocked_services(policy, at("2026-10-03", 17)) == frozenset({"minecraft"})  # Saturday


def test_window_crossing_midnight_covers_late_evening_on_start_day():
    policy = HostPolicy("aa:bb", Mode.SCHEDULE, (WEEKEND_MORNING,))
    assert blocked_services(policy, at("2026-10-03", 23)) == frozenset()  # Saturday 23:00


def test_window_crossing_midnight_covers_early_morning_on_next_day():
    policy = HostPolicy("aa:bb", Mode.SCHEDULE, (WEEKEND_MORNING,))
    assert blocked_services(policy, at("2026-10-04", 1)) == frozenset()  # Sunday 01:00, from Saturday's rule


def test_window_crossing_midnight_does_not_leak_to_unrelated_day():
    policy = HostPolicy("aa:bb", Mode.SCHEDULE, (WEEKEND_MORNING,))
    assert blocked_services(policy, at("2026-09-30", 1)) == frozenset({"minecraft"})  # Wednesday 01:00


def test_rule_with_no_windows_is_always_blocked():
    policy = HostPolicy("aa:bb", Mode.SCHEDULE, (NEVER_TIKTOK,))
    assert blocked_services(policy, at("2026-09-28", 12)) == frozenset({"tiktok"})


def test_several_rules_for_same_service_combine_as_any_allows():
    weekday_rule = Rule("tiktok", frozenset({0, 1, 2, 3, 4}), ((time(18, 0), time(19, 0)),))
    weekend_rule = Rule("tiktok", frozenset({5, 6}), ((time(10, 0), time(20, 0)),))
    policy = HostPolicy("aa:bb", Mode.SCHEDULE, (weekday_rule, weekend_rule))
    assert blocked_services(policy, at("2026-10-03", 12)) == frozenset()  # Saturday, weekend rule allows
    assert blocked_services(policy, at("2026-09-28", 12)) == frozenset({"tiktok"})  # Monday, outside both


def test_services_without_rules_are_unaffected():
    policy = HostPolicy("aa:bb", Mode.SCHEDULE, (MON_16_19,))
    assert "roblox" not in blocked_services(policy, at("2026-09-28", 20))


@pytest.mark.parametrize(
    "text,expected",
    [
        ("", ()),
        ("never", ()),
        ("16:00-19:00", ((time(16, 0), time(19, 0)),)),
        ("16:00-19:00, 20:00-21:30", ((time(16, 0), time(19, 0)), (time(20, 0), time(21, 30)))),
    ],
)
def test_parse_windows(text, expected):
    assert parse_windows(text) == expected


@pytest.mark.parametrize("text", ["16:00", "16:00-", "1600-1900", "16:00-19:00-20:00", "16:60-19:00"])
def test_parse_windows_rejects_bad_input(text):
    with pytest.raises(PolicyError):
        parse_windows(text)


def test_format_windows_round_trips():
    windows = ((time(16, 0), time(19, 0)), (time(20, 0), time(21, 30)))
    assert format_windows(windows) == "16:00-19:00, 20:00-21:30"
    assert parse_windows(format_windows(windows)) == windows


def test_format_windows_empty_is_never():
    assert format_windows(()) == "never"


@pytest.mark.parametrize(
    "days,expected",
    [
        (frozenset(), "never"),
        (frozenset(range(7)), "every day"),
        (frozenset({0}), "Mon"),
        (frozenset({0, 1, 2, 3, 4}), "Mon-Fri"),
        (frozenset({5, 6}), "Sat-Sun"),
        (frozenset({0, 2, 4}), "Mon, Wed, Fri"),
        (frozenset({5, 6, 0}), "Mon, Sat-Sun"),
    ],
)
def test_format_days(days, expected):
    assert format_days(days) == expected


@pytest.fixture
def store_path(tmp_path):
    return tmp_path / "policies.json"


def test_missing_file_starts_empty(store_path):
    store = PolicyStore(store_path)
    assert store.get("aa:bb:cc:dd:ee:01") == HostPolicy("aa:bb:cc:dd:ee:01", Mode.NONE, ())


def test_get_lowercases_mac(store_path):
    store = PolicyStore(store_path)
    store.set_mode("AA:BB:CC:DD:EE:01", Mode.PAUSED)
    assert store.get("aa:bb:cc:dd:ee:01").mode is Mode.PAUSED


def test_set_mode_persists_and_reloads(store_path):
    store = PolicyStore(store_path)
    store.set_mode("aa:bb:cc:dd:ee:01", Mode.PAUSED)
    reloaded = PolicyStore(store_path)
    assert reloaded.get("aa:bb:cc:dd:ee:01").mode is Mode.PAUSED


def test_toggle_paused_sets_and_clears(store_path):
    store = PolicyStore(store_path)
    store.toggle_paused("aa:bb:cc:dd:ee:01")
    assert store.get("aa:bb:cc:dd:ee:01").mode is Mode.PAUSED
    store.toggle_paused("aa:bb:cc:dd:ee:01")
    assert store.get("aa:bb:cc:dd:ee:01").mode is Mode.NONE


def test_unpausing_returns_to_schedule_when_rules_remain(store_path):
    store = PolicyStore(store_path)
    store.replace_rules("aa:bb:cc:dd:ee:01", (MON_16_19,))
    store.toggle_paused("aa:bb:cc:dd:ee:01")
    assert store.get("aa:bb:cc:dd:ee:01").mode is Mode.PAUSED
    store.toggle_paused("aa:bb:cc:dd:ee:01")
    assert store.get("aa:bb:cc:dd:ee:01").mode is Mode.SCHEDULE


def test_replace_rules_promotes_none_to_schedule(store_path):
    store = PolicyStore(store_path)
    store.replace_rules("aa:bb:cc:dd:ee:01", (MON_16_19,))
    assert store.get("aa:bb:cc:dd:ee:01").mode is Mode.SCHEDULE


def test_replace_rules_demotes_schedule_to_none_when_emptied(store_path):
    store = PolicyStore(store_path)
    store.replace_rules("aa:bb:cc:dd:ee:01", (MON_16_19,))
    store.replace_rules("aa:bb:cc:dd:ee:01", ())
    assert store.get("aa:bb:cc:dd:ee:01").mode is Mode.NONE


def test_replace_rules_round_trips_through_json(store_path):
    store = PolicyStore(store_path)
    store.replace_rules("aa:bb:cc:dd:ee:01", (MON_16_19, NEVER_TIKTOK))
    reloaded = PolicyStore(store_path)
    assert reloaded.get("aa:bb:cc:dd:ee:01").rules == (MON_16_19, NEVER_TIKTOK)


def test_clearing_last_rule_removes_host_from_file(store_path):
    store = PolicyStore(store_path)
    store.replace_rules("aa:bb:cc:dd:ee:01", (MON_16_19,))
    store.replace_rules("aa:bb:cc:dd:ee:01", ())
    reloaded = PolicyStore(store_path)
    assert reloaded.get("aa:bb:cc:dd:ee:01") == HostPolicy("aa:bb:cc:dd:ee:01", Mode.NONE, ())
    assert not store_path.exists() or store_path.read_text().strip() == "{}"


def test_corrupt_file_raises_and_is_not_overwritten(store_path):
    store_path.write_text("not json")
    with pytest.raises(PolicyError):
        PolicyStore(store_path)
    assert store_path.read_text() == "not json"


def test_invalid_mode_raises(store_path):
    store_path.write_text('{"aa:bb": {"mode": "not-a-mode", "rules": []}}')
    with pytest.raises(PolicyError):
        PolicyStore(store_path)
