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

from datetime import time

from textual.widgets import Checkbox, DataTable, Input, Select, Static

from network_snooker.app import DetailScreen, HostScreen
from network_snooker.policy import Mode, Rule
from network_snooker.schedule_screen import RuleDialog, ScheduleScreen
from test_app import HOST_MAC, PING, WEB, fresh_store, make_app, make_neighbors, record_notifications


def rows(app):
    table = app.screen.query_one("#rules", DataTable)
    return [tuple(str(cell) for cell in table.get_row_at(index)) for index in range(table.row_count)]


async def test_e_opens_schedule_screen_for_known_mac(topology):
    app = make_app(topology, lambda: [WEB])
    async with app.run_test() as pilot:
        await pilot.pause(0.2)
        await pilot.press("e")
        await pilot.pause(0.1)
        assert isinstance(app.screen, ScheduleScreen)
        assert HOST_MAC in str(app.screen.query_one("#summary", Static).render())


async def test_e_notifies_for_unknown_mac(topology):
    app = make_app(topology, lambda: [WEB], neighbors=make_neighbors({}))
    messages = record_notifications(app)
    async with app.run_test() as pilot:
        await pilot.pause(0.2)
        await pilot.press("e")
        await pilot.pause(0.1)
        assert isinstance(app.screen, HostScreen)
        assert any("Unknown MAC address" in message for message, _ in messages)


async def test_e_notifies_for_router(topology):
    app = make_app(topology, lambda: [PING])
    messages = record_notifications(app)
    async with app.run_test() as pilot:
        await pilot.pause(0.2)
        await pilot.press("e")
        await pilot.pause(0.1)
        assert isinstance(app.screen, HostScreen)
        assert any("no schedule" in message for message, _ in messages)


async def test_e_on_detail_screen_opens_schedule(topology):
    app = make_app(topology, lambda: [WEB])
    async with app.run_test() as pilot:
        await pilot.pause(0.2)
        await pilot.press("enter")
        await pilot.pause(0.1)
        assert isinstance(app.screen, DetailScreen)
        await pilot.press("e")
        await pilot.pause(0.1)
        assert isinstance(app.screen, ScheduleScreen)


def fill_dialog(dialog, service="minecraft", days=(0,), windows="16:00-19:00"):
    dialog.query_one("#service", Select).value = service
    for index in days:
        dialog.query_one(f"#day-{index}", Checkbox).value = True
    dialog.query_one("#windows", Input).value = windows


async def test_add_rule_creates_schedule_and_shows_row(topology):
    store = fresh_store()
    app = make_app(topology, lambda: [WEB], store=store)
    async with app.run_test() as pilot:
        await pilot.pause(0.2)
        await pilot.press("e")
        await pilot.pause(0.1)
        await pilot.press("a")
        await pilot.pause(0.1)
        dialog = app.screen
        assert isinstance(dialog, RuleDialog)
        fill_dialog(dialog)
        await pilot.click("#ok")
        await pilot.pause(0.1)
        assert isinstance(app.screen, ScheduleScreen)
        assert rows(app) == [("Minecraft", "Mon", "16:00-19:00")]
        assert store.get(HOST_MAC).mode is Mode.SCHEDULE


async def test_cancel_discards_rule(topology):
    store = fresh_store()
    app = make_app(topology, lambda: [WEB], store=store)
    async with app.run_test() as pilot:
        await pilot.pause(0.2)
        await pilot.press("e")
        await pilot.pause(0.1)
        await pilot.press("a")
        await pilot.pause(0.1)
        fill_dialog(app.screen)
        await pilot.click("#cancel")
        await pilot.pause(0.1)
        assert rows(app) == []
        assert store.get(HOST_MAC).mode is Mode.NONE


async def test_edit_rule_updates_row(topology):
    store = fresh_store()
    store.replace_rules(HOST_MAC, (Rule("minecraft", frozenset({0}), ((time(16, 0), time(19, 0)),)),))
    app = make_app(topology, lambda: [WEB], store=store)
    async with app.run_test() as pilot:
        await pilot.pause(0.2)
        await pilot.press("e")
        await pilot.pause(0.1)
        await pilot.press("enter")
        await pilot.pause(0.1)
        dialog = app.screen
        assert isinstance(dialog, RuleDialog)
        dialog.query_one("#windows", Input).value = "17:00-18:00"
        await pilot.click("#ok")
        await pilot.pause(0.1)
        assert rows(app) == [("Minecraft", "Mon", "17:00-18:00")]


async def test_delete_rule_removes_row_and_clears_mode(topology):
    store = fresh_store()
    store.replace_rules(HOST_MAC, (Rule("minecraft", frozenset({0}), ((time(16, 0), time(19, 0)),)),))
    app = make_app(topology, lambda: [WEB], store=store)
    async with app.run_test() as pilot:
        await pilot.pause(0.2)
        await pilot.press("e")
        await pilot.pause(0.1)
        await pilot.press("d")
        await pilot.pause(0.1)
        assert rows(app) == []
        assert store.get(HOST_MAC).mode is Mode.NONE


async def test_toggle_mode_switches_between_schedule_and_none(topology):
    store = fresh_store()
    store.replace_rules(HOST_MAC, (Rule("minecraft", frozenset({0}), ()),))
    app = make_app(topology, lambda: [WEB], store=store)
    async with app.run_test() as pilot:
        await pilot.pause(0.2)
        await pilot.press("e")
        await pilot.pause(0.1)
        await pilot.press("m")
        await pilot.pause(0.1)
        assert store.get(HOST_MAC).mode is Mode.NONE
        await pilot.press("m")
        await pilot.pause(0.1)
        assert store.get(HOST_MAC).mode is Mode.SCHEDULE


async def test_rule_dialog_rejects_missing_service(topology):
    app = make_app(topology, lambda: [WEB])
    async with app.run_test() as pilot:
        await pilot.pause(0.2)
        await pilot.press("e")
        await pilot.pause(0.1)
        await pilot.press("a")
        await pilot.pause(0.1)
        await pilot.click("#ok")
        await pilot.pause(0.1)
        assert isinstance(app.screen, RuleDialog)
        assert "Choose a service" in str(app.screen.query_one("#error", Static).render())


async def test_rule_dialog_rejects_no_days(topology):
    app = make_app(topology, lambda: [WEB])
    async with app.run_test() as pilot:
        await pilot.pause(0.2)
        await pilot.press("e")
        await pilot.pause(0.1)
        await pilot.press("a")
        await pilot.pause(0.1)
        app.screen.query_one("#service", Select).value = "minecraft"
        await pilot.click("#ok")
        await pilot.pause(0.1)
        assert "Choose at least one day" in str(app.screen.query_one("#error", Static).render())


async def test_rule_dialog_rejects_bad_window(topology):
    app = make_app(topology, lambda: [WEB])
    async with app.run_test() as pilot:
        await pilot.pause(0.2)
        await pilot.press("e")
        await pilot.pause(0.1)
        await pilot.press("a")
        await pilot.pause(0.1)
        fill_dialog(app.screen, windows="not-a-window")
        await pilot.click("#ok")
        await pilot.pause(0.1)
        assert "bad time window" in str(app.screen.query_one("#error", Static).render())


async def test_escape_returns_to_host_screen(topology):
    app = make_app(topology, lambda: [WEB])
    async with app.run_test() as pilot:
        await pilot.pause(0.2)
        await pilot.press("e")
        await pilot.pause(0.1)
        await pilot.press("escape")
        await pilot.pause(0.1)
        assert isinstance(app.screen, HostScreen)
