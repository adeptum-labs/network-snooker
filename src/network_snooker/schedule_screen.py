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

from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen, Screen
from textual.widgets import Button, Checkbox, DataTable, Footer, Header, Input, Select, Static

from network_snooker.enforcement import ALL_TRAFFIC_LABEL, service_label
from network_snooker.policy import ALL_TRAFFIC, Mode, PolicyError, Rule, format_days, format_windows, parse_windows
from network_snooker.tables import build_table, refill, selected_key

RULE_COLUMNS = ("Service", "Days", "Allowed")
DAY_LABELS = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")


class ScheduleScreen(Screen):
    AUTO_FOCUS = "#rules"
    BINDINGS = [
        ("a", "add_rule", "Add"),
        ("d", "delete_rule", "Delete"),
        ("m", "toggle_mode", "Mode"),
        ("escape", "app.pop_screen", "Back"),
        ("q", "app.quit", "Quit"),
    ]

    def __init__(self, host_id: str, mac: str) -> None:
        super().__init__()
        self._host_id = host_id
        self._mac = mac
        self._rules: tuple[Rule, ...] = ()

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(id="summary", markup=False)
        yield build_table("rules", RULE_COLUMNS)
        yield Footer()

    def on_mount(self) -> None:
        self.refresh_rules()

    def on_screen_resume(self) -> None:
        self.refresh_rules()

    # DataTable's own "enter" binding fires this message rather than
    # bubbling the key up to the screen, so editing hooks into it instead.
    def on_data_table_row_selected(self) -> None:
        self.action_edit_rule()

    def refresh_rules(self) -> None:
        policy = self.app.policy(self._mac)
        self._rules = policy.rules
        host = self.app.hosts.get(self._host_id)
        name = self.app.display_name(host) if host is not None else self._host_id
        mode = "off" if policy.mode is Mode.NONE else policy.mode.value
        self.query_one("#summary", Static).update(f"{name}  {self._mac}  mode: {mode}")
        refill(self.query_one(DataTable), (self._row(index, rule) for index, rule in enumerate(self._rules)), 0)

    def _row(self, index: int, rule: Rule) -> tuple[str, list[Text]]:
        return str(index), [Text(service_label(self.app.catalog, rule.service)), Text(format_days(rule.days)), Text(format_windows(rule.windows))]

    def _selected_index(self) -> int | None:
        key = selected_key(self.query_one(DataTable))
        return None if key is None else int(key)

    def action_add_rule(self) -> None:
        self.app.push_screen(RuleDialog(self.app.catalog), self._on_rule_added)

    def action_edit_rule(self) -> None:
        index = self._selected_index()
        if index is not None:
            self.app.push_screen(RuleDialog(self.app.catalog, self._rules[index]), lambda rule: self._on_rule_edited(index, rule))

    def action_delete_rule(self) -> None:
        index = self._selected_index()
        if index is not None:
            self._save_rules(self._rules[:index] + self._rules[index + 1 :])

    def action_toggle_mode(self) -> None:
        mode = Mode.NONE if self.app.policy(self._mac).mode is Mode.SCHEDULE else Mode.SCHEDULE
        self.app.set_mode(self._mac, mode)
        self.refresh_rules()

    def _on_rule_added(self, rule: Rule | None) -> None:
        if rule is not None:
            self._save_rules((*self._rules, rule))

    def _on_rule_edited(self, index: int, rule: Rule | None) -> None:
        if rule is not None:
            self._save_rules((*self._rules[:index], rule, *self._rules[index + 1 :]))

    def _save_rules(self, rules: tuple[Rule, ...]) -> None:
        self.app.replace_rules(self._mac, rules)
        self.refresh_rules()


class RuleDialog(ModalScreen[Rule | None]):
    DEFAULT_CSS = """
    RuleDialog { align: center middle; }
    RuleDialog > Vertical { width: 64; height: auto; border: round $primary; padding: 1 2; background: $surface; }
    RuleDialog #days { height: 1; margin: 1 0; }
    RuleDialog #error { color: $error; height: 1; }
    RuleDialog #buttons { height: 3; align-horizontal: right; }
    RuleDialog #buttons Button { margin-left: 1; }
    """

    def __init__(self, catalog, rule: Rule | None = None) -> None:
        super().__init__()
        self._catalog = catalog
        self._rule = rule

    def compose(self) -> ComposeResult:
        services = sorted(self._catalog, key=lambda service: (service.category, service.name))
        options = [(ALL_TRAFFIC_LABEL, ALL_TRAFFIC)] + [(f"{service.category.title()} · {service.name}", service.key) for service in services]
        with Vertical():
            yield Select(options, id="service", **({"value": self._rule.service} if self._rule else {}))
            with Horizontal(id="days"):
                for index, label in enumerate(DAY_LABELS):
                    yield Checkbox(label, value=self._rule is not None and index in self._rule.days, id=f"day-{index}", compact=True)
            yield Input(value=format_windows(self._rule.windows) if self._rule else "", placeholder="16:00-19:00, 20:00-21:00", id="windows")
            yield Static("", id="error", markup=False)
            with Horizontal(id="buttons"):
                yield Button("Cancel", id="cancel")
                yield Button("OK", id="ok", variant="primary")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.dismiss(None)
        else:
            self._submit()

    def _submit(self) -> None:
        select = self.query_one("#service", Select)
        if select.is_blank():
            self._show_error("Choose a service")
            return
        service = select.value
        days = frozenset(index for index in range(7) if self.query_one(f"#day-{index}", Checkbox).value)
        if not days:
            self._show_error("Choose at least one day")
            return
        try:
            windows = parse_windows(self.query_one("#windows", Input).value)
        except PolicyError as error:
            self._show_error(str(error))
            return
        self.dismiss(Rule(service, days, windows))

    def _show_error(self, message: str) -> None:
        self.query_one("#error", Static).update(message)
