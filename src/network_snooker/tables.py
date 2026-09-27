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

from collections.abc import Iterable, Sequence

from rich.text import Text
from textual.widgets import DataTable


def build_table(table_id: str, columns: tuple[str, ...]) -> DataTable:
    table = DataTable(id=table_id, cursor_type="row")
    table.add_columns(*columns)
    return table


def selected_key(table: DataTable) -> str | None:
    if table.row_count == 0:
        return None
    return table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value


# Textual sizes columns lazily and never narrows them, so the widths come
# from the rows being shown, and the name column takes whatever is left over.
def fit_columns(table: DataTable, rows: list[tuple[str | None, Sequence[Text]]], name_column: int) -> None:
    columns = list(table.columns.values())
    widths = [max([column.label.cell_len, *(cells[index].cell_len for _, cells in rows)]) for index, column in enumerate(columns)]
    widths[name_column] += max(table.scrollable_content_region.width - sum(widths) - 2 * table.cell_padding * len(columns), 0)
    for column, width in zip(columns, widths):
        column.auto_width = False
        column.width = width


def refill(table: DataTable, rows: Iterable[tuple[str | None, Sequence[Text]]], name_column: int) -> None:
    rows = list(rows)
    selected, selected_row = selected_key(table), table.cursor_row
    scroll_x, scroll_y = table.scroll_x, table.scroll_y
    table.clear()
    for key, cells in rows:
        table.add_row(*cells, key=key)
    fit_columns(table, rows, name_column)
    if selected in table.rows:
        selected_row = table.get_row_index(selected)
    table.move_cursor(row=min(selected_row, table.row_count - 1), scroll=False)
    table.scroll_to(scroll_x, scroll_y, animate=False)
