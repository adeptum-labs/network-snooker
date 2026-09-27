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
