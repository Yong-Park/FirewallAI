"""Shared Qt table model over PRECOMPUTED display rows (M1.3 pattern, shared since M1.4).

Rows (texts + sort keys) are built off the GUI thread. The GUI thread only swaps lists, sorts by
precomputed keys, and filters with a cheap predicate: with ~1,600 rows, computing texts or proxy
sorting through ``data()`` on the GUI thread stalled it for 250-350 ms (measured on TE-1, M1.3).
"""

from collections.abc import Callable
from typing import Any, Protocol

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QPersistentModelIndex, Qt

_Index = QModelIndex | QPersistentModelIndex


class PrecomputedRow(Protocol):
    @property
    def key(self) -> str: ...

    @property
    def texts(self) -> tuple[str, ...]: ...

    @property
    def sort_keys(self) -> tuple[str, ...]: ...


class PrecomputedTableModel[R: PrecomputedRow](QAbstractTableModel):
    """Plain list model; sorting is a Python sort of precomputed keys; optional row filter."""

    def __init__(self, columns: tuple[str, ...]) -> None:
        super().__init__()
        self._columns = columns
        self._all: list[R] = []
        self._rows: list[R] = []
        self._row_by_key: dict[str, int] = {}
        self._sort: tuple[int, Qt.SortOrder] | None = None
        self._filter: Callable[[R], bool] | None = None

    def _refresh(self) -> None:
        rows = [r for r in self._all if self._filter is None or self._filter(r)]
        if self._sort is not None:
            column, order = self._sort
            rows.sort(
                key=lambda r: r.sort_keys[column],
                reverse=order == Qt.SortOrder.DescendingOrder,
            )
        self._rows = rows
        self._row_by_key = {r.key: i for i, r in enumerate(self._rows)}

    def set_rows(self, rows: tuple[R, ...]) -> None:
        self.beginResetModel()
        self._all = list(rows)
        self._refresh()
        self.endResetModel()

    def set_filter(self, predicate: Callable[[R], bool] | None) -> None:
        self.beginResetModel()
        self._filter = predicate
        self._refresh()
        self.endResetModel()

    def update_rows(self, rows: tuple[R, ...]) -> None:
        """Replace rows in place (batched); unknown keys are ignored. Filters are not re-run."""
        by_key = {r.key: r for r in rows}
        self._all = [by_key.get(r.key, r) for r in self._all]
        changed = []
        for key, row in by_key.items():
            index = self._row_by_key.get(key)
            if index is not None:
                self._rows[index] = row
                changed.append(index)
        if changed:
            self.dataChanged.emit(
                self.index(min(changed), 0), self.index(max(changed), len(self._columns) - 1)
            )

    def row_at(self, row: int) -> R:
        return self._rows[row]

    def row_key(self, row: int) -> str:
        return self._rows[row].key

    def sort(self, column: int, order: Qt.SortOrder = Qt.SortOrder.AscendingOrder) -> None:
        self.layoutAboutToBeChanged.emit()
        self._sort = (column, order)
        self._refresh()
        self.layoutChanged.emit()

    def rowCount(self, parent: _Index = QModelIndex()) -> int:  # noqa: B008, N802 - Qt API
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent: _Index = QModelIndex()) -> int:  # noqa: B008, N802 - Qt API
        return 0 if parent.isValid() else len(self._columns)

    def data(self, index: _Index, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid() or role not in (
            Qt.ItemDataRole.DisplayRole,
            Qt.ItemDataRole.AccessibleTextRole,
            Qt.ItemDataRole.ToolTipRole,
        ):
            return None
        return self._rows[index.row()].texts[index.column()]

    def headerData(  # noqa: N802 - Qt API
        self,
        section: int,
        orientation: Qt.Orientation,
        role: int = Qt.ItemDataRole.DisplayRole,
    ) -> Any:
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return self._columns[section]
        return None
