"""Table model for firewall rules.

Missing evidence is always shown as its state ("Pending...", "Not collected", "Unreadable"),
never as "Any" or as an empty value. Evidence status is text, not color.

Performance: display rows are PRECOMPUTED off the GUI thread (``rows_for``) and sorted by
precomputed keys. With ~1,600 rules, computing texts or proxy-sorting through ``data()`` on the
GUI thread stalled it for 250-350 ms (measured on TE-1, M1.3).
"""

from dataclasses import dataclass
from typing import Any

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QPersistentModelIndex, Qt

from firewallai.core.evidence import IncompleteEvidence, evidence_for_verdict
from firewallai.core.rules import FilterResult, FilterState, FirewallRule, NotCollectedReason

_Index = QModelIndex | QPersistentModelIndex

COLUMNS: tuple[str, ...] = (
    "Name",
    "Direction",
    "Action",
    "Enabled",
    "Profiles",
    "Protocol",
    "Local ports",
    "Remote addresses",
    "Interfaces",
    "Program",
    "Evidence",
)


def _state_text(result: FilterResult[Any]) -> str | None:
    if result.state is FilterState.COLLECTED:
        return None
    if result.state is FilterState.UNREADABLE:
        return "Unreadable"
    if result.reason is NotCollectedReason.PENDING:
        return "Pending…"
    return f"Not collected ({result.reason.value if result.reason else '?'})"


def evidence_text(rule: FirewallRule) -> str:
    ev = evidence_for_verdict(rule)
    if isinstance(ev, IncompleteEvidence):
        kinds = sorted({r.split(":", 1)[0] for r in ev.reasons})
        return "Incomplete: " + ", ".join(kinds)
    return "Complete"


def cell_text(rule: FirewallRule, column: int) -> str:
    name = COLUMNS[column]
    if name == "Name":
        return rule.display_name or rule.id
    if name == "Direction":
        return rule.direction.value.capitalize()
    if name == "Action":
        return rule.action.value.capitalize()
    if name == "Enabled":
        return "Yes" if rule.enabled else "No"
    if name == "Profiles":
        return ", ".join(p.value.capitalize() for p in rule.profiles)
    if name in ("Protocol", "Local ports"):
        state = _state_text(rule.port)
        if state is not None or rule.port.value is None:
            return state or ""
        if name == "Protocol":
            return rule.port.value.protocol.upper()
        return ", ".join(t.value for t in rule.port.value.local_ports) or "(none)"
    if name == "Remote addresses":
        state = _state_text(rule.address)
        if state is not None or rule.address.value is None:
            return state or ""
        return ", ".join(t.value for t in rule.address.value.remote_addresses) or "(none)"
    if name == "Interfaces":
        state = _state_text(rule.interface)
        if state is not None or rule.interface.value is None:
            return state or ""
        value = rule.interface.value
        return "any" if value.any_interface else ", ".join(value.aliases)
    if name == "Program":
        state = _state_text(rule.application)
        if state is not None or rule.application.value is None:
            return state or ""
        return rule.application.value.program or "any"
    return evidence_text(rule)


@dataclass(frozen=True, slots=True)
class RuleRow:
    """Precomputed display row (texts + sort keys) for one rule."""

    rule_id: str
    texts: tuple[str, ...]
    sort_keys: tuple[str, ...]


def rows_for(rules: tuple[FirewallRule, ...]) -> tuple[RuleRow, ...]:
    """Build display rows. Call on a worker thread, not the GUI thread."""
    out = []
    for rule in rules:
        texts = tuple(cell_text(rule, c) for c in range(len(COLUMNS)))
        out.append(RuleRow(rule.id, texts, tuple(s.casefold() for s in texts)))
    return tuple(out)


class RulesTableModel(QAbstractTableModel):
    """Plain list model over precomputed rows; sorting is a Python sort of precomputed keys."""

    def __init__(self) -> None:
        super().__init__()
        self._rows: list[RuleRow] = []
        self._row_by_id: dict[str, int] = {}
        self._sort: tuple[int, Qt.SortOrder] | None = None

    def _reindex(self) -> None:
        self._row_by_id = {r.rule_id: i for i, r in enumerate(self._rows)}

    def _apply_sort(self) -> None:
        if self._sort is not None:
            column, order = self._sort
            self._rows.sort(
                key=lambda r: r.sort_keys[column],
                reverse=order == Qt.SortOrder.DescendingOrder,
            )
        self._reindex()

    def set_rows(self, rows: tuple[RuleRow, ...]) -> None:
        self.beginResetModel()
        self._rows = list(rows)
        self._apply_sort()
        self.endResetModel()

    def update_rows(self, rows: tuple[RuleRow, ...]) -> None:
        """Replace rows in place (batched per detail chunk); unknown IDs are ignored."""
        changed = []
        for row in rows:
            index = self._row_by_id.get(row.rule_id)
            if index is not None:
                self._rows[index] = row
                changed.append(index)
        if changed:
            self.dataChanged.emit(
                self.index(min(changed), 0), self.index(max(changed), len(COLUMNS) - 1)
            )

    def row_id(self, row: int) -> str:
        return self._rows[row].rule_id

    def sort(self, column: int, order: Qt.SortOrder = Qt.SortOrder.AscendingOrder) -> None:
        self.layoutAboutToBeChanged.emit()
        self._sort = (column, order)
        self._apply_sort()
        self.layoutChanged.emit()

    def rowCount(self, parent: _Index = QModelIndex()) -> int:  # noqa: B008, N802 - Qt API
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent: _Index = QModelIndex()) -> int:  # noqa: B008, N802 - Qt API
        return 0 if parent.isValid() else len(COLUMNS)

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
            return COLUMNS[section]
        return None
