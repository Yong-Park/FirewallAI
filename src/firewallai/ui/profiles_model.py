"""Table model for firewall profiles. Status is always conveyed as text, never by color alone."""

from typing import Any

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QPersistentModelIndex, Qt

from firewallai.core.models import FirewallAction, FirewallProfile, TriState

_TRI = {TriState.TRUE: "Yes", TriState.FALSE: "No", TriState.NOT_CONFIGURED: "Not configured"}
_ACTION = {
    FirewallAction.ALLOW: "Allow",
    FirewallAction.BLOCK: "Block",
    FirewallAction.NOT_CONFIGURED: "Not configured",
}

COLUMNS: tuple[tuple[str, str], ...] = (
    ("Profile", "name"),
    ("Firewall on", "enabled"),
    ("Default inbound", "default_inbound_action"),
    ("Default outbound", "default_outbound_action"),
    ("Inbound allow rules apply", "allow_inbound_rules"),
    ("Local rules merged", "allow_local_firewall_rules"),
    ("Log blocked", "log_blocked"),
)

_Index = QModelIndex | QPersistentModelIndex


def display_value(profile: FirewallProfile, attribute: str) -> str:
    value = getattr(profile, attribute)
    if isinstance(value, TriState):
        return _TRI[value]
    if isinstance(value, FirewallAction):
        return _ACTION[value]
    return str(value.value).capitalize() if hasattr(value, "value") else str(value)


class ProfilesTableModel(QAbstractTableModel):
    def __init__(self) -> None:
        super().__init__()
        self._profiles: tuple[FirewallProfile, ...] = ()

    def set_profiles(self, profiles: tuple[FirewallProfile, ...]) -> None:
        self.beginResetModel()
        self._profiles = profiles
        self.endResetModel()

    def rowCount(self, parent: _Index = QModelIndex()) -> int:  # noqa: B008, N802 - Qt API
        return 0 if parent.isValid() else len(self._profiles)

    def columnCount(self, parent: _Index = QModelIndex()) -> int:  # noqa: B008, N802 - Qt API
        return 0 if parent.isValid() else len(COLUMNS)

    def data(self, index: _Index, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid() or role not in (
            Qt.ItemDataRole.DisplayRole,
            Qt.ItemDataRole.AccessibleTextRole,
        ):
            return None
        profile = self._profiles[index.row()]
        return display_value(profile, COLUMNS[index.column()][1])

    def headerData(  # noqa: N802 - Qt API
        self,
        section: int,
        orientation: Qt.Orientation,
        role: int = Qt.ItemDataRole.DisplayRole,
    ) -> Any:
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return COLUMNS[section][0]
        return None
