"""Table model for firewall rules.

Missing evidence is always shown as its state ("Pending...", "Not collected", "Unreadable"),
never as "Any" or as an empty value. Evidence status is text, not color.

Performance: display rows are PRECOMPUTED off the GUI thread (``rows_for``) and sorted by
precomputed keys. With ~1,600 rules, computing texts or proxy-sorting through ``data()`` on the
GUI thread stalled it for 250-350 ms (measured on TE-1, M1.3).
"""

from dataclasses import dataclass
from typing import Any

from firewallai.core.evidence import IncompleteEvidence, evidence_for_verdict
from firewallai.core.rules import FilterResult, FilterState, FirewallRule, NotCollectedReason
from firewallai.ui.table_model import PrecomputedTableModel

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

    @property
    def key(self) -> str:
        return self.rule_id


def rows_for(rules: tuple[FirewallRule, ...]) -> tuple[RuleRow, ...]:
    """Build display rows. Call on a worker thread, not the GUI thread."""
    out = []
    for rule in rules:
        texts = tuple(cell_text(rule, c) for c in range(len(COLUMNS)))
        out.append(RuleRow(rule.id, texts, tuple(s.casefold() for s in texts)))
    return tuple(out)


class RulesTableModel(PrecomputedTableModel[RuleRow]):
    """Rules over precomputed rows (see ``firewallai.ui.table_model``)."""

    def __init__(self) -> None:
        super().__init__(COLUMNS)

    def row_id(self, row: int) -> str:
        return self.row_key(row)
