"""Endpoint table rows and the related-rules text (M1.4). Built OFF the GUI thread.

Untrusted text (process names, paths, service names, rule names) always goes through
``display_safe``. Unavailable process details are shown with their reason, never as blanks.
Nothing here states that an endpoint is reachable, exposed, or that traffic is permitted (SB-20).
"""

from dataclasses import dataclass

from firewallai.core.correlation import (
    CORRELATION_DISCLAIMER,
    CorrelationStatus,
    EndpointCorrelation,
    Outcome,
    RuleRelation,
)
from firewallai.core.endpoints import Endpoint, EndpointKind, Observed, display_safe
from firewallai.core.rules import FirewallRule
from firewallai.ui.table_model import PrecomputedTableModel

COLUMNS: tuple[str, ...] = (
    "Protocol",
    "Family",
    "Kind",
    "TCP state",
    "Local address",
    "Local port",
    "Remote address",
    "Remote port",
    "PID",
    "Process",
    "Process details",
    "Services",
    "Bind scope",
)
MAX_LISTED = 50


def _reason[T](obs: Observed[T]) -> str:
    return obs.reason.value.replace("_", " ") if obs.reason else "unavailable"


def _process_texts(ep: Endpoint) -> tuple[str, str, str]:
    p = ep.process
    if p.reason is not None:
        why = p.reason.value.replace("_", " ")
        return f"({why})", f"Not attributed: {why}", f"({why})"
    name = display_safe(p.name.value, 80) if p.name.value is not None else f"({_reason(p.name)})"
    if p.image_path.value is not None:
        details = display_safe(p.image_path.value, 200)
    else:
        details = f"Path unavailable: {_reason(p.image_path)}"
    if p.services.value is None:
        services = f"({_reason(p.services)})"
    else:
        services = ", ".join(display_safe(s, 60) for s in p.services.value) or "none"
    return name, details, services


def _num(value: int | None, width: int = 10) -> str:
    return "" if value is None else str(value).rjust(width, "0")


@dataclass(frozen=True, slots=True)
class EndpointRow:
    endpoint_id: str
    kind: EndpointKind
    texts: tuple[str, ...]
    sort_keys: tuple[str, ...]

    @property
    def key(self) -> str:
        return self.endpoint_id


def endpoint_row(ep: Endpoint) -> EndpointRow:
    name, details, services = _process_texts(ep)
    remote = "" if ep.remote_address is None else display_safe(ep.remote_address, 64)
    texts = (
        ep.protocol.value.upper(),
        ep.family.value.replace("ipv", "IPv"),
        ep.kind.value.capitalize(),
        ep.tcp_state.value if ep.tcp_state is not None else "—",
        display_safe(ep.local_address, 64),
        str(ep.local_port),
        remote or "—",
        "—" if ep.remote_port is None else str(ep.remote_port),
        "—" if ep.process.pid is None else str(ep.process.pid),
        name,
        details,
        services,
        ep.bind_scope.value.replace("_", " ")
        + (" (dual-stack unknown)" if ep.dual_stack_unknown else ""),
    )
    keys = list(t.casefold() for t in texts)
    keys[5] = _num(ep.local_port)
    keys[7] = _num(ep.remote_port)
    keys[8] = _num(ep.process.pid)
    return EndpointRow(ep.id, ep.kind, texts, tuple(keys))


def rows_for_endpoints(endpoints: tuple[Endpoint, ...]) -> tuple[EndpointRow, ...]:
    """Build display rows. Call on a worker thread, not the GUI thread."""
    return tuple(endpoint_row(ep) for ep in endpoints)


class EndpointsTableModel(PrecomputedTableModel[EndpointRow]):
    def __init__(self) -> None:
        super().__init__(COLUMNS)


# --- related-rules text -------------------------------------------------------------------------

RULES_NOT_AVAILABLE_TEXT = (
    "Related firewall rules: not available. Collect firewall rules in the Rules tab first. "
    "A rule scan is never started automatically."
)


def _rule_name(rule: FirewallRule | None, rule_id: str) -> str:
    if rule is None:
        return rule_id
    return display_safe(rule.display_name or rule.id, 120)


def _related_lines(rel: RuleRelation, rule: FirewallRule | None) -> list[str]:
    head = f"• {_rule_name(rule, rel.rule_id)}"
    if rule is not None:
        profiles = ", ".join(p.value for p in rule.profiles)
        head += f" — rule action: {rule.action.value}; profiles: {profiles}"
    lines = [head]
    matched = "; ".join(
        f"{c.dimension} ({c.detail})" for c in rel.checks if c.outcome is Outcome.MATCH
    )
    lines.append(f"    consistent filters: {matched}")
    if rel.conditions:
        lines.append("    not evaluated: " + "; ".join(rel.conditions))
    return lines


def describe_correlation(corr: EndpointCorrelation, rules_by_id: dict[str, FirewallRule]) -> str:
    """Plain-text, descriptive related-rules panel for one endpoint."""
    header = ["Related firewall rules (descriptive only)", CORRELATION_DISCLAIMER, ""]
    if corr.status is CorrelationStatus.RULES_NOT_AVAILABLE:
        return RULES_NOT_AVAILABLE_TEXT
    if corr.status is not CorrelationStatus.EVALUATED:
        return "\n".join([*header, f"Not evaluated: {corr.note}"])
    lines = [*header]
    completeness = "complete" if corr.rule_set_complete else "INCOMPLETE (rules may be missing)"
    lines.append(
        f"Rule collection: {completeness}. Considered {corr.rules_considered} enabled inbound "
        f"rules; {corr.rules_skipped} outbound or disabled rules were not considered."
    )
    if corr.note:
        lines.append(corr.note)
    related = sorted(
        corr.related,
        key=lambda r: _rule_name(rules_by_id.get(r.rule_id), r.rule_id).casefold(),
    )
    conditional = sorted(
        corr.related_with_conditions,
        key=lambda r: _rule_name(rules_by_id.get(r.rule_id), r.rule_id).casefold(),
    )
    lines += ["", f"Related ({len(related)}): identity filters consistent; no network conditions"]
    for rel in related[:MAX_LISTED]:
        lines += _related_lines(rel, rules_by_id.get(rel.rule_id))
    if len(related) > MAX_LISTED:
        lines.append(f"… and {len(related) - MAX_LISTED} more")
    lines += [
        "",
        f"Related with unevaluated conditions ({len(conditional)}): whether these rules apply "
        "depends on the conditions listed, which were not evaluated",
    ]
    for rel in conditional[:MAX_LISTED]:
        lines += _related_lines(rel, rules_by_id.get(rel.rule_id))
    if len(conditional) > MAX_LISTED:
        lines.append(f"… and {len(conditional) - MAX_LISTED} more")
    unknown = corr.cannot_evaluate
    lines += ["", f"Cannot evaluate ({len(unknown)}):"]
    for rel in unknown[:MAX_LISTED]:
        lines.append(f"• {_rule_name(rules_by_id.get(rel.rule_id), rel.rule_id)}")
        lines.append("    reasons: " + "; ".join(rel.reasons[:6]))
    if len(unknown) > MAX_LISTED:
        lines.append(f"… and {len(unknown) - MAX_LISTED} more")
    lines += [
        "",
        f"Not related: {corr.not_related} rule(s) have a filter that contradicts this endpoint.",
    ]
    return "\n".join(lines)
