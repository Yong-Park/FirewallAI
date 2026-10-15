"""Evidence completeness guard (M1.3).

A future verdict engine may only consume ``CompleteRuleEvidence``. Anything else yields
``IncompleteEvidence`` with explicit reasons, so incomplete evidence cannot produce a definitive
verdict. Scan-level limitations (non-firewall WFP filters, service hardening, Group Policy merge)
apply on top of this per-rule check and are reported separately (ADR 0009).
"""

from dataclasses import dataclass
from enum import StrEnum

from firewallai.core.rules import (
    ALL_FILTERS,
    AddressFilter,
    ApplicationFilter,
    FilterResult,
    FirewallRule,
    InterfaceFilter,
    InterfaceTypeFilter,
    PolicySourceType,
    PortFilter,
    SecurityFilter,
    ServiceFilter,
    TokenKind,
)

KNOWN_PROTOCOLS = frozenset({"any", "tcp", "udp", "icmpv4", "icmpv6"})
KNOWN_DYNAMIC_TARGETS = frozenset({"any"})
KNOWN_DYNAMIC_TRANSPORTS = frozenset({"any"})


class IncompleteReason(StrEnum):
    FILTER_NOT_COLLECTED = "filter_not_collected"
    FILTER_UNREADABLE = "filter_unreadable"
    UNKNOWN_VALUE = "unknown_value"
    UNKNOWN_PROTOCOL = "unknown_protocol"
    UNSUPPORTED_DYNAMIC_TARGET = "unsupported_dynamic_target"
    UNKNOWN_POLICY_SOURCE = "unknown_policy_source"
    UNSUPPORTED_DYNAMIC_TRANSPORT = "unsupported_dynamic_transport"
    DYNAMIC_KEYWORD_ADDRESSES = "dynamic_keyword_addresses"


@dataclass(frozen=True, slots=True)
class CompleteRuleEvidence:
    rule: FirewallRule
    application: ApplicationFilter
    service: ServiceFilter
    security: SecurityFilter
    port: PortFilter
    address: AddressFilter
    interface_type: InterfaceTypeFilter
    interface: InterfaceFilter


@dataclass(frozen=True, slots=True)
class IncompleteEvidence:
    rule_id: str
    reasons: tuple[str, ...]  # "<IncompleteReason>:<detail>"


def _value[T](result: FilterResult[T], name: str, reasons: list[str]) -> T | None:
    if result.value is not None and result.is_collected:
        return result.value
    if result.reason is not None:
        reasons.append(
            f"{IncompleteReason.FILTER_NOT_COLLECTED.value}:{name}:{result.reason.value}"
        )
    else:
        reasons.append(f"{IncompleteReason.FILTER_UNREADABLE.value}:{name}")
    return None


def evidence_for_verdict(rule: FirewallRule) -> CompleteRuleEvidence | IncompleteEvidence:
    """Return complete evidence, or the explicit reasons why a verdict must not be made."""
    reasons: list[str] = []
    application = _value(rule.application, "application", reasons)
    service = _value(rule.service, "service", reasons)
    security = _value(rule.security, "security", reasons)
    port = _value(rule.port, "port", reasons)
    address = _value(rule.address, "address", reasons)
    interface_type = _value(rule.interface_type, "interface_type", reasons)
    interface = _value(rule.interface, "interface", reasons)

    if rule.policy_source_type is PolicySourceType.UNKNOWN:
        reasons.append(IncompleteReason.UNKNOWN_POLICY_SOURCE.value)
    if rule.remote_dynamic_keyword_addresses:
        reasons.append(IncompleteReason.DYNAMIC_KEYWORD_ADDRESSES.value)
    if port is not None:
        if port.protocol not in KNOWN_PROTOCOLS and not port.protocol.isdigit():
            reasons.append(IncompleteReason.UNKNOWN_PROTOCOL.value)
        if port.dynamic_target not in KNOWN_DYNAMIC_TARGETS:
            reasons.append(IncompleteReason.UNSUPPORTED_DYNAMIC_TARGET.value)
        if port.dynamic_transport not in KNOWN_DYNAMIC_TRANSPORTS:
            reasons.append(IncompleteReason.UNSUPPORTED_DYNAMIC_TRANSPORT.value)
        for field, tokens in (
            ("local_ports", port.local_ports),
            ("remote_ports", port.remote_ports),
            ("icmp_types", port.icmp_types),
        ):
            if any(t.kind is TokenKind.UNKNOWN for t in tokens):
                reasons.append(f"{IncompleteReason.UNKNOWN_VALUE.value}:{field}")
    if address is not None:
        for field, addr_tokens in (
            ("local_addresses", address.local_addresses),
            ("remote_addresses", address.remote_addresses),
        ):
            if any(t.kind is TokenKind.UNKNOWN for t in addr_tokens):
                reasons.append(f"{IncompleteReason.UNKNOWN_VALUE.value}:{field}")

    if (
        reasons
        or application is None
        or service is None
        or security is None
        or port is None
        or address is None
        or interface_type is None
        or interface is None
    ):
        return IncompleteEvidence(rule_id=rule.id, reasons=tuple(reasons))
    return CompleteRuleEvidence(
        rule=rule,
        application=application,
        service=service,
        security=security,
        port=port,
        address=address,
        interface_type=interface_type,
        interface=interface,
    )


def filter_states(rule: FirewallRule) -> dict[str, str]:
    """Per-filter evidence state names (for reports and UI)."""
    return {name: getattr(rule, name).state.value for name in ALL_FILTERS}
