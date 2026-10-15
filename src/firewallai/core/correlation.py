"""Descriptive listener-to-firewall-rule correlation (M1.4, SB-20). Pure; no verdicts.

What it answers: "Which previously collected inbound rules have endpoint-identity filters that are
consistent with this listening/bound endpoint?" It never answers whether traffic is allowed or
blocked, whether a rule applies to real traffic, or whether the endpoint is reachable (SB-20).

Per (endpoint, rule) the endpoint-identity filters are checked: protocol, local port, dynamic
port target/transport, program, app package, service, rule owner, and local address. Each check is
MATCH, MISMATCH (a known contradiction), or UNKNOWN (missing or ambiguous data).

- Any MISMATCH                      -> NOT_RELATED (a known contradictory filter).
- Incomplete rule evidence (SB-18)  -> CANNOT_EVALUATE, with the evidence reasons.
- Any UNKNOWN                       -> CANNOT_EVALUATE, with the reasons.
- All MATCH, no network conditions -> RELATED.
- All MATCH, with network conditions -> RELATED_WITH_UNEVALUATED_CONDITIONS, listing every
  restriction that was NOT evaluated (profiles, interface type, interfaces, remote addresses and
  ports, edge traversal, IPsec/authorization settings). Unevaluated conditions are never treated
  as satisfied; they decide whether the rule applies, and that is not known.

A matching port alone never makes a rule related: every identity filter must match. Process
identity (program, service) comes from best-effort attribution (``core.endpoints``). Service
hosting ambiguity and app-container/package/owner scopes are UNKNOWN (-> CANNOT_EVALUATE).
"""

import ipaddress
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum

from firewallai.core.endpoints import (
    Availability,
    BindScope,
    Endpoint,
    EndpointKind,
    TransportProtocol,
    parse_local_address,
)
from firewallai.core.evidence import IncompleteEvidence, evidence_for_verdict
from firewallai.core.models import ProfileName
from firewallai.core.rules import (
    AddressToken,
    FirewallRule,
    PortToken,
    RuleCollection,
    RuleDirection,
    TokenKind,
)

CORRELATION_DISCLAIMER = (
    "Related rules are inbound rules whose protocol, local port, program, package, service, and "
    "local-address filters are consistent with this endpoint. This does not show that a rule "
    "applies to real traffic, that traffic is permitted or denied, or that the endpoint can be "
    "reached from any other host. Profiles, interfaces, remote peers, IPsec settings, and rule "
    "precedence are not evaluated, and process identity is best effort."
)
WILDCARD = "*"
SYSTEM_PROGRAM = "system"  # rule program "System" = kernel-mode traffic (PID 4)
_TCP = frozenset({"tcp", "6"})
_UDP = frozenset({"udp", "17"})
_NO_PORT_PROTOCOLS = frozenset({"icmpv4", "icmpv6"})
_VAR = re.compile(r"%([^%]+)%")
_ALL_PROFILES = frozenset(ProfileName)


class Outcome(StrEnum):
    MATCH = "match"
    MISMATCH = "mismatch"
    UNKNOWN = "unknown"


class RelationStatus(StrEnum):
    RELATED = "related"  # identity filters consistent; the rule has no network conditions
    RELATED_WITH_UNEVALUATED_CONDITIONS = "related_with_unevaluated_conditions"
    CANNOT_EVALUATE = "cannot_evaluate"
    NOT_RELATED = "not_related"


class CorrelationStatus(StrEnum):
    EVALUATED = "evaluated"
    NOT_APPLICABLE = "not_applicable"  # TCP connections: no listener semantics
    CANNOT_EVALUATE = "cannot_evaluate"  # e.g. loopback-bound endpoints
    RULES_NOT_AVAILABLE = "rules_not_available"  # no rule scan in this session


@dataclass(frozen=True, slots=True)
class Check:
    dimension: str
    outcome: Outcome
    detail: str


@dataclass(frozen=True, slots=True)
class RuleRelation:
    rule_id: str
    status: RelationStatus
    checks: tuple[Check, ...]
    conditions: tuple[str, ...]  # restrictions NOT evaluated (RELATED_WITH_... only)
    reasons: tuple[str, ...]  # why CANNOT_EVALUATE


@dataclass(frozen=True, slots=True)
class EndpointCorrelation:
    endpoint_id: str
    status: CorrelationStatus
    note: str
    related: tuple[RuleRelation, ...] = ()
    related_with_conditions: tuple[RuleRelation, ...] = ()
    cannot_evaluate: tuple[RuleRelation, ...] = ()
    not_related: int = 0
    rules_considered: int = 0  # enabled inbound rules
    rules_skipped: int = 0  # outbound or disabled rules (they do not describe a listener)
    rule_set_complete: bool = False


# --- normalization ------------------------------------------------------------------------------


def normalize_program_path(path: str, env: Mapping[str, str]) -> str | None:
    """Case-folded Windows path with system variables expanded, or None if not comparable.

    Not comparable: unresolved ``%VAR%``, 8.3 short names (``~``), and device/UNC paths. Such
    values become UNKNOWN, never a mismatch.
    """
    folded_env = {k.casefold(): v for k, v in env.items()}
    missing = False

    def expand(m: re.Match[str]) -> str:
        nonlocal missing
        value = folded_env.get(m.group(1).casefold())
        if value is None:
            missing = True
            return m.group(0)
        return value

    text = _VAR.sub(expand, path.strip().strip('"'))
    if missing or "%" in text or "~" in text or text.startswith(("\\\\", "\\")):
        return None
    return text.replace("/", "\\").casefold()


def _port_in(tokens: Sequence[PortToken], port: int) -> tuple[Outcome, str]:
    if not tokens:
        return Outcome.UNKNOWN, "no local port values reported"
    unresolved = False
    for t in tokens:
        if t.kind is TokenKind.ANY:
            return Outcome.MATCH, "any local port"
        if t.kind is TokenKind.NUMBER and t.value.isdigit() and int(t.value) == port:
            return Outcome.MATCH, f"local port {port}"
        if t.kind is TokenKind.RANGE:
            lo, _, hi = t.value.partition("-")
            if lo.isdigit() and hi.isdigit() and int(lo) <= port <= int(hi):
                return Outcome.MATCH, f"local port range {t.value}"
        if t.kind in (TokenKind.KEYWORD, TokenKind.UNKNOWN):
            unresolved = True
    if unresolved:
        return Outcome.UNKNOWN, "local port keyword or unknown value not resolved"
    return Outcome.MISMATCH, "local ports do not include this port"


def _address_contains(value: str, addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if "-" in value and "/" not in value:
        lo_s, _, hi_s = value.partition("-")
        lo, hi = ipaddress.ip_address(lo_s), ipaddress.ip_address(hi_s)
        return lo.version == hi.version == addr.version and int(lo) <= int(addr) <= int(hi)
    network = ipaddress.ip_network(value, strict=False)
    return network.version == addr.version and addr in network


def _local_address(tokens: Sequence[AddressToken], endpoint: Endpoint) -> tuple[Outcome, str]:
    if not tokens:
        return Outcome.UNKNOWN, "no local address values reported"
    if any(t.kind is TokenKind.ANY for t in tokens):
        return Outcome.MATCH, "any local address"
    if endpoint.bind_scope is BindScope.ALL_INTERFACES:
        return (
            Outcome.UNKNOWN,
            "rule restricts local addresses; the endpoint is bound to all local addresses, "
            "which are not mapped yet (Sprint 2)",
        )
    addr = parse_local_address(endpoint.local_address)
    if addr is None:
        return Outcome.UNKNOWN, "endpoint address could not be parsed"
    unresolved = False
    for t in tokens:
        if t.kind is TokenKind.ADDRESS:
            try:
                if _address_contains(t.value, addr):
                    return Outcome.MATCH, "local address within the rule's local addresses"
            except ValueError:
                unresolved = True
        else:
            unresolved = True
    if unresolved:
        return Outcome.UNKNOWN, "local address keyword or unknown value not resolved"
    return Outcome.MISMATCH, "local address outside the rule's local addresses"


# --- per-rule checks -----------------------------------------------------------------------------


def _check_protocol(rule: FirewallRule, ep: Endpoint) -> list[Check]:
    port = rule.port
    if not port.is_collected or port.value is None:
        return [Check("protocol", Outcome.UNKNOWN, f"port filter {port.state.value}")]
    pf = port.value
    proto = pf.protocol.strip().casefold()
    is_tcp = ep.protocol is TransportProtocol.TCP
    if proto == "any":
        checks = [Check("protocol", Outcome.MATCH, "any protocol")]
    elif proto in _TCP or proto in _UDP:
        same = (proto in _TCP) == is_tcp
        checks = [
            Check(
                "protocol",
                Outcome.MATCH if same else Outcome.MISMATCH,
                f"rule protocol {pf.protocol}",
            )
        ]
        if not same:
            return checks
    elif proto in _NO_PORT_PROTOCOLS or proto.isdigit():
        return [Check("protocol", Outcome.MISMATCH, f"rule protocol {pf.protocol}")]
    else:
        return [Check("protocol", Outcome.UNKNOWN, "unrecognized rule protocol")]
    outcome, detail = _port_in(pf.local_ports, ep.local_port)
    checks.append(Check("local_port", outcome, detail))
    if pf.dynamic_target != "any" or pf.dynamic_transport != "any":
        checks.append(Check("dynamic_port", Outcome.UNKNOWN, "dynamic port target not resolved"))
    return checks


def _check_program(rule_program: str | None, ep: Endpoint, env: Mapping[str, str]) -> Check:
    if rule_program is None:
        return Check("program", Outcome.MATCH, "any program")
    pid = ep.process.pid
    if rule_program.strip().casefold() == SYSTEM_PROGRAM:
        if pid == 4:
            return Check("program", Outcome.MATCH, "System (PID 4)")
        if ep.process.attribution is Availability.COLLECTED:
            return Check("program", Outcome.MISMATCH, "rule is for System (PID 4)")
        return Check("program", Outcome.UNKNOWN, "owning process not attributed")
    path = ep.process.image_path
    if not path.is_collected or path.value is None:
        reason = path.reason.value if path.reason else "unavailable"
        return Check("program", Outcome.UNKNOWN, f"process path {reason}")
    rule_norm = normalize_program_path(rule_program, env)
    ep_norm = normalize_program_path(path.value, {})
    if rule_norm is None or ep_norm is None:
        return Check("program", Outcome.UNKNOWN, "program paths cannot be compared reliably")
    if rule_norm == ep_norm:
        return Check("program", Outcome.MATCH, "program path")
    return Check("program", Outcome.MISMATCH, "different program path")


def _check_service(rule: FirewallRule, ep: Endpoint) -> Check:
    if not rule.service.is_collected or rule.service.value is None:
        return Check("service", Outcome.UNKNOWN, f"service filter {rule.service.state.value}")
    wanted = rule.service.value.service
    if wanted is None:
        return Check("service", Outcome.MATCH, "any service")
    services = ep.process.services
    if not services.is_collected or services.value is None:
        reason = services.reason.value if services.reason else "unavailable"
        return Check("service", Outcome.UNKNOWN, f"process services {reason}")
    hosted = services.value
    if wanted == WILDCARD:
        if hosted:
            return Check("service", Outcome.MATCH, "rule applies to services; process hosts one")
        return Check("service", Outcome.MISMATCH, "rule applies to services; process hosts none")
    folded = {s.casefold() for s in hosted}
    if wanted.casefold() not in folded:
        return Check("service", Outcome.MISMATCH, "service not hosted by this process")
    if len(hosted) == 1:
        return Check("service", Outcome.MATCH, "service hosted by this process")
    return Check(
        "service",
        Outcome.UNKNOWN,
        "shared service host: which hosted service owns the socket is unknown",
    )


def _identity_checks(rule: FirewallRule, ep: Endpoint, env: Mapping[str, str]) -> list[Check]:
    checks = _check_protocol(rule, ep)
    if any(c.outcome is Outcome.MISMATCH for c in checks):
        return checks
    app = rule.application
    if not app.is_collected or app.value is None:
        checks.append(Check("program", Outcome.UNKNOWN, f"application filter {app.state.value}"))
    else:
        checks.append(_check_program(app.value.program, ep, env))
        if app.value.package is None:
            checks.append(Check("package", Outcome.MATCH, "any app package"))
        else:
            checks.append(
                Check("package", Outcome.UNKNOWN, "app package identity of the process unknown")
            )
    checks.append(_check_service(rule, ep))
    if rule.has_owner:
        checks.append(Check("owner", Outcome.UNKNOWN, "rule owner scope not evaluated"))
    addr = rule.address
    if not addr.is_collected or addr.value is None:
        checks.append(Check("local_address", Outcome.UNKNOWN, f"address filter {addr.state.value}"))
    else:
        outcome, detail = _local_address(addr.value.local_addresses, ep)
        checks.append(Check("local_address", outcome, detail))
    return checks


def _conditions(rule: FirewallRule) -> tuple[str, ...]:
    out: list[str] = []
    if set(rule.profiles) != _ALL_PROFILES:
        names = ", ".join(sorted(p.value for p in rule.profiles))
        out.append(f"profiles: {names} (active profile per interface not mapped)")
    if rule.interface_type.value is not None:
        itype = rule.interface_type.value.interface_type
        if itype.strip().casefold() != "any":
            out.append(f"interface type: {itype} (not evaluated)")
    if rule.interface.value is not None and not rule.interface.value.any_interface:
        n = len(rule.interface.value.aliases)
        out.append(f"restricted to {n} named interface(s) (not evaluated)")
    if rule.address.value is not None and any(
        t.kind is not TokenKind.ANY for t in rule.address.value.remote_addresses
    ):
        out.append("remote addresses restricted (not evaluated)")
    if rule.port.value is not None and any(
        t.kind is not TokenKind.ANY for t in rule.port.value.remote_ports
    ):
        out.append("remote ports restricted (not evaluated)")
    edge = rule.edge_traversal.strip().casefold()
    if edge not in ("", "block"):
        out.append(f"edge traversal: {rule.edge_traversal} (not evaluated)")
    sec = rule.security.value
    if sec is not None:
        if sec.authentication.casefold() != "notrequired" or (
            sec.encryption.casefold() != "notrequired"
        ):
            out.append("requires IPsec authentication/encryption (not evaluated)")
        if sec.override_block_rules:
            out.append("authenticated bypass (override block rules) (not evaluated)")
        if sec.local_user or sec.remote_user or sec.remote_machine:
            out.append("user/machine authorization restricted (not evaluated)")
    if rule.local_only_mapping or rule.loose_source_mapping:
        out.append("NAT mapping options set (not evaluated)")
    return tuple(out)


def relate(
    rule: FirewallRule,
    endpoint: Endpoint,
    env: Mapping[str, str],
    evidence: IncompleteEvidence | None = None,
) -> RuleRelation:
    """Describe one (enabled inbound) rule against one listening/bound endpoint."""
    checks = tuple(_identity_checks(rule, endpoint, env))
    if any(c.outcome is Outcome.MISMATCH for c in checks):
        return RuleRelation(rule.id, RelationStatus.NOT_RELATED, checks, (), ())
    reasons: list[str] = []
    if evidence is not None:
        reasons.extend(f"incomplete rule evidence: {r}" for r in evidence.reasons)
    reasons.extend(f"{c.dimension}: {c.detail}" for c in checks if c.outcome is Outcome.UNKNOWN)
    if reasons:
        return RuleRelation(rule.id, RelationStatus.CANNOT_EVALUATE, checks, (), tuple(reasons))
    conditions = _conditions(rule)
    status = (
        RelationStatus.RELATED_WITH_UNEVALUATED_CONDITIONS if conditions else RelationStatus.RELATED
    )
    return RuleRelation(rule.id, status, checks, conditions, ())


class RuleIndex:
    """Rules from one completed scan, prepared once for repeated per-endpoint correlation."""

    def __init__(self, collection: RuleCollection, env: Mapping[str, str]) -> None:
        self._env = dict(env)
        self.rule_set_complete = collection.detail_complete and (
            len(collection.rules) == collection.total_in_source
        )
        self.rules_by_id = {r.id: r for r in collection.rules}
        considered: list[tuple[FirewallRule, IncompleteEvidence | None]] = []
        self.skipped = 0
        for rule in collection.rules:
            if rule.direction is not RuleDirection.INBOUND or not rule.enabled:
                self.skipped += 1
                continue
            ev = evidence_for_verdict(rule)
            considered.append((rule, ev if isinstance(ev, IncompleteEvidence) else None))
        self._considered = tuple(considered)

    def correlate(self, endpoint: Endpoint) -> EndpointCorrelation:
        if endpoint.kind is EndpointKind.CONNECTION:
            return EndpointCorrelation(
                endpoint.id,
                CorrelationStatus.NOT_APPLICABLE,
                "TCP connections are not correlated; only listening TCP and bound UDP endpoints.",
            )
        if endpoint.bind_scope in (BindScope.LOOPBACK, BindScope.UNPARSEABLE):
            return EndpointCorrelation(
                endpoint.id,
                CorrelationStatus.CANNOT_EVALUATE,
                "Loopback-bound or unparseable address: how firewall rules treat this traffic is "
                "not evaluated [VERIFY].",
                rule_set_complete=self.rule_set_complete,
            )
        related: list[RuleRelation] = []
        conditional: list[RuleRelation] = []
        unknown: list[RuleRelation] = []
        not_related = 0
        for rule, evidence in self._considered:
            relation = relate(rule, endpoint, self._env, evidence)
            if relation.status is RelationStatus.RELATED:
                related.append(relation)
            elif relation.status is RelationStatus.RELATED_WITH_UNEVALUATED_CONDITIONS:
                conditional.append(relation)
            elif relation.status is RelationStatus.CANNOT_EVALUATE:
                unknown.append(relation)
            else:
                not_related += 1
        note = "" if self.rule_set_complete else "Rule collection was incomplete."
        return EndpointCorrelation(
            endpoint.id,
            CorrelationStatus.EVALUATED,
            note,
            related=tuple(related),
            related_with_conditions=tuple(conditional),
            cannot_evaluate=tuple(unknown),
            not_related=not_related,
            rules_considered=len(self._considered),
            rules_skipped=self.skipped,
            rule_set_complete=self.rule_set_complete,
        )
