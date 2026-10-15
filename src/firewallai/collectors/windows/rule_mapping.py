"""Raw NetSecurity rule payloads -> typed ``FirewallRule`` models (M1.3, ADR 0009).

Shared by the real Windows collector and the fixture collector, so tests exercise the same path.

Principles:
- Explicit mapping tables. Unknown direction/action/enabled/profile values make a rule INVALID
  (excluded and reported). They are never guessed.
- Unknown port/address/ICMP values become UNKNOWN tokens (never ANY). The evidence guard then
  treats the rule as incomplete.
- A filter that is missing from the source becomes NOT_COLLECTED(missing_from_source), never Any.
- Error details carry public rule IDs, field names, and enum/category names only. They never
  carry raw Windows rule IDs, names, paths, or addresses (host-sensitive).
"""

import ipaddress
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from firewallai.core.models import ProfileName
from firewallai.core.results import CollectorError, CollectorErrorCode
from firewallai.core.rules import (
    DETAIL_FILTERS,
    AddressFilter,
    AddressToken,
    ApplicationFilter,
    FilterResult,
    FilterState,
    FirewallRule,
    InterfaceFilter,
    InterfaceTypeFilter,
    NotCollectedReason,
    PolicySourceType,
    PortFilter,
    PortToken,
    RuleAction,
    RuleDirection,
    SecurityFilter,
    ServiceFilter,
    TokenKind,
    rule_id,
)

DIRECTION: Mapping[str, RuleDirection] = {
    "Inbound": RuleDirection.INBOUND,
    "Outbound": RuleDirection.OUTBOUND,
}
ACTION: Mapping[str, RuleAction] = {"Allow": RuleAction.ALLOW, "Block": RuleAction.BLOCK}
ENABLED: Mapping[str, bool] = {"True": True, "False": False}
PROFILE: Mapping[str, ProfileName] = {
    "Domain": ProfileName.DOMAIN,
    "Private": ProfileName.PRIVATE,
    "Public": ProfileName.PUBLIC,
}
SOURCE_TYPE: Mapping[str, PolicySourceType] = {
    "Local": PolicySourceType.LOCAL,
    "GroupPolicy": PolicySourceType.GROUP_POLICY,
    "Dynamic": PolicySourceType.DYNAMIC,
    "Generated": PolicySourceType.GENERATED,
    "Hardcoded": PolicySourceType.HARDCODED,
    "MDM": PolicySourceType.MDM,
    "HostFirewall": PolicySourceType.HOST_FIREWALL,
}
# Keyword vocabularies accepted as KEYWORD tokens (lower-cased). Anything else that is not a
# number, range, or IP literal is UNKNOWN. [VERIFY completeness against Microsoft docs]
PORT_KEYWORDS = frozenset(
    {"rpc", "rpcepmap", "teredo", "iphttpsin", "iphttpsout", "playtodiscovery", "mdns"}
)
ADDRESS_KEYWORDS = frozenset(
    {
        "localsubnet",
        "localsubnet4",
        "localsubnet6",
        "dns",
        "dhcp",
        "wins",
        "defaultgateway",
        "internet",
        "intranet",
        "intranetremoteaccess",
        "playtodevice",
    }
)
_ANY = "any"
_MAX_RULES = 50_000


# --- raw payload shapes (strict) ----------------------------------------------------------------


class _Raw(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)


class RawRule(_Raw):
    id: str = Field(min_length=1, max_length=1024)
    display: str = Field(max_length=1024)
    description: str = Field(max_length=4096)
    group: str = Field(max_length=1024)
    direction: str = Field(max_length=32)
    action: str = Field(max_length=32)
    enabled: str = Field(max_length=16)
    profile: str = Field(max_length=64)
    source_type: str = Field(max_length=64)
    enforcement: str = Field(max_length=512)
    primary_status: str = Field(max_length=64)
    edge: str = Field(max_length=64)
    has_owner: bool
    dynamic_keywords: list[str] = Field(max_length=256)
    local_only_mapping: bool
    loose_source_mapping: bool


class RawApp(_Raw):
    id: str = Field(min_length=1, max_length=1024)
    program: str = Field(max_length=2048)
    package: str = Field(max_length=512)


class RawService(_Raw):
    id: str = Field(min_length=1, max_length=1024)
    service: str = Field(max_length=512)


class RawSecurity(_Raw):
    id: str = Field(min_length=1, max_length=1024)
    authentication: str = Field(max_length=64)
    encryption: str = Field(max_length=64)
    override_block: str = Field(max_length=16)
    local_user: str = Field(max_length=8192)
    remote_user: str = Field(max_length=8192)
    remote_machine: str = Field(max_length=8192)


class RawInventory(_Raw):
    stage: str
    rules: list[RawRule] = Field(max_length=_MAX_RULES)
    apps: list[RawApp] = Field(max_length=_MAX_RULES)
    services: list[RawService] = Field(max_length=_MAX_RULES)
    security: list[RawSecurity] = Field(max_length=_MAX_RULES)


class RawPort(_Raw):
    id: str = Field(min_length=1, max_length=1024)
    protocol: str = Field(max_length=32)
    local: list[str] = Field(max_length=512)
    remote: list[str] = Field(max_length=512)
    icmp: list[str] = Field(max_length=256)
    dynamic_target: str = Field(max_length=64)
    dynamic_transport: str = Field(max_length=64)


class RawAddress(_Raw):
    id: str = Field(min_length=1, max_length=1024)
    local: list[str] = Field(max_length=4096)
    remote: list[str] = Field(max_length=4096)


class RawIfType(_Raw):
    id: str = Field(min_length=1, max_length=1024)
    type: str = Field(max_length=64)


class RawIfAlias(_Raw):
    id: str = Field(min_length=1, max_length=1024)
    aliases: list[str] = Field(max_length=256)


class RawDetailError(_Raw):
    kind: str = Field(max_length=32)
    target: str = Field(max_length=1024)
    category: str = Field(max_length=64)
    error_id: str = Field(max_length=256)


class RawDetail(_Raw):
    stage: str
    done: int = Field(ge=0)
    total: int = Field(ge=0)
    ids: list[str] = Field(max_length=10_000)
    port: list[RawPort] = Field(max_length=10_000)
    address: list[RawAddress] = Field(max_length=10_000)
    iftype: list[RawIfType] = Field(max_length=10_000)
    ifalias: list[RawIfAlias] = Field(max_length=10_000)
    errors: list[RawDetailError] = Field(max_length=40_000)


# --- token parsing -----------------------------------------------------------------------------


def _is_port(text: str) -> bool:
    return text.isdigit() and 0 <= int(text) <= 65535


def parse_port_token(raw: str) -> PortToken:
    text = raw.strip()
    low = text.lower()
    if low == _ANY:
        return PortToken(kind=TokenKind.ANY, value=_ANY)
    if _is_port(text):
        return PortToken(kind=TokenKind.NUMBER, value=str(int(text)))
    if "-" in text:
        lo, _, hi = text.partition("-")
        if _is_port(lo) and _is_port(hi) and int(lo) <= int(hi):
            return PortToken(kind=TokenKind.RANGE, value=f"{int(lo)}-{int(hi)}")
    if low in PORT_KEYWORDS:
        return PortToken(kind=TokenKind.KEYWORD, value=low)
    return PortToken(kind=TokenKind.UNKNOWN, value=text[:64])


def parse_icmp_token(raw: str) -> PortToken:
    text = raw.strip()
    if text.lower() == _ANY:
        return PortToken(kind=TokenKind.ANY, value=_ANY)
    head, sep, tail = text.partition(":")
    if head.isdigit() and int(head) <= 255 and (not sep or (tail.isdigit() and int(tail) <= 255)):
        return PortToken(kind=TokenKind.NUMBER, value=text)
    return PortToken(kind=TokenKind.UNKNOWN, value=text[:64])


def _is_ip_literal(text: str) -> bool:
    try:
        if "/" in text:
            ipaddress.ip_network(text, strict=False)
        elif "-" in text:
            lo, _, hi = text.partition("-")
            a, b = ipaddress.ip_address(lo), ipaddress.ip_address(hi)
            return a.version == b.version and int(a) <= int(b)
        else:
            ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def parse_address_token(raw: str) -> AddressToken:
    text = raw.strip()
    low = text.lower()
    if low == _ANY:
        return AddressToken(kind=TokenKind.ANY, value=_ANY)
    if low in ADDRESS_KEYWORDS:
        return AddressToken(kind=TokenKind.KEYWORD, value=low)
    if _is_ip_literal(text):
        return AddressToken(kind=TokenKind.ADDRESS, value=text)
    return AddressToken(kind=TokenKind.UNKNOWN, value=text[:128])


def _tokens[T](values: Iterable[str], parse: Any) -> tuple[T, ...]:
    out = tuple(parse(v) for v in values if v is not None and str(v).strip() != "")
    return out


def _optional(value: str) -> str | None:
    v = value.strip()
    return None if v == "" or v.lower() in (_ANY, "*") else v


def _optional_keep_wildcard(value: str) -> str | None:
    """Like ``_optional`` but keeps ``*``: for service and package filters ``*`` is a RESTRICTION
    ("services only" / "app packages only"), not "Any" (M1.4 fix; SB-18)."""
    v = value.strip()
    return None if v == "" or v.lower() == _ANY else v


# --- rule IDs with collision detection ---------------------------------------------------------


@dataclass
class IdAllocation:
    public_ids: dict[str, str]  # raw -> public
    duplicates: set[str]  # raw IDs that appeared more than once (excluded)
    extended: set[str]  # raw IDs that needed the full digest (64-bit prefix collision)


def allocate_rule_ids(raw_ids: Iterable[str]) -> IdAllocation:
    """Short h1 IDs; full-digest IDs for raw IDs whose 64-bit prefix collides. Never merges."""
    seen: dict[str, int] = {}
    for raw in raw_ids:
        seen[raw] = seen.get(raw, 0) + 1
    duplicates = {raw for raw, n in seen.items() if n > 1}
    unique = [raw for raw in seen if raw not in duplicates]
    by_short: dict[str, list[str]] = {}
    for raw in unique:
        by_short.setdefault(rule_id(raw), []).append(raw)
    extended = {raw for raws in by_short.values() if len(raws) > 1 for raw in raws}
    public = {raw: rule_id(raw, extended=raw in extended) for raw in unique}
    if len(set(public.values())) != len(public):  # full SHA-256 collision: refuse to merge
        raise ValueError("rule ID collision even with the full digest")
    return IdAllocation(public_ids=public, duplicates=duplicates, extended=extended)


# --- assembler -----------------------------------------------------------------------------------


def _err(source: str, code: CollectorErrorCode, detail: str) -> CollectorError:
    return CollectorError(code=code, source=source, detail=detail[:300])


_CATEGORY_CODE = {
    "PermissionDenied": CollectorErrorCode.ACCESS_DENIED,
    "SecurityError": CollectorErrorCode.ACCESS_DENIED,
    "ObjectNotFound": CollectorErrorCode.NOT_FOUND,
}
_KIND_TO_FILTER = {
    "port": "port",
    "address": "address",
    "iftype": "interface_type",
    "ifalias": "interface",
}


@dataclass
class RuleAssembler:
    """Builds ``FirewallRule`` objects progressively from inventory and detail events."""

    source: str
    detail_requested: bool = True
    errors: list[CollectorError] = field(default_factory=list)
    _base: dict[str, dict[str, Any]] = field(default_factory=dict)  # raw id -> rule fields
    _public: dict[str, str] = field(default_factory=dict)
    _order: list[str] = field(default_factory=list)
    # Built-model cache: rebuild only rules whose fields changed (avoids GIL-heavy rebuilds).
    _built: dict[str, FirewallRule] = field(default_factory=dict)
    _dirty: set[str] = field(default_factory=set)
    inventory_received: bool = False
    total_in_source: int = 0
    detail_done: int = 0

    # -- inventory --
    def ingest_inventory(self, payload: Any) -> tuple[FirewallRule, ...]:
        if self.inventory_received:
            raise ValueError("inventory received twice")
        try:
            inv = RawInventory.model_validate(payload)
        except ValidationError as exc:
            first = exc.errors(include_input=False, include_url=False)[0]
            loc = ".".join(str(p) for p in first.get("loc", ()))[:80]
            raise ValueError(f"invalid inventory payload; loc={loc}") from None
        self.inventory_received = True
        self.total_in_source = len(inv.rules)
        alloc = allocate_rule_ids(r.id for r in inv.rules)
        for raw in sorted(alloc.duplicates):
            self.errors.append(
                _err(
                    self.source,
                    CollectorErrorCode.INVALID_VALUE,
                    f"duplicate raw rule id excluded; rule={rule_id(raw)}",
                )
            )
        if alloc.extended:
            self.errors.append(
                _err(
                    self.source,
                    CollectorErrorCode.INVALID_VALUE,
                    f"64-bit rule id prefix collision; {len(alloc.extended)} rules use full digest",
                )
            )
        apps = {a.id: a for a in inv.apps}
        svcs = {s.id: s for s in inv.services}
        secs = {s.id: s for s in inv.security}
        pending: FilterResult[Any] = FilterResult.not_collected(
            NotCollectedReason.PENDING
            if self.detail_requested
            else NotCollectedReason.NOT_REQUESTED
        )
        for raw_rule in inv.rules:
            if raw_rule.id in alloc.duplicates:
                continue
            public = alloc.public_ids[raw_rule.id]
            base = self._map_rule(raw_rule, public)
            if base is None:
                continue
            base["application"] = self._map_app(apps.get(raw_rule.id), public)
            base["service"] = self._map_service(svcs.get(raw_rule.id), public)
            base["security"] = self._map_security(secs.get(raw_rule.id), public)
            for name in DETAIL_FILTERS:
                base[name] = pending
            self._base[raw_rule.id] = base
            self._public[raw_rule.id] = public
            self._order.append(raw_rule.id)
            self._dirty.add(raw_rule.id)
        return self.rules()

    def _map_rule(self, r: RawRule, public: str) -> dict[str, Any] | None:
        problems = []
        direction = DIRECTION.get(r.direction)
        action = ACTION.get(r.action)
        enabled = ENABLED.get(r.enabled)
        if direction is None:
            problems.append("direction")
        if action is None:
            problems.append("action")
        if enabled is None:
            problems.append("enabled")
        if r.profile.strip() == "Any":
            profiles: tuple[ProfileName, ...] | None = tuple(ProfileName)
        else:
            parts = [p.strip() for p in r.profile.split(",") if p.strip()]
            mapped = [PROFILE.get(p) for p in parts]
            profiles = (
                tuple(dict.fromkeys(m for m in mapped if m is not None))
                if parts and all(mapped)
                else None
            )
        if profiles is None:
            problems.append("profile")
        if problems:
            self.errors.append(
                _err(
                    self.source,
                    CollectorErrorCode.INVALID_VALUE,
                    f"rule excluded; rule={public}; invalid fields={','.join(problems)}",
                )
            )
            return None
        return {
            "id": public,
            "instance_id": r.id,
            "display_name": r.display,
            "description": r.description,
            "group": r.group,
            "direction": direction,
            "action": action,
            "enabled": enabled,
            "profiles": profiles,
            "policy_source_type": SOURCE_TYPE.get(r.source_type, PolicySourceType.UNKNOWN),
            "policy_source_type_raw": r.source_type,
            "enforcement_status": tuple(t for t in r.enforcement.split() if t),
            "primary_status": r.primary_status,
            "edge_traversal": r.edge,
            "has_owner": r.has_owner,
            "remote_dynamic_keyword_addresses": tuple(k for k in r.dynamic_keywords if k),
            "local_only_mapping": r.local_only_mapping,
            "loose_source_mapping": r.loose_source_mapping,
        }

    def _missing(self) -> FilterResult[Any]:
        return FilterResult.not_collected(NotCollectedReason.MISSING_FROM_SOURCE)

    def _invalid(self, public: str, name: str, what: str) -> FilterResult[Any]:
        error = _err(
            self.source,
            CollectorErrorCode.INVALID_VALUE,
            f"rule={public}; filter={name}; invalid {what}",
        )
        self.errors.append(error)
        return FilterResult.unreadable(error)

    def _map_app(self, a: RawApp | None, public: str) -> FilterResult[ApplicationFilter]:
        if a is None:
            return self._missing()
        return FilterResult.collected(
            ApplicationFilter(
                program=_optional(a.program), package=_optional_keep_wildcard(a.package)
            )
        )

    def _map_service(self, s: RawService | None, public: str) -> FilterResult[ServiceFilter]:
        if s is None:
            return self._missing()
        return FilterResult.collected(ServiceFilter(service=_optional_keep_wildcard(s.service)))

    def _map_security(self, s: RawSecurity | None, public: str) -> FilterResult[SecurityFilter]:
        if s is None:
            return self._missing()
        override = ENABLED.get(s.override_block)
        if override is None:
            return self._invalid(public, "security", "override_block_rules")
        return FilterResult.collected(
            SecurityFilter(
                authentication=s.authentication.lower(),
                encryption=s.encryption.lower(),
                override_block_rules=override,
                local_user=_optional(s.local_user),
                remote_user=_optional(s.remote_user),
                remote_machine=_optional(s.remote_machine),
            )
        )

    # -- detail --
    def ingest_detail(self, payload: Any) -> tuple[FirewallRule, ...]:
        if not self.inventory_received:
            raise ValueError("detail before inventory")
        try:
            d = RawDetail.model_validate(payload)
        except ValidationError as exc:
            first = exc.errors(include_input=False, include_url=False)[0]
            loc = ".".join(str(p) for p in first.get("loc", ()))[:80]
            raise ValueError(f"invalid detail payload; loc={loc}") from None
        self.detail_done = max(self.detail_done, d.done)
        ports = {x.id: x for x in d.port}
        addrs = {x.id: x for x in d.address}
        types = {x.id: x for x in d.iftype}
        aliases = {x.id: x for x in d.ifalias}
        errs: dict[tuple[str, str], RawDetailError] = {(e.kind, e.target): e for e in d.errors}
        updated: list[str] = []
        for raw in d.ids:
            base = self._base.get(raw)
            if base is None:
                continue  # duplicate/invalid rule already reported at inventory time
            public = self._public[raw]
            for kind, found, mapper in (
                ("port", ports.get(raw), self._map_port),
                ("address", addrs.get(raw), self._map_address),
                ("iftype", types.get(raw), self._map_iftype),
                ("ifalias", aliases.get(raw), self._map_ifalias),
            ):
                name = _KIND_TO_FILTER[kind]
                if found is not None:
                    base[name] = mapper(found, public)
                elif (kind, raw) in errs:
                    e = errs[(kind, raw)]
                    error = _err(
                        self.source,
                        _CATEGORY_CODE.get(e.category, CollectorErrorCode.EXECUTION_FAILED),
                        f"rule={public}; filter={name}; category={e.category}; "
                        f"error_id={e.error_id[:120]}",
                    )
                    self.errors.append(error)
                    base[name] = FilterResult.unreadable(error)
                else:
                    base[name] = self._missing()
            updated.append(raw)
            self._dirty.add(raw)
        return tuple(self._build(raw) for raw in updated)

    def _map_port(self, p: Any, public: str) -> FilterResult[PortFilter]:
        protocol = p.protocol.strip().lower()
        if not protocol:
            return self._invalid(public, "port", "protocol")
        return FilterResult.collected(
            PortFilter(
                protocol=protocol,
                local_ports=_tokens(p.local, parse_port_token),
                remote_ports=_tokens(p.remote, parse_port_token),
                icmp_types=_tokens(p.icmp, parse_icmp_token),
                dynamic_target=p.dynamic_target.strip().lower(),
                dynamic_transport=p.dynamic_transport.strip().lower(),
            )
        )

    def _map_address(self, a: Any, public: str) -> FilterResult[AddressFilter]:
        return FilterResult.collected(
            AddressFilter(
                local_addresses=_tokens(a.local, parse_address_token),
                remote_addresses=_tokens(a.remote, parse_address_token),
            )
        )

    def _map_iftype(self, t: Any, public: str) -> FilterResult[InterfaceTypeFilter]:
        value = t.type.strip().lower()
        if not value:
            return self._invalid(public, "interface_type", "interface type")
        return FilterResult.collected(InterfaceTypeFilter(interface_type=value))

    def _map_ifalias(self, a: Any, public: str) -> FilterResult[InterfaceFilter]:
        values = [v for v in a.aliases if v.strip()]
        if not values:
            return self._invalid(public, "interface", "empty interface list")
        if any(v.strip().lower() == _ANY for v in values):
            if len(values) != 1:
                return self._invalid(public, "interface", "Any mixed with names")
            return FilterResult.collected(InterfaceFilter(any_interface=True, aliases=()))
        return FilterResult.collected(InterfaceFilter(any_interface=False, aliases=tuple(values)))

    # -- results --
    def finalize(self, reason: NotCollectedReason) -> tuple[FirewallRule, ...]:
        """Replace any still-pending detail filter with NOT_COLLECTED(reason)."""
        for raw, base in self._base.items():
            for name in DETAIL_FILTERS:
                current: FilterResult[Any] = base[name]
                if current.state is FilterState.NOT_COLLECTED and (
                    current.reason is NotCollectedReason.PENDING
                ):
                    base[name] = FilterResult.not_collected(reason)
                    self._dirty.add(raw)
        return self.rules()

    def pending_count(self) -> int:
        return sum(
            1
            for base in self._base.values()
            if any(
                base[n].state is FilterState.NOT_COLLECTED
                and base[n].reason is NotCollectedReason.PENDING
                for n in DETAIL_FILTERS
            )
        )

    def _build(self, raw: str) -> FirewallRule:
        if raw in self._dirty or raw not in self._built:
            self._built[raw] = FirewallRule.model_validate(self._base[raw])
            self._dirty.discard(raw)
        return self._built[raw]

    def rules(self) -> tuple[FirewallRule, ...]:
        return tuple(self._build(raw) for raw in self._order)
