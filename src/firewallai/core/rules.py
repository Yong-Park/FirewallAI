"""Firewall rule domain models (M1.3, ADR 0009).

Design rules:
- Every filter is a ``FilterResult``: COLLECTED (with a value), NOT_COLLECTED (with a reason), or
  UNREADABLE (with a structured error). There is NO default value: a missing filter never means
  "Any" or "unrestricted".
- Port and address values are parsed into typed tokens. Unrecognized values become UNKNOWN tokens,
  never ANY.
- Raw Windows identifiers, names, paths, addresses, interface names, and SDDL strings are
  HOST_SENSITIVE.
"""

import hashlib
from enum import StrEnum
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from firewallai.core.models import EntityId, ProfileName
from firewallai.core.results import CollectorError
from firewallai.core.sensitivity import DataClass, sensitivity

_ABSTRACT = sensitivity(DataClass.DERIVED_ABSTRACT)
_SENSITIVE = sensitivity(DataClass.HOST_SENSITIVE)

# Public rule ID scheme, version "h1": "fw_rule:h1-" + first 16 hex chars (64 bits) of
# SHA-256(UTF-8 raw Windows rule ID). On a 64-bit prefix collision between different raw IDs, the
# affected rules use the full 64-hex digest ("fw_rule:h1-<64 hex>"); see RuleIdAllocator.
RULE_ID_SCHEME = "h1"
RULE_ID_SHORT_HEX = 16


def rule_id_digest(raw_instance_id: str) -> str:
    return hashlib.sha256(raw_instance_id.encode("utf-8")).hexdigest()


def rule_id(raw_instance_id: str, *, extended: bool = False) -> str:
    digest = rule_id_digest(raw_instance_id)
    return f"fw_rule:{RULE_ID_SCHEME}-{digest if extended else digest[:RULE_ID_SHORT_HEX]}"


class RuleDirection(StrEnum):
    INBOUND = "inbound"
    OUTBOUND = "outbound"


class RuleAction(StrEnum):
    ALLOW = "allow"
    BLOCK = "block"


class PolicySourceType(StrEnum):
    LOCAL = "local"
    GROUP_POLICY = "group_policy"
    DYNAMIC = "dynamic"
    GENERATED = "generated"
    HARDCODED = "hardcoded"
    MDM = "mdm"
    HOST_FIREWALL = "host_firewall"
    UNKNOWN = "unknown"


class TokenKind(StrEnum):
    ANY = "any"
    NUMBER = "number"  # a single port / ICMP type
    RANGE = "range"  # "a-b"
    KEYWORD = "keyword"  # Windows keyword (RPC, LocalSubnet, ...), value lower-cased
    ADDRESS = "address"  # explicit IP / CIDR / mask / range
    UNKNOWN = "unknown"  # not recognized: never interpreted


class PortToken(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: TokenKind = Field(json_schema_extra=_ABSTRACT)
    value: str = Field(max_length=64, json_schema_extra=_ABSTRACT)


class AddressToken(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: TokenKind = Field(json_schema_extra=_ABSTRACT)
    # Explicit addresses can identify networks/hosts.
    value: str = Field(max_length=128, json_schema_extra=_SENSITIVE)


class FilterState(StrEnum):
    COLLECTED = "collected"
    NOT_COLLECTED = "not_collected"
    UNREADABLE = "unreadable"


class NotCollectedReason(StrEnum):
    PENDING = "pending"  # detail collection has not reached this rule yet
    NOT_REQUESTED = "not_requested"  # e.g. inventory-only scan
    CANCELLED = "cancelled"
    PHASE_FAILED = "phase_failed"  # the detail phase failed or timed out before this rule
    MISSING_FROM_SOURCE = "missing_from_source"  # source returned no entry for this rule


class FilterResult[T](BaseModel):
    """Explicit evidence state for one filter of one rule."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    state: FilterState = Field(json_schema_extra=_ABSTRACT)
    value: T | None = Field(default=None, json_schema_extra=_SENSITIVE)
    reason: NotCollectedReason | None = Field(default=None, json_schema_extra=_ABSTRACT)
    error: CollectorError | None = Field(default=None, json_schema_extra=_ABSTRACT)

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if self.state is FilterState.COLLECTED:
            ok = self.value is not None and self.reason is None and self.error is None
        elif self.state is FilterState.NOT_COLLECTED:
            ok = self.value is None and self.reason is not None and self.error is None
        else:
            ok = self.value is None and self.reason is None and self.error is not None
        if not ok:
            raise ValueError(f"inconsistent FilterResult for state={self.state.value}")
        return self

    @classmethod
    def collected(cls, value: T) -> "FilterResult[T]":
        return cls(state=FilterState.COLLECTED, value=value)

    @classmethod
    def not_collected(cls, reason: NotCollectedReason) -> "FilterResult[T]":
        return cls(state=FilterState.NOT_COLLECTED, reason=reason)

    @classmethod
    def unreadable(cls, error: CollectorError) -> "FilterResult[T]":
        return cls(state=FilterState.UNREADABLE, error=error)

    @property
    def is_collected(self) -> bool:
        return self.state is FilterState.COLLECTED


class ApplicationFilter(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    # None = any. ``package == "*"`` means "app packages only" (a restriction, not "any").
    program: str | None = Field(default=None, max_length=2048, json_schema_extra=_SENSITIVE)
    package: str | None = Field(default=None, max_length=512, json_schema_extra=_SENSITIVE)


class ServiceFilter(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    # None = any. ``service == "*"`` means "services only" (a restriction, not "any").
    service: str | None = Field(default=None, max_length=512, json_schema_extra=_SENSITIVE)


class SecurityFilter(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    authentication: str = Field(max_length=64, json_schema_extra=_ABSTRACT)
    encryption: str = Field(max_length=64, json_schema_extra=_ABSTRACT)
    override_block_rules: bool = Field(json_schema_extra=_ABSTRACT)  # authenticated bypass
    local_user: str | None = Field(default=None, max_length=8192, json_schema_extra=_SENSITIVE)
    remote_user: str | None = Field(default=None, max_length=8192, json_schema_extra=_SENSITIVE)
    remote_machine: str | None = Field(default=None, max_length=8192, json_schema_extra=_SENSITIVE)


class PortFilter(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    protocol: str = Field(max_length=32, json_schema_extra=_ABSTRACT)  # tcp/udp/any/icmpv4/...
    local_ports: tuple[PortToken, ...] = Field(max_length=512, json_schema_extra=_ABSTRACT)
    remote_ports: tuple[PortToken, ...] = Field(max_length=512, json_schema_extra=_ABSTRACT)
    icmp_types: tuple[PortToken, ...] = Field(max_length=256, json_schema_extra=_ABSTRACT)
    dynamic_target: str = Field(max_length=64, json_schema_extra=_ABSTRACT)  # raw, lower-cased
    dynamic_transport: str = Field(max_length=64, json_schema_extra=_ABSTRACT)  # raw, lower-cased


class AddressFilter(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    local_addresses: tuple[AddressToken, ...] = Field(max_length=4096, json_schema_extra=_SENSITIVE)
    remote_addresses: tuple[AddressToken, ...] = Field(
        max_length=4096, json_schema_extra=_SENSITIVE
    )


class InterfaceTypeFilter(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    interface_type: str = Field(max_length=64, json_schema_extra=_ABSTRACT)


class InterfaceFilter(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    any_interface: bool = Field(json_schema_extra=_ABSTRACT)
    # Interface names (e.g. virtual switch names) can identify the host setup.
    aliases: tuple[str, ...] = Field(max_length=256, json_schema_extra=_SENSITIVE)


class FirewallRule(BaseModel):
    """One ActiveStore rule with explicit per-filter evidence states."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: EntityId = Field(json_schema_extra=_ABSTRACT)
    instance_id: str = Field(min_length=1, max_length=1024, json_schema_extra=_SENSITIVE)
    display_name: str = Field(max_length=1024, json_schema_extra=_SENSITIVE)
    description: str = Field(default="", max_length=4096, json_schema_extra=_SENSITIVE)
    group: str = Field(default="", max_length=1024, json_schema_extra=_SENSITIVE)
    direction: RuleDirection = Field(json_schema_extra=_ABSTRACT)
    action: RuleAction = Field(json_schema_extra=_ABSTRACT)
    enabled: bool = Field(json_schema_extra=_ABSTRACT)
    profiles: tuple[ProfileName, ...] = Field(min_length=1, json_schema_extra=_ABSTRACT)
    policy_source_type: PolicySourceType = Field(json_schema_extra=_ABSTRACT)
    policy_source_type_raw: str = Field(max_length=64, json_schema_extra=_ABSTRACT)
    # Raw, uninterpreted tokens (semantics unverified, ADR 0009).
    enforcement_status: tuple[str, ...] = Field(max_length=32, json_schema_extra=_ABSTRACT)
    primary_status: str = Field(max_length=64, json_schema_extra=_ABSTRACT)
    edge_traversal: str = Field(max_length=64, json_schema_extra=_ABSTRACT)
    has_owner: bool = Field(json_schema_extra=_ABSTRACT)
    # Dynamic keyword address objects referenced by the rule (IDs); not resolved in v0.1.
    remote_dynamic_keyword_addresses: tuple[str, ...] = Field(
        default=(), max_length=256, json_schema_extra=_SENSITIVE
    )
    local_only_mapping: bool = Field(default=False, json_schema_extra=_ABSTRACT)
    loose_source_mapping: bool = Field(default=False, json_schema_extra=_ABSTRACT)

    application: FilterResult[ApplicationFilter] = Field(json_schema_extra=_SENSITIVE)
    service: FilterResult[ServiceFilter] = Field(json_schema_extra=_SENSITIVE)
    security: FilterResult[SecurityFilter] = Field(json_schema_extra=_SENSITIVE)
    port: FilterResult[PortFilter] = Field(json_schema_extra=_ABSTRACT)
    address: FilterResult[AddressFilter] = Field(json_schema_extra=_SENSITIVE)
    interface_type: FilterResult[InterfaceTypeFilter] = Field(json_schema_extra=_ABSTRACT)
    interface: FilterResult[InterfaceFilter] = Field(json_schema_extra=_SENSITIVE)

    @model_validator(mode="after")
    def _id_matches_instance(self) -> Self:
        if self.id not in (
            rule_id(self.instance_id),
            rule_id(self.instance_id, extended=True),
        ):
            raise ValueError("id must be derived from instance_id (scheme h1)")
        return self


class ScanLimitationCode(StrEnum):
    """Scan-level limitations (ADR 0009, M1.2 report §5). Reported with every rule scan."""

    LOCAL_POLICY_ONLY = "local_policy_only"  # never a claim about external reachability
    WFP_FILTERS_NOT_OBSERVABLE = "wfp_filters_not_observable"
    SERVICE_HARDENING_NOT_EVALUATED = "service_hardening_not_evaluated"
    GROUP_POLICY_MERGE_UNVERIFIED = "group_policy_merge_unverified"
    ENFORCEMENT_STATUS_UNINTERPRETED = "enforcement_status_uninterpreted"
    DYNAMIC_KEYWORDS_NOT_RESOLVED = "dynamic_keywords_not_resolved"
    DETAIL_NOT_COLLECTED = "detail_not_collected"  # inventory-only scan
    DETAIL_INCOMPLETE = "detail_incomplete"  # cancelled / timed out / failed detail phase


class ScanLimitation(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    code: ScanLimitationCode = Field(json_schema_extra=_ABSTRACT)
    detail: str = Field(default="", max_length=300, json_schema_extra=_ABSTRACT)


class RuleCollection(BaseModel):
    """Result payload of a rule scan: rules plus explicit completeness information."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    rules: tuple[FirewallRule, ...] = Field(json_schema_extra=_SENSITIVE)
    total_in_source: int = Field(ge=0, json_schema_extra=_ABSTRACT)
    detail_requested: bool = Field(json_schema_extra=_ABSTRACT)
    detail_complete: bool = Field(json_schema_extra=_ABSTRACT)
    limitations: tuple[ScanLimitation, ...] = Field(json_schema_extra=_ABSTRACT)


DETAIL_FILTERS = ("port", "address", "interface_type", "interface")
INVENTORY_FILTERS = ("application", "service", "security")
ALL_FILTERS = INVENTORY_FILTERS + DETAIL_FILTERS
