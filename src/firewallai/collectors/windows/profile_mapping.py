"""Explicit mapping from raw NetSecurity profile values to normalized domain models.

Shared by the real Windows collector and the fixture-backed fake collector, so tests exercise the
same parsing path. Unknown enum values are errors, never guesses. Error details contain field
names and enum integers only, never raw host data such as paths.
"""

from collections.abc import Mapping
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from firewallai.core.models import (
    FirewallAction,
    FirewallProfile,
    ProfileName,
    TriState,
    profile_id,
)
from firewallai.core.results import CollectorError, CollectorErrorCode, CollectorResult

GPO_BOOLEAN: Mapping[int, TriState] = {
    0: TriState.FALSE,
    1: TriState.TRUE,
    2: TriState.NOT_CONFIGURED,
}
ACTION: Mapping[int, FirewallAction] = {
    0: FirewallAction.NOT_CONFIGURED,
    2: FirewallAction.ALLOW,
    4: FirewallAction.BLOCK,
}
PROFILE_NAME: Mapping[str, ProfileName] = {
    "Domain": ProfileName.DOMAIN,
    "Private": ProfileName.PRIVATE,
    "Public": ProfileName.PUBLIC,
}
_NOT_CONFIGURED_TEXT = "NotConfigured"
_MAX_PROFILES = 16


class RawNetFirewallProfile(BaseModel):
    """Shape emitted by the ``firewall_profiles`` script (field names as in NetSecurity)."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    Name: str = Field(max_length=32)
    Enabled: int
    DefaultInboundAction: int
    DefaultOutboundAction: int
    AllowInboundRules: int
    AllowLocalFirewallRules: int
    AllowLocalIPsecRules: int
    NotifyOnListen: int
    LogAllowed: int
    LogBlocked: int
    LogMaxSizeKilobytes: int = Field(ge=0)
    LogFileName: str = Field(max_length=1024)
    DisabledInterfaceAliases: list[str] = Field(max_length=256)


class ProfileMappingError(ValueError):
    def __init__(self, field: str, value: object) -> None:
        super().__init__(f"field={field}; value={value!r}")
        self.field = field
        self.value = value


def _gpo(field: str, value: int) -> TriState:
    try:
        return GPO_BOOLEAN[value]
    except KeyError:
        raise ProfileMappingError(field, value) from None


def _action(field: str, value: int) -> FirewallAction:
    try:
        return ACTION[value]
    except KeyError:
        raise ProfileMappingError(field, value) from None


def map_raw_profile(raw: RawNetFirewallProfile) -> FirewallProfile:
    try:
        name = PROFILE_NAME[raw.Name]
    except KeyError:
        # Profile names are a fixed set; report without echoing unexpected text.
        raise ProfileMappingError("Name", "<unexpected>") from None
    log_file = raw.LogFileName.strip()
    aliases = tuple(
        alias for alias in raw.DisabledInterfaceAliases if alias and alias != _NOT_CONFIGURED_TEXT
    )
    return FirewallProfile(
        id=profile_id(name),
        name=name,
        enabled=_gpo("Enabled", raw.Enabled),
        default_inbound_action=_action("DefaultInboundAction", raw.DefaultInboundAction),
        default_outbound_action=_action("DefaultOutboundAction", raw.DefaultOutboundAction),
        allow_inbound_rules=_gpo("AllowInboundRules", raw.AllowInboundRules),
        allow_local_firewall_rules=_gpo("AllowLocalFirewallRules", raw.AllowLocalFirewallRules),
        allow_local_ipsec_rules=_gpo("AllowLocalIPsecRules", raw.AllowLocalIPsecRules),
        notify_on_listen=_gpo("NotifyOnListen", raw.NotifyOnListen),
        log_allowed=_gpo("LogAllowed", raw.LogAllowed),
        log_blocked=_gpo("LogBlocked", raw.LogBlocked),
        log_max_size_kb=raw.LogMaxSizeKilobytes,
        log_file_name=None if log_file in ("", _NOT_CONFIGURED_TEXT) else log_file,
        disabled_interface_aliases=aliases,
    )


def _validation_detail(exc: ValidationError) -> str:
    first = exc.errors(include_input=False, include_url=False)[0]
    location = ".".join(str(part) for part in first.get("loc", ()))
    return f"invalid raw profile; loc={location}; type={first.get('type', '')}"


def parse_profiles_payload(
    payload: Any, source: str
) -> CollectorResult[tuple[FirewallProfile, ...]]:
    """Validate and map a ``{"profiles": [...]}`` payload. Bad items become errors (partial)."""

    def error(code: CollectorErrorCode, detail: str) -> CollectorError:
        return CollectorError(code=code, source=source, detail=detail)

    if not isinstance(payload, dict) or not isinstance(payload.get("profiles"), list):
        return CollectorResult(
            errors=(error(CollectorErrorCode.PARSE_ERROR, "payload lacks a profiles list"),)
        )
    items = payload["profiles"]
    if len(items) > _MAX_PROFILES:
        return CollectorResult(
            errors=(error(CollectorErrorCode.PARSE_ERROR, f"too many profiles: {len(items)}"),)
        )

    profiles: list[FirewallProfile] = []
    errors: list[CollectorError] = []
    for index, item in enumerate(items):
        try:
            raw = RawNetFirewallProfile.model_validate(item)
            profiles.append(map_raw_profile(raw))
        except ValidationError as exc:
            errors.append(
                error(CollectorErrorCode.PARSE_ERROR, f"item={index}; {_validation_detail(exc)}")
            )
        except ProfileMappingError as exc:
            errors.append(error(CollectorErrorCode.INVALID_VALUE, f"item={index}; {exc}"))

    seen: set[ProfileName] = set()
    for profile in profiles:
        if profile.name in seen:
            errors.append(
                error(CollectorErrorCode.INVALID_VALUE, f"duplicate profile={profile.name.value}")
            )
        seen.add(profile.name)

    ordered = tuple(sorted(profiles, key=lambda p: list(ProfileName).index(p.name)))
    if not ordered:
        if not errors:
            errors.append(error(CollectorErrorCode.PARSE_ERROR, "no profiles returned"))
        return CollectorResult(errors=tuple(errors))
    return CollectorResult(data=ordered, errors=tuple(errors), partial=bool(errors))
