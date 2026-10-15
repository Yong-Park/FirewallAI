"""Domain models for firewall state (M1.1: profiles only).

Models are immutable, strictly validated, carry stable typed IDs, and declare per-field sensitivity.
Values are normalized, platform-independent enums. Mapping from Windows-specific raw values happens
in ``firewallai.collectors``.
"""

from enum import StrEnum
from typing import Annotated, Self

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from firewallai.core.sensitivity import DataClass, sensitivity

# Stable entity IDs: "<kind>:<key>", lowercase. Used later for evidence references (ADR 0021 §9).
EntityId = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]*:[a-z0-9][a-z0-9_.:-]*$")]


class ProfileName(StrEnum):
    DOMAIN = "domain"
    PRIVATE = "private"
    PUBLIC = "public"


class TriState(StrEnum):
    """A setting that may be explicitly on, off, or left to defaults/policy."""

    TRUE = "true"
    FALSE = "false"
    NOT_CONFIGURED = "not_configured"


class FirewallAction(StrEnum):
    ALLOW = "allow"
    BLOCK = "block"
    NOT_CONFIGURED = "not_configured"


def profile_id(name: ProfileName) -> str:
    """Stable ID for a firewall profile, e.g. ``fw_profile:public``."""
    return f"fw_profile:{name.value}"


_ABSTRACT = sensitivity(DataClass.DERIVED_ABSTRACT)
_SENSITIVE = sensitivity(DataClass.HOST_SENSITIVE)


class FirewallProfile(BaseModel):
    """Effective settings of one Windows Firewall profile (from the ActiveStore)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: EntityId = Field(json_schema_extra=_ABSTRACT)
    name: ProfileName = Field(json_schema_extra=_ABSTRACT)
    enabled: TriState = Field(json_schema_extra=_ABSTRACT)
    default_inbound_action: FirewallAction = Field(json_schema_extra=_ABSTRACT)
    default_outbound_action: FirewallAction = Field(json_schema_extra=_ABSTRACT)
    allow_inbound_rules: TriState = Field(json_schema_extra=_ABSTRACT)
    allow_local_firewall_rules: TriState = Field(json_schema_extra=_ABSTRACT)
    allow_local_ipsec_rules: TriState = Field(json_schema_extra=_ABSTRACT)
    notify_on_listen: TriState = Field(json_schema_extra=_ABSTRACT)
    log_allowed: TriState = Field(json_schema_extra=_ABSTRACT)
    log_blocked: TriState = Field(json_schema_extra=_ABSTRACT)
    log_max_size_kb: int | None = Field(default=None, ge=0, json_schema_extra=_ABSTRACT)
    # A file path may contain a user or host name.
    log_file_name: str | None = Field(default=None, max_length=1024, json_schema_extra=_SENSITIVE)
    # Interface aliases can identify the host's network setup.
    disabled_interface_aliases: tuple[str, ...] = Field(default=(), json_schema_extra=_SENSITIVE)

    @model_validator(mode="after")
    def _id_matches_name(self) -> Self:
        if self.id != profile_id(self.name):
            raise ValueError("id must equal profile_id(name)")
        return self
