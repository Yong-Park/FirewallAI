"""Local network endpoint models (M1.4).

These are FACTS about local sockets at one moment: protocol, addresses, ports, reported TCP
state, and the owning process where it could be attributed. Nothing here says that an endpoint is
reachable from another host, exposed, allowed, or blocked (SB-20). A listening socket is a fact,
not a finding.

Design rules (same as M1.3, SB-18):
- Process details are ``Observed`` values: COLLECTED (with a value) or UNAVAILABLE (with a
  reason). There are no defaults and no guesses.
- Process attribution is BEST EFFORT, never a guarantee of process identity. Details are
  attached only when the socket and its PID appear in two socket snapshots taken before and after
  the process lookup (a consistency check that reduces, but does not remove, PID-reuse risk; see
  ``collectors.endpoint_assembly``). Otherwise the attribution is ``attribution_unverified`` and
  no process details are attached.
- Addresses, process names, paths, and service names are HOST_SENSITIVE.
"""

import hashlib
import ipaddress
import unicodedata
from enum import StrEnum
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from firewallai.core.models import EntityId
from firewallai.core.sensitivity import DataClass, sensitivity

_ABSTRACT = sensitivity(DataClass.DERIVED_ABSTRACT)
_SENSITIVE = sensitivity(DataClass.HOST_SENSITIVE)

ENDPOINT_ID_SCHEME = "h1"
MAX_ENDPOINTS = 65_536  # per snapshot; more is reported as an error, never truncated silently
MAX_PROCESS_NAME = 1024
MAX_IMAGE_PATH = 32_767  # Windows long-path limit
MAX_SERVICE_NAME = 256
MAX_SERVICES_PER_PROCESS = 512
SYSTEM_PSEUDO_PIDS = frozenset({0, 4})  # System Idle Process, System (kernel)


class TransportProtocol(StrEnum):
    TCP = "tcp"
    UDP = "udp"


class IpFamily(StrEnum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"


class EndpointKind(StrEnum):
    LISTENING = "listening"  # TCP socket in the LISTEN state
    BOUND = "bound"  # UDP socket bound to a local address (UDP has no listen state)
    CONNECTION = "connection"  # TCP socket in any other reported state


class TcpState(StrEnum):
    """TCP states as reported by the socket table (psutil names), preserved as reported."""

    LISTEN = "LISTEN"
    SYN_SENT = "SYN_SENT"
    SYN_RECV = "SYN_RECV"
    ESTABLISHED = "ESTABLISHED"
    FIN_WAIT1 = "FIN_WAIT1"
    FIN_WAIT2 = "FIN_WAIT2"
    CLOSE_WAIT = "CLOSE_WAIT"
    CLOSING = "CLOSING"
    LAST_ACK = "LAST_ACK"
    TIME_WAIT = "TIME_WAIT"
    CLOSE = "CLOSE"
    DELETE_TCB = "DELETE_TCB"
    UNRECOGNIZED = "UNRECOGNIZED"  # the source reported a state this version does not know


class BindScope(StrEnum):
    """Where the socket is bound locally. Descriptive only: never a reachability statement."""

    LOOPBACK = "loopback"  # 127.0.0.0/8 or ::1 (incl. IPv4-mapped loopback)
    ALL_INTERFACES = "all_interfaces"  # 0.0.0.0 or ::
    LINK_LOCAL = "link_local"  # 169.254.0.0/16 or fe80::/10
    SPECIFIC = "specific"  # one specific local address
    UNPARSEABLE = "unparseable"  # the reported address could not be parsed


class Availability(StrEnum):
    COLLECTED = "collected"
    UNAVAILABLE = "unavailable"


class UnavailableReason(StrEnum):
    NO_PID = "no_pid"  # the socket table reported no owning PID
    SYSTEM_PSEUDO_PROCESS = "system_pseudo_process"  # PID 0 (idle) or 4 (System kernel)
    ACCESS_DENIED = "access_denied"  # Windows denied the query as a standard user
    PROCESS_EXITED = "process_exited"  # the process ended before it could be queried
    ATTRIBUTION_UNVERIFIED = "attribution_unverified"  # socket/PID changed during the snapshot
    LOOKUP_FAILED = "lookup_failed"  # the lookup itself failed (e.g. service query error)
    NOT_REPORTED = "not_reported"  # the source returned no value
    INVALID_VALUE = "invalid_value"  # the value failed validation (e.g. over the length cap)
    NOT_COLLECTED = "not_collected"  # collection was cancelled before this process


class Observed[T](BaseModel):
    """One observed value with an explicit state. No default value exists."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    availability: Availability = Field(json_schema_extra=_ABSTRACT)
    value: T | None = Field(default=None, json_schema_extra=_SENSITIVE)
    reason: UnavailableReason | None = Field(default=None, json_schema_extra=_ABSTRACT)

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if self.availability is Availability.COLLECTED:
            ok = self.value is not None and self.reason is None
        else:
            ok = self.value is None and self.reason is not None
        if not ok:
            raise ValueError(f"inconsistent Observed for {self.availability.value}")
        return self

    @classmethod
    def of(cls, value: T) -> "Observed[T]":
        return cls(availability=Availability.COLLECTED, value=value)

    @classmethod
    def missing(cls, reason: UnavailableReason) -> "Observed[T]":
        return cls(availability=Availability.UNAVAILABLE, reason=reason)

    @property
    def is_collected(self) -> bool:
        return self.availability is Availability.COLLECTED


class ProcessInfo(BaseModel):
    """The owning process of a socket (best effort), or an explicit reason why it is not attributed.

    ``attribution == COLLECTED`` means "consistent across two socket snapshots", not "proven".
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    pid: int | None = Field(ge=0, le=2**32 - 1, json_schema_extra=_ABSTRACT)
    attribution: Availability = Field(json_schema_extra=_ABSTRACT)
    reason: UnavailableReason | None = Field(default=None, json_schema_extra=_ABSTRACT)
    name: Observed[str] = Field(json_schema_extra=_SENSITIVE)
    image_path: Observed[str] = Field(json_schema_extra=_SENSITIVE)
    services: Observed[tuple[str, ...]] = Field(json_schema_extra=_SENSITIVE)

    @model_validator(mode="after")
    def _no_partial_misattribution(self) -> Self:
        details = (self.name, self.image_path, self.services)
        if self.attribution is Availability.COLLECTED:
            if self.reason is not None or self.pid is None:
                raise ValueError("an attributed process needs a PID and no reason")
        elif self.reason is None or any(d.is_collected for d in details):
            raise ValueError("an unattributed process carries a reason and no details")
        return self

    @classmethod
    def unattributed(cls, pid: int | None, reason: UnavailableReason) -> "ProcessInfo":
        return cls(
            pid=pid,
            attribution=Availability.UNAVAILABLE,
            reason=reason,
            name=Observed.missing(reason),
            image_path=Observed.missing(reason),
            services=Observed.missing(reason),
        )


def endpoint_id(
    protocol: TransportProtocol,
    family: IpFamily,
    local_address: str,
    local_port: int,
    remote_address: str | None,
    remote_port: int | None,
    pid: int | None,
) -> str:
    """Snapshot-local ID; stable for the same socket tuple and PID."""
    key = "|".join(
        (
            protocol.value,
            family.value,
            local_address,
            str(local_port),
            remote_address or "",
            "" if remote_port is None else str(remote_port),
            "" if pid is None else str(pid),
        )
    )
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]
    return f"net_ep:{ENDPOINT_ID_SCHEME}-{digest}"


class Endpoint(BaseModel):
    """One local socket (listening/bound endpoint or TCP connection) at snapshot time."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: EntityId = Field(json_schema_extra=_ABSTRACT)
    protocol: TransportProtocol = Field(json_schema_extra=_ABSTRACT)
    family: IpFamily = Field(json_schema_extra=_ABSTRACT)
    kind: EndpointKind = Field(json_schema_extra=_ABSTRACT)
    tcp_state: TcpState | None = Field(json_schema_extra=_ABSTRACT)
    local_address: str = Field(min_length=1, max_length=64, json_schema_extra=_SENSITIVE)
    local_port: int = Field(ge=0, le=65535, json_schema_extra=_ABSTRACT)
    remote_address: str | None = Field(default=None, max_length=64, json_schema_extra=_SENSITIVE)
    remote_port: int | None = Field(default=None, ge=0, le=65535, json_schema_extra=_ABSTRACT)
    bind_scope: BindScope = Field(json_schema_extra=_ABSTRACT)
    # A "::" socket may also accept IPv4 unless IPV6_V6ONLY is set; that is not observable here.
    dual_stack_unknown: bool = Field(json_schema_extra=_ABSTRACT)
    process: ProcessInfo = Field(json_schema_extra=_SENSITIVE)

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if self.protocol is TransportProtocol.UDP:
            if self.kind is not EndpointKind.BOUND or self.tcp_state is not None:
                raise ValueError("a UDP socket is a bound endpoint without a TCP state")
            if self.remote_address is not None or self.remote_port is not None:
                raise ValueError("a UDP endpoint has no remote endpoint in the socket table")
        else:
            if self.tcp_state is None:
                raise ValueError("a TCP socket carries its reported state")
            listening = self.tcp_state is TcpState.LISTEN
            if (self.kind is EndpointKind.LISTENING) != listening or self.kind is (
                EndpointKind.BOUND
            ):
                raise ValueError("TCP kind must follow the reported state")
        if (self.remote_address is None) != (self.remote_port is None):
            raise ValueError("remote address and port come together")
        return self


class EndpointLimitationCode(StrEnum):
    LOCAL_SOCKET_FACTS_ONLY = "local_socket_facts_only"  # never a reachability assessment
    PROFILE_MAPPING_DEFERRED = "profile_mapping_deferred"  # endpoint -> interface -> profile
    SNAPSHOT_NOT_ATOMIC = "snapshot_not_atomic"
    PROCESS_DETAILS_UNAVAILABLE = "process_details_unavailable"
    ATTRIBUTION_UNVERIFIED = "attribution_unverified"
    ATTRIBUTION_BEST_EFFORT = "attribution_best_effort"  # always reported
    SERVICE_LOOKUP_FAILED = "service_lookup_failed"
    DUAL_STACK_UNKNOWN = "dual_stack_unknown"
    UNRECOGNIZED_RECORDS = "unrecognized_records"
    PROCESS_LOOKUP_INCOMPLETE = "process_lookup_incomplete"  # cancelled during enrichment


class EndpointLimitation(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    code: EndpointLimitationCode = Field(json_schema_extra=_ABSTRACT)
    detail: str = Field(default="", max_length=300, json_schema_extra=_ABSTRACT)


class EndpointTimings(BaseModel):
    """Phase durations inside the collector, in seconds (the service wall time is separate)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    sockets_s: float = Field(ge=0, json_schema_extra=_ABSTRACT)
    processes_s: float = Field(ge=0, json_schema_extra=_ABSTRACT)
    services_s: float | None = Field(default=None, ge=0, json_schema_extra=_ABSTRACT)


class EndpointSnapshot(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    endpoints: tuple[Endpoint, ...] = Field(max_length=MAX_ENDPOINTS, json_schema_extra=_SENSITIVE)
    services_collected: bool = Field(json_schema_extra=_ABSTRACT)
    process_lookup_complete: bool = Field(json_schema_extra=_ABSTRACT)
    limitations: tuple[EndpointLimitation, ...] = Field(json_schema_extra=_ABSTRACT)
    timings: EndpointTimings = Field(json_schema_extra=_ABSTRACT)


# --- pure helpers --------------------------------------------------------------------------------


def parse_local_address(text: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Parse a socket-table address. IPv6 zone IDs (``fe80::1%12``) are ignored."""
    try:
        addr = ipaddress.ip_address(text.split("%", 1)[0])
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr


def classify_bind(address: str) -> tuple[BindScope, bool]:
    """Return (bind scope, dual-stack-unknown) for a local address."""
    if address.split("%", 1)[0] == "::":
        return BindScope.ALL_INTERFACES, True
    addr = parse_local_address(address)
    if addr is None:
        return BindScope.UNPARSEABLE, False
    if addr.is_unspecified:
        return BindScope.ALL_INTERFACES, False
    if addr.is_loopback:
        return BindScope.LOOPBACK, False
    if addr.is_link_local:
        return BindScope.LINK_LOCAL, False
    return BindScope.SPECIFIC, False


def display_safe(text: str, max_len: int = 200) -> str:
    """Render untrusted text (process names, paths, rule names) safely for display.

    Control, format (incl. bidi overrides and zero-width characters), and surrogate characters are
    shown as ``\\uXXXX`` escapes, so they cannot reorder or hide text. Long values are truncated.
    """
    out: list[str] = []
    for ch in text:
        if unicodedata.category(ch) in ("Cc", "Cf", "Cs", "Zl", "Zp"):
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    rendered = "".join(out)
    return rendered if len(rendered) <= max_len else rendered[: max_len - 1] + "…"
