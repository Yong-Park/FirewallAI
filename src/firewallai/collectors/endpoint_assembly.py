"""Assemble endpoint models from two raw socket snapshots, process lookups, and services (M1.4).

Platform-neutral and side-effect free: used by the Windows collector and the fixture collector.

Attribution rule (best-effort PID-reuse check): an endpoint from the FIRST snapshot gets process
details only if the identical socket tuple with the identical PID is also present in the SECOND
snapshot, taken after the process lookups. Otherwise it is reported as ``attribution_unverified``
with no process details.

This is a CONSISTENCY CHECK, not proof of process identity. Residual risks (documented, and
reported with every snapshot as ``attribution_best_effort``):
1. Exit, PID reuse, and re-bind inside the window: the original owner exits after the first
   snapshot, Windows reuses its PID for a new process, and that process binds the identical socket
   tuple before the second snapshot. The details then describe the new process. This needs the same
   PID and the same local (and remote) address and port within about 0.1-0.3 s: unlikely, but
   possible, for example when a service restarts quickly.
2. Shared sockets: socket handles can be inherited or duplicated into other processes; the socket
   table reports one owning PID, which may not be the process using the socket [VERIFY].
3. Kernel-owned sockets (PID 4) have no queryable image path and are never attributed.
Process creation times would narrow risk 1, but cost about 660 ms as a standard user (M1.4
measurement) and were not used.
"""

from collections import Counter
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from firewallai.core.endpoints import (
    MAX_ENDPOINTS,
    MAX_IMAGE_PATH,
    MAX_PROCESS_NAME,
    MAX_SERVICE_NAME,
    MAX_SERVICES_PER_PROCESS,
    SYSTEM_PSEUDO_PIDS,
    Availability,
    Endpoint,
    EndpointKind,
    EndpointLimitation,
    EndpointLimitationCode,
    EndpointSnapshot,
    EndpointTimings,
    IpFamily,
    Observed,
    ProcessInfo,
    TcpState,
    TransportProtocol,
    UnavailableReason,
    classify_bind,
    endpoint_id,
)

FieldError = Literal["access_denied", "process_exited", "lookup_failed", "not_reported"]
MAX_RAW_SERVICES = 8192


class _Raw(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)


class RawSocket(_Raw):
    protocol: Literal["tcp", "udp"]
    family: Literal["ipv4", "ipv6"]
    local_address: str = Field(min_length=1, max_length=64)
    local_port: int = Field(ge=0, le=65535)
    remote_address: str | None = Field(default=None, max_length=64)
    remote_port: int | None = Field(default=None, ge=0, le=65535)
    status: str = Field(max_length=32)  # TCP state name, "NONE" for UDP
    pid: int | None = Field(default=None, ge=0, le=2**32 - 1)

    def key(self) -> tuple[object, ...]:
        return (
            self.protocol,
            self.family,
            self.local_address,
            self.local_port,
            self.remote_address,
            self.remote_port,
            self.pid,
        )


class RawField(_Raw):
    value: str | None = None  # length is validated during assembly (invalid -> explicit state)
    error: FieldError | None = None


class RawProcess(_Raw):
    pid: int = Field(ge=0, le=2**32 - 1)
    exited: bool = False
    name: RawField
    exe: RawField


class RawService(_Raw):
    name: str = Field(min_length=1, max_length=MAX_SERVICE_NAME)
    pid: int = Field(ge=1, le=2**32 - 1)


class RawEndpointSnapshot(_Raw):
    first: list[RawSocket] = Field(max_length=MAX_ENDPOINTS)
    second: list[RawSocket] = Field(max_length=MAX_ENDPOINTS)
    processes: list[RawProcess] = Field(max_length=MAX_ENDPOINTS)
    services: list[RawService] | None = Field(default=None, max_length=MAX_RAW_SERVICES)
    services_error: str | None = Field(default=None, max_length=300)
    process_lookup_complete: bool = True
    unrecognized_records: int = Field(default=0, ge=0)


_STATE_NAMES = {s.value for s in TcpState if s is not TcpState.UNRECOGNIZED}
_FIELD_REASON = {
    "access_denied": UnavailableReason.ACCESS_DENIED,
    "process_exited": UnavailableReason.PROCESS_EXITED,
    "lookup_failed": UnavailableReason.LOOKUP_FAILED,
    "not_reported": UnavailableReason.NOT_REPORTED,
}


def _observe_text(raw: RawField, cap: int) -> Observed[str]:
    if raw.error is not None:
        return Observed.missing(_FIELD_REASON[raw.error])
    if raw.value is None or raw.value == "":
        return Observed.missing(UnavailableReason.NOT_REPORTED)
    if len(raw.value) > cap:
        return Observed.missing(UnavailableReason.INVALID_VALUE)
    return Observed.of(raw.value)


def _services_by_pid(
    raw: RawEndpointSnapshot,
) -> tuple[dict[int, tuple[str, ...]] | None, set[int]]:
    """Service names per PID, plus PIDs that reported more services than the cap."""
    if raw.services is None:
        return None, set()
    by_pid: dict[int, list[str]] = {}
    for svc in raw.services:
        by_pid.setdefault(svc.pid, []).append(svc.name)
    oversized: set[int] = set()
    result: dict[int, tuple[str, ...]] = {}
    for pid, names in by_pid.items():
        if len(names) > MAX_SERVICES_PER_PROCESS:
            oversized.add(pid)
        else:
            result[pid] = tuple(sorted(names, key=str.lower))
    return result, oversized


def _process_info(
    sock: RawSocket,
    verified: bool,
    procs: dict[int, RawProcess],
    services: dict[int, tuple[str, ...]] | None,
    oversized_service_pids: set[int],
) -> ProcessInfo:
    pid = sock.pid
    if pid is None:
        return ProcessInfo.unattributed(None, UnavailableReason.NO_PID)
    if pid in SYSTEM_PSEUDO_PIDS:
        return ProcessInfo.unattributed(pid, UnavailableReason.SYSTEM_PSEUDO_PROCESS)
    if not verified:
        return ProcessInfo.unattributed(pid, UnavailableReason.ATTRIBUTION_UNVERIFIED)
    proc = procs.get(pid)
    if proc is None:
        return ProcessInfo.unattributed(pid, UnavailableReason.NOT_COLLECTED)
    if proc.exited:
        return ProcessInfo.unattributed(pid, UnavailableReason.PROCESS_EXITED)
    if services is None:
        svc: Observed[tuple[str, ...]] = Observed.missing(UnavailableReason.LOOKUP_FAILED)
    elif pid in oversized_service_pids:
        svc = Observed.missing(UnavailableReason.INVALID_VALUE)
    else:
        svc = Observed.of(services.get(pid, ()))
    return ProcessInfo(
        pid=pid,
        attribution=Availability.COLLECTED,
        name=_observe_text(proc.name, MAX_PROCESS_NAME),
        image_path=_observe_text(proc.exe, MAX_IMAGE_PATH),
        services=svc,
    )


def _endpoint(sock: RawSocket, process: ProcessInfo) -> Endpoint | None:
    protocol = TransportProtocol(sock.protocol)
    if protocol is TransportProtocol.UDP:
        kind, state = EndpointKind.BOUND, None
        remote_address: str | None = None
        remote_port: int | None = None
    else:
        state = TcpState(sock.status) if sock.status in _STATE_NAMES else TcpState.UNRECOGNIZED
        kind = EndpointKind.LISTENING if state is TcpState.LISTEN else EndpointKind.CONNECTION
        remote_address, remote_port = sock.remote_address, sock.remote_port
        if (remote_address is None) != (remote_port is None):
            return None
    scope, dual = classify_bind(sock.local_address)
    family = IpFamily(sock.family)
    try:
        return Endpoint(
            id=endpoint_id(
                protocol,
                family,
                sock.local_address,
                sock.local_port,
                remote_address,
                remote_port,
                sock.pid,
            ),
            protocol=protocol,
            family=family,
            kind=kind,
            tcp_state=state,
            local_address=sock.local_address,
            local_port=sock.local_port,
            remote_address=remote_address,
            remote_port=remote_port,
            bind_scope=scope,
            dual_stack_unknown=dual,
            process=process,
        )
    except ValidationError:
        return None


def _unique_ids(endpoints: list[Endpoint]) -> list[Endpoint]:
    """Identical socket tuples (e.g. SO_REUSEADDR) keep separate rows with suffixed IDs."""
    seen: Counter[str] = Counter()
    out: list[Endpoint] = []
    for ep in endpoints:
        seen[ep.id] += 1
        n = seen[ep.id]
        out.append(ep if n == 1 else ep.model_copy(update={"id": f"{ep.id}-{n}"}))
    return out


def assemble_snapshot(raw: RawEndpointSnapshot, timings: EndpointTimings) -> EndpointSnapshot:
    second = {s.key() for s in raw.second}
    procs = {p.pid: p for p in raw.processes}
    services, oversized_pids = _services_by_pid(raw)
    endpoints: list[Endpoint] = []
    dropped = raw.unrecognized_records
    for sock in raw.first:
        process = _process_info(sock, sock.key() in second, procs, services, oversized_pids)
        ep = _endpoint(sock, process)
        if ep is None:
            dropped += 1
        else:
            endpoints.append(ep)
    endpoints = _unique_ids(endpoints)

    reasons: Counter[str] = Counter(
        ep.process.reason.value for ep in endpoints if ep.process.reason is not None
    )
    detail_gaps = sum(
        1
        for ep in endpoints
        if ep.process.attribution is Availability.COLLECTED
        and not (ep.process.name.is_collected and ep.process.image_path.is_collected)
    )
    limitations = [
        EndpointLimitation(
            code=EndpointLimitationCode.LOCAL_SOCKET_FACTS_ONLY,
            detail="local sockets only; not an exposure, reachability, or firewall assessment",
        ),
        EndpointLimitation(
            code=EndpointLimitationCode.PROFILE_MAPPING_DEFERRED,
            detail="endpoint-to-interface-to-firewall-profile mapping is not done (Sprint 2)",
        ),
        EndpointLimitation(
            code=EndpointLimitationCode.ATTRIBUTION_BEST_EFFORT,
            detail="process details are consistent across two socket snapshots; this is not a "
            "guarantee of process identity (PID reuse inside the window is possible)",
        ),
        EndpointLimitation(
            code=EndpointLimitationCode.SNAPSHOT_NOT_ATOMIC,
            detail="sockets can open or close during the snapshot; endpoints are from the first "
            "socket table",
        ),
    ]
    unverified = reasons.get(UnavailableReason.ATTRIBUTION_UNVERIFIED.value, 0)
    if unverified:
        limitations.append(
            EndpointLimitation(
                code=EndpointLimitationCode.ATTRIBUTION_UNVERIFIED,
                detail=f"{unverified} endpoint(s) changed during the snapshot; no process shown",
            )
        )
    unavailable = {
        k: v for k, v in reasons.items() if k != UnavailableReason.ATTRIBUTION_UNVERIFIED.value
    }
    if unavailable or detail_gaps:
        parts = [f"{k}: {v}" for k, v in sorted(unavailable.items())]
        if detail_gaps:
            parts.append(f"partial details: {detail_gaps}")
        limitations.append(
            EndpointLimitation(
                code=EndpointLimitationCode.PROCESS_DETAILS_UNAVAILABLE,
                detail=("; ".join(parts))[:300],
            )
        )
    if raw.services is None:
        limitations.append(
            EndpointLimitation(
                code=EndpointLimitationCode.SERVICE_LOOKUP_FAILED,
                detail=(raw.services_error or "service lookup failed")[:300],
            )
        )
    elif oversized_pids:
        limitations.append(
            EndpointLimitation(
                code=EndpointLimitationCode.SERVICE_LOOKUP_FAILED,
                detail=f"{len(oversized_pids)} process(es) reported too many services; not shown",
            )
        )
    if any(ep.dual_stack_unknown for ep in endpoints):
        limitations.append(
            EndpointLimitation(
                code=EndpointLimitationCode.DUAL_STACK_UNKNOWN,
                detail="'::' sockets may also accept IPv4; IPV6_V6ONLY is not observable",
            )
        )
    if dropped:
        limitations.append(
            EndpointLimitation(
                code=EndpointLimitationCode.UNRECOGNIZED_RECORDS,
                detail=f"{dropped} socket record(s) could not be interpreted and are not shown",
            )
        )
    if not raw.process_lookup_complete:
        limitations.append(
            EndpointLimitation(
                code=EndpointLimitationCode.PROCESS_LOOKUP_INCOMPLETE,
                detail="cancelled during process lookup; remaining processes not collected",
            )
        )
    return EndpointSnapshot(
        endpoints=tuple(endpoints),
        services_collected=raw.services is not None,
        process_lookup_complete=raw.process_lookup_complete,
        limitations=tuple(limitations),
        timings=timings,
    )
