"""Real, read-only, non-elevated endpoint collector (M1.4): sockets, owning processes, services.

Sources (human decisions Q1/Q2, 2026-10-15):
- Sockets: ``psutil.net_connections("inet")`` (the Windows ``GetExtendedTcpTable`` /
  ``GetExtendedUdpTable`` socket tables). Taken twice, before and after the process lookups, for
  the best-effort PID-reuse check (see ``endpoint_assembly`` for its residual risks).
- Processes: ``psutil.Process(pid)`` name and image path only. No command lines, no owners,
  no creation time (the latter costs ~10 ms per protected process as a standard user).
- Services: the registered read-only ``WIN32_SERVICES`` script through the audited PowerShell
  runner. It runs in parallel with the psutil work; its failure never invalidates socket data.

Only read-only psutil APIs are used (enforced by tests/security/test_endpoint_collector_security).
"""

import threading
import time
from collections.abc import Callable, Iterable
from typing import Any, Literal

import psutil
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from firewallai.collectors.endpoint_assembly import (
    MAX_RAW_SERVICES,
    RawEndpointSnapshot,
    RawField,
    RawProcess,
    RawService,
    RawSocket,
    assemble_snapshot,
)
from firewallai.collectors.protocols import EndpointsResult
from firewallai.collectors.windows.powershell_runner import (
    PowerShellRunner,
    RunOutcome,
    UnsupportedPlatformError,
)
from firewallai.collectors.windows.scripts import WIN32_SERVICES
from firewallai.core.endpoints import MAX_ENDPOINTS, SYSTEM_PSEUDO_PIDS, EndpointTimings
from firewallai.core.results import CollectorError, CollectorErrorCode, CollectorResult

# One endpoint snapshot at a time per process (a second concurrent request returns BUSY).
# This is NOT the M1.3 HEAVY_QUERY_LOCK: no firewall query is made here (SB-19 unaffected).
ENDPOINT_SNAPSHOT_LOCK = threading.Lock()

_FAMILIES: dict[str, Literal["ipv4", "ipv6"]] = {"AF_INET": "ipv4", "AF_INET6": "ipv6"}
_TYPES: dict[str, Literal["tcp", "udp"]] = {"SOCK_STREAM": "tcp", "SOCK_DGRAM": "udp"}


class _ServicesPayload(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    services: list[RawService] = Field(max_length=MAX_RAW_SERVICES)


def _to_raw_sockets(conns: Iterable[Any]) -> tuple[list[RawSocket], int]:
    """Convert psutil records to strict raw models; count records that cannot be interpreted."""
    out: list[RawSocket] = []
    dropped = 0
    for c in conns:
        try:
            laddr, raddr = c.laddr, c.raddr
            out.append(
                RawSocket(
                    protocol=_TYPES[c.type.name],
                    family=_FAMILIES[c.family.name],
                    local_address=str(laddr[0]),
                    local_port=int(laddr[1]),
                    remote_address=str(raddr[0]) if raddr else None,
                    remote_port=int(raddr[1]) if raddr else None,
                    status=str(c.status),
                    pid=None if c.pid is None else int(c.pid),
                )
            )
        except (KeyError, IndexError, AttributeError, TypeError, ValueError, ValidationError):
            dropped += 1
    return out, dropped


ProcessFieldError = Literal["access_denied", "process_exited", "lookup_failed"]


def _read(getter: Callable[[], Any]) -> RawField:
    error: ProcessFieldError
    try:
        value = getter()
    except psutil.NoSuchProcess:  # includes ZombieProcess
        error = "process_exited"
    except psutil.AccessDenied:
        error = "access_denied"
    except (psutil.Error, OSError):
        error = "lookup_failed"
    else:
        return RawField(value=value if isinstance(value, str) else None)
    return RawField(error=error)


def probe_process(pid: int) -> RawProcess:
    """Read name and image path of one process (read-only)."""
    try:
        proc = psutil.Process(pid)
    except psutil.NoSuchProcess:
        return RawProcess(pid=pid, exited=True, name=RawField(), exe=RawField())
    except psutil.AccessDenied:
        denied = RawField(error="access_denied")
        return RawProcess(pid=pid, name=denied, exe=denied)
    with proc.oneshot():
        name = _read(proc.name)
        exe = _read(proc.exe)
    # Conservative: if the process ended during the lookup, nothing read from it is attributed.
    exited = "process_exited" in (name.error, exe.error)
    return RawProcess(pid=pid, exited=exited, name=name, exe=exe)


class WindowsEndpointCollector:
    SOURCE_ID = "windows.psutil.endpoints"

    def __init__(
        self,
        runner: PowerShellRunner | None = None,
        *,
        net_connections: Callable[[], Iterable[Any]] | None = None,
        process_probe: Callable[[int], RawProcess] = probe_process,
        clock: Callable[[], float] = time.perf_counter,
    ) -> None:
        self._runner = runner
        self._net_connections = (
            net_connections
            if net_connections is not None
            else (lambda: psutil.net_connections(kind="inet"))
        )
        self._probe = process_probe
        self._clock = clock

    @property
    def source_id(self) -> str:
        return self.SOURCE_ID

    def _error(self, code: CollectorErrorCode, detail: str) -> EndpointsResult:
        return CollectorResult(
            errors=(CollectorError(code=code, source=self.SOURCE_ID, detail=detail),)
        )

    def _services(self, box: dict[str, Any]) -> None:
        start = self._clock()
        try:
            runner = self._runner if self._runner is not None else PowerShellRunner()
            box["outcome"] = runner.run(WIN32_SERVICES, source=self.SOURCE_ID)
        except UnsupportedPlatformError:
            box["outcome"] = RunOutcome(
                error=CollectorError(
                    code=CollectorErrorCode.UNSUPPORTED_PLATFORM,
                    source=self.SOURCE_ID,
                    detail="Windows PowerShell is not available",
                )
            )
        except Exception as exc:  # never let the service lookup break the socket snapshot
            box["outcome"] = RunOutcome(
                error=CollectorError(
                    code=CollectorErrorCode.EXECUTION_FAILED,
                    source=self.SOURCE_ID,
                    detail=f"service lookup raised {type(exc).__name__}",
                )
            )
        box["elapsed"] = self._clock() - start

    def _snapshot(self) -> tuple[list[RawSocket], int] | CollectorError:
        try:
            conns = list(self._net_connections())
        except psutil.AccessDenied:
            return CollectorError(
                code=CollectorErrorCode.ACCESS_DENIED,
                source=self.SOURCE_ID,
                detail="socket table: access_denied",
            )
        except (psutil.Error, OSError) as exc:
            return CollectorError(
                code=CollectorErrorCode.EXECUTION_FAILED,
                source=self.SOURCE_ID,
                detail=f"socket table: {type(exc).__name__}",
            )
        if len(conns) > MAX_ENDPOINTS:
            return CollectorError(
                code=CollectorErrorCode.OUTPUT_TOO_LARGE,
                source=self.SOURCE_ID,
                detail=f"socket table has {len(conns)} entries (cap {MAX_ENDPOINTS})",
            )
        return _to_raw_sockets(conns)

    def collect_endpoints(self, *, cancel: threading.Event | None = None) -> EndpointsResult:
        if not ENDPOINT_SNAPSHOT_LOCK.acquire(blocking=False):
            return self._error(CollectorErrorCode.BUSY, "an endpoint snapshot is already running")
        try:
            return self._collect(cancel)
        finally:
            ENDPOINT_SNAPSHOT_LOCK.release()

    def _collect(self, cancel: threading.Event | None) -> EndpointsResult:
        box: dict[str, Any] = {}
        service_thread = threading.Thread(
            target=self._services, args=(box,), name="fwai-services", daemon=True
        )
        service_thread.start()  # runs in parallel with the psutil work below
        try:
            t0 = self._clock()
            first = self._snapshot()
            if isinstance(first, CollectorError):
                return CollectorResult(errors=(first,))
            first_sockets, dropped = first
            sockets_s = self._clock() - t0

            t1 = self._clock()
            pids = sorted(
                {
                    s.pid
                    for s in first_sockets
                    if s.pid is not None and s.pid not in SYSTEM_PSEUDO_PIDS
                }
            )
            processes: list[RawProcess] = []
            complete = True
            for pid in pids:
                if cancel is not None and cancel.is_set():
                    complete = False
                    break
                processes.append(self._probe(pid))
            processes_s = self._clock() - t1

            t2 = self._clock()
            second = self._snapshot()  # best-effort PID-reuse check (endpoint_assembly)
            sockets_s += self._clock() - t2
        finally:
            # Bounded by the script timeout; the runner kills the child on timeout.
            service_thread.join(timeout=WIN32_SERVICES.timeout_s + 5)

        services, services_error = self._service_result(box)
        errors: list[CollectorError] = []
        if not complete:
            errors.append(
                CollectorError(
                    code=CollectorErrorCode.CANCELLED,
                    source=self.SOURCE_ID,
                    detail="cancelled during process lookup",
                )
            )
        if services_error is not None:
            errors.append(services_error)
        if isinstance(second, CollectorError):
            errors.append(second)
        raw = RawEndpointSnapshot(
            first=first_sockets,
            second=[] if isinstance(second, CollectorError) else second[0],
            processes=processes,
            services=services,
            services_error=None if services_error is None else services_error.detail,
            process_lookup_complete=complete,
            unrecognized_records=dropped,
        )
        timings = EndpointTimings(
            sockets_s=sockets_s, processes_s=processes_s, services_s=box.get("elapsed")
        )
        snapshot = assemble_snapshot(raw, timings)
        return CollectorResult(data=snapshot, errors=tuple(errors), partial=bool(errors))

    def _service_result(
        self, box: dict[str, Any]
    ) -> tuple[list[RawService] | None, CollectorError | None]:
        outcome = box.get("outcome")
        if not isinstance(outcome, RunOutcome):
            return None, CollectorError(
                code=CollectorErrorCode.TIMEOUT,
                source=self.SOURCE_ID,
                detail="service lookup did not finish",
            )
        if outcome.error is not None:
            return None, outcome.error.model_copy(update={"source": self.SOURCE_ID})
        try:
            payload = _ServicesPayload.model_validate(outcome.data)
        except ValidationError as exc:
            return None, CollectorError(
                code=CollectorErrorCode.PARSE_ERROR,
                source=self.SOURCE_ID,
                detail=f"service lookup: {exc.error_count()} validation error(s)",
            )
        return payload.services, None
