"""Endpoint snapshot service (M1.4): measured end-to-end duration, privacy-aware export.

Performance: the human-approved M1.4 target is a complete endpoint snapshot (sockets, process
details, and the required service lookup) in under 1 s, measured end to end here. It is separate
from N-04 (the rule scan) and is never combined with it. A snapshot whose process lookup was
cancelled or whose service lookup failed is "not evaluated", never "met".
"""

import os
import threading
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from firewallai import __version__
from firewallai.collectors.fake.network_endpoints import FixtureEndpointCollector
from firewallai.collectors.protocols import EndpointCollector, EndpointsResult
from firewallai.collectors.windows.network_endpoints import WindowsEndpointCollector
from firewallai.collectors.windows.privilege import is_elevated
from firewallai.core.correlation import RuleIndex
from firewallai.core.endpoints import EndpointKind, EndpointSnapshot
from firewallai.core.rules import RuleCollection

ENDPOINTS_REPORT_SCHEMA = "firewallai.endpoints/1"
SNAPSHOT_TARGET_S = 1.0
ENDPOINT_SCOPE_NOTE = (
    "Read-only. Local socket facts only: not an exposure, reachability, or firewall assessment."
)
ENDPOINTS_PRIVACY_NOTE = (
    "This export contains host-sensitive data: local and remote IP addresses (including the "
    "peers of active connections), process names and paths, and service names. Keep it local "
    "and do not share it publicly."
)
# System-wide variables used in firewall rule program paths. User-specific variables (e.g.
# %USERPROFILE%) are deliberately excluded: the firewall does not expand them per user
# [VERIFY], so such paths stay "cannot evaluate".
PROGRAM_PATH_VARIABLES = (
    "SystemRoot",
    "windir",
    "SystemDrive",
    "ProgramFiles",
    "ProgramFiles(x86)",
    "ProgramW6432",
    "ProgramData",
    "CommonProgramFiles",
    "CommonProgramFiles(x86)",
    "CommonProgramW6432",
)


class TargetStatus(StrEnum):
    MET = "met"
    EXCEEDED = "exceeded"
    NOT_EVALUATED = "not_evaluated"


@dataclass(frozen=True, slots=True)
class SnapshotTarget:
    status: TargetStatus
    target_s: float
    measured_s: float | None
    reason: str

    def describe(self) -> str:
        if self.status is TargetStatus.NOT_EVALUATED or self.measured_s is None:
            return f"Endpoint snapshot target (M1.4, < {self.target_s:.0f} s) not evaluated: " + (
                self.reason
            )
        verdict = "met" if self.status is TargetStatus.MET else "EXCEEDED"
        return (
            f"Endpoint snapshot target (M1.4, < {self.target_s:.0f} s) {verdict}: "
            f"{self.measured_s:.2f} s end to end"
        )


@dataclass(frozen=True, slots=True)
class EndpointScanReport:
    result: EndpointsResult
    source_id: str
    started_at: datetime
    total_s: float
    target: SnapshotTarget
    elevated: bool | None


def evaluate_target(result: EndpointsResult, total_s: float) -> SnapshotTarget:
    data = result.data
    if data is None:
        return SnapshotTarget(TargetStatus.NOT_EVALUATED, SNAPSHOT_TARGET_S, None, "failed")
    if not data.process_lookup_complete:
        return SnapshotTarget(TargetStatus.NOT_EVALUATED, SNAPSHOT_TARGET_S, None, "cancelled")
    if not data.services_collected:
        return SnapshotTarget(
            TargetStatus.NOT_EVALUATED, SNAPSHOT_TARGET_S, None, "service lookup failed"
        )
    status = TargetStatus.MET if total_s < SNAPSHOT_TARGET_S else TargetStatus.EXCEEDED
    return SnapshotTarget(status, SNAPSHOT_TARGET_S, total_s, "")


class EndpointScanService:
    def __init__(
        self,
        collector: EndpointCollector,
        *,
        clock: Callable[[], float] = time.perf_counter,
        wall_clock: Callable[[], datetime] | None = None,
        elevation_check: Callable[[], bool | None] = is_elevated,
    ) -> None:
        self._collector = collector
        self._clock = clock
        self._wall_clock = wall_clock if wall_clock is not None else (lambda: datetime.now(UTC))
        self._elevation_check = elevation_check

    @property
    def source_id(self) -> str:
        return self._collector.source_id

    def scan(self, *, cancel: threading.Event | None = None) -> EndpointScanReport:
        started_at = self._wall_clock()
        start = self._clock()
        result = self._collector.collect_endpoints(cancel=cancel)
        total_s = self._clock() - start
        return EndpointScanReport(
            result=result,
            source_id=self._collector.source_id,
            started_at=started_at,
            total_s=total_s,
            target=evaluate_target(result, total_s),
            elevated=self._elevation_check(),
        )


def create_endpoint_scan_service(fixture: Path | None = None) -> EndpointScanService:
    collector: EndpointCollector
    if fixture is not None:
        collector = FixtureEndpointCollector.from_file(fixture)
    else:
        collector = WindowsEndpointCollector()
    return EndpointScanService(collector)


def program_path_environment() -> dict[str, str]:
    """System-wide path variables for comparing rule program paths (read from this process)."""
    return {name: os.environ[name] for name in PROGRAM_PATH_VARIABLES if name in os.environ}


def build_rule_index(collection: RuleCollection) -> RuleIndex:
    return RuleIndex(collection, program_path_environment())


def summarize(snapshot: EndpointSnapshot) -> dict[str, Any]:
    kinds = Counter(ep.kind.value for ep in snapshot.endpoints)
    families = Counter(ep.family.value for ep in snapshot.endpoints)
    process = Counter(
        "attributed" if ep.process.reason is None else ep.process.reason.value
        for ep in snapshot.endpoints
    )
    return {
        "total": len(snapshot.endpoints),
        "listening_tcp": kinds.get(EndpointKind.LISTENING.value, 0),
        "bound_udp": kinds.get(EndpointKind.BOUND.value, 0),
        "tcp_connections": kinds.get(EndpointKind.CONNECTION.value, 0),
        "families": dict(sorted(families.items())),
        "process_attribution": dict(sorted(process.items())),
    }


def endpoints_report_to_dict(report: EndpointScanReport) -> dict[str, Any]:
    data = report.result.data
    return {
        "schema": ENDPOINTS_REPORT_SCHEMA,
        "app_version": __version__,
        "note": ENDPOINTS_PRIVACY_NOTE,
        "sensitivity": {
            "data_class": "host_sensitive",
            "contains": [
                "local IP addresses",
                "remote IP addresses and ports of active TCP connections",
                "process names and image paths",
                "service names",
            ],
            "remote_addresses_included": True,  # --show-remote affects text output only
            "share_publicly": False,
            "not_collected": ["process command lines", "process owners"],
        },
        "started_at": report.started_at.isoformat(),
        "source": report.source_id,
        "scope": "local_socket_facts_only",
        "read_only": True,
        "elevated": report.elevated,
        "ok": report.result.ok,
        "partial": report.result.partial,
        "timing": {
            "total_s": round(report.total_s, 3),
            "phases": None if data is None else data.timings.model_dump(mode="json"),
        },
        "snapshot_target": {
            "status": report.target.status.value,
            "target_s": report.target.target_s,
            "measured_s": None
            if report.target.measured_s is None
            else round(report.target.measured_s, 3),
            "reason": report.target.reason,
            "text": report.target.describe(),
            "note": "M1.4 endpoint snapshot target; separate from N-04 (rule scan)",
        },
        "summary": None if data is None else summarize(data),
        "limitations": []
        if data is None
        else [x.model_dump(mode="json") for x in data.limitations],
        "errors": [e.model_dump(mode="json") for e in report.result.errors],
        "endpoints": [] if data is None else [e.model_dump(mode="json") for e in data.endpoints],
    }
