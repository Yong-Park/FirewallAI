"""Rule scan service: progressive collection, measured duration, N-04 status, evidence summary.

N-04 (requirements 02): a COMPLETE scan (inventory + all detail filters) must finish in 10 s.
The duration measured here is the real end-to-end time of ``collect_rules``. Early inventory
results or UI responsiveness never count as N-04 compliance. Scans that are cancelled, failed,
partial in the detail phase, or inventory-only are reported as "not evaluated".
"""

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
from firewallai.collectors.fake.firewall_rules import FixtureFirewallRuleCollector
from firewallai.collectors.protocols import (
    FirewallRuleCollector,
    RuleCollectionObserver,
    RulesResult,
)
from firewallai.collectors.windows.firewall_rules import WindowsFirewallRuleCollector
from firewallai.collectors.windows.privilege import is_elevated
from firewallai.core.evidence import IncompleteEvidence, evidence_for_verdict

RULES_REPORT_SCHEMA = "firewallai.rules/1"
N04_TARGET_S = 10.0
SENSITIVE_EXPORT_NOTE = (
    "This export may contain host-sensitive data (rule names, program paths, addresses, "
    "interface names). Review before sharing."
)


class N04Status(StrEnum):
    MET = "met"
    EXCEEDED = "exceeded"
    NOT_EVALUATED = "not_evaluated"


@dataclass(frozen=True, slots=True)
class N04Result:
    status: N04Status
    target_s: float
    measured_s: float | None
    reason: str

    def describe(self) -> str:
        if self.status is N04Status.MET:
            return f"N-04 met: full scan {self.measured_s:.1f} s (target {self.target_s:.0f} s)"
        if self.status is N04Status.EXCEEDED and self.measured_s is not None:
            over = self.measured_s - self.target_s
            return (
                f"N-04 EXCEEDED: full scan {self.measured_s:.1f} s "
                f"(target {self.target_s:.0f} s, over by {over:.1f} s)"
            )
        return f"N-04 not evaluated: {self.reason}"


@dataclass(frozen=True, slots=True)
class EvidenceSummary:
    complete: int
    incomplete: int
    reasons: dict[str, int]  # top-level reason -> count of rules


@dataclass(frozen=True, slots=True)
class RuleScanReport:
    result: RulesResult
    source_id: str
    started_at: datetime
    mode: str  # "full" | "inventory_only"
    inventory_s: float | None
    total_s: float
    n04: N04Result
    evidence: EvidenceSummary
    elevated: bool | None


def evaluate_n04(result: RulesResult, *, detail: bool, total_s: float) -> N04Result:
    data = result.data
    if not detail:
        return N04Result(N04Status.NOT_EVALUATED, N04_TARGET_S, None, "inventory-only scan")
    if data is None:
        return N04Result(N04Status.NOT_EVALUATED, N04_TARGET_S, None, "scan failed")
    if not data.detail_complete:
        return N04Result(
            N04Status.NOT_EVALUATED, N04_TARGET_S, None, "scan incomplete (cancelled or failed)"
        )
    status = N04Status.MET if total_s <= N04_TARGET_S else N04Status.EXCEEDED
    return N04Result(status, N04_TARGET_S, total_s, "")


def summarize_evidence(result: RulesResult) -> EvidenceSummary:
    if result.data is None:
        return EvidenceSummary(0, 0, {})
    reasons: Counter[str] = Counter()
    complete = incomplete = 0
    for rule in result.data.rules:
        ev = evidence_for_verdict(rule)
        if isinstance(ev, IncompleteEvidence):
            incomplete += 1
            for reason in {r.split(":", 1)[0] for r in ev.reasons}:
                reasons[reason] += 1
        else:
            complete += 1
    return EvidenceSummary(complete, incomplete, dict(reasons.most_common()))


class _Timing:
    def __init__(self, start: float, clock: Callable[[], float], inner: Any) -> None:
        self.start = start
        self.clock = clock
        self.inner = inner
        self.inventory_s: float | None = None

    def inventory_ready(self, rules: Any) -> None:
        self.inventory_s = self.clock() - self.start
        if self.inner is not None:
            self.inner.inventory_ready(rules)

    def detail_progress(self, done: int, total: int, updated: Any) -> None:
        if self.inner is not None:
            self.inner.detail_progress(done, total, updated)


class RuleScanService:
    """Single-flight rule scans (a second concurrent scan returns a BUSY result)."""

    def __init__(
        self,
        collector: FirewallRuleCollector,
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

    def scan(
        self,
        *,
        detail: bool = True,
        observer: RuleCollectionObserver | None = None,
        cancel: threading.Event | None = None,
    ) -> RuleScanReport:
        started_at = self._wall_clock()
        start = self._clock()
        timing = _Timing(start, self._clock, observer)
        result = self._collector.collect_rules(detail=detail, observer=timing, cancel=cancel)
        total_s = self._clock() - start
        return RuleScanReport(
            result=result,
            source_id=self._collector.source_id,
            started_at=started_at,
            mode="full" if detail else "inventory_only",
            inventory_s=timing.inventory_s,
            total_s=total_s,
            n04=evaluate_n04(result, detail=detail, total_s=total_s),
            evidence=summarize_evidence(result),
            elevated=self._elevation_check(),
        )


def create_rule_scan_service(fixture: Path | None = None) -> RuleScanService:
    collector: FirewallRuleCollector
    if fixture is not None:
        collector = FixtureFirewallRuleCollector.from_file(fixture)
    else:
        collector = WindowsFirewallRuleCollector()
    return RuleScanService(collector)


def rules_report_to_dict(report: RuleScanReport) -> dict[str, Any]:
    data = report.result.data
    return {
        "schema": RULES_REPORT_SCHEMA,
        "app_version": __version__,
        "note": SENSITIVE_EXPORT_NOTE,
        "started_at": report.started_at.isoformat(),
        "source": report.source_id,
        "scope": "local_policy_only",
        "read_only": True,
        "elevated": report.elevated,
        "mode": report.mode,
        "ok": report.result.ok,
        "partial": report.result.partial,
        "timing": {
            "inventory_s": None if report.inventory_s is None else round(report.inventory_s, 3),
            "total_s": round(report.total_s, 3),
        },
        "n04": {
            "status": report.n04.status.value,
            "target_s": report.n04.target_s,
            "measured_s": None
            if report.n04.measured_s is None
            else round(report.n04.measured_s, 3),
            "reason": report.n04.reason,
            "text": report.n04.describe(),
        },
        "evidence": {
            "complete": report.evidence.complete,
            "incomplete": report.evidence.incomplete,
            "incomplete_reasons": report.evidence.reasons,
            "verdicts": "none (M1.3 collects evidence only; incomplete evidence never yields one)",
        },
        "collection": None
        if data is None
        else {
            "total_in_source": data.total_in_source,
            "collected": len(data.rules),
            "detail_requested": data.detail_requested,
            "detail_complete": data.detail_complete,
            "limitations": [lim.model_dump(mode="json") for lim in data.limitations],
        },
        "errors": [e.model_dump(mode="json") for e in report.result.errors],
        "rules": [] if data is None else [r.model_dump(mode="json") for r in data.rules],
    }
