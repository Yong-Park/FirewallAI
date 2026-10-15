"""Read-only, non-elevated integration tests against the real ActiveStore (M1.3).

The full-scan duration is MEASURED and printed. It is not asserted against N-04, because the gap
is known and documented (ADR 0009). The tests assert correctness and completeness instead.
"""

import time

import pytest

from firewallai.app.rule_service import N04Status, RuleScanReport, RuleScanService
from firewallai.collectors.windows.firewall_rules import WindowsFirewallRuleCollector
from firewallai.collectors.windows.privilege import is_elevated
from firewallai.core.evidence import IncompleteEvidence, evidence_for_verdict
from firewallai.core.rules import ALL_FILTERS, FilterState, NotCollectedReason

pytestmark = [pytest.mark.windows, pytest.mark.integration]


@pytest.fixture(scope="module")
def full_report() -> RuleScanReport:
    assert is_elevated() is False, "must run as a standard user (SB-02)"
    return RuleScanService(WindowsFirewallRuleCollector()).scan()


def test_full_scan_collects_every_rule_with_explicit_states(full_report: RuleScanReport) -> None:
    data = full_report.result.data
    assert data is not None
    assert len(data.rules) == data.total_in_source > 0
    assert data.detail_complete
    for rule in data.rules:
        for name in ALL_FILTERS:
            result = getattr(rule, name)
            assert result.state in set(FilterState)
            if result.state is not FilterState.COLLECTED:
                assert result.value is None  # never a default value
    assert len({r.id for r in data.rules}) == len(data.rules)


def test_incomplete_evidence_is_flagged_never_hidden(full_report: RuleScanReport) -> None:
    summary = full_report.evidence
    assert summary.complete + summary.incomplete == len(full_report.result.data.rules)
    for rule in full_report.result.data.rules:
        ev = evidence_for_verdict(rule)
        if isinstance(ev, IncompleteEvidence):
            assert ev.reasons


def test_dynamic_or_unreadable_rules_are_never_complete(full_report: RuleScanReport) -> None:
    """SB-18 on live data: rules with a non-"any" dynamic target/transport, dynamic keyword
    addresses, or any filter not COLLECTED must never be usable for a verdict."""
    data = full_report.result.data
    assert data is not None
    flagged = 0
    for rule in data.rules:
        port = rule.port.value
        risky = (
            any(getattr(rule, n).state is not FilterState.COLLECTED for n in ALL_FILTERS)
            or bool(rule.remote_dynamic_keyword_addresses)
            or (
                port is not None and (port.dynamic_target, port.dynamic_transport) != ("any", "any")
            )
        )
        if risky:
            flagged += 1
            assert isinstance(evidence_for_verdict(rule), IncompleteEvidence)
    assert flagged <= full_report.evidence.incomplete
    print(f"\n[SB-18] rules forced to incomplete evidence: {flagged}")


def test_full_scan_duration_is_measured_and_n04_reported(full_report: RuleScanReport) -> None:
    n04 = full_report.n04
    assert n04.status in (N04Status.MET, N04Status.EXCEEDED)
    assert n04.measured_s == pytest.approx(full_report.total_s)
    print(
        f"\n[measurement] full rule scan: total {full_report.total_s:.2f}s, "
        f"inventory {full_report.inventory_s:.2f}s, rules {len(full_report.result.data.rules)}, "
        f"evidence complete {full_report.evidence.complete} / incomplete "
        f"{full_report.evidence.incomplete}; {n04.describe()}"
    )


def test_inventory_only_is_fast_but_never_full_compliance() -> None:
    started = time.perf_counter()
    report = RuleScanService(WindowsFirewallRuleCollector()).scan(detail=False)
    elapsed = time.perf_counter() - started
    assert report.result.data is not None
    assert report.n04.status is N04Status.NOT_EVALUATED
    assert all(r.port.reason is NotCollectedReason.NOT_REQUESTED for r in report.result.data.rules)
    print(f"\n[measurement] inventory-only scan: {elapsed:.2f}s (not an N-04 measurement)")


def test_rule_ids_stable_across_scans() -> None:
    first = RuleScanService(WindowsFirewallRuleCollector()).scan(detail=False)
    second = RuleScanService(WindowsFirewallRuleCollector()).scan(detail=False)
    assert first.result.data is not None and second.result.data is not None
    assert {r.id for r in first.result.data.rules} == {r.id for r in second.result.data.rules}
