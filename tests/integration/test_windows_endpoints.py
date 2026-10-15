"""Read-only, non-elevated integration tests against the real socket tables (M1.4).

The end-to-end snapshot duration is MEASURED and printed with the M1.4 target status. It is not
asserted against the 1 s target (machine-dependent); correctness and explicit states are asserted.
Only counts and timings are printed: no addresses, names, or paths.
"""

from collections import Counter

import pytest

from firewallai.app.endpoint_service import (
    EndpointScanReport,
    EndpointScanService,
    TargetStatus,
    build_rule_index,
)
from firewallai.app.rule_service import RuleScanService
from firewallai.collectors.windows.firewall_rules import WindowsFirewallRuleCollector
from firewallai.collectors.windows.network_endpoints import WindowsEndpointCollector
from firewallai.collectors.windows.privilege import is_elevated
from firewallai.core.correlation import CorrelationStatus, RelationStatus
from firewallai.core.endpoints import (
    Availability,
    EndpointKind,
    TcpState,
    TransportProtocol,
)

pytestmark = [pytest.mark.windows, pytest.mark.integration]


@pytest.fixture(scope="module")
def reports() -> list[EndpointScanReport]:
    assert is_elevated() is False, "must run as a standard user (SB-02)"
    service = EndpointScanService(WindowsEndpointCollector())
    return [service.scan() for _ in range(3)]


def test_snapshot_is_complete_and_explicit(reports: list[EndpointScanReport]) -> None:
    report = reports[-1]
    assert report.result.ok, report.result.errors
    data = report.result.data
    assert data is not None and data.services_collected and data.process_lookup_complete
    kinds = Counter((e.protocol, e.kind) for e in data.endpoints)
    assert kinds[(TransportProtocol.TCP, EndpointKind.LISTENING)] > 0
    assert kinds[(TransportProtocol.UDP, EndpointKind.BOUND)] > 0
    for ep in data.endpoints:
        if ep.protocol is TransportProtocol.UDP:
            assert ep.kind is EndpointKind.BOUND and ep.tcp_state is None
        else:
            assert ep.tcp_state is not None
            assert (ep.kind is EndpointKind.LISTENING) == (ep.tcp_state is TcpState.LISTEN)
        p = ep.process
        if p.attribution is Availability.UNAVAILABLE:
            assert p.reason is not None and not p.name.is_collected  # explicit, no details
        else:
            for obs in (p.name, p.image_path, p.services):
                assert obs.is_collected or obs.reason is not None  # never a silent blank
    attribution = Counter(
        "attributed" if e.process.reason is None else e.process.reason.value for e in data.endpoints
    )
    print(
        f"\n[measurement] endpoints {len(data.endpoints)}: "
        f"{dict(Counter(e.kind.value for e in data.endpoints))}; "
        f"families {dict(Counter(e.family.value for e in data.endpoints))}; "
        f"process attribution {dict(attribution)}"
    )


def test_end_to_end_duration_is_measured(reports: list[EndpointScanReport]) -> None:
    for i, report in enumerate(reports):
        data = report.result.data
        assert data is not None
        assert report.target.status in (TargetStatus.MET, TargetStatus.EXCEEDED)
        t = data.timings
        print(
            f"\n[measurement] endpoint snapshot run {i + 1}: total {report.total_s:.3f} s "
            f"(sockets {t.sockets_s:.3f} s, processes {t.processes_s:.3f} s, services "
            f"{t.services_s if t.services_s is None else round(t.services_s, 3)} s, parallel); "
            f"{report.target.describe()}"
        )


def test_live_correlation_is_descriptive_only() -> None:
    """Uses a real rule scan (read-only, ~30 s) and a real snapshot. Counts only."""
    rules = RuleScanService(WindowsFirewallRuleCollector()).scan().result.data
    assert rules is not None
    snapshot = EndpointScanService(WindowsEndpointCollector()).scan().result.data
    assert snapshot is not None
    index = build_rule_index(rules)
    statuses: Counter[str] = Counter()
    relations: Counter[str] = Counter()
    for ep in snapshot.endpoints:
        corr = index.correlate(ep)
        statuses[corr.status.value] += 1
        if ep.kind is EndpointKind.CONNECTION:
            assert corr.status is CorrelationStatus.NOT_APPLICABLE
        for rel in corr.related:
            assert rel.status is RelationStatus.RELATED and rel.conditions == ()
            assert all(c.outcome.value == "match" for c in rel.checks)
            relations["related"] += 1
        for rel in corr.related_with_conditions:
            assert rel.status is RelationStatus.RELATED_WITH_UNEVALUATED_CONDITIONS
            assert rel.conditions and all(c.outcome.value == "match" for c in rel.checks)
            relations["related_with_unevaluated_conditions"] += 1
        relations["cannot_evaluate"] += len(corr.cannot_evaluate)
        relations["not_related"] += corr.not_related
    print(
        f"\n[measurement] live correlation: endpoints by status {dict(statuses)}; "
        f"relations {dict(relations)}; rule set complete {index.rule_set_complete}"
    )
