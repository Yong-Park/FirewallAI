"""Progressive rule collection through the shared driver (fixture collector, no system access).

Covers complete, partial, denied, malformed, timed-out, cancelled, inventory-only, and
unsupported-value cases.
"""

import threading
from typing import Any

import pytest

from firewallai.collectors.fake.firewall_rules import FixtureFirewallRuleCollector
from firewallai.collectors.windows import firewall_rules as win_rules
from firewallai.collectors.windows.powershell_runner import RunOutcome
from firewallai.core.evidence import (
    CompleteRuleEvidence,
    IncompleteEvidence,
    evidence_for_verdict,
)
from firewallai.core.results import CollectorError, CollectorErrorCode
from firewallai.core.rules import (
    DETAIL_FILTERS,
    FilterState,
    FirewallRule,
    NotCollectedReason,
    PolicySourceType,
    ScanLimitationCode,
    TokenKind,
)
from rule_builders import address, complete_fixture, detail, inventory, port, raw_rule


class Recorder:
    def __init__(self) -> None:
        self.calls: list[tuple[str, int]] = []

    def inventory_ready(self, rules: tuple[FirewallRule, ...]) -> None:
        self.calls.append(("inventory", len(rules)))

    def detail_progress(self, done: int, total: int, updated: tuple[FirewallRule, ...]) -> None:
        self.calls.append(("detail", done))


def _collect(fixture: dict[str, Any], **kw: Any) -> Any:
    return FixtureFirewallRuleCollector(fixture, **kw)


def _limit_codes(result: Any) -> set[ScanLimitationCode]:
    return {lim.code for lim in result.data.limitations}


# --- complete -----------------------------------------------------------------------------------


def test_complete_collection_has_explicit_complete_evidence() -> None:
    rec = Recorder()
    result = _collect(complete_fixture(n=4, chunk=2)).collect_rules(observer=rec)
    assert result.ok
    data = result.data
    assert data.detail_complete and data.total_in_source == 4 and len(data.rules) == 4
    assert rec.calls == [("inventory", 4), ("detail", 2), ("detail", 4)]  # inventory first
    for rule in data.rules:
        assert all(getattr(rule, f).state is FilterState.COLLECTED for f in DETAIL_FILTERS)
        assert isinstance(evidence_for_verdict(rule), CompleteRuleEvidence)
    assert ScanLimitationCode.LOCAL_POLICY_ONLY in _limit_codes(result)
    assert ScanLimitationCode.WFP_FILTERS_NOT_OBSERVABLE in _limit_codes(result)
    assert ScanLimitationCode.SERVICE_HARDENING_NOT_EVALUATED in _limit_codes(result)


def test_ids_are_unique_and_order_preserved() -> None:
    result = _collect(complete_fixture(n=6, chunk=4)).collect_rules()
    ids = [r.id for r in result.data.rules]
    assert len(set(ids)) == 6
    assert [r.instance_id for r in result.data.rules] == [f"Rule-{i}" for i in range(6)]


# --- partial / denied / missing ----------------------------------------------------------------


def test_missing_detail_and_denied_filter_are_explicit_never_any() -> None:
    ids = ["A", "B", "C"]
    events = [
        inventory([raw_rule(i) for i in ids]),
        detail(
            ids,
            done=3,
            total=3,
            ports=[port("A")],  # B: denied (error), C: missing (no entry, no error)
            errors=[
                {"kind": "port", "target": "B", "category": "PermissionDenied", "error_id": "E5"}
            ],
        ),
    ]
    result = _collect({"events": events}).collect_rules()
    assert result.partial
    rules = {r.instance_id: r for r in result.data.rules}
    assert rules["A"].port.state is FilterState.COLLECTED
    assert rules["B"].port.state is FilterState.UNREADABLE
    assert rules["B"].port.error.code is CollectorErrorCode.ACCESS_DENIED
    assert rules["C"].port.state is FilterState.NOT_COLLECTED
    assert rules["C"].port.reason is NotCollectedReason.MISSING_FROM_SOURCE
    for rid in ("B", "C"):
        assert rules[rid].port.value is None  # never defaulted to "Any"
        assert isinstance(evidence_for_verdict(rules[rid]), IncompleteEvidence)
    assert any("filter=port" in e.detail and "B" not in e.detail for e in result.errors)


def test_inventory_query_denied_fails_without_rules() -> None:
    fixture = {"events": [], "final_error": {"code": "access_denied", "detail": "denied"}}
    result = _collect(fixture).collect_rules()
    assert result.data is None
    assert result.errors[0].code is CollectorErrorCode.ACCESS_DENIED


def test_missing_bulk_filter_entry_is_not_collected() -> None:
    inv = inventory([raw_rule("A")])
    inv["apps"] = []
    result = _collect({"events": [inv, detail(["A"], done=1, total=1)]}).collect_rules()
    rule = result.data.rules[0]
    assert rule.application.reason is NotCollectedReason.MISSING_FROM_SOURCE
    assert isinstance(evidence_for_verdict(rule), IncompleteEvidence)


# --- timed out / cancelled / inventory-only ---------------------------------------------------


def test_timeout_during_detail_keeps_inventory_and_marks_rest() -> None:
    fixture = complete_fixture(n=4, chunk=2)
    result = _collect(fixture, fail_after_events=2).collect_rules()  # inventory + 1 chunk
    assert result.partial and result.data is not None
    assert not result.data.detail_complete
    assert ScanLimitationCode.DETAIL_INCOMPLETE in _limit_codes(result)
    reasons = [r.port.reason for r in result.data.rules if not r.port.is_collected]
    assert reasons == [NotCollectedReason.PHASE_FAILED] * 2
    assert any(e.code is CollectorErrorCode.TIMEOUT for e in result.errors)


def test_cancel_marks_pending_filters_cancelled() -> None:
    cancel = threading.Event()

    class CancelAfterInventory(Recorder):
        def inventory_ready(self, rules: tuple[FirewallRule, ...]) -> None:
            super().inventory_ready(rules)
            cancel.set()

    result = _collect(complete_fixture(n=4)).collect_rules(
        observer=CancelAfterInventory(), cancel=cancel
    )
    assert result.partial and not result.data.detail_complete
    assert all(r.port.reason is NotCollectedReason.CANCELLED for r in result.data.rules)
    assert any(e.code is CollectorErrorCode.CANCELLED for e in result.errors)


def test_inventory_only_marks_detail_not_requested() -> None:
    result = _collect(complete_fixture(n=3)).collect_rules(detail=False)
    assert result.data is not None and not result.data.detail_requested
    assert ScanLimitationCode.DETAIL_NOT_COLLECTED in _limit_codes(result)
    for rule in result.data.rules:
        assert rule.port.reason is NotCollectedReason.NOT_REQUESTED
        assert isinstance(evidence_for_verdict(rule), IncompleteEvidence)


# --- malformed / unsupported ---------------------------------------------------------------------


def test_invalid_direction_excludes_rule_and_reports() -> None:
    events = [inventory([raw_rule("A"), raw_rule("B", direction="Sideways")])]
    events.append(detail(["A", "B"], done=2, total=2))
    result = _collect({"events": events}).collect_rules()
    assert [r.instance_id for r in result.data.rules] == ["A"]
    assert result.data.total_in_source == 2
    assert any("invalid fields=direction" in e.detail for e in result.errors)


def test_duplicate_raw_ids_excluded_not_merged() -> None:
    events = [inventory([raw_rule("A"), raw_rule("A"), raw_rule("B")])]
    events.append(detail(["A", "B"], done=2, total=2))
    result = _collect({"events": events}).collect_rules()
    assert [r.instance_id for r in result.data.rules] == ["B"]
    assert any("duplicate raw rule id" in e.detail for e in result.errors)


@pytest.mark.parametrize(
    "bad_event",
    [{"stage": "inventory", "rules": "nope"}, {"stage": "surprise"}, "text", [1, 2]],
)
def test_malformed_events_are_parse_errors(bad_event: Any) -> None:
    result = _collect({"events": [bad_event]}).collect_rules()
    assert result.data is None
    assert result.errors[0].code is CollectorErrorCode.PARSE_ERROR


def test_malformed_detail_after_inventory_keeps_inventory() -> None:
    fixture = complete_fixture(n=2, chunk=2)
    fixture["events"][1] = {"stage": "detail", "done": "x"}
    result = _collect(fixture).collect_rules()
    assert result.data is not None and not result.data.detail_complete
    assert any(e.code is CollectorErrorCode.PARSE_ERROR for e in result.errors)


def test_unknown_values_become_unknown_and_block_verdicts() -> None:
    ids = ["A", "B", "C", "D"]
    events = [
        inventory(
            [
                raw_rule("A", source_type="FutureStore"),
                raw_rule("B"),
                raw_rule("C", dynamic_keywords=["{kw-1}"]),
                raw_rule("D"),
            ]
        ),
        detail(
            ids,
            done=4,
            total=4,
            ports=[
                port("A"),
                port("B", local=["NewPortKeyword"]),
                port("C"),
                port("D", dynamic_target="ProximitySharing"),
            ],
            addresses=[address(i) for i in ids],
        ),
    ]
    result = _collect({"events": events}).collect_rules()
    rules = {r.instance_id: r for r in result.data.rules}
    assert rules["A"].policy_source_type is PolicySourceType.UNKNOWN
    assert rules["B"].port.value.local_ports[0].kind is TokenKind.UNKNOWN
    expected = {
        "A": "unknown_policy_source",
        "B": "unknown_value",
        "C": "dynamic_keyword_addresses",
        "D": "unsupported_dynamic_target",
    }
    for rid, reason in expected.items():
        ev = evidence_for_verdict(rules[rid])
        assert isinstance(ev, IncompleteEvidence), rid
        assert any(r.startswith(reason) for r in ev.reasons), (rid, ev.reasons)
    assert ScanLimitationCode.DYNAMIC_KEYWORDS_NOT_RESOLVED in _limit_codes(result)


def test_interface_alias_restriction_is_preserved() -> None:
    ids = ["A", "B"]
    events = [
        inventory([raw_rule(i) for i in ids]),
        detail(
            ids,
            done=2,
            total=2,
            ifaliases=[{"id": "A", "aliases": ["Any"]}, {"id": "B", "aliases": ["vSwitch X"]}],
        ),
    ]
    rules = {r.instance_id: r for r in _collect({"events": events}).collect_rules().data.rules}
    assert rules["A"].interface.value.any_interface is True
    assert rules["B"].interface.value.any_interface is False
    assert rules["B"].interface.value.aliases == ("vSwitch X",)


def test_unsupported_platform_and_busy(monkeypatch: pytest.MonkeyPatch) -> None:
    def no_ps(*_a: Any, **_k: Any) -> Any:
        raise win_rules.UnsupportedPlatformError("x")

    monkeypatch.setattr(win_rules, "PowerShellRunner", no_ps)
    result = win_rules.WindowsFirewallRuleCollector().collect_rules()
    assert result.errors[0].code is CollectorErrorCode.UNSUPPORTED_PLATFORM

    assert win_rules.HEAVY_QUERY_LOCK.acquire(blocking=False)
    try:
        busy = win_rules.WindowsFirewallRuleCollector().collect_rules()
    finally:
        win_rules.HEAVY_QUERY_LOCK.release()
    assert busy.errors[0].code is CollectorErrorCode.BUSY


class _BlockingRunner:
    """Fake runner whose stream blocks until released; records concurrent invocations."""

    def __init__(self) -> None:
        self.entered = threading.Event()
        self.release = threading.Event()
        self.active = 0
        self.max_active = 0
        self.calls = 0

    def run_stream(self, *_a: Any, **_k: Any) -> RunOutcome:
        self.calls += 1
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        self.entered.set()
        self.release.wait(timeout=10)
        self.active -= 1
        return RunOutcome(
            error=CollectorError(code=CollectorErrorCode.CANCELLED, source="t", detail="test")
        )


def test_concurrent_collections_never_run_heavy_queries_in_parallel() -> None:
    """SB-19: a second collection while one is running returns BUSY without touching
    PowerShell, including from a different collector instance on another thread."""
    runner = _BlockingRunner()
    first: list[Any] = []
    worker = threading.Thread(
        target=lambda: first.append(win_rules.WindowsFirewallRuleCollector(runner).collect_rules())
    )
    worker.start()
    try:
        assert runner.entered.wait(timeout=5)
        second = win_rules.WindowsFirewallRuleCollector(runner).collect_rules()
        assert second.errors[0].code is CollectorErrorCode.BUSY
        assert second.data is None
    finally:
        runner.release.set()
        worker.join(timeout=10)
    assert runner.calls == 1
    assert runner.max_active == 1
    assert first[0].errors[0].code is not CollectorErrorCode.BUSY
    third = win_rules.WindowsFirewallRuleCollector(runner).collect_rules()
    assert third.errors[0].code is not CollectorErrorCode.BUSY  # lock released afterwards
