"""Network tab UI tests (fixture collectors with delays; no system access)."""

import gc
import itertools
import threading
import time
from typing import Any

from PySide6.QtCore import Qt, QTimer
from pytestqt.qtbot import QtBot

from endpoint_builders import proc, snapshot, sock
from firewallai.app.endpoint_service import EndpointScanService
from firewallai.app.profile_service import ProfileService
from firewallai.app.rule_service import RuleScanService
from firewallai.collectors.fake.firewall_profiles import FixtureFirewallProfileCollector
from firewallai.collectors.fake.firewall_rules import FixtureFirewallRuleCollector
from firewallai.collectors.fake.network_endpoints import FixtureEndpointCollector
from firewallai.collectors.protocols import EndpointsResult
from firewallai.core.results import CollectorErrorCode
from firewallai.ui.app import prepare_gc_for_gui
from firewallai.ui.main_window import MainWindow
from firewallai.ui.network_model import COLUMNS, RULES_NOT_AVAILABLE_TEXT
from firewallai.ui.network_tab import NetworkTab
from rule_builders import complete_fixture

FORBIDDEN_CLAIMS = (
    "is reachable",
    "is exposed",
    "exposed to",
    "is allowed",
    "is blocked",
    "allows traffic",
    "blocks traffic",
    "open to the internet",
    "vulnerable",
)


class ThreadRecording(FixtureEndpointCollector):
    def __init__(self, fixture: Any, **kw: Any) -> None:
        super().__init__(fixture, **kw)
        self.thread_ids: list[int] = []

    def collect_endpoints(self, **kw: Any) -> EndpointsResult:
        self.thread_ids.append(threading.get_ident())
        return super().collect_endpoints(**kw)


def _small() -> dict[str, Any]:
    return snapshot(
        [
            sock(lport=443, pid=1000),
            sock("udp", "ipv6", "2001:db8::10", 5353, pid=1000),
            sock(lport=50000, raddr="198.51.100.7", rport=443, pid=1000),
        ],
        processes=[proc(1000, name="evil\u202eexe.txt")],
    )


def _large(n: int = 5000) -> dict[str, Any]:
    first = []
    for i in range(n):
        if i % 3 == 0:
            first.append(sock(lport=1024 + i % 60000, pid=1000 + i % 200))
        elif i % 3 == 1:
            first.append(sock("udp", lport=1024 + i % 60000, pid=1000 + i % 200))
        else:
            first.append(
                sock(lport=20000 + i % 40000, raddr="198.51.100.7", rport=443, pid=1000 + i % 200)
            )
    return snapshot(first)


def _tab(qtbot: QtBot, fixture: dict[str, Any], **kw: Any) -> tuple[NetworkTab, ThreadRecording]:
    collector = ThreadRecording(fixture, **kw)
    tab = NetworkTab(EndpointScanService(collector, elevation_check=lambda: False))
    qtbot.addWidget(tab)
    return tab, collector


def _texts(tab: NetworkTab) -> list[str]:
    return [
        tab.model.data(tab.model.index(r, c))
        for r in range(tab.model.rowCount())
        for c in range(len(COLUMNS))
    ]


def test_collects_off_gui_thread_and_defaults_to_listening_and_bound(qtbot: QtBot) -> None:
    tab, collector = _tab(qtbot, _small(), delay_s=0.2)
    tab.start()
    tab.start()  # re-entrant click ignored (single-flight)
    assert tab.is_running
    qtbot.waitUntil(lambda: not tab.is_running, timeout=5000)
    assert len(collector.thread_ids) == 1
    assert threading.get_ident() not in collector.thread_ids
    assert tab.model.rowCount() == 2  # the TCP connection is filtered out by default
    assert "Snapshot: 3 endpoints" in tab.phase.text()
    tab.filter.setCurrentIndex(1)
    assert tab.model.rowCount() == 1
    tab.filter.setCurrentIndex(2)
    assert tab.model.rowCount() == 3


def test_udp_shown_as_bound_and_process_name_escaped(qtbot: QtBot) -> None:
    tab, _ = _tab(qtbot, _small())
    tab.start()
    qtbot.waitUntil(lambda: not tab.is_running, timeout=5000)
    texts = _texts(tab)
    assert "Bound" in texts and "Listening" in texts
    assert not any("\u202e" in t for t in texts)
    assert any("\\u202e" in t for t in texts)


def test_cancel_and_failure_states(qtbot: QtBot) -> None:
    tab, _ = _tab(qtbot, _small(), delay_s=2.0)
    tab.start()
    tab.cancel()
    qtbot.waitUntil(lambda: not tab.is_running, timeout=5000)
    assert "failed" in tab.phase.text() and "cancelled" in tab.limitations.text()
    tab2, _ = _tab(qtbot, _small(), fail_code=CollectorErrorCode.ACCESS_DENIED)
    tab2.start()
    qtbot.waitUntil(lambda: not tab2.is_running, timeout=5000)
    assert "access_denied" in tab2.limitations.text()
    assert "not evaluated" in tab2.timing.text()


def test_unexpected_exception_is_reported_by_type_only(qtbot: QtBot) -> None:
    class Boom(FixtureEndpointCollector):
        def collect_endpoints(self, **kw: Any) -> EndpointsResult:
            raise RuntimeError("secret detail C:\\Users\\someone")

    tab = NetworkTab(EndpointScanService(Boom(_small()), elevation_check=lambda: False))
    qtbot.addWidget(tab)
    tab.start()
    qtbot.waitUntil(lambda: not tab.is_running, timeout=5000)
    assert "RuntimeError" in tab.limitations.text()
    assert "someone" not in tab.limitations.text()


def _select_first(tab: NetworkTab, qtbot: QtBot) -> None:
    tab.table.setCurrentIndex(tab.model.index(0, 0))


def test_related_rules_need_a_prior_rule_scan_and_never_start_one(qtbot: QtBot) -> None:
    class CountingRules(FixtureFirewallRuleCollector):
        calls = 0

        def collect_rules(self, **kw: Any) -> Any:
            CountingRules.calls += 1
            return super().collect_rules(**kw)

    window = MainWindow(
        ProfileService(FixtureFirewallProfileCollector({"profiles": []})),
        rule_service=RuleScanService(
            CountingRules(complete_fixture(n=2)), elevation_check=lambda: False
        ),
        endpoint_service=EndpointScanService(
            FixtureEndpointCollector(_small()), elevation_check=lambda: False
        ),
    )
    qtbot.addWidget(window)
    tab = window.network_tab
    assert tab is not None
    tab.start()
    qtbot.waitUntil(lambda: not tab.is_running, timeout=5000)
    _select_first(tab, qtbot)
    qtbot.wait(100)
    assert tab.related.toPlainText() == RULES_NOT_AVAILABLE_TEXT
    assert CountingRules.calls == 0  # no rule scan was started automatically

    assert window.rules_tab is not None
    window.rules_tab.start()  # the user runs the rule scan explicitly
    qtbot.waitUntil(lambda: tab.has_rule_index, timeout=10000)
    assert CountingRules.calls == 1
    tab.filter.setCurrentIndex(2)
    tab.table.setCurrentIndex(tab.model.index(0, 0))
    qtbot.waitUntil(lambda: "Related (" in tab.related.toPlainText(), timeout=5000)
    text = tab.related.toPlainText()
    assert "descriptive only" in text and "Not related:" in text


def test_related_rules_text_for_listener_and_connection(qtbot: QtBot) -> None:
    rules = FixtureFirewallRuleCollector(complete_fixture(n=4, chunk=4)).collect_rules().data
    assert rules is not None
    tab, _ = _tab(qtbot, _small())
    tab.set_rule_collection(rules)
    qtbot.waitUntil(lambda: tab.has_rule_index, timeout=5000)
    tab.start()
    qtbot.waitUntil(lambda: not tab.is_running, timeout=5000)
    tab.filter.setCurrentIndex(2)
    tab.table.sortByColumn(COLUMNS.index("Local port"), Qt.SortOrder.AscendingOrder)
    # rows sorted by local port: 443 (TCP listener), 5353 (UDP), 50000 (connection)
    tab.table.setCurrentIndex(tab.model.index(0, 0))
    qtbot.waitUntil(lambda: "Related (4)" in tab.related.toPlainText(), timeout=5000)
    listener_text = tab.related.toPlainText()
    tab.table.setCurrentIndex(tab.model.index(2, 0))
    qtbot.waitUntil(lambda: "not correlated" in tab.related.toPlainText(), timeout=5000)
    blob = (listener_text + tab.related.toPlainText() + tab.notice.text()).lower()
    for claim in FORBIDDEN_CLAIMS:
        assert claim not in blob, claim


def test_clearing_rules_returns_to_not_available(qtbot: QtBot) -> None:
    rules = FixtureFirewallRuleCollector(complete_fixture(n=2)).collect_rules().data
    tab, _ = _tab(qtbot, _small())
    tab.set_rule_collection(rules)
    tab.set_rule_collection(None)
    qtbot.wait(200)
    assert not tab.has_rule_index and tab.related.toPlainText() == RULES_NOT_AVAILABLE_TEXT


def test_gui_stays_responsive_at_realistic_scale(qtbot: QtBot) -> None:
    """5,000 synthetic endpoints and a 2,000-rule index: heartbeat gaps stay under 100 ms while
    collecting, filtering, sorting, and describing related rules for selected endpoints."""
    rules = FixtureFirewallRuleCollector(complete_fixture(n=2000, chunk=100)).collect_rules().data
    tab, _ = _tab(qtbot, _large(), delay_s=0.2)
    prepare_gc_for_gui()
    try:
        ticks: list[float] = []
        timer = QTimer()
        timer.setInterval(20)
        timer.timeout.connect(lambda: ticks.append(time.perf_counter()))
        timer.start()
        tab.set_rule_collection(rules)
        tab.start()
        qtbot.waitUntil(lambda: not tab.is_running and tab.has_rule_index, timeout=30000)
        tab.table.sortByColumn(COLUMNS.index("Local port"), Qt.SortOrder.DescendingOrder)
        for f in (2, 1, 0):
            tab.filter.setCurrentIndex(f)
            qtbot.wait(50)
        for row in range(5):
            tab.table.setCurrentIndex(tab.model.index(row, 0))
            qtbot.waitUntil(lambda: "Related (" in tab.related.toPlainText(), timeout=10000)
        qtbot.wait(100)
        timer.stop()
    finally:
        gc.unfreeze()
    gaps = [b - a for a, b in itertools.pairwise(ticks)]
    assert tab.model.rowCount() > 3000
    print(f"\n[measurement] network tab max GUI gap: {max(gaps) * 1000:.0f} ms")
    assert max(gaps) < 0.1, f"GUI blocked for {max(gaps) * 1000:.0f} ms"
