"""Rules tab UI tests (fixture collector with delays; no system access)."""

import gc
import itertools
import json
import threading
import time
from pathlib import Path
from typing import Any

from PySide6.QtCore import Qt, QTimer
from pytestqt.qtbot import QtBot

from firewallai.app.profile_service import ProfileService
from firewallai.app.rule_service import RuleScanService
from firewallai.collectors.fake.firewall_profiles import FixtureFirewallProfileCollector
from firewallai.collectors.fake.firewall_rules import FixtureFirewallRuleCollector
from firewallai.collectors.protocols import RulesResult
from firewallai.ui.app import prepare_gc_for_gui
from firewallai.ui.main_window import MainWindow
from firewallai.ui.rules_model import COLUMNS, rows_for
from firewallai.ui.rules_tab import RulesTab
from rule_builders import complete_fixture


class ThreadRecording(FixtureFirewallRuleCollector):
    def __init__(self, fixture: Any, **kw: Any) -> None:
        super().__init__(fixture, **kw)
        self.thread_ids: list[int] = []

    def collect_rules(self, **kw: Any) -> RulesResult:
        self.thread_ids.append(threading.get_ident())
        return super().collect_rules(**kw)


def _tab(qtbot: QtBot, fixture: dict[str, Any], **kw: Any) -> tuple[RulesTab, ThreadRecording]:
    collector = ThreadRecording(fixture, **kw)
    tab = RulesTab(RuleScanService(collector, elevation_check=lambda: False))
    qtbot.addWidget(tab)
    return tab, collector


def _col(name: str) -> int:
    return COLUMNS.index(name)


def test_inventory_rows_appear_before_details_with_pending_state(qtbot: QtBot) -> None:
    tab, _ = _tab(qtbot, complete_fixture(n=4, chunk=2), delay_s=0.3)
    tab.start()
    qtbot.waitUntil(lambda: tab.model.rowCount() == 4, timeout=5000)
    assert tab.is_running
    pending = [tab.model.data(tab.model.index(r, _col("Protocol"))) for r in range(4)]
    assert "Pending…" in pending  # details not yet collected: never shown as a value or "Any"
    qtbot.waitUntil(lambda: not tab.is_running, timeout=10000)
    assert all(tab.model.data(tab.model.index(r, _col("Evidence"))) == "Complete" for r in range(4))
    assert tab.progress.value() == tab.progress.maximum()
    assert "No verdicts" in tab.phase.text()


def test_gui_stays_responsive_and_collection_is_off_gui_thread(qtbot: QtBot) -> None:
    tab, collector = _tab(qtbot, complete_fixture(n=8, chunk=2), delay_s=0.25)
    ticks: list[float] = []
    timer = QTimer()
    timer.setInterval(20)
    timer.timeout.connect(lambda: ticks.append(time.perf_counter()))
    timer.start()
    tab.start()
    tab.start()  # re-entrant click ignored (single-flight)
    qtbot.waitUntil(lambda: not tab.is_running, timeout=15000)
    timer.stop()
    gaps = [b - a for a, b in itertools.pairwise(ticks)]
    assert len(ticks) > 20
    assert max(gaps) < 0.1, f"GUI blocked for {max(gaps):.3f}s"
    assert len(collector.thread_ids) == 1
    assert threading.get_ident() not in collector.thread_ids


def test_gui_thread_work_per_update_is_small_at_scale(qtbot: QtBot) -> None:
    """Direct regression (M1.3): with ~1,600 real rules, GUI-thread slots took 250-350 ms when
    display texts were computed/proxy-sorted on the GUI thread. Rows are now precomputed on the
    worker; the GUI-thread handling of a 2,000-rule inventory must stay well under 100 ms."""
    tab, _ = _tab(qtbot, complete_fixture(n=2000, chunk=100))
    tab.table.sortByColumn(0, Qt.SortOrder.AscendingOrder)
    collection = FixtureFirewallRuleCollector(complete_fixture(n=2000, chunk=100)).collect_rules()
    assert collection.data is not None
    rows = rows_for(collection.data.rules)  # worker-side work, not timed
    started = time.perf_counter()
    tab._on_inventory(rows)
    tab._on_progress(100, 2000, rows[:100])
    elapsed = time.perf_counter() - started
    assert tab.model.rowCount() == 2000
    assert elapsed < 0.05, f"GUI-thread slots took {elapsed * 1000:.0f} ms"


def test_gui_stays_responsive_at_realistic_scale(qtbot: QtBot) -> None:
    """2,000 synthetic rules at a realistic cadence (0.2 s per 100-rule chunk; real collection
    on TE-1 is about 1.6 s per chunk): heartbeat gaps stay under 100 ms. A fully CPU-saturated
    synthetic stream (0.02 s per chunk) measured 93-126 ms (GIL + GC contention); recorded as
    a limitation in HANDOFF, not hidden."""
    tab, _ = _tab(qtbot, complete_fixture(n=2000, chunk=100), delay_s=0.2)
    prepare_gc_for_gui()  # same startup step as the real GUI entry point (ui.app.main)
    try:
        tab.table.sortByColumn(0, Qt.SortOrder.AscendingOrder)  # sorting active, like a user
        ticks: list[float] = []
        timer = QTimer()
        timer.setInterval(20)
        timer.timeout.connect(lambda: ticks.append(time.perf_counter()))
        timer.start()
        tab.start()
        qtbot.waitUntil(lambda: not tab.is_running, timeout=60000)
        qtbot.wait(100)
        timer.stop()
    finally:
        gc.unfreeze()  # don't leak the frozen test-process heap into later tests
    gaps = [b - a for a, b in itertools.pairwise(ticks)]
    assert tab.model.rowCount() == 2000
    assert max(gaps) < 0.1, f"GUI blocked for {max(gaps):.3f}s at 2,000 rules"


def test_sorting_uses_precomputed_keys(qtbot: QtBot) -> None:
    tab, _ = _tab(qtbot, complete_fixture(n=5, chunk=5))
    tab.start()
    qtbot.waitUntil(lambda: not tab.is_running, timeout=5000)
    tab.model.sort(0, Qt.SortOrder.DescendingOrder)
    names = [tab.model.data(tab.model.index(r, 0)) for r in range(5)]
    assert names == sorted(names, reverse=True)
    rid = tab.model.row_id(0)
    assert rid.startswith("fw_rule:h1-")


def test_progress_increases(qtbot: QtBot) -> None:
    tab, _ = _tab(qtbot, complete_fixture(n=6, chunk=2), delay_s=0.2)
    seen: list[int] = []
    tab.progress.valueChanged.connect(seen.append)
    tab.start()
    qtbot.waitUntil(lambda: not tab.is_running, timeout=10000)
    assert seen == sorted(seen) and seen[-1] == 6
    assert len(set(seen)) >= 3


def test_cancel_leaves_incomplete_state(qtbot: QtBot) -> None:
    tab, _ = _tab(qtbot, complete_fixture(n=10, chunk=1), delay_s=0.3)
    tab.start()
    qtbot.waitUntil(lambda: tab.model.rowCount() == 10, timeout=5000)
    tab.cancel()
    qtbot.waitUntil(lambda: not tab.is_running, timeout=10000)
    assert "Incomplete" in tab.phase.text()
    assert "detail_incomplete" in tab.limitations.text()
    assert "not evaluated" in tab.timing.text()
    evidence = {tab.model.data(tab.model.index(r, _col("Evidence"))) for r in range(10)}
    assert any(e.startswith("Incomplete") for e in evidence)


def test_limitations_and_n04_text_shown(qtbot: QtBot) -> None:
    tab, _ = _tab(qtbot, complete_fixture(n=2, chunk=2))
    tab.start()
    qtbot.waitUntil(lambda: not tab.is_running, timeout=5000)
    assert "local_policy_only" in tab.limitations.text()
    assert "wfp_filters_not_observable" in tab.limitations.text()
    assert "N-04" in tab.timing.text()


def test_main_window_has_profiles_and_rules_tabs(qtbot: QtBot, fixtures_dir: Path) -> None:
    payload = json.loads((fixtures_dir / "profiles" / "win11_default.json").read_text("utf-8"))
    window = MainWindow(
        ProfileService(FixtureFirewallProfileCollector(payload), elevation_check=lambda: False),
        rule_service=RuleScanService(
            FixtureFirewallRuleCollector(complete_fixture()), elevation_check=lambda: False
        ),
    )
    qtbot.addWidget(window)
    assert window.tabs.count() == 2
    assert window.rules_tab is not None
    window.refresh()  # profiles still work
    qtbot.waitUntil(lambda: not window.is_loading, timeout=5000)
    assert window.model.rowCount() == 3
