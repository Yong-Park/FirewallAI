"""UI smoke tests with the fixture collector (no system access)."""

import json
import threading
from pathlib import Path

import pytest
from PySide6.QtCore import Qt
from pytestqt.qtbot import QtBot

from firewallai.app.profile_service import ProfileService
from firewallai.collectors.fake.firewall_profiles import FixtureFirewallProfileCollector
from firewallai.collectors.protocols import ProfilesResult
from firewallai.ui.main_window import STATUS_LOADING, MainWindow
from firewallai.ui.profiles_model import COLUMNS


class _ThreadRecordingCollector(FixtureFirewallProfileCollector):
    def __init__(self, path: Path, delay_s: float) -> None:
        super().__init__(json.loads(path.read_text(encoding="utf-8")), delay_s=delay_s)
        self.thread_ids: list[int] = []

    def collect_profiles(self) -> ProfilesResult:
        self.thread_ids.append(threading.get_ident())
        return super().collect_profiles()


def _window(
    qtbot: QtBot, fixture: Path, delay_s: float = 0.0
) -> tuple[MainWindow, _ThreadRecordingCollector]:
    collector = _ThreadRecordingCollector(fixture, delay_s)
    window = MainWindow(ProfileService(collector, elevation_check=lambda: False))
    qtbot.addWidget(window)
    return window, collector


def test_profiles_load_into_table(qtbot: QtBot, fixtures_dir: Path) -> None:
    window, _ = _window(qtbot, fixtures_dir / "profiles" / "win11_default.json")
    window.refresh()
    qtbot.waitUntil(lambda: not window.is_loading, timeout=5000)
    assert window.model.rowCount() == 3
    assert window.model.columnCount() == len(COLUMNS)
    assert window.model.data(window.model.index(2, 0)) == "Public"
    assert window.model.data(window.model.index(2, 2)) == "Block"
    assert "Read-only" in window.notice.text()
    assert window.limitations.text() == ""


def test_collection_runs_off_gui_thread_and_ui_stays_responsive(
    qtbot: QtBot, fixtures_dir: Path
) -> None:
    window, collector = _window(qtbot, fixtures_dir / "profiles" / "win11_default.json", 0.5)
    window.refresh()
    # refresh() returned immediately: still loading, button disabled, GUI thread free.
    assert window.is_loading
    assert not window.refresh_button.isEnabled()
    assert window.statusBar().currentMessage() == STATUS_LOADING
    window.refresh()  # re-entrant clicks are ignored while loading
    qtbot.waitUntil(lambda: not window.is_loading, timeout=5000)
    assert collector.thread_ids
    assert threading.get_ident() not in collector.thread_ids
    assert len(collector.thread_ids) == 1
    assert window.refresh_button.isEnabled()


def test_partial_results_show_limitations(qtbot: QtBot, fixtures_dir: Path) -> None:
    window, _ = _window(qtbot, fixtures_dir / "profiles" / "invalid_values.json")
    window.refresh()
    qtbot.waitUntil(lambda: not window.is_loading, timeout=5000)
    assert window.model.rowCount() == 1
    assert "Limitations" in window.limitations.text()
    assert "Partial data" in window.statusBar().currentMessage()


@pytest.mark.parametrize("column", range(len(COLUMNS)))
def test_headers_are_text(qtbot: QtBot, fixtures_dir: Path, column: int) -> None:
    window, _ = _window(qtbot, fixtures_dir / "profiles" / "win11_default.json")
    header = window.model.headerData(column, Qt.Orientation.Horizontal)
    assert isinstance(header, str)
    assert header
