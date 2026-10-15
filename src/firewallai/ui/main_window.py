"""Main window: Profiles (M1.1), optional Rules (M1.3) and Network (M1.4) tabs. Read-only."""

from PySide6.QtCore import Qt, QThreadPool
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMainWindow,
    QPushButton,
    QTableView,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from firewallai.app.endpoint_service import EndpointScanService
from firewallai.app.profile_service import SCOPE_NOTE, ProfileReport, ProfileService
from firewallai.app.rule_service import RuleScanService
from firewallai.ui.network_tab import NetworkTab
from firewallai.ui.profiles_model import ProfilesTableModel
from firewallai.ui.rules_tab import RulesTab
from firewallai.ui.worker import ProfileLoadSignals, ProfileLoadTask

STATUS_IDLE = "Ready."
STATUS_LOADING = "Collecting firewall profiles…"


class MainWindow(QMainWindow):
    def __init__(
        self,
        service: ProfileService,
        *,
        rule_service: RuleScanService | None = None,
        endpoint_service: EndpointScanService | None = None,
        pool: QThreadPool | None = None,
    ) -> None:
        super().__init__()
        self._service = service
        self._pool = pool if pool is not None else QThreadPool.globalInstance()
        self._signals = ProfileLoadSignals()
        self._signals.finished.connect(self._on_finished)
        self._signals.failed.connect(self._on_failed)
        self._loading = False

        self.setWindowTitle("FirewallAI (read-only)")
        self.resize(1100, 520)

        self.notice = QLabel(SCOPE_NOTE)
        self.notice.setWordWrap(True)
        self.notice.setAccessibleName("Scope notice")

        self.refresh_button = QPushButton("&Refresh")
        self.refresh_button.setAccessibleName("Refresh firewall profiles")
        self.refresh_button.clicked.connect(self.refresh)

        self.model = ProfilesTableModel()
        self.table = QTableView()
        self.table.setModel(self.model)
        self.table.setAccessibleName("Firewall profiles")
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.table.verticalHeader().setVisible(False)

        self.limitations = QLabel("")
        self.limitations.setWordWrap(True)
        self.limitations.setAccessibleName("Limitations")
        self.limitations.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)

        top = QHBoxLayout()
        top.addWidget(self.notice, stretch=1)
        top.addWidget(self.refresh_button)
        layout = QVBoxLayout()
        layout.addLayout(top)
        layout.addWidget(self.table, stretch=1)
        layout.addWidget(self.limitations)
        profiles_page = QWidget()
        profiles_page.setLayout(layout)
        self.tabs = QTabWidget()
        self.tabs.setAccessibleName("FirewallAI views")
        self.tabs.addTab(profiles_page, "&Profiles")
        self.rules_tab: RulesTab | None = None
        if rule_service is not None:
            self.rules_tab = RulesTab(rule_service, pool=self._pool)
            self.tabs.addTab(self.rules_tab, "R&ules")
        self.network_tab: NetworkTab | None = None
        if endpoint_service is not None:
            self.network_tab = NetworkTab(endpoint_service, pool=self._pool)
            self.tabs.addTab(self.network_tab, "&Network")
            if self.rules_tab is not None:
                self.rules_tab.collection_ready.connect(self.network_tab.set_rule_collection)
        self.setCentralWidget(self.tabs)
        self.statusBar().showMessage(STATUS_IDLE)

    @property
    def is_loading(self) -> bool:
        return self._loading

    def refresh(self) -> None:
        if self._loading:
            return
        self._loading = True
        self.refresh_button.setEnabled(False)
        self.statusBar().showMessage(STATUS_LOADING)
        self._pool.start(ProfileLoadTask(self._service, self._signals))

    def _done(self, message: str) -> None:
        self._loading = False
        self.refresh_button.setEnabled(True)
        self.statusBar().showMessage(message)

    def _on_finished(self, report: ProfileReport) -> None:
        result = report.result
        self.model.set_profiles(result.data or ())
        lines = [f"• {e.code.value} ({e.source}): {e.detail}" for e in result.errors]
        if report.elevated:
            lines.append(
                "• Running elevated is not needed; FirewallAI is designed for standard users."
            )
        self.limitations.setText("Limitations:\n" + "\n".join(lines) if lines else "")
        if result.data is None:
            status = "Collection failed. See limitations."
        elif result.partial:
            status = f"Partial data: {len(result.data)} profile(s). See limitations."
        else:
            status = f"Loaded {len(result.data)} profile(s) from {report.source_id}."
        self._done(status)

    def _on_failed(self, error_type: str) -> None:
        self.limitations.setText(f"Limitations:\n• Unexpected error: {error_type}")
        self._done("Collection failed. See limitations.")
