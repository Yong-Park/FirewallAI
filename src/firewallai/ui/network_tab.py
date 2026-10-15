"""Network tab (M1.4): local listening/bound sockets and TCP connections, with owning processes.

Collection, display-row building, rule indexing, and correlation all run in QThreadPool workers;
the GUI thread only swaps precomputed rows and texts. Related rules are descriptive (SB-20) and
use only a rule scan the user already ran in the Rules tab; no rule scan is started here.
"""

import threading

from PySide6.QtCore import QObject, QRunnable, Qt, QThreadPool, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSplitter,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from firewallai.app.endpoint_service import (
    EndpointScanReport,
    EndpointScanService,
    build_rule_index,
    summarize,
)
from firewallai.core.correlation import RuleIndex
from firewallai.core.endpoints import Endpoint, EndpointKind
from firewallai.core.rules import FirewallRule, RuleCollection
from firewallai.ui.network_model import (
    RULES_NOT_AVAILABLE_TEXT,
    EndpointRow,
    EndpointsTableModel,
    describe_correlation,
    rows_for_endpoints,
)

NETWORK_NOTICE = (
    "Read-only. Local socket facts only: this is not an exposure, reachability, or firewall "
    "assessment. A listening port is not a finding. Firewall profiles per interface are not "
    "mapped yet."
)
NETWORK_IDLE = "Endpoints not collected yet."
FILTERS: tuple[tuple[str, frozenset[EndpointKind]], ...] = (
    ("Listening TCP and bound UDP", frozenset({EndpointKind.LISTENING, EndpointKind.BOUND})),
    ("TCP connections", frozenset({EndpointKind.CONNECTION})),
    ("All endpoints", frozenset(EndpointKind)),
)
SELECT_PROMPT = "Select a listening or bound endpoint to see related firewall rules."


class EndpointScanSignals(QObject):
    finished = Signal(object, object)  # EndpointScanReport, tuple[EndpointRow, ...]
    failed = Signal(str)  # exception type name only


class EndpointScanTask(QRunnable):
    def __init__(
        self, service: EndpointScanService, signals: EndpointScanSignals, cancel: threading.Event
    ) -> None:
        super().__init__()
        self._service = service
        self._signals = signals
        self._cancel = cancel

    def run(self) -> None:
        try:
            report = self._service.scan(cancel=self._cancel)
            data = report.result.data
            rows = rows_for_endpoints(data.endpoints) if data is not None else ()
        except Exception as exc:  # surface any unexpected failure, type name only
            self._signals.failed.emit(type(exc).__name__)
            return
        self._signals.finished.emit(report, rows)


class CorrelationSignals(QObject):
    index_ready = Signal(object, int)  # RuleIndex, generation
    described = Signal(str, str, int)  # endpoint id, text, generation


class _BuildIndexTask(QRunnable):
    def __init__(self, collection: RuleCollection, signals: CorrelationSignals, gen: int) -> None:
        super().__init__()
        self._collection, self._signals, self._gen = collection, signals, gen

    def run(self) -> None:
        self._signals.index_ready.emit(build_rule_index(self._collection), self._gen)


class _CorrelateTask(QRunnable):
    def __init__(
        self,
        index: RuleIndex,
        endpoint: Endpoint,
        rules: dict[str, FirewallRule],
        signals: CorrelationSignals,
        gen: int,
    ) -> None:
        super().__init__()
        self._index, self._endpoint, self._rules = index, endpoint, rules
        self._signals, self._gen = signals, gen

    def run(self) -> None:
        text = describe_correlation(self._index.correlate(self._endpoint), self._rules)
        self._signals.described.emit(self._endpoint.id, text, self._gen)


class NetworkTab(QWidget):
    def __init__(self, service: EndpointScanService, *, pool: QThreadPool | None = None) -> None:
        super().__init__()
        self._service = service
        self._pool = pool if pool is not None else QThreadPool.globalInstance()
        self._signals = EndpointScanSignals()
        self._signals.finished.connect(self._on_finished)
        self._signals.failed.connect(self._on_failed)
        self._corr = CorrelationSignals()
        self._corr.index_ready.connect(self._on_index_ready)
        self._corr.described.connect(self._on_described)
        self._cancel = threading.Event()
        self._running = False
        self._endpoints: dict[str, Endpoint] = {}
        self._index: RuleIndex | None = None
        self._rules: dict[str, FirewallRule] = {}
        self._rules_pending = False
        self._rules_generation = 0  # invalidates a stale rule index build
        self._generation = 0  # invalidates stale per-endpoint descriptions

        self.notice = QLabel(NETWORK_NOTICE)
        self.notice.setWordWrap(True)
        self.notice.setAccessibleName("Network scope notice")
        self.collect_button = QPushButton("Collect &endpoints")
        self.collect_button.setAccessibleName("Collect local network endpoints")
        self.collect_button.clicked.connect(self.start)
        self.cancel_button = QPushButton("Ca&ncel")
        self.cancel_button.setAccessibleName("Cancel endpoint collection")
        self.cancel_button.setEnabled(False)
        self.cancel_button.clicked.connect(self.cancel)
        self.filter = QComboBox()
        self.filter.setAccessibleName("Endpoint filter")
        for label, _ in FILTERS:
            self.filter.addItem(label)
        self.filter.currentIndexChanged.connect(self._apply_filter)

        self.progress = QProgressBar()
        self.progress.setAccessibleName("Endpoint collection progress")
        self.progress.setRange(0, 1)
        self.phase = QLabel(NETWORK_IDLE)
        self.phase.setAccessibleName("Endpoint collection status")

        self.model = EndpointsTableModel()
        self.table = QTableView()
        self.table.setModel(self.model)
        self.table.setSortingEnabled(True)
        self.table.setAccessibleName("Local network endpoints")
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.table.verticalHeader().setVisible(False)
        self.table.selectionModel().currentRowChanged.connect(self._on_current_row)

        self.related = QPlainTextEdit()
        self.related.setReadOnly(True)
        self.related.setAccessibleName("Related firewall rules (descriptive only)")
        self.related.setPlainText(RULES_NOT_AVAILABLE_TEXT)

        self.timing = QLabel("")
        self.timing.setAccessibleName("Endpoint snapshot timing")
        self.limitations = QLabel("")
        self.limitations.setWordWrap(True)
        self.limitations.setAccessibleName("Endpoint snapshot limitations")
        self.limitations.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)

        top = QHBoxLayout()
        top.addWidget(self.notice, stretch=1)
        top.addWidget(self.filter)
        top.addWidget(self.collect_button)
        top.addWidget(self.cancel_button)
        bar = QHBoxLayout()
        bar.addWidget(self.phase, stretch=1)
        bar.addWidget(self.progress, stretch=1)
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(self.table)
        splitter.addWidget(self.related)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 1)
        layout = QVBoxLayout()
        layout.addLayout(top)
        layout.addLayout(bar)
        layout.addWidget(splitter, stretch=1)
        layout.addWidget(self.timing)
        layout.addWidget(self.limitations)
        self.setLayout(layout)
        self._apply_filter(0)

    # --- collection ------------------------------------------------------------------------------

    @property
    def is_running(self) -> bool:
        return self._running

    def start(self) -> None:
        if self._running:
            return  # single-flight: repeated clicks are ignored
        self._running = True
        self._cancel = threading.Event()
        self.collect_button.setEnabled(False)
        self.cancel_button.setEnabled(True)
        self.progress.setRange(0, 0)  # busy indicator
        self.phase.setText("Collecting local endpoints…")
        self.timing.setText("")
        self.limitations.setText("")
        self._pool.start(EndpointScanTask(self._service, self._signals, self._cancel))

    def cancel(self) -> None:
        if self._running:
            self._cancel.set()
            self.cancel_button.setEnabled(False)
            self.phase.setText("Cancelling…")

    def _finish(self) -> None:
        self._running = False
        self.collect_button.setEnabled(True)
        self.cancel_button.setEnabled(False)
        self.progress.setRange(0, 1)
        self.progress.setValue(1)

    def _on_finished(self, report: EndpointScanReport, rows: tuple[EndpointRow, ...]) -> None:
        data = report.result.data
        self._generation += 1
        self._endpoints = {} if data is None else {e.id: e for e in data.endpoints}
        self.model.set_rows(rows)
        self.related.setPlainText(
            SELECT_PROMPT if self._index is not None else RULES_NOT_AVAILABLE_TEXT
        )
        lines = [f"• {lim.code.value}: {lim.detail}" for lim in (data.limitations if data else ())]
        lines += [f"• {e.code.value}: {e.detail}" for e in report.result.errors[:10]]
        if report.elevated:
            lines.append("• Running elevated is not needed.")
        self.limitations.setText("Limitations:\n" + "\n".join(lines) if lines else "")
        self.timing.setText(report.target.describe())
        if data is None:
            self.phase.setText("Endpoint collection failed. See limitations.")
        else:
            s = summarize(data)
            prefix = "Partial snapshot" if report.result.partial else "Snapshot"
            self.phase.setText(
                f"{prefix}: {s['total']} endpoints (listening TCP {s['listening_tcp']}, "
                f"bound UDP {s['bound_udp']}, TCP connections {s['tcp_connections']}). "
                "Local socket facts only."
            )
        self._finish()

    def _on_failed(self, error_type: str) -> None:
        self.limitations.setText(f"Limitations:\n• Unexpected error: {error_type}")
        self.phase.setText("Endpoint collection failed. See limitations.")
        self._finish()

    def _apply_filter(self, index: int) -> None:
        kinds = FILTERS[index][1]
        self.model.set_filter(lambda row: row.kind in kinds)

    # --- descriptive correlation -----------------------------------------------------------------

    @property
    def has_rule_index(self) -> bool:
        return self._index is not None

    @property
    def rule_index_pending(self) -> bool:
        return self._rules_pending

    def set_rule_collection(self, collection: RuleCollection | None) -> None:
        """Use a rule scan the user already ran (never starts one). Indexing runs on a worker."""
        self._rules_generation += 1
        self._generation += 1
        self._index = None
        self._rules = {}
        if collection is None:
            self._rules_pending = False
            self.related.setPlainText(RULES_NOT_AVAILABLE_TEXT)
            return
        self._rules_pending = True
        self._rules = {r.id: r for r in collection.rules}
        self.related.setPlainText("Preparing collected firewall rules…")
        self._pool.start(_BuildIndexTask(collection, self._corr, self._rules_generation))

    def _on_index_ready(self, index: RuleIndex, generation: int) -> None:
        if generation != self._rules_generation:
            return
        self._index = index
        self._rules_pending = False
        self.related.setPlainText(SELECT_PROMPT)
        self._describe_current()

    def _on_current_row(self, *_args: object) -> None:
        self._generation += 1
        self._describe_current()

    def _describe_current(self) -> None:
        current = self.table.currentIndex()
        if not current.isValid():
            return
        endpoint = self._endpoints.get(self.model.row_key(current.row()))
        if endpoint is None:
            return
        if self._index is None:
            if not self._rules_pending:
                self.related.setPlainText(RULES_NOT_AVAILABLE_TEXT)
            return
        self.related.setPlainText("Describing related firewall rules…")
        self._pool.start(
            _CorrelateTask(self._index, endpoint, self._rules, self._corr, self._generation)
        )

    def _on_described(self, endpoint_id: str, text: str, generation: int) -> None:
        if generation == self._generation:
            self.related.setPlainText(text)
