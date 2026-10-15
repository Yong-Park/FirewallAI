"""Rules tab: progressive collection with progress, cancellation, limitations, and N-04 timing.

Collection runs in a QThreadPool worker. Observer callbacks run on that worker thread and are
forwarded to the GUI thread through Qt signals (queued connections), so the GUI never blocks.
No security verdicts are shown.
"""

import threading

from PySide6.QtCore import QObject, QRunnable, Qt, QThreadPool, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QProgressBar,
    QPushButton,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from firewallai.app.rule_service import N04Status, RuleScanReport, RuleScanService
from firewallai.core.rules import FirewallRule
from firewallai.ui.rules_model import RuleRow, RulesTableModel, rows_for

RULES_IDLE = "Rules not collected yet."
RULES_NOTICE = (
    "Read-only. Shows local Windows Firewall rules only. Collection takes tens of seconds; "
    "no security verdicts are made, and incomplete evidence is marked."
)


class RuleScanSignals(QObject):
    inventory = Signal(object)  # tuple[RuleRow, ...] (precomputed on the worker thread)
    progress = Signal(int, int, object)  # done, total, tuple[RuleRow, ...]
    finished = Signal(object, object)  # RuleScanReport, tuple[RuleRow, ...]
    failed = Signal(str)  # exception type name only


class _Forwarder:
    """Observer on the worker thread: precomputes display rows, then only emits signals."""

    def __init__(self, signals: RuleScanSignals) -> None:
        self._signals = signals
        # rule id -> (rule object, row). Rules are immutable and the assembler reuses unchanged
        # rule objects, so an identity check tells us which rows must be recomputed.
        self._cache: dict[str, tuple[FirewallRule, RuleRow]] = {}

    def rows(self, rules: tuple[FirewallRule, ...]) -> tuple[RuleRow, ...]:
        stale = tuple(r for r in rules if self._cache.get(r.id, (None,))[0] is not r)
        for rule, row in zip(stale, rows_for(stale), strict=True):
            self._cache[rule.id] = (rule, row)
        return tuple(self._cache[r.id][1] for r in rules)

    def inventory_ready(self, rules: tuple[FirewallRule, ...]) -> None:
        self._signals.inventory.emit(self.rows(rules))

    def detail_progress(self, done: int, total: int, updated: tuple[FirewallRule, ...]) -> None:
        self._signals.progress.emit(done, total, self.rows(updated))


class RuleScanTask(QRunnable):
    def __init__(
        self, service: RuleScanService, signals: RuleScanSignals, cancel: threading.Event
    ) -> None:
        super().__init__()
        self._service = service
        self._signals = signals
        self._cancel = cancel

    def run(self) -> None:
        forwarder = _Forwarder(self._signals)
        try:
            report = self._service.scan(observer=forwarder, cancel=self._cancel)
        except Exception as exc:  # surface any unexpected failure, type name only
            self._signals.failed.emit(type(exc).__name__)
            return
        data = report.result.data
        rows = forwarder.rows(data.rules) if data is not None else ()
        self._signals.finished.emit(report, rows)


class RulesTab(QWidget):
    # Emitted with the RuleCollection of a finished scan (complete or partial); used by the
    # Network tab for descriptive correlation (M1.4). Never triggers another scan.
    collection_ready = Signal(object)

    def __init__(self, service: RuleScanService, *, pool: QThreadPool | None = None) -> None:
        super().__init__()
        self._service = service
        self._pool = pool if pool is not None else QThreadPool.globalInstance()
        self._signals = RuleScanSignals()
        self._signals.inventory.connect(self._on_inventory)
        self._signals.progress.connect(self._on_progress)
        self._signals.finished.connect(self._on_finished)
        self._signals.failed.connect(self._on_failed)
        self._cancel = threading.Event()
        self._running = False

        self.notice = QLabel(RULES_NOTICE)
        self.notice.setWordWrap(True)
        self.notice.setAccessibleName("Rules scope notice")

        self.collect_button = QPushButton("&Collect rules")
        self.collect_button.setAccessibleName("Collect firewall rules")
        self.collect_button.clicked.connect(self.start)
        self.cancel_button = QPushButton("C&ancel")
        self.cancel_button.setAccessibleName("Cancel rule collection")
        self.cancel_button.setEnabled(False)
        self.cancel_button.clicked.connect(self.cancel)

        self.progress = QProgressBar()
        self.progress.setAccessibleName("Rule collection progress")
        self.progress.setRange(0, 1)
        self.progress.setValue(0)
        self.phase = QLabel(RULES_IDLE)
        self.phase.setAccessibleName("Rule collection phase")

        self.model = RulesTableModel()
        self.table = QTableView()
        self.table.setModel(self.model)  # model sorts precomputed keys (no proxy on GUI thread)
        self.table.setSortingEnabled(True)
        self.table.setAccessibleName("Firewall rules")
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.table.verticalHeader().setVisible(False)

        self.timing = QLabel("")
        self.timing.setAccessibleName("Scan timing and N-04 status")
        self.limitations = QLabel("")
        self.limitations.setWordWrap(True)
        self.limitations.setAccessibleName("Rule scan limitations")
        self.limitations.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)

        top = QHBoxLayout()
        top.addWidget(self.notice, stretch=1)
        top.addWidget(self.collect_button)
        top.addWidget(self.cancel_button)
        bar = QHBoxLayout()
        bar.addWidget(self.phase, stretch=1)
        bar.addWidget(self.progress, stretch=2)
        layout = QVBoxLayout()
        layout.addLayout(top)
        layout.addLayout(bar)
        layout.addWidget(self.table, stretch=1)
        layout.addWidget(self.timing)
        layout.addWidget(self.limitations)
        self.setLayout(layout)

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
        self.progress.setRange(0, 0)  # busy indicator until the inventory arrives
        self.phase.setText("Collecting rule inventory…")
        self.timing.setText("")
        self.limitations.setText("")
        self._pool.start(RuleScanTask(self._service, self._signals, self._cancel))

    def cancel(self) -> None:
        if self._running:
            self._cancel.set()
            self.cancel_button.setEnabled(False)
            self.phase.setText("Cancelling…")

    def _on_inventory(self, rows: tuple[RuleRow, ...]) -> None:
        self.model.set_rows(rows)
        self.progress.setRange(0, max(1, len(rows)))
        self.progress.setValue(0)
        self.phase.setText(
            f"Inventory: {len(rows)} rules. Collecting port, address and interface filters…"
        )

    def _on_progress(self, done: int, total: int, updated: tuple[RuleRow, ...]) -> None:
        self.model.update_rows(updated)
        self.progress.setRange(0, max(1, total))
        self.progress.setValue(done)
        self.phase.setText(f"Collecting rule details: {done} of {total} rules…")

    def _finish(self) -> None:
        self._running = False
        self.collect_button.setEnabled(True)
        self.cancel_button.setEnabled(False)
        if self.progress.maximum() == 0:
            self.progress.setRange(0, 1)

    def _on_finished(self, report: RuleScanReport, rows: tuple[RuleRow, ...]) -> None:
        data = report.result.data
        if data is not None:
            self.collection_ready.emit(data)
        if data is not None:
            if self.model.rowCount() == len(rows):
                self.model.update_rows(rows)  # final states (e.g. cancelled), no full reset
            else:
                self.model.set_rows(rows)
        inv = "n/a" if report.inventory_s is None else f"{report.inventory_s:.1f} s"
        n04 = report.n04.describe()
        self.timing.setText(f"Inventory {inv} · total {report.total_s:.1f} s · {n04}")
        lines = [f"• {lim.code.value}: {lim.detail}" for lim in (data.limitations if data else ())]
        lines += [f"• {e.code.value}: {e.detail}" for e in report.result.errors[:10]]
        if len(report.result.errors) > 10:
            lines.append(f"• … {len(report.result.errors) - 10} more errors")
        if report.elevated:
            lines.append("• Running elevated is not needed.")
        self.limitations.setText("Limitations:\n" + "\n".join(lines) if lines else "")
        ev = report.evidence
        if data is None:
            self.phase.setText("Rule collection failed. See limitations.")
        elif not data.detail_complete:
            self.phase.setText(
                f"Incomplete: {len(data.rules)} rules; detail not finished. "
                f"Evidence complete for {ev.complete}, incomplete for {ev.incomplete}."
            )
        else:
            suffix = " (N-04 exceeded)" if report.n04.status is N04Status.EXCEEDED else ""
            self.phase.setText(
                f"Done: {len(data.rules)} rules. Evidence complete for {ev.complete}, "
                f"incomplete for {ev.incomplete}. No verdicts.{suffix}"
            )
            self.progress.setValue(self.progress.maximum())
        self._finish()

    def _on_failed(self, error_type: str) -> None:
        self.limitations.setText(f"Limitations:\n• Unexpected error: {error_type}")
        self.phase.setText("Rule collection failed. See limitations.")
        self._finish()
