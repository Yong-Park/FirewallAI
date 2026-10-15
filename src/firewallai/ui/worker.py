"""Background collection so the GUI thread never blocks on PowerShell."""

from PySide6.QtCore import QObject, QRunnable, Signal

from firewallai.app.profile_service import ProfileService


class ProfileLoadSignals(QObject):
    finished = Signal(object)  # ProfileReport
    failed = Signal(str)  # exception type name only (no message text: may contain host data)


class ProfileLoadTask(QRunnable):
    def __init__(self, service: ProfileService, signals: ProfileLoadSignals) -> None:
        super().__init__()
        self._service = service
        self._signals = signals

    def run(self) -> None:
        try:
            report = self._service.get_profiles()
        except Exception as exc:  # surface any unexpected failure to the UI, type name only
            self._signals.failed.emit(type(exc).__name__)
            return
        self._signals.finished.emit(report)
