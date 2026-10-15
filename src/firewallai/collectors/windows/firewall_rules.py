"""Real, read-only, non-elevated ActiveStore rule collector (ADR 0009, M1.3)."""

import threading
from collections.abc import Callable

from firewallai.collectors.protocols import RuleCollectionObserver, RulesResult
from firewallai.collectors.rule_collection import collect_progressively
from firewallai.collectors.windows.powershell_runner import (
    JsonValue,
    PowerShellRunner,
    RunOutcome,
    UnsupportedPlatformError,
)
from firewallai.collectors.windows.scripts import FIREWALL_RULES
from firewallai.core.results import CollectorError, CollectorErrorCode, CollectorResult

# Process-wide single-flight guard for heavy firewall queries: M1.2 showed that parallel
# NetSecurity queries contend in the provider and slow each other down.
HEAVY_QUERY_LOCK = threading.Lock()


class WindowsFirewallRuleCollector:
    SOURCE_ID = "windows.netsecurity.firewall_rules"

    def __init__(self, runner: PowerShellRunner | None = None) -> None:
        self._runner = runner

    @property
    def source_id(self) -> str:
        return self.SOURCE_ID

    def _error(self, code: CollectorErrorCode, detail: str) -> RulesResult:
        return CollectorResult(
            errors=(CollectorError(code=code, source=self.SOURCE_ID, detail=detail),)
        )

    def collect_rules(
        self,
        *,
        detail: bool = True,
        observer: RuleCollectionObserver | None = None,
        cancel: threading.Event | None = None,
    ) -> RulesResult:
        if not HEAVY_QUERY_LOCK.acquire(blocking=False):
            return self._error(CollectorErrorCode.BUSY, "a rule collection is already running")
        try:
            try:
                runner = self._runner if self._runner is not None else PowerShellRunner()
            except UnsupportedPlatformError:
                return self._error(
                    CollectorErrorCode.UNSUPPORTED_PLATFORM,
                    "Windows PowerShell is not available on this platform",
                )

            def source(
                on_event: Callable[[JsonValue], None],
                stop: threading.Event | None,
                want_detail: bool,
            ) -> RunOutcome:
                return runner.run_stream(
                    FIREWALL_RULES,
                    {"inventory_only": not want_detail},
                    source=self.SOURCE_ID,
                    on_event=on_event,
                    cancel=stop,
                )

            return collect_progressively(
                self.SOURCE_ID, source, detail=detail, observer=observer, cancel=cancel
            )
        finally:
            HEAVY_QUERY_LOCK.release()
