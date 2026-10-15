"""Fixture-backed rule collector: replays recorded/synthetic stream events through the real
progressive-collection driver, with optional delays and injected failures (for tests and
non-Windows development)."""

import json
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from firewallai.collectors.protocols import RuleCollectionObserver, RulesResult
from firewallai.collectors.rule_collection import collect_progressively
from firewallai.collectors.windows.powershell_runner import JsonValue, RunOutcome
from firewallai.core.results import CollectorError, CollectorErrorCode

_MAX_FIXTURE_BYTES = 8 * 1024 * 1024


class FixtureFirewallRuleCollector:
    """Fixture format: ``{"events": [<inventory>, <detail>...], "final_error": {...} | null}``.

    ``final_error`` (code/detail) simulates how the stream ended (e.g. ``timeout``).
    ``fail_after_events`` truncates the stream with ``fail_code`` after N events.
    """

    SOURCE_ID = "fixture.firewall_rules"

    def __init__(
        self,
        fixture: Any,
        *,
        delay_s: float = 0.0,
        fail_after_events: int | None = None,
        fail_code: CollectorErrorCode = CollectorErrorCode.TIMEOUT,
    ) -> None:
        self._events: list[Any] = list(fixture.get("events", []))
        final = fixture.get("final_error")
        self._final_error = (
            None
            if final is None
            else CollectorError(
                code=CollectorErrorCode(final["code"]),
                source=self.SOURCE_ID,
                detail=str(final.get("detail", ""))[:300],
            )
        )
        self._delay_s = delay_s
        self._fail_after = fail_after_events
        self._fail_code = fail_code

    @classmethod
    def from_file(cls, path: Path, **kwargs: Any) -> "FixtureFirewallRuleCollector":
        if path.stat().st_size > _MAX_FIXTURE_BYTES:
            raise ValueError("fixture file too large")
        return cls(json.loads(path.read_text(encoding="utf-8")), **kwargs)

    @property
    def source_id(self) -> str:
        return self.SOURCE_ID

    def _replay(
        self,
        on_event: Callable[[JsonValue], None],
        cancel: threading.Event | None,
        want_detail: bool,
    ) -> RunOutcome:
        for index, event in enumerate(self._events):
            if cancel is not None and cancel.is_set():
                return RunOutcome(
                    error=CollectorError(
                        code=CollectorErrorCode.CANCELLED,
                        source=self.SOURCE_ID,
                        detail="cancelled by the caller",
                    )
                )
            if self._fail_after is not None and index >= self._fail_after:
                return RunOutcome(
                    error=CollectorError(
                        code=self._fail_code, source=self.SOURCE_ID, detail="injected failure"
                    )
                )
            if not want_detail and isinstance(event, dict) and event.get("stage") == "detail":
                continue
            if self._delay_s:
                time.sleep(self._delay_s)
            on_event(event)
        if self._final_error is not None:
            return RunOutcome(error=self._final_error)
        return RunOutcome(data={"total": None})

    def collect_rules(
        self,
        *,
        detail: bool = True,
        observer: RuleCollectionObserver | None = None,
        cancel: threading.Event | None = None,
    ) -> RulesResult:
        return collect_progressively(
            self.SOURCE_ID, self._replay, detail=detail, observer=observer, cancel=cancel
        )
