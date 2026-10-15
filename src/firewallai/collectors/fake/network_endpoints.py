"""Fixture-backed endpoint collector (tests and non-Windows development).

Fixture format: the ``RawEndpointSnapshot`` JSON shape (``first``, ``second``, ``processes``,
``services`` or ``null`` plus ``services_error``). It runs through the same assembler as the
Windows collector, so attribution and limitation rules are identical.
"""

import json
import threading
import time
from pathlib import Path
from typing import Any

from firewallai.collectors.endpoint_assembly import RawEndpointSnapshot, assemble_snapshot
from firewallai.collectors.protocols import EndpointsResult
from firewallai.core.endpoints import EndpointTimings
from firewallai.core.results import CollectorError, CollectorErrorCode, CollectorResult

_MAX_FIXTURE_BYTES = 16 * 1024 * 1024


class FixtureEndpointCollector:
    SOURCE_ID = "fixture.endpoints"

    def __init__(
        self,
        fixture: Any,
        *,
        delay_s: float = 0.0,
        fail_code: CollectorErrorCode | None = None,
    ) -> None:
        self._fixture = fixture
        self._delay_s = delay_s
        self._fail_code = fail_code

    @classmethod
    def from_file(cls, path: Path, **kwargs: Any) -> "FixtureEndpointCollector":
        if path.stat().st_size > _MAX_FIXTURE_BYTES:
            raise ValueError("fixture file too large")
        return cls(json.loads(path.read_text(encoding="utf-8")), **kwargs)

    @property
    def source_id(self) -> str:
        return self.SOURCE_ID

    def _error(self, code: CollectorErrorCode, detail: str) -> EndpointsResult:
        return CollectorResult(
            errors=(CollectorError(code=code, source=self.SOURCE_ID, detail=detail),)
        )

    def collect_endpoints(self, *, cancel: threading.Event | None = None) -> EndpointsResult:
        deadline = time.monotonic() + self._delay_s
        while time.monotonic() < deadline:
            if cancel is not None and cancel.is_set():
                return self._error(CollectorErrorCode.CANCELLED, "cancelled by the caller")
            time.sleep(0.01)
        if self._fail_code is not None:
            return self._error(self._fail_code, "injected failure")
        try:
            raw = RawEndpointSnapshot.model_validate(self._fixture)
        except ValueError as exc:
            return self._error(CollectorErrorCode.PARSE_ERROR, f"fixture: {type(exc).__name__}")
        timings = EndpointTimings(sockets_s=0.0, processes_s=0.0, services_s=None)
        return CollectorResult(data=assemble_snapshot(raw, timings))
