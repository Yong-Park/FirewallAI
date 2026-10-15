"""M1.4 Windows endpoint collector with injected fakes (no system queries, no PowerShell).

Covers service-lookup failure isolation, malformed/oversized socket data, psutil errors, the
PID-reuse guard, cancellation, single-flight, and parallel service lookup.
"""

import os
import threading
import time
from collections.abc import Iterable, Iterator
from typing import Any

import psutil
import pytest

from endpoint_builders import psutil_conn
from firewallai.collectors.endpoint_assembly import RawField, RawProcess
from firewallai.collectors.windows import network_endpoints as ne
from firewallai.collectors.windows.powershell_runner import RunOutcome
from firewallai.core.endpoints import (
    Availability,
    EndpointLimitationCode,
    UnavailableReason,
)
from firewallai.core.results import CollectorError, CollectorErrorCode


class FakeRunner:
    def __init__(self, outcome: Any = None, *, delay_s: float = 0.0, raises: bool = False) -> None:
        self.outcome = (
            outcome
            if outcome is not None
            else RunOutcome(data={"services": [{"name": "SyntheticSvc", "pid": 1000}]})
        )
        self.delay_s = delay_s
        self.raises = raises
        self.calls: list[str] = []

    def run(self, script: Any, params: Any = None, *, source: str) -> RunOutcome:
        self.calls.append(script.name)
        time.sleep(self.delay_s)
        if self.raises:
            raise RuntimeError("boom")
        return self.outcome


def _probe(pid: int) -> RawProcess:
    return RawProcess(
        pid=pid, name=RawField(value="synthetic.exe"), exe=RawField(value="C:\\S\\synthetic.exe")
    )


def _collector(
    conns: Iterable[Any] | None = None,
    *,
    runner: FakeRunner | None = None,
    sequence: list[list[Any]] | None = None,
    probe: Any = _probe,
) -> ne.WindowsEndpointCollector:
    snapshots: Iterator[list[Any]] | None = iter(sequence) if sequence is not None else None
    fixed = list(conns) if conns is not None else [psutil_conn(pid=1000)]

    def net() -> list[Any]:
        return next(snapshots) if snapshots is not None else fixed

    return ne.WindowsEndpointCollector(
        runner or FakeRunner(),  # type is duck-typed in tests
        net_connections=net,
        process_probe=probe,
    )


def test_happy_path_with_services() -> None:
    runner = FakeRunner()
    result = _collector(runner=runner).collect_endpoints()
    assert result.ok and result.data is not None
    p = result.data.endpoints[0].process
    assert p.attribution is Availability.COLLECTED
    assert p.services.value == ("SyntheticSvc",)
    assert runner.calls == ["win32_services"]  # the registered script, nothing else
    assert result.data.timings.services_s is not None


@pytest.mark.parametrize(
    "runner",
    [
        FakeRunner(
            RunOutcome(
                error=CollectorError(code=CollectorErrorCode.ACCESS_DENIED, source="x", detail="")
            )
        ),
        FakeRunner(RunOutcome(data={"services": [{"name": "x" * 300, "pid": 1}]})),
        FakeRunner(RunOutcome(data={"services": "not a list"})),
        FakeRunner(RunOutcome(data={"services": [], "extra": 1})),
        FakeRunner(RunOutcome(data={"services": [{"name": "a", "pid": "1000"}]})),
        FakeRunner(raises=True),
    ],
    ids=["error", "overlong-name", "wrong-type", "extra-field", "string-pid", "raises"],
)
def test_service_lookup_failure_never_invalidates_sockets(runner: FakeRunner) -> None:
    result = _collector(runner=runner).collect_endpoints()
    assert result.partial and result.data is not None
    ep = result.data.endpoints[0]
    assert ep.process.attribution is Availability.COLLECTED and ep.process.name.is_collected
    assert ep.process.services.reason is UnavailableReason.LOOKUP_FAILED
    codes = {lim.code for lim in result.data.limitations}
    assert EndpointLimitationCode.SERVICE_LOOKUP_FAILED in codes
    assert all(e.source == ne.WindowsEndpointCollector.SOURCE_ID for e in result.errors)


def test_service_lookup_runs_in_parallel_with_process_lookup() -> None:
    def slow_probe(pid: int) -> RawProcess:
        time.sleep(0.3)
        return _probe(pid)

    collector = _collector(runner=FakeRunner(delay_s=0.3), probe=slow_probe)
    started = time.perf_counter()
    assert collector.collect_endpoints().ok
    assert time.perf_counter() - started < 0.55  # sequential would be >= 0.6 s


@pytest.mark.parametrize(
    ("exc", "code"),
    [
        (psutil.AccessDenied(), CollectorErrorCode.ACCESS_DENIED),
        (OSError("x"), CollectorErrorCode.EXECUTION_FAILED),
    ],
)
def test_socket_table_errors_are_structured(exc: Exception, code: CollectorErrorCode) -> None:
    def net() -> list[Any]:
        raise exc

    collector = ne.WindowsEndpointCollector(FakeRunner(), net_connections=net)
    result = collector.collect_endpoints()
    assert result.data is None and result.errors[0].code is code


def test_oversized_socket_table_fails_explicitly() -> None:
    conns = [psutil_conn(pid=1000)] * 70_000
    result = _collector(conns).collect_endpoints()
    assert result.data is None
    assert result.errors[0].code is CollectorErrorCode.OUTPUT_TOO_LARGE


def test_malformed_psutil_records_are_dropped_and_counted() -> None:
    conns = [
        psutil_conn(pid=1000),
        psutil_conn(family="AF_UNIX"),
        psutil_conn(kind="SOCK_RAW"),
        psutil_conn(laddr=()),
        psutil_conn(laddr=("192.0.2.10", 99999)),
        psutil_conn(laddr=("x" * 200, 1)),
        object(),
    ]
    result = _collector(conns).collect_endpoints()
    assert result.data is not None and len(result.data.endpoints) == 1
    lim = {x.code: x.detail for x in result.data.limitations}
    assert lim[EndpointLimitationCode.UNRECOGNIZED_RECORDS].startswith("6 ")


def test_pid_reuse_guard_with_changing_socket_tables() -> None:
    first = [psutil_conn(pid=1000), psutil_conn(laddr=("192.0.2.10", 9), pid=2000)]
    second = [psutil_conn(pid=1000), psutil_conn(laddr=("192.0.2.10", 9), pid=3000)]
    result = _collector(sequence=[first, second]).collect_endpoints()
    assert result.data is not None
    reasons = [e.process.reason for e in result.data.endpoints]
    assert reasons == [None, UnavailableReason.ATTRIBUTION_UNVERIFIED]


def test_second_snapshot_failure_marks_all_unverified() -> None:
    calls = {"n": 0}

    def net() -> list[Any]:
        calls["n"] += 1
        if calls["n"] == 2:
            raise OSError("table changed")
        return [psutil_conn(pid=1000)]

    result = ne.WindowsEndpointCollector(FakeRunner(), net_connections=net).collect_endpoints()
    assert result.partial and result.data is not None
    assert result.data.endpoints[0].process.reason is UnavailableReason.ATTRIBUTION_UNVERIFIED


def test_cancel_during_process_lookup_returns_explicit_partial_data() -> None:
    cancel = threading.Event()

    def probe(pid: int) -> RawProcess:
        cancel.set()  # cancel after the first process
        return _probe(pid)

    conns = [psutil_conn(pid=1000), psutil_conn(laddr=("192.0.2.10", 2), pid=2000)]
    result = _collector(conns, probe=probe).collect_endpoints(cancel=cancel)
    assert result.partial and result.data is not None
    assert result.errors[0].code is CollectorErrorCode.CANCELLED
    assert not result.data.process_lookup_complete
    reasons = [e.process.reason for e in result.data.endpoints]
    assert reasons == [None, UnavailableReason.NOT_COLLECTED]


def test_single_flight_busy() -> None:
    assert ne.ENDPOINT_SNAPSHOT_LOCK.acquire(blocking=False)
    try:
        result = _collector().collect_endpoints()
    finally:
        ne.ENDPOINT_SNAPSHOT_LOCK.release()
    assert result.data is None and result.errors[0].code is CollectorErrorCode.BUSY
    assert _collector().collect_endpoints().ok  # released afterwards


def test_endpoint_lock_is_not_the_rule_scan_lock() -> None:
    from firewallai.collectors.windows.firewall_rules import HEAVY_QUERY_LOCK

    assert ne.ENDPOINT_SNAPSHOT_LOCK is not HEAVY_QUERY_LOCK


# --- probe_process against psutil error types (monkeypatched) -----------------------------------


class _FakeProcess:
    def __init__(self, name: Any = "a.exe", exe: Any = "C:\\a.exe") -> None:
        self._name, self._exe = name, exe

    def oneshot(self) -> Any:
        import contextlib

        return contextlib.nullcontext()

    def _get(self, value: Any) -> Any:
        if isinstance(value, Exception):
            raise value
        return value

    def name(self) -> Any:
        return self._get(self._name)

    def exe(self) -> Any:
        return self._get(self._exe)


@pytest.mark.parametrize(
    ("factory", "expect"),
    [
        (lambda pid: _FakeProcess(), ("a.exe", None, "C:\\a.exe", None, False)),
        (
            lambda pid: _FakeProcess(exe=psutil.AccessDenied(pid)),
            ("a.exe", None, None, "access_denied", False),
        ),
        (
            lambda pid: _FakeProcess(name=psutil.NoSuchProcess(pid), exe=psutil.NoSuchProcess(pid)),
            (None, "process_exited", None, "process_exited", True),
        ),
        (
            lambda pid: _FakeProcess(exe=OSError("odd")),
            ("a.exe", None, None, "lookup_failed", False),
        ),
        (lambda pid: _FakeProcess(exe=12345), ("a.exe", None, None, None, False)),
        (
            lambda pid: _FakeProcess(exe=psutil.NoSuchProcess(pid)),
            ("a.exe", None, None, "process_exited", True),  # exited mid-lookup: not attributed
        ),
    ],
    ids=["ok", "exe-denied", "exited", "os-error", "non-string", "exited-mid-lookup"],
)
def test_probe_process_maps_psutil_errors(
    monkeypatch: pytest.MonkeyPatch, factory: Any, expect: tuple[Any, ...]
) -> None:
    monkeypatch.setattr(ne.psutil, "Process", factory)
    p = ne.probe_process(1234)
    assert (p.name.value, p.name.error, p.exe.value, p.exe.error, p.exited) == expect


@pytest.mark.parametrize(
    ("exc", "exited", "error"),
    [(psutil.NoSuchProcess(1), True, None), (psutil.AccessDenied(1), False, "access_denied")],
)
def test_probe_process_constructor_errors(
    monkeypatch: pytest.MonkeyPatch, exc: Exception, exited: bool, error: str | None
) -> None:
    def boom(pid: int) -> Any:
        raise exc

    monkeypatch.setattr(ne.psutil, "Process", boom)
    p = ne.probe_process(1)
    assert p.exited is exited and p.name.error == error


def test_probe_process_reads_own_process_read_only() -> None:
    p = ne.probe_process(os.getpid())
    assert p.name.value and p.name.value.lower().startswith("python")
