"""SB-03 (M1.3): the opt-in JSON Lines streaming mode of the PowerShell runner.

The protocol, caps, timeout, cancellation, and child cleanup are exercised with harmless Python
child processes that emit crafted streams.
"""

import json
import sys
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from firewallai.collectors.windows.powershell_runner import (
    STREAM_WRAPPER_TEMPLATE,
    PowerShellRunner,
    PowerShellScript,
    execute_stream,
)
from firewallai.collectors.windows.scripts import FIREWALL_PROFILES, REGISTERED_SCRIPTS
from firewallai.core.results import CollectorErrorCode

pytestmark = pytest.mark.security

STREAM = PowerShellScript(
    name="t",
    body="",
    allowed_commands=frozenset(),
    streaming=True,
    timeout_s=20,
    max_output_bytes=100_000,
    max_line_bytes=10_000,
    max_events=50,
)


def _py(code: str) -> list[str]:
    return [sys.executable, "-c", code]


def _emit(lines: list[Any]) -> str:
    payload = [json.dumps(x) if not isinstance(x, str) else x for x in lines]
    return "import sys\n" + "".join(f"print({p!r}, flush=True)\n" for p in payload)


def _run(code: str, script: PowerShellScript = STREAM, **kw: Any) -> tuple[Any, list[Any]]:
    events: list[Any] = []
    outcome = execute_stream(
        _py(code), b"", script=script, source="t", on_event=events.append, **kw
    )
    return outcome, events


RESULT_OK = {"type": "result", "ok": True, "data": {"total": 2}}


def test_valid_stream_delivers_events_in_order_then_result() -> None:
    code = _emit([{"type": "event", "data": 1}, {"type": "event", "data": 2}, RESULT_OK])
    outcome, events = _run(code)
    assert outcome.error is None and outcome.data == {"total": 2}
    assert events == [1, 2]


@pytest.mark.parametrize(
    ("lines", "code"),
    [
        (["not json", RESULT_OK], CollectorErrorCode.PARSE_ERROR),
        ([[1, 2], RESULT_OK], CollectorErrorCode.PARSE_ERROR),
        ([{"type": "event"}, RESULT_OK], CollectorErrorCode.PARSE_ERROR),  # missing data
        ([{"type": "event", "data": 1, "x": 2}, RESULT_OK], CollectorErrorCode.PARSE_ERROR),
        ([{"type": "log", "data": 1}, RESULT_OK], CollectorErrorCode.PARSE_ERROR),
        ([RESULT_OK, {"type": "event", "data": 1}], CollectorErrorCode.PARSE_ERROR),
        ([{"type": "event", "data": 1}], CollectorErrorCode.PARSE_ERROR),  # truncated
        (
            [
                {
                    "type": "result",
                    "ok": False,
                    "error": {"category": "PermissionDenied", "error_id": "X", "hresult": 5},
                }
            ],
            CollectorErrorCode.ACCESS_DENIED,
        ),
    ],
)
def test_protocol_violations_are_structured_errors(
    lines: list[Any], code: CollectorErrorCode
) -> None:
    outcome, _ = _run(_emit(lines))
    assert outcome.error is not None
    assert outcome.error.code is code


def test_truncated_stream_with_nonzero_exit_is_execution_failed() -> None:
    outcome, events = _run(_emit([{"type": "event", "data": 1}]) + "sys.exit(3)\n")
    assert outcome.error is not None
    assert outcome.error.code is CollectorErrorCode.EXECUTION_FAILED
    assert events == [1]


def test_per_line_cap() -> None:
    code = "import sys\nsys.stdout.write('x' * 50_000)\nsys.stdout.flush()\n"
    outcome, _ = _run(code)
    assert outcome.error.code is CollectorErrorCode.OUTPUT_TOO_LARGE


def test_total_cap() -> None:
    line = json.dumps({"type": "event", "data": "y" * 9_000})
    code = f"import sys\nfor _ in range(50):\n    print({line!r}, flush=True)\n"
    outcome, events = _run(code)
    assert outcome.error.code is CollectorErrorCode.OUTPUT_TOO_LARGE
    assert len(events) < 50


def test_event_count_cap() -> None:
    line = json.dumps({"type": "event", "data": 0})
    code = f"import sys\nfor _ in range(60):\n    print({line!r}, flush=True)\n"
    outcome, events = _run(code)
    assert outcome.error.code is CollectorErrorCode.OUTPUT_TOO_LARGE
    assert len(events) == STREAM.max_events


def test_non_utf8_line_is_parse_error() -> None:
    code = "import sys\nsys.stdout.buffer.write(b'\\xff\\xfe\\n')\nsys.stdout.flush()\n"
    outcome, _ = _run(code)
    assert outcome.error.code is CollectorErrorCode.PARSE_ERROR


def _sleeper(marker: Path, before: str = "") -> str:
    return (
        "import time, pathlib\n"
        + before
        + f"time.sleep(2.0)\npathlib.Path({str(marker)!r}).write_text('alive')\n"
    )


def test_timeout_kills_child(tmp_path: Path) -> None:
    marker = tmp_path / "survived.txt"
    script = PowerShellScript(
        name="t", body="", allowed_commands=frozenset(), streaming=True, timeout_s=0.5
    )
    started = time.monotonic()
    outcome, _ = _run(_sleeper(marker), script)
    assert outcome.error.code is CollectorErrorCode.TIMEOUT
    assert time.monotonic() - started < 2.0
    time.sleep(2.5)
    assert not marker.exists(), "child process was not killed"


def test_cancel_kills_child(tmp_path: Path) -> None:
    marker = tmp_path / "survived.txt"
    cancel = threading.Event()
    timer = threading.Timer(0.3, cancel.set)
    timer.start()
    outcome, _ = _run(_sleeper(marker), cancel=cancel)
    timer.cancel()
    assert outcome.error.code is CollectorErrorCode.CANCELLED
    time.sleep(2.5)
    assert not marker.exists(), "child process was not killed"


def test_consumer_exception_kills_child_and_propagates(tmp_path: Path) -> None:
    marker = tmp_path / "survived.txt"
    first = json.dumps({"type": "event", "data": 1})
    code = _sleeper(marker, before=f"print({first!r}, flush=True)\n")

    def boom(_: Any) -> None:
        raise ValueError("consumer rejected event")

    with pytest.raises(ValueError, match="consumer rejected"):
        execute_stream(_py(code), b"", script=STREAM, source="t", on_event=boom)
    time.sleep(2.5)
    assert not marker.exists(), "child process was not killed"


def test_run_stream_requires_streaming_script() -> None:
    runner = PowerShellRunner(
        Path("C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"),
        system_dir=Path("C:/Windows/System32"),
    )
    with pytest.raises(ValueError, match="streaming"):
        runner.run_stream(FIREWALL_PROFILES, source="t", on_event=lambda _: None)


def test_stream_wrapper_is_constant_and_read_only() -> None:
    assert '"' not in STREAM_WRAPPER_TEMPLATE
    lowered = STREAM_WRAPPER_TEMPLATE.lower()
    for token in ("bypass", "invoke-expression", "start-process", "encodedcommand"):
        assert token not in lowered


@pytest.mark.parametrize(
    "script", [s for s in REGISTERED_SCRIPTS if s.streaming], ids=lambda s: s.name
)
def test_streaming_scripts_have_bounded_lines_and_events(script: PowerShellScript) -> None:
    assert 0 < script.max_line_bytes <= script.max_output_bytes
    assert 0 < script.max_events <= 10_000


# --- M1.3 final security review findings (regression tests) -------------------------------------

BIG_LINES = PowerShellScript(
    name="t",
    body="",
    allowed_commands=frozenset(),
    streaming=True,
    timeout_s=20,
    max_output_bytes=1_000_000,
    max_line_bytes=200_000,
    max_events=50,
)


def test_json_nesting_bomb_is_a_structured_parse_error() -> None:
    # Within the line cap, but deep enough to exceed the JSON parser's recursion limit.
    # Built in the child: a literal this long would exceed the Windows command-line limit.
    code = (
        'head = \'{"type": "event", "data": \'\n'
        "print(head + '[' * 20_000 + ']' * 20_000 + '}', flush=True)\n"
    )
    outcome, events = _run(code, BIG_LINES)
    assert outcome.error is not None
    assert outcome.error.code is CollectorErrorCode.PARSE_ERROR
    assert events == []


def test_stderr_flood_does_not_block_the_child() -> None:
    result_line = json.dumps(RESULT_OK)
    code = (
        "import sys\n"
        "sys.stderr.write('e' * 2_000_000)\n"
        "sys.stderr.flush()\n"
        f"print({result_line!r}, flush=True)\n"
    )
    started = time.monotonic()
    outcome, _ = _run(code)
    assert outcome.error is None, outcome.error
    assert time.monotonic() - started < 10  # no stall until the 20 s timeout


def test_child_closing_stdout_without_exiting_is_failed_and_killed(tmp_path: Path) -> None:
    marker = tmp_path / "survived.txt"
    code = (
        "import os, time, pathlib\n"
        "os.close(1)\n"
        "time.sleep(6.5)\n"
        f"pathlib.Path({str(marker)!r}).write_text('alive')\n"
    )
    # The venv launcher keeps its own copy of the pipe handle, which would hide the EOF, so this
    # test runs the base interpreter directly (as production runs powershell.exe directly).
    base = getattr(sys, "_base_executable", sys.executable)
    events: list[Any] = []
    started = time.monotonic()
    outcome = execute_stream(
        [base, "-c", code], b"", script=STREAM, source="t", on_event=events.append
    )
    assert outcome.error is not None
    assert outcome.error.code is CollectorErrorCode.EXECUTION_FAILED
    assert "exit_code=None" in outcome.error.detail
    assert time.monotonic() - started < 6.5
    time.sleep(7.0 - (time.monotonic() - started))
    assert not marker.exists(), "child process was not killed"
