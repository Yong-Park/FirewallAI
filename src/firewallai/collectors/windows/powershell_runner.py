"""The single, audited entry point for running PowerShell (SB-03, ADR 0009).

Security properties:
- The executable is resolved by absolute path from ``GetSystemDirectoryW``, not from ``PATH`` or
  environment variables (CWE-427).
- Script text is a constant compiled into FirewallAI (see ``scripts.py``). It is passed as the
  ``-Command`` argument and never interpolated with untrusted data (CWE-78).
- Parameters travel only as JSON on stdin and are read by the script as data.
- No ``-ExecutionPolicy Bypass``, no ``-EncodedCommand``, no ``-File``. ``-Command`` is not subject
  to execution policy, and these flags are common malware indicators (Day 0 evidence, ADR 0009).
- ``shell=False``, a hard timeout, output-size caps, and a restricted ``PSModulePath`` so only
  system modules load.
- Errors are classified by stable category/ID, never by (localized) message text.
"""

import contextlib
import json
import os
import queue
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Any

from firewallai.core.results import CollectorError, CollectorErrorCode

JsonValue = Any  # JSON-compatible value produced by ``json.loads``

_BODY_MARKER = "__FIREWALLAI_SCRIPT_BODY__"

# Constant wrapper. Reads JSON params from stdin, runs the body, and writes exactly one JSON
# envelope to stdout: {"ok": true, "data": ...} or {"ok": false, "error": {...}}.
# Uses single quotes only (see tests/security): the whole text is one -Command argument.
WRAPPER_TEMPLATE = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
[Console]::InputEncoding = [System.Text.UTF8Encoding]::new($false)
try {
    $FwaiParams = $null
    $FwaiRaw = [Console]::In.ReadToEnd()
    if ($FwaiRaw) { $FwaiParams = ConvertFrom-Json -InputObject $FwaiRaw }
    $FwaiData = & {
__FIREWALLAI_SCRIPT_BODY__
    }
    $FwaiEnvelope = [ordered]@{ ok = $true; data = $FwaiData }
} catch {
    $FwaiHresult = 0
    if ($_.Exception -and $_.Exception.HResult) { $FwaiHresult = [int]$_.Exception.HResult }
    $FwaiEnvelope = [ordered]@{
        ok = $false
        error = [ordered]@{
            category = [string]$_.CategoryInfo.Category
            error_id = [string]$_.FullyQualifiedErrorId
            hresult = $FwaiHresult
        }
    }
}
[Console]::Out.Write((ConvertTo-Json -InputObject $FwaiEnvelope -Depth 8 -Compress))
"""

# Streaming variant (opt-in, PowerShellScript.streaming=True). The body may call ``FwaiEmit $obj``
# to write one JSON Lines event: {"type":"event","data":...}. The wrapper always ends with exactly
# one result line: {"type":"result","ok":true,"data":...} or {"type":"result","ok":false,...}.
STREAM_WRAPPER_TEMPLATE = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
[Console]::InputEncoding = [System.Text.UTF8Encoding]::new($false)
function FwaiEmit($FwaiEvent) {
    $FwaiLine = [ordered]@{ type = 'event'; data = $FwaiEvent }
    [Console]::Out.WriteLine((ConvertTo-Json -InputObject $FwaiLine -Depth 8 -Compress))
    [Console]::Out.Flush()
}
try {
    $FwaiParams = $null
    $FwaiRaw = [Console]::In.ReadToEnd()
    if ($FwaiRaw) { $FwaiParams = ConvertFrom-Json -InputObject $FwaiRaw }
    $FwaiData = & {
__FIREWALLAI_SCRIPT_BODY__
    }
    $FwaiEnvelope = [ordered]@{ type = 'result'; ok = $true; data = $FwaiData }
} catch {
    $FwaiHresult = 0
    if ($_.Exception -and $_.Exception.HResult) { $FwaiHresult = [int]$_.Exception.HResult }
    $FwaiEnvelope = [ordered]@{
        type = 'result'
        ok = $false
        error = [ordered]@{
            category = [string]$_.CategoryInfo.Category
            error_id = [string]$_.FullyQualifiedErrorId
            hresult = $FwaiHresult
        }
    }
}
[Console]::Out.WriteLine((ConvertTo-Json -InputObject $FwaiEnvelope -Depth 8 -Compress))
[Console]::Out.Flush()
"""

FORBIDDEN_ARGUMENTS = frozenset({"-executionpolicy", "-ep", "-encodedcommand", "-enc", "-file"})
BASE_ARGUMENTS = ("-NoProfile", "-NonInteractive", "-NoLogo", "-Command")

_STDERR_CAP_BYTES = 64 * 1024
_CATEGORY_TO_CODE = {
    "PermissionDenied": CollectorErrorCode.ACCESS_DENIED,
    "SecurityError": CollectorErrorCode.ACCESS_DENIED,
    "ObjectNotFound": CollectorErrorCode.NOT_FOUND,
}


@dataclass(frozen=True, slots=True)
class PowerShellScript:
    """A constant, reviewed, read-only script body (registered in ``scripts.py``)."""

    name: str
    body: str
    allowed_commands: frozenset[str]
    timeout_s: float = 30.0
    max_output_bytes: int = 4 * 1024 * 1024
    streaming: bool = False  # JSON Lines events via FwaiEmit (use PowerShellRunner.run_stream)
    max_line_bytes: int = 1024 * 1024  # streaming only: cap per JSON line
    max_events: int = 10_000  # streaming only: cap on event lines


@dataclass(frozen=True, slots=True)
class RunOutcome:
    data: JsonValue | None = None
    error: CollectorError | None = None


@dataclass(frozen=True, slots=True)
class ExecResult:
    returncode: int | None
    stdout: bytes
    stderr: bytes
    timed_out: bool
    output_too_large: bool


class UnsupportedPlatformError(RuntimeError):
    """Raised when the Windows PowerShell executable cannot be located (non-Windows host)."""


def system_directory() -> Path:
    """Return the Windows system directory (e.g. C:\\Windows\\System32) via the Win32 API."""
    if sys.platform != "win32":
        raise UnsupportedPlatformError("Windows PowerShell is only available on Windows")
    import ctypes  # Windows-only API access

    buffer = ctypes.create_unicode_buffer(32768)
    length = ctypes.windll.kernel32.GetSystemDirectoryW(buffer, len(buffer))
    if length == 0 or length >= len(buffer):
        raise UnsupportedPlatformError("GetSystemDirectoryW failed")
    return Path(buffer.value)


def system_powershell_path() -> Path:
    """Absolute path of Windows PowerShell 5.1."""
    path = system_directory() / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    if not path.is_file():
        raise UnsupportedPlatformError("powershell.exe not found in the system directory")
    return path


def render_script(script: PowerShellScript) -> str:
    """Insert a constant script body into the constant wrapper."""
    if _BODY_MARKER in script.body:
        raise ValueError("script body must not contain the wrapper token")
    template = STREAM_WRAPPER_TEMPLATE if script.streaming else WRAPPER_TEMPLATE
    return template.replace(_BODY_MARKER, script.body)


def build_environment(system_dir: Path, base: Mapping[str, str] | None = None) -> dict[str, str]:
    """Child environment with ``PSModulePath`` restricted to the system module directory."""
    env = dict(os.environ if base is None else base)
    for key in list(env):
        if key.upper() == "PSMODULEPATH":
            del env[key]
    env["PSModulePath"] = str(system_dir / "WindowsPowerShell" / "v1.0" / "Modules")
    return env


def _read_limited(
    stream: IO[bytes], limit: int, sink: list[bytes], overflow: threading.Event
) -> None:
    total = 0
    while True:
        chunk = stream.read(65536)
        if not chunk:
            return
        if total + len(chunk) > limit:
            sink.append(chunk[: limit - total])
            overflow.set()
            return
        sink.append(chunk)
        total += len(chunk)


def _drain_stderr(stream: IO[bytes], limit: int, sink: list[bytes]) -> None:
    """Keep up to ``limit`` bytes of stderr, then keep READING and discard the rest.

    Stopping at the cap would let a chatty child block on a full stderr pipe until the timeout
    (found in the M1.3 security review). stderr is never parsed or shown (it is localized and
    may contain host data); only its presence matters.
    """
    kept = 0
    with contextlib.suppress(OSError, ValueError):
        while True:
            chunk = stream.read(65536)
            if not chunk:
                return
            if kept < limit:
                sink.append(chunk[: limit - kept])
                kept += min(len(chunk), limit - kept)


def _write_and_close(stream: IO[bytes], payload: bytes) -> None:
    # If the child exits early, writing fails; the result is judged by its output and exit code.
    with contextlib.suppress(OSError):
        stream.write(payload)
    with contextlib.suppress(OSError):
        stream.close()


def execute(
    args: list[str],
    stdin_bytes: bytes,
    *,
    timeout_s: float,
    max_output_bytes: int,
    env: Mapping[str, str] | None = None,
) -> ExecResult:
    """Run ``args`` with ``shell=False``, a hard timeout, and bounded stdout/stderr capture."""
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    proc = subprocess.Popen(
        args,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        env=None if env is None else dict(env),
        creationflags=creationflags,
    )
    assert proc.stdin and proc.stdout and proc.stderr  # noqa: S101 - PIPE guarantees these
    out_chunks: list[bytes] = []
    err_chunks: list[bytes] = []
    out_overflow = threading.Event()
    threads = [
        threading.Thread(target=_write_and_close, args=(proc.stdin, stdin_bytes), daemon=True),
        threading.Thread(
            target=_read_limited,
            args=(proc.stdout, max_output_bytes, out_chunks, out_overflow),
            daemon=True,
        ),
        threading.Thread(
            target=_drain_stderr,
            args=(proc.stderr, _STDERR_CAP_BYTES, err_chunks),
            daemon=True,
        ),
    ]
    for thread in threads:
        thread.start()

    deadline = time.monotonic() + timeout_s
    timed_out = False
    while proc.poll() is None:
        if out_overflow.is_set():
            break
        if time.monotonic() >= deadline:
            timed_out = True
            break
        time.sleep(0.02)
    if proc.poll() is None:
        proc.kill()
    returncode = proc.wait()
    for thread in threads:
        thread.join(timeout=5)
    return ExecResult(
        returncode=None if (timed_out or out_overflow.is_set()) else returncode,
        stdout=b"".join(out_chunks),
        stderr=b"".join(err_chunks),
        timed_out=timed_out,
        output_too_large=out_overflow.is_set(),
    )


def interpret(result: ExecResult, *, source: str) -> RunOutcome:
    """Turn raw process output into data or a structured, non-localized error."""

    def fail(code: CollectorErrorCode, detail: str) -> RunOutcome:
        return RunOutcome(error=CollectorError(code=code, source=source, detail=detail[:300]))

    if result.timed_out:
        return fail(CollectorErrorCode.TIMEOUT, "process killed after timeout")
    if result.output_too_large:
        return fail(CollectorErrorCode.OUTPUT_TOO_LARGE, "stdout exceeded the size cap")
    text = result.stdout.decode("utf-8", errors="strict").lstrip("\ufeff").strip()
    if not text:
        return fail(
            CollectorErrorCode.EXECUTION_FAILED, f"no output; exit_code={result.returncode}"
        )
    try:
        envelope = json.loads(text)
    except (json.JSONDecodeError, RecursionError):
        return fail(CollectorErrorCode.PARSE_ERROR, "stdout is not a JSON envelope")
    return interpret_envelope(envelope, source=source)


def interpret_envelope(envelope: JsonValue, *, source: str) -> RunOutcome:
    """Interpret a decoded result envelope (shared by the buffered and streaming paths)."""

    def fail(code: CollectorErrorCode, detail: str) -> RunOutcome:
        return RunOutcome(error=CollectorError(code=code, source=source, detail=detail[:300]))

    if not isinstance(envelope, dict) or "ok" not in envelope:
        return fail(CollectorErrorCode.PARSE_ERROR, "unexpected envelope shape")
    if envelope["ok"] is True:
        return RunOutcome(data=envelope.get("data"))
    error = envelope.get("error")
    if not isinstance(error, dict):
        return fail(CollectorErrorCode.PARSE_ERROR, "error envelope without error object")
    category = str(error.get("category", ""))[:60]
    error_id = str(error.get("error_id", ""))[:160]
    hresult = error.get("hresult", 0)
    code = _CATEGORY_TO_CODE.get(category, CollectorErrorCode.EXECUTION_FAILED)
    hresult_text = f"0x{hresult & 0xFFFFFFFF:08X}" if isinstance(hresult, int) else "n/a"
    return fail(code, f"category={category}; error_id={error_id}; hresult={hresult_text}")


class PowerShellRunner:
    """Runs registered, constant, read-only scripts. Never runs caller-supplied script text."""

    def __init__(
        self,
        executable: Path | None = None,
        *,
        system_dir: Path | None = None,
        max_param_bytes: int = 64 * 1024,
    ) -> None:
        self._system_dir = system_dir if system_dir is not None else system_directory()
        self._executable = executable if executable is not None else system_powershell_path()
        if not self._executable.is_absolute():
            raise ValueError("PowerShell executable path must be absolute")
        self._max_param_bytes = max_param_bytes

    @property
    def executable(self) -> Path:
        return self._executable

    def build_args(self, script: PowerShellScript) -> list[str]:
        args = [str(self._executable), *BASE_ARGUMENTS, render_script(script)]
        lowered = {a.lower() for a in args[1:-1]}
        if lowered & FORBIDDEN_ARGUMENTS:  # defense in depth; BASE_ARGUMENTS is constant
            raise ValueError("forbidden PowerShell argument")
        return args

    def encode_params(self, params: Mapping[str, JsonValue] | None) -> bytes:
        if params is None:
            return b""
        payload = json.dumps(dict(params), ensure_ascii=True, allow_nan=False).encode("ascii")
        if len(payload) > self._max_param_bytes:
            raise ValueError("parameters exceed the size limit")
        return payload

    def run(
        self,
        script: PowerShellScript,
        params: Mapping[str, JsonValue] | None = None,
        *,
        source: str,
    ) -> RunOutcome:
        result = execute(
            self.build_args(script),
            self.encode_params(params),
            timeout_s=script.timeout_s,
            max_output_bytes=script.max_output_bytes,
            env=build_environment(self._system_dir),
        )
        return interpret(result, source=source)

    def run_stream(
        self,
        script: PowerShellScript,
        params: Mapping[str, JsonValue] | None = None,
        *,
        source: str,
        on_event: Callable[[JsonValue], None],
        cancel: threading.Event | None = None,
    ) -> RunOutcome:
        """Run a registered streaming script; deliver each validated event to ``on_event``.

        ``on_event`` runs on the calling thread. If it raises, the child process is killed and
        the exception propagates.
        """
        if not script.streaming:
            raise ValueError("run_stream requires a streaming script")
        return execute_stream(
            self.build_args(script),
            self.encode_params(params),
            script=script,
            source=source,
            on_event=on_event,
            cancel=cancel,
            env=build_environment(self._system_dir),
        )


# --- streaming execution ----------------------------------------------------------------------

_Line = tuple[str, bytes]  # ("line" | "too_long" | "too_large" | "eof", payload)


def _read_lines(
    stream: IO[bytes],
    max_line_bytes: int,
    max_total_bytes: int,
    out: "queue.Queue[_Line]",
) -> None:
    """Reader thread: push lines to ``out``.

    Enforces the per-line AND total caps itself, so memory stays bounded even if the consumer is
    slow, and the reader never blocks on a full queue after the process is killed.
    """
    total = 0
    try:
        while True:
            line = stream.readline(max_line_bytes + 1)
            if not line:
                break
            if len(line) > max_line_bytes and not line.endswith(b"\n"):
                out.put(("too_long", b""))
                return
            total += len(line)
            if total > max_total_bytes:
                out.put(("too_large", b""))
                return
            out.put(("line", line))
    except (OSError, ValueError):
        pass  # pipe closed because the process was killed
    out.put(("eof", b""))


def execute_stream(
    args: list[str],
    stdin_bytes: bytes,
    *,
    script: PowerShellScript,
    source: str,
    on_event: Callable[[JsonValue], None],
    cancel: threading.Event | None = None,
    env: Mapping[str, str] | None = None,
) -> RunOutcome:
    """Run ``args`` (shell=False) and validate a JSON Lines stream with hard limits.

    Protocol: zero or more ``{"type":"event","data":...}`` lines, then exactly one
    ``{"type":"result",...}`` line, then EOF. Anything else is a structured error.
    """

    def fail(code: CollectorErrorCode, detail: str) -> RunOutcome:
        return RunOutcome(error=CollectorError(code=code, source=source, detail=detail[:300]))

    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    proc = subprocess.Popen(
        args,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        env=None if env is None else dict(env),
        creationflags=creationflags,
    )
    assert proc.stdin and proc.stdout and proc.stderr  # noqa: S101 - PIPE guarantees these
    lines: queue.Queue[_Line] = queue.Queue()  # bounded by the reader's total cap
    err_chunks: list[bytes] = []
    threads = [
        threading.Thread(target=_write_and_close, args=(proc.stdin, stdin_bytes), daemon=True),
        threading.Thread(
            target=_read_lines,
            args=(proc.stdout, script.max_line_bytes, script.max_output_bytes, lines),
            daemon=True,
        ),
        threading.Thread(
            target=_drain_stderr,
            args=(proc.stderr, _STDERR_CAP_BYTES, err_chunks),
            daemon=True,
        ),
    ]
    for thread in threads:
        thread.start()

    deadline = time.monotonic() + script.timeout_s
    events = 0
    result: RunOutcome | None = None
    outcome: RunOutcome | None = None
    try:
        while outcome is None:
            if cancel is not None and cancel.is_set():
                outcome = fail(CollectorErrorCode.CANCELLED, "cancelled by the caller")
                break
            if time.monotonic() >= deadline:
                outcome = fail(CollectorErrorCode.TIMEOUT, "process killed after timeout")
                break
            try:
                kind, raw = lines.get(timeout=0.05)
            except queue.Empty:
                continue
            if kind == "too_long":
                outcome = fail(CollectorErrorCode.OUTPUT_TOO_LARGE, "stream line exceeded cap")
                break
            if kind == "too_large":
                outcome = fail(CollectorErrorCode.OUTPUT_TOO_LARGE, "stream exceeded total cap")
                break
            if kind == "eof":
                if result is not None:
                    outcome = result
                else:
                    try:
                        code: int | None = proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        code = None  # stdout closed but the process is still running
                    outcome = fail(
                        CollectorErrorCode.EXECUTION_FAILED
                        if code != 0
                        else CollectorErrorCode.PARSE_ERROR,
                        f"stream ended without a result line; exit_code={code}",
                    )
                break
            try:
                text = raw.decode("utf-8", errors="strict").lstrip("\ufeff").strip()
            except UnicodeDecodeError:
                outcome = fail(CollectorErrorCode.PARSE_ERROR, "stream line is not UTF-8")
                break
            if not text:
                continue
            if result is not None:
                outcome = fail(CollectorErrorCode.PARSE_ERROR, "data after the result line")
                break
            try:
                message = json.loads(text)
            except (json.JSONDecodeError, RecursionError):
                outcome = fail(CollectorErrorCode.PARSE_ERROR, "stream line is not JSON")
                break
            if not isinstance(message, dict):
                outcome = fail(CollectorErrorCode.PARSE_ERROR, "stream line is not an object")
                break
            line_type = message.get("type")
            if line_type == "event" and set(message) == {"type", "data"}:
                events += 1
                if events > script.max_events:
                    outcome = fail(CollectorErrorCode.OUTPUT_TOO_LARGE, "too many stream events")
                    break
                on_event(message["data"])
            elif line_type == "result":
                body = {k: v for k, v in message.items() if k != "type"}
                result = interpret_envelope(body, source=source)
            else:
                outcome = fail(CollectorErrorCode.PARSE_ERROR, "unexpected stream line schema")
                break
    finally:
        if proc.poll() is None:
            proc.kill()
        with contextlib.suppress(subprocess.TimeoutExpired):
            proc.wait(timeout=10)
        for stream in (proc.stdout, proc.stderr):
            with contextlib.suppress(OSError):
                stream.close()
        for thread in threads:
            thread.join(timeout=5)
    return outcome
