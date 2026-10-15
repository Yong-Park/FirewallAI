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
import subprocess
import sys
import threading
import time
from collections.abc import Mapping
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
    return WRAPPER_TEMPLATE.replace(_BODY_MARKER, script.body)


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
    err_overflow = threading.Event()
    threads = [
        threading.Thread(target=_write_and_close, args=(proc.stdin, stdin_bytes), daemon=True),
        threading.Thread(
            target=_read_limited,
            args=(proc.stdout, max_output_bytes, out_chunks, out_overflow),
            daemon=True,
        ),
        threading.Thread(
            target=_read_limited,
            args=(proc.stderr, _STDERR_CAP_BYTES, err_chunks, err_overflow),
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
    except json.JSONDecodeError:
        return fail(CollectorErrorCode.PARSE_ERROR, "stdout is not a JSON envelope")
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
