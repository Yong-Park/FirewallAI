# ADR 0022: psutil for local endpoint and process collection

- **Status:** Accepted
- **Decision ID:** D22 (continues after D21; see the [living index](README.md))
- **Date:** 2026-10-15
- **Proposed by:** claude-code
- **Decided by:** human, 2026-10-15. Accepted psutil 7.2.2 as the M1.4 endpoint collection dependency, with its documented rationale, licensing, maintenance considerations, privacy constraints, and typing limitations (after choosing psutil as decision Q1 and conditionally approving the psutil-only mypy configuration).

## 1. Problem
M1.4 needs local TCP/UDP sockets (IPv4 and IPv6, listening, bound, and connections) with their owning PIDs, plus the name and image path of each owning process.
- It must run as a **standard user**, **read-only**, with **no network access**.
- It must finish within the M1.4 snapshot target (< 1 s), which is separate from N-04.
- The planning stack ([04](../planning/04-technology-evaluation.md), [06 §1](../planning/06-windows-integration.md)) named psutil, but no ADR covered it, and it was not a project dependency before M1.4.

## 2. Decision (recommended)
Use **psutil 7.2.2**, pinned exactly, as the source of socket tables and per-process name and image path. Its use is confined to `collectors/windows/network_endpoints.py`.
- **Calls used (read-only only):** `psutil.net_connections("inet")` (Windows `GetExtendedTcpTable` / `GetExtendedUdpTable`) and `psutil.Process(pid).name() / .exe()` inside `oneshot()`.
- **Not used:**
  - command lines, owners, environment, and creation time;
  - any process control (kill, suspend, priority, affinity).
- **Service names** do not come from psutil. They come from the registered read-only `WIN32_SERVICES` CIM query through the audited PowerShell runner (decision Q2).

## 3. Alternatives considered
| Alternative | Why not chosen |
|---|---|
| **ctypes against iphlpapi / kernel32** (no dependency) | Same underlying API and speed (socket tables in 4–5 ms, measured). But we would parse variable-layout binary structures (`MIB_TCP6ROW_OWNER_PID`, …) ourselves, which is a memory-safety and maintenance risk in first-party code. A standard user also got **access denied for 29–30 of 91 PIDs** with `QueryFullProcessImageNameW`, while psutil's fallback returned paths for all of them on TE-1. |
| **PowerShell `Get-NetTCPConnection` / `Get-NetUDPEndpoint`** via the existing runner (no dependency) | **2.4–4.5 s** wall time including start-up, against the < 1 s target. Row counts also differed from the Windows API (more TCP rows, fewer UDP rows; unexplained `[VERIFY]`). `Win32_Process` returned no `ExecutablePath` for 240 of 569 processes as a standard user. |
| **`types-psutil` stub package** for typing | A second new dependency; deferred by the human (2026-10-15). See §5. |

## 4. Advantages and disadvantages
**Advantages:**
- mature, widely used, and cross-platform;
- handles protected processes better than plain `OpenProcess` for a standard user;
- **no runtime dependencies**;
- a stable `cp37-abi3-win_amd64` wheel that works on CPython 3.12.

**Disadvantages:**
- a compiled C extension, so a larger native attack surface than pure Python;
- no type information (§5);
- it wraps the same non-atomic Windows socket tables, so snapshots are not atomic.

## 5. Security implications
- **License and maintenance:** BSD-3-Clause, compatible with MIT distribution and PySide6 LGPL. It is actively maintained; 7.2.2 was released 2026-01-28.
- **Pinning and verification:**
  - pinned as `psutil==7.2.2` in `pyproject.toml` and hash-locked in `uv.lock`;
  - the locked `win_amd64` sha256 (`eb7e8143…`) matches PyPI;
  - it resolves inside the project's `exclude-newer` window;
  - installed with `uv add` (no other package changed); `uv lock --check` and `uv sync --frozen` are clean;
  - advisories: PyPI lists none for 7.2.2, and OSV's only entry (CVE-2019-18874) affects ≤ 5.6.5;
  - `pip-audit` is not yet installed `[VERIFY when CI exists]`.
- **Confinement:**
  - import-linter contract 5 limits psutil to the Windows endpoint collector;
  - an AST security test allowlists the psutil APIs used and forbids process control, command lines, owners, and environment;
  - every psutil value is converted into strict pydantic models (`RawSocket`, `RawField`, `RawProcess`) before use.
- **Typing:** psutil ships no `py.typed`. The configuration in `pyproject.toml` is limited to psutil:
  - `[[tool.mypy.overrides]] module = ["psutil", "psutil.*"]` with `follow_untyped_imports = true`, so mypy reads psutil's source rather than rejecting the import;
  - `untyped_calls_exclude = ["psutil"]`, which allows calls into psutil's unannotated functions.
  - **Effect:** psutil's API is typed `Any` (for example, `Process(…).name()` is `Any`). First-party strict checks are unchanged; a probe module confirmed that `no-untyped-def`, first-party `no-untyped-call`, `assignment`, `arg-type`, and `no-any-return` are all still reported.
  - **Limitation:** an `Any` from psutil assigned to a typed variable is not checked by mypy. This is mitigated by the runtime validation above.
- **Privacy:**
  - process paths and names, and local and remote addresses, are HOST_SENSITIVE;
  - text output hides remote addresses unless `--show-remote` is given;
  - JSON is labelled sensitive;
  - nothing is logged or uploaded.
- **Process identity is best effort:** a two-snapshot consistency check, not proof (see `collectors/endpoint_assembly.py`).
- **No network access:** psutil reads local OS tables only, and SB-05 tests still pass.

## 6. Performance implications
Measured on TE-1 (2026-10-15), non-elevated:
- **Sockets:** about 0.02 s for two tables.
- **Names and paths:** 0.10–0.19 s for about 90 processes.
- **Snapshot end to end** (including the parallel PowerShell service lookup):
  - 0.69–0.94 s warm;
  - **1.26–1.67 s cold**.
- The < 1 s target is therefore **not consistently met**. The cold cost is PowerShell/CIM start-up, not psutil.
- psutil's `create_time()` was rejected: about 660 ms for about 87 processes as a standard user.

## 7. Validation
- **Unit tests** with injected psutil fakes (`tests/unit/test_endpoint_collector.py`).
- **Security tests** (`tests/security/test_endpoint_collector_security.py`).
- **Windows integration tests** (`tests/integration/test_windows_endpoints.py`).
- **Import contract 5.**
- **Exit criteria for acceptance:**
  - verified on Windows 10 22H2 (VM) as well as Windows 11;
  - `pip-audit` clean once CI exists;
  - a review of psutil upgrades (pin bumps) with the same verification steps.

## 8. What the developer needs to learn
- Windows socket tables (`GetExtendedTcpTable`), PID reuse, and protected processes (PPL).
- psutil `net_connections` / `Process` on Windows: https://psutil.readthedocs.io/
- mypy handling of untyped third-party packages (`follow_untyped_imports`, `untyped_calls_exclude`): https://mypy.readthedocs.io/en/stable/config_file.html

## Open items
- Whether to add `types-psutil` later instead of the mypy overrides (human decision; not now).
- `[VERIFY]` the NetTCPIP vs psutil row-count difference.
- `[VERIFY]` socket ownership semantics for inherited or duplicated socket handles.
- Re-measure on other hardware and Windows 10.
