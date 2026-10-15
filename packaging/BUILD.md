# Building the FirewallAI portable development bundle (M1.5)

This produces an **unsigned, portable, one-folder Windows x64 development build**. It is **not a public release**: it is not code-signed, not published, and not uploaded anywhere. The decision record is [ADR 0006](../docs/adr/0006-v0-1-distribution.md) (Proposed). The installer is deferred to Sprint 4.

## What you get
```
dist/
  FirewallAI/                      the portable folder (about 108 MiB)
    FirewallAI.exe                 GUI, no console
    firewallai-cli.exe             CLI: profiles | rules | endpoints
    _internal/                     Python runtime, Qt, dependencies (shared by both executables)
    licenses/  THIRD_PARTY_NOTICES.txt  README.txt  build-info.json  sbom.cdx.json
  FirewallAI-<version>-g<commit>-win64-portable.zip
  FirewallAI-<version>-g<commit>-win64-portable.sbom.cdx.json
  SHA256SUMS.txt
```
Both executables use an `asInvoker` manifest: they run as a standard user and never ask for administrator rights. Neither writes into its own folder.

## Build (PowerShell, from the repository root)
```powershell
# 1. Isolated build environment: runtime dependencies + the "build" group (PyInstaller) only.
#    Dev tools (mypy, pytest, ruff, ...) are never in it, so they can't end up in the bundle.
$env:UV_PROJECT_ENVIRONMENT = ".venv-build"; uv sync --frozen --no-default-groups --group build; Remove-Item Env:UV_PROJECT_ENVIRONMENT

# 2. Dependency audit (OSV; sends only public package names and versions) and SBOM.
uv audit --frozen
uv export --frozen --no-default-groups --format cyclonedx1.5 -o build/sbom.cdx.json

# 3. Reproducible build. -s -P (not -I): -I would ignore PYTHONHASHSEED. PYTHONPATH must be unset.
$env:PYTHONHASHSEED = "0"; $env:SOURCE_DATE_EPOCH = "315532800"
.venv-build\Scripts\python.exe -s -P packaging\build.py --sbom build\sbom.cdx.json
Remove-Item Env:PYTHONHASHSEED; Remove-Item Env:SOURCE_DATE_EPOCH

# 4. Verify the bundle (exit code 1 on any failure).
.venv-build\Scripts\python.exe -I packaging\verify_build.py dist

# 5. Smoke-test the frozen executables (standard user; runs a real rule scan, about 30 s).
uv run --frozen pytest packaging/smoke -p no:cacheprovider -s --bundle dist/FirewallAI
```
`build.py` refuses to run if dev tools are importable, if `PYTHONPATH` is set, or without the reproducibility settings. Build from a clean, committed checkout: `build-info.json` records the commit read from `.git` and cannot detect uncommitted changes.

## What `verify_build.py` checks
1. Layout: only the expected top-level entries; no sources, tests, VCS, env, or scratch files.
2. Both executables: `asInvoker` manifest (`uiAccess="false"`), GUI or console subsystem, version resource matching `pyproject.toml`, an icon, and no UPX packing.
3. **Code integrity:** every `firewallai` module inside each executable is structurally identical to the reviewed source (bytecode, constants including the registered PowerShell script bodies, names, line tables).
4. Attack surface: `ssl`, `http`, `urllib.request`, `asyncio`, `multiprocessing`, other network clients, and dev tools are absent.
5. No local data: no absolute source paths in code objects; the build user name, computer name, and source directory appear in no bundled file.
6. Licenses for every bundled component, the LGPL replaceability notice, README, `build-info.json` (`signed: false`), the SBOM, SHA-256 sums, and a ZIP with exactly the bundle.

## Running a downloaded or copied build
- The build is **unsigned**. If the ZIP came from a download, Windows SmartScreen may show "Windows protected your PC". Check the SHA-256 first (`Get-FileHash <zip> -Algorithm SHA256`, compared with `SHA256SUMS.txt` from a trusted channel).
- Extract anywhere you can write, for example under `%LOCALAPPDATA%`. No administrator rights are needed. Delete the folder to remove it.
- The folder is user-writable: other programs running as the same user could modify it. This gives them no elevation, because FirewallAI never runs elevated (see ADR 0006 §5).

## Manual GUI checklist (decision Q5: automated launch tests plus this checklist)
**Status: PENDING.** Authorized by the human on 2026-10-15; not yet performed. Do not record it as passed without real results.

### How to run it
1. Build and verify the bundle (steps 1-4 above), or use the existing local build.
2. Start the GUI **as a standard user**, without "Run as administrator", from the repository root:
   ```powershell
   .\dist\FirewallAI\FirewallAI.exe
   ```
   The executable is `dist\FirewallAI\FirewallAI.exe` inside your clone of the repository. The CLI is next to it: `dist\FirewallAI\firewallai-cli.exe`.
3. Optional: open Task Manager → Details. While collecting, check that `powershell.exe` children appear and disappear, and that no extra console windows open.
4. Work through the list below. Write down **pass / fail / not tested**, plus a note for anything unexpected.
5. Record the results in `docs/development/HANDOFF.md` (section "Manual GUI checklist"), with the date, Windows version, display scaling, and bundle commit (from `build-info.json`). Only the human reviewer marks this checklist complete.

### Checklist
| # | Step | Expected | Result |
|---|---|---|---|
| 1 | Start `FirewallAI.exe` | Window opens; no console window; title "FirewallAI (read-only)" | pending |
| 2 | Wait for the Profiles tab | Domain, Private, and Public profiles load; no console flash | pending |
| 3 | Rules tab → **Collect rules**, then **Cancel** after a few seconds | Collection stops; status says incomplete/cancelled; window stays usable | pending |
| 4 | Rules tab → **Collect rules** to completion (about 30 s) | Rules listed; the timing line shows the N-04 status (expected: **EXCEEDED**); "No verdicts" | pending |
| 5 | During step 4, drag and resize the window | The window keeps responding (no "Not responding") | pending |
| 6 | Network tab **before** any rule scan in a fresh session: **Collect endpoints**, select a row | Default filter "Listening TCP and bound UDP"; panel says related rules are **not available** and that no rule scan is started automatically | pending |
| 7 | Network tab after step 4: select a listening/bound endpoint | Panel shows Related / Related with unevaluated conditions / Cannot evaluate / Not related, with the disclaimer; no claims of reachability or permission | pending |
| 8 | Network tab → **Collect endpoints**, then **Cancel** immediately | No freeze; the result is cancelled or partial, with limitations shown | pending |
| 9 | Switch the filter to "TCP connections" and "All endpoints"; sort a column | Instant; remote addresses are visible in the GUI (they are hidden only in CLI text output) | pending |
| 10 | Display scaling 100 %, 150 %, 200 % (Settings → Display; sign out if Windows asks) | Text readable, nothing clipped | pending |
| 11 | Keyboard only: Tab / Shift+Tab, Ctrl+Tab between tabs, Alt+underlined letters | Every control is reachable | pending |
| 12 | Close the window **during** a rule collection | The process exits within a few seconds; no `powershell.exe` left in Task Manager | pending |
| 13 | After closing: check the `dist\FirewallAI` folder | No new files (no logs, caches, or settings written there) | pending |

## Not yet covered
Clean Windows 11 VM and clean Windows 10 22H2 tests (Hyper-V availability pending), code signing ([ADR 0007](../docs/adr/0007-code-signing.md)), the installer (Sprint 4), and a running CI workflow (prepared in `.github/workflows/ci.yml`, not yet run).
