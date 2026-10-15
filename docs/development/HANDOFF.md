# Handoff: last updated 2026-10-15 by claude-code

Active agent lock: RELEASED

> **[Verified]** means it was checked by a command in the session that wrote this section, with the output pasted.
> **[Assumed]** means it was not checked.
> Protocol: [AGENT_WORKFLOW.md](AGENT_WORKFLOW.md).

## Position
- **Sprint 1, M1.5 (first distributable Windows desktop app): implemented and verified as a portable, unsigned development build** on `feat/s1-m1-5-packaging` (from `main` `5eb158e`).
- The human reviewed the report and **authorized the M1.5 commit and `git push -u origin feat/s1-m1-5-packaging`** (2026-10-15). The commit SHA is reported in the session; see `git log`.
- **Not authorized:** merging, opening the PR (the human reviews it separately), a GitHub Release, uploading the unsigned ZIP or executables, changing branch protection, marking ADR 0006 Accepted, and Sprint 2.
- The N-04 gap (rule scan) and the endpoint cold-start gap stay documented limitations.
- M1.4 is merged (PR #7, `5eb158e`). Its full handoff is in git: `git show 5eb158e:docs/development/HANDOFF.md`.
- `main` history: M0 (#1, #2), ADR 0021 (#3), M1.1 (#4), M1.2 (#5), M1.3 (#6), M1.4 (#7). Ruleset 25123659 protects `main` (ADR 0018).

## Git after the M1.4 merge [Verified, 2026-10-15]
```
$ git status --short --untracked-files=all   # on feat/s1-m1-4-network-endpoints, before sync
(empty; no stash entries)
$ git fetch origin                     -> 7e52e93..5eb158e  main
$ git rev-parse c52ed77^{tree} origin/main^{tree}
6f0bff1a...  6f0bff1a...               # merged tree identical to the reviewed commit
$ git switch main && git merge --ff-only origin/main     -> 5eb158e
$ git switch -c feat/s1-m1-5-packaging
```

## Human decisions for M1.5 (2026-10-15)
- **Q1:** PyInstaller 6.22.3 as a development-only dependency, after verification.
- **Q2:** dependency audit and SBOM with uv tooling. Only public package names and versions may go out.
- **Q3:** a one-folder portable x64 development build. The installer is deferred to Sprint 4. **ADR 0006 stays Proposed**; the proposed Accepted wording is drafted for review.
- **Q4:** executable names `FirewallAI.exe` (GUI) and `firewallai-cli.exe` (CLI).
- **Q5:** automated launch/smoke tests plus a manual checklist. **No `--self-test` feature.**
- **Q6:** a local Microsoft Defender scan, as a standard user, with no setting changes and no uploads.
- **Q7:** narrowly scoped cleanup of PyInstaller-specific environment values for the PowerShell child.
- **Q8:** a minimal Windows CI workflow for pull requests:
  - least privilege;
  - SHA-pinned actions;
  - no secrets, artifacts, or releases;
  - required checks not enabled.
- **Q9:** a simple original provisional icon, without an image library.

## Human decisions after the M1.5 report (2026-10-15)
- **Decision 1:** the dedicated `build` dependency group and the isolated `.venv-build` are **approved**. PyInstaller and its build-only dependencies stay out of the runtime bundle.
- **Decision 2:** **ADR 0006 stays Proposed.** It may be accepted only after:
  - the first GitHub Actions CI run succeeds;
  - the manual GUI checklist is completed;
  - any packaging defects found by either are resolved.
  - The drafted Accepted wording stays in the ADR for later review.
- **Decision 3:** **no change to PowerShell module resolution in M1.5.** It is recorded as a separate security review item (below). The runner controls stay as they are.
- **Decision 4:** the manual GUI checklist is authorized but **not yet performed**. Its status is **PENDING**. Instructions and the exact repo-relative executable path (`dist\FirewallAI\FirewallAI.exe`) are in [packaging/BUILD.md](../../packaging/BUILD.md). It must not be marked passed without real results.
- **Decision 5:** commit and push authorized after the final checks.

## Security review item SR-M1.5-01: PowerShell module resolution (open; not changed in M1.5)
- **Observed** on TE-1 (2026-10-15), through the real runner:
  - the runner passes `PSModulePath` = System32 `WindowsPowerShell\v1.0\Modules` only;
  - Windows PowerShell 5.1 inserts `%ProgramFiles%\WindowsPowerShell\Modules` **before** it at start-up;
  - the user-profile module path is not added;
  - `Get-NetFirewallProfile` resolved to the NetSecurity module under System32.
- **Risk:** low. Program Files is admin-writable by default, so a standard-user process can't plant a module there. But a module placed there by an administrator or another installer would be searched first. This has been true since M1.1.
- **Proposed hardening (separate decision, not implemented):** import the required modules (NetSecurity, CimCmdlets) explicitly by full System32 path in the constant scripts, and test that the loaded module path is under System32.
- **Status:** open, for human review. SB-03 wording already corrected.

## Manual GUI checklist: PENDING (human)
Not performed yet. No results are recorded. See packaging/BUILD.md for steps 1–13 and how to record them here.

## M1.5 status [Verified unless marked]
**Implemented:**
- **`pyproject.toml`:**
  - `pyinstaller==6.22.3` in a new **`build`** dependency group (not `dev`, so dev tools can never be bundled);
  - per-file lint ignores for `packaging/smoke/**` (S101, S603, S607, the same as `tests/**`).
- **`.gitignore`:** `.venv-build/`, and an exception for `packaging/firewallai.spec`.
- **`packaging/`:**
  - `firewallai.spec`: two executables sharing one `_internal`; `asInvoker`, `uiAccess=false`; no UPX; version resource; icon; excludes for network clients, async, multiprocessing, and dev tools;
  - `entry_gui.py`, `entry_cli.py`;
  - `buildinfo.py`: version single-sourced and checked against `firewallai.__version__`; the commit read from `.git` without subprocesses;
  - `make_icon.py`: an original slate tile with an amber brick wall and a teal dot; no shield; Qt and a hand-written `.ico`; deterministic;
  - `build.py`: refuses dev environments, `PYTHONPATH`, and non-reproducible settings; licenses, notices, README, build info, SBOM, deterministic ZIP, SHA-256;
  - `verify_build.py`: 28 checks;
  - `smoke/`: 11 frozen-binary tests;
  - `BUILD.md`, including the manual GUI checklist.
- **Runner hardening (Q7)** in `powershell_runner.build_environment`:
  - removes `_PYI_*` and `_MEIPASS2`;
  - when frozen, removes `PATH`, `QT_PLUGIN_PATH`, and `QML2_IMPORT_PATH` entries inside the bundle;
  - nothing else is changed.
- **CI:** `.github/workflows/ci.yml` (**prepared, not run**).
- **Tests:** `tests/unit/test_packaging_helpers.py` (12) and runner hardening tests in `tests/security/test_powershell_runner.py`.
- **Docs:**
  - ADR 0006 implementation notes and proposed Accepted wording (status **unchanged: Proposed**);
  - ADR index note;
  - `security-boundaries.md`: SB-02 implemented; SB-03 correction and hardening; SB-05; SB-13;
  - `module-map.md` (packaging section);
  - README;
  - AI_DEVELOPMENT.md.

## Dependency audit, SBOM, and toolchain [Verified, 2026-10-15]
- **uv 0.12.21:** `uv audit` and `uv export --format cyclonedx1.5` are available. `uv audit` is marked **experimental** by uv.
- **Audit before PyInstaller:** "no known vulnerabilities … in 37 packages".
- **Audit after PyInstaller:** "no known vulnerabilities … in 44 packages" (repeated in the final run).
- **PyInstaller 6.22.3:**
  - uploaded 2026-09-12;
  - GPLv2-or-later with the bootloader exception;
  - PyPI `vulnerabilities` empty; OSV advisories all fixed before 6.0;
  - locked wheel sha256 `500bd58c…` matches PyPI.
  - New transitive packages: altgraph 0.17.5 (MIT), pefile 2024.8.26 (MIT), pywin32-ctypes 0.2.3 (BSD-3-Clause), pyinstaller-hooks-contrib 2026.7 (GPLv2 / Apache-2.0), setuptools 84.0.0 (MIT).
  - `packaging` 26.3 was already locked.
  - **No existing package changed.** All are build-time only, except the bootloader.
- **SBOM:** CycloneDX 1.5 with **8 runtime components**: annotated-types, psutil, pydantic, pydantic-core, pyside6-essentials, shiboken6, typing-extensions, typing-inspection.
  - It contains no local paths or user names.
  - It is not byte-reproducible (random serial number).
- **CI action pins** (each release at least two weeks old):

  | Action | Version | Commit | Note |
  |---|---|---|---|
  | `actions/checkout` | v7.0.1 | `3d3c42e5…` | |
  | `actions/setup-python` | v7.0.0 | `5fda3b95…` | |
  | `astral-sh/setup-uv` | v10.2.0 | `c18668ad…` | v10.3.0 skipped: only 6 days old |

## Build, size, and start-up [Verified, TE-1, Windows 11, standard user]
| Measure | Result |
|---|---|
| Spike (dev environment) | 123 MiB, 289 files; it pulled in mypy, rich, pygments, hypothesis, setuptools, `ssl`, `http` (via pydantic's optional plug-ins). **This is why the isolated `.venv-build` and the excludes exist** |
| Final bundle | **108.1 MiB, 223 files**; ZIP **43.3 MiB** (`FirewallAI-0.1.0.dev0-g5eb158ec-win64-portable.zip`, sha256 `d294330c…`). The commit label is HEAD `5eb158e` plus uncommitted changes, so this artifact is **not** a committed build |
| Build time | 86–103 s |
| Reproducibility | Without fixed settings, 3 of 223 files differed. With `PYTHONHASHSEED=0` + `SOURCE_DATE_EPOCH`, **three builds, including the ZIP, were byte-identical** |
| CLI `--version` | 0.68 s first run from a fresh copy; 0.28–0.31 s warm |
| GUI window visible | 1.35 s first run from a fresh copy; 0.62–0.66 s warm. Not post-reboot cold starts |
| Frozen rule scan | 27.7–29.1 s. **N-04 EXCEEDED** (unchanged) |
| Frozen endpoint snapshot | 0.91–1.57 s across runs. **1 s target not consistently met** (unchanged) |

## Verification of the bundle [Verified]
- **`packaging/verify_build.py dist`: 28/28 checks passed.**
  - Layout.
  - Both executables: `asInvoker` with `uiAccess=false`, the right subsystem, a version resource, an icon, no UPX.
  - **All `firewallai` modules structurally identical to the source.**
  - Forbidden modules absent; no absolute paths; no user name, computer name, or source path in any file.
  - Licenses, notices, README, build info (`signed: false`), SBOM, SHA256SUMS, and the ZIP contents.
- **Mutation checks:**
  - a one-word change in a PowerShell script body in `src` (ActiveStore → PersistentStore) made the integrity check fail for both executables;
  - a planted file containing the user name made the local-data check fail.
  - Both were reverted, and the verifier passed again.

## Smoke tests against the frozen binaries [Verified: `pytest packaging/smoke --bundle dist/FirewallAI`, 11 passed]
- CLI version (no installed Python needed).
- `profiles --json` with `elevated: false`.
- Rules: N-04 reported (EXCEEDED).
- Endpoints: the text hides remote addresses (all connection rows `<hidden>`).
- JSON `sensitivity` block and the stderr privacy note, with and without `--show-remote`.
- Hostile process names escaped in frozen text output.
- **GUI launch (offscreen):** a PowerShell child observed with **no `_PYI_*` variables and no bundle entries in `PATH` or `QT_PLUGIN_PATH`**.
- GUI start to first collection: 0.47–0.49 s.
- **Install directory unchanged** after CLI and GUI runs.
- Runs from a path with spaces and non-ASCII characters (`Carpeta con espacios Ñandú`).
- No executable-name collision.

## Microsoft Defender [Verified, standard user, no settings changed]
- `MpCmdRun.exe -Scan -ScanType 3 -File <dist>`: **"found no threats"**, exit 0, 6.1 s.
- Engine 1.1.26090.9; signatures 1.461.40.0 (updated 2026-10-15); real-time protection on.
- Nothing was uploaded.

## New findings and deviations
1. **PyInstaller moved from `dev` to a dedicated `build` group, built from an isolated environment.** It is still development-only, and this is why the bundle contains no dev tools. **Approved by the human (decision 1).**
2. **PowerShell 5.1 rewrites `PSModulePath`.**
   - The runner passes only the System32 module path. A probe through the real runner showed that PowerShell sees `%ProgramFiles%\WindowsPowerShell\Modules` *before* System32. The user-profile path was not added, and NetSecurity loaded from System32.
   - This has been true **since M1.1**; SB-03's wording is corrected.
   - Risk is low: Program Files is admin-writable by default.
   - Not changed in M1.5 (decision 3). Tracked as **SR-M1.5-01** (above).
3. **Reading another process's environment** (psutil) gave an empty `PSModulePath` for the PowerShell child, so it is unreliable after PowerShell modifies its environment. The frozen smoke test therefore checks only the PyInstaller-related values.
4. **Reproducibility needs `PYTHONHASHSEED=0` and `SOURCE_DATE_EPOCH`**, which means running with `-s -P` instead of `-I`. `build.py` enforces this and refuses `PYTHONPATH`.
5. **`build-info.json` can't detect uncommitted changes** (no subprocess to git). Release builds must come from a clean checkout; CI does that.
6. **CI integration tests are excluded:** GitHub's Windows runners execute as admin, and the integration and frozen smoke tests assert standard-user execution. CI builds and verifies the bundle and runs a fixture-based frozen CLI check instead.

## Tests and quality gates [Verified, 2026-10-15, uncommitted tree on `5eb158e`, TE-1, non-elevated]
| Command | Result |
|---|---|
| `uv run --frozen pytest -q -s` (source) | **399 passed** in 118.28 s (security 78, integration/windows 13, unit 281, UI 27) |
| `ruff check` / `ruff format --check` / `mypy` / `lint-imports` / `uv lock --check` / `uv audit --frozen` | All checks passed / 83 files formatted / no issues in 43 source files / 5 kept, 0 broken / resolved 45 packages / no known vulnerabilities in 44 packages |
| `packaging/verify_build.py dist` (frozen bundle) | 28/28 checks passed |
| `pytest packaging/smoke --bundle dist/FirewallAI` (frozen binaries) | **11 passed** |
| **Pre-commit re-run (2026-10-15, after the human's final decisions)** | Source suite **399 passed** in 109.50 s; ruff, format (84 files), mypy (43), 5 contracts, lock, audit (44 packages) clean; `verify_build.py` exit 0 (28/28); frozen smoke **11 passed** (frozen rule scan 27.9 s, N-04 EXCEEDED; frozen endpoints 0.90 s; GUI to first collection 0.43 s); source endpoint snapshot 1.00 s cold (EXCEEDS) / 0.75 / 0.79 s |
| Suppressions vs `main` | `noqa` src 8/8, tests 0/0, packaging 0; `type: ignore` src 0/0, tests 4/4; skip/xfail 1/1 (unchanged) |
| Source-run measurements in the same suite | rule scan 29.97 s (**N-04 EXCEEDED by 20.0 s**); endpoint snapshot 1.15 s cold (exceeds) / 0.78 / 0.82 s; network tab max GUI gap 72 ms |

**Not run / not executable here:**
- the **CI workflow** (only runs on a PR; local PowerShell 7 not installed, so its `pwsh` step wasn't executed locally);
- the **manual GUI checklist** (human);
- **clean Windows 11 VM** and **clean Windows 10 22H2** (Hyper-V pending);
- **SmartScreen** behaviour of a downloaded ZIP;
- a **post-reboot cold start**.
- No claim of clean-VM or Windows 10 compatibility is made.

## Known limitations and release blockers
- **N-04 not met** (rule scan about 27–30 s against 10 s). It is a documented limitation, not a waiver. The **endpoint snapshot** misses 1 s on cold starts.
- **Unsigned** (ADR 0007: SignPath after the first public release), so SmartScreen will warn on downloaded copies. **Not ready for public distribution.**
- **No installer yet** (Sprint 4). The portable folder is user-writable; no elevated component may ever run from it (SB-13).
- **Clean-VM and Windows 10 validation missing.** CI is prepared but not run.
- **v0.1 features still missing:** onboarding, reports, verdict engine, storage.
- The ZIP is about 43 MiB; Qt is about 73 MiB of the unpacked bundle.

## Pending items for the human
1. Authorize and review the M1.5 PR. **The first CI run happens on that PR.** The merge decision is yours.
2. Perform the **manual GUI checklist** (PENDING).
3. **ADR 0006:** decide on acceptance only after a successful CI run, the completed checklist, and any packaging fixes.
4. **SR-M1.5-01** (PowerShell module resolution): a separate security review.
5. Still open: Hyper-V / Windows 10 VMs, D17 (Codex), an N-04 plan, and whether to enable CI as a required check (repository settings: human only).

## M1.5 commit (authorized by the human 2026-10-15)
```
build(packaging): add M1.5 portable one-folder Windows development build

PyInstaller 6.22.3 (dedicated "build" group, isolated build env) producing
FirewallAI.exe (GUI) and firewallai-cli.exe (CLI) in one asInvoker, non-UPX
one-folder bundle with version resources, an original provisional icon,
third-party licenses, CycloneDX SBOM and SHA-256 sums; reproducible build
settings; bundle verifier (code identical to source, no network-client or dev
modules, no local data); frozen smoke tests; runner strips PyInstaller-specific
environment values from the PowerShell child; minimal SHA-pinned Windows CI
(pull requests, read-only). Unsigned development build, not a public release.
N-04 and the endpoint cold-start target remain unmet.

AI-Agent: claude-code
Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
```

## Next steps
1. The human opens and reviews the PR; the first CI run follows. Fix any CI or packaging defects found.
2. The manual GUI checklist; then the ADR 0006 decision. Do not start Sprint 2 without authorization.

## Resume commands
```
git fetch origin
git switch feat/s1-m1-5-packaging
git status --short
uv sync --frozen
uv run --frozen pytest -q
# packaging: see packaging/BUILD.md
```
