# ADR 0006: v0.1 distribution: PyInstaller one-dir + Inno Setup per-user installer

- **Status:** **Accepted for the PyInstaller one-folder DEVELOPMENT distribution only** (human, 2026-10-15). **Public release is NOT approved.** · **Decision ID:** D6 · **Date:** 2026-10-14 · **Proposed by:** claude-code · **Decided by:** human, 2026-10-15 (see "Decision record")

## 1. Problem
Users must be able to install FirewallAI without Python or dev tools. v0.1 is read-only and needs no admin rights, so the installer shouldn't require them either.

## 2. Decision (recommended)
- **PyInstaller one-dir** bundle wrapped in an **Inno Setup per-user** installer (`PrivilegesRequired=lowest`, installs under `%LOCALAPPDATA%\Programs\FirewallAI`).
- Built in GitHub Actions from the lockfile.
- Published on **GitHub Releases** with SHA-256 checksums, a CycloneDX SBOM, and GitHub artifact attestations.
- The first releases are unsigned until [ADR 0007](0007-code-signing.md) is resolved.

## 3. Alternatives considered
- **PyInstaller one-file:** unpacks to `%TEMP%` on every launch, which is slower and triggers more AV heuristics.
- **Nuitka:** compiles to C, may start faster and get fewer AV hits, but builds are slower. Benchmark it in v0.3 [NEEDS PROTOTYPE].
- **WiX MSI:** better for enterprise or GPO deployment and service installation. Reconsider at v0.4/v0.5, when a per-machine install is needed.
- **MSIX:** its containerization conflicts with firewall and service access, so not suitable.

## 4. Advantages and disadvantages
- **Advantages:** installs without admin rights, simple scripting, and familiar installer UX.
- **Disadvantages:** the per-user install directory is user-writable (see Security). Bundling Python is **not** automatically portable: Qt plugins and VC++ runtime DLLs must be bundled, and paths can break.

## 5. Security implications
- **DLL hijacking (CWE-427):** a user-writable install directory means any process running as that user can plant DLLs. v0.1 runs unelevated, so this gives no privilege gain, but it is still a persistence and tampering vector.
  - **Rule: no elevated component may ever load from the per-user directory.** v0.4+ helpers and services require a per-machine install under `Program Files`.
- Unsigned binaries get SmartScreen warnings, and users must be told how to verify checksums.
- No auto-updater in v0.1, which avoids an update-channel attack surface.

## 6. Performance implications
One-dir starts faster than one-file. Bundle size is expected to be about 100–200 MB with Qt [NEEDS PROTOTYPE].

## 7. Validation
On clean Windows 11 (required) and Windows 10 22H2 (best-effort) Hyper-V VMs:
1. Install, run a scan, export a report, uninstall.
2. Confirm no leftover files except the user data directory, if the user chose to keep it.
3. Log the results in a checklist.

## 8. What to learn
- How PyInstaller's bootloader works.
- The Windows DLL search order and `SetDefaultDllDirectories`.
- Per-user vs. per-machine install semantics.
- Inno Setup scripting.

## M1.5 implementation notes (2026-10-15; status unchanged: Proposed)
The one-folder part of this decision was implemented and measured in M1.5 as a **portable ZIP development build**. The Inno Setup installer is still deferred to Sprint 4. Details: [packaging/BUILD.md](../../packaging/BUILD.md).

- **Toolchain:**
  - PyInstaller 6.22.3 in a dedicated `build` dependency group (human decision Q1), all hash-locked;
  - built from an isolated environment (`.venv-build`) with runtime dependencies and PyInstaller only;
  - `uv audit` clean (44 packages); CycloneDX 1.5 SBOM via `uv export` (8 runtime components).
- **Layout:** `FirewallAI.exe` (windowed) and `firewallai-cli.exe` (console) share one `_internal` directory, plus licenses, third-party notices, a README, `build-info.json`, and the SBOM.
- **Measured on TE-1** (Windows 11, standard user):

  | Measure | Result |
  |---|---|
  | Bundle | 108.1 MiB, 223 files |
  | ZIP | 43.3 MiB |
  | Build time | 86–103 s |
  | CLI `--version` | 0.68 s first run from a fresh copy; about 0.29 s warm |
  | GUI window visible | 1.35 s first run; about 0.63 s warm (not post-reboot cold starts) |

- **Reproducibility:**
  - with `PYTHONHASHSEED=0` and `SOURCE_DATE_EPOCH`, three builds (including the ZIP) were byte-identical;
  - without them, 3 of 223 files differed. `build.py` enforces the settings.
  - Only verified on one machine and one environment.
- **Security:**
  - both executables: `asInvoker` manifest with `uiAccess="false"`, no UPX;
  - `ssl`, `http`, `urllib.request`, `asyncio`, `multiprocessing`, and dev tools are excluded and verified absent;
  - every bundled `firewallai` module is verified structurally identical to the reviewed source, including the PowerShell script bodies (`packaging/verify_build.py`, mutation-checked);
  - PyInstaller-specific environment values are stripped from the PowerShell child (human decision Q7).
- **Antivirus:** a local Microsoft Defender custom scan as a standard user (engine 1.1.26090.9, signatures 1.461.40.0) found no threats. Nothing was uploaded to third-party scanners.
- **Not yet validated:** clean Windows 11 VM, clean Windows 10 22H2, the SmartScreen behaviour of a downloaded ZIP, the installer, signing, and CI execution.

## Acceptance review (2026-10-15, before the decision; kept for history)
The human set three conditions for accepting the one-folder portable development approach (M1.5 decision 2):

| Condition | Status | Evidence |
|---|---|---|
| 1. A GitHub Actions CI run succeeds | **Met**, after one fix | The first run (`5822cd9`, run 38807641539) **failed**: the bundle privacy check gave a false positive on pydantic-core's upstream build paths. The fix `9af1f96` (run 38810306571) **passed both jobs** ("Gates and tests", "Build and verify the portable bundle"). Merged as PR #8 (`6b150a3`) |
| 2. The manual GUI checklist is completed | **Partly met** | The human reported **7 of 7 basic checks PASS** (startup, profiles, rules, network, cancellation, resize/navigation, shutdown/restart). **Still pending:** DPI scaling at 100/150/200 %, keyboard-only operation, closing during collection, related-rules panel details, and a manual install-folder check (that one is verified automatically) |
| 3. Packaging defects found are resolved | **Met** | The one defect (the CI privacy false positive) is fixed with provenance-aware matching and 28 regression tests. No packaging defect was reported from the manual checks |

**Out of scope for this acceptance; stays a release gate:**
- §7 clean-VM validation (Windows 11 required, Windows 10 22H2 best-effort);
- the Inno Setup installer (Sprint 4);
- signing ([ADR 0007](0007-code-signing.md)).

## Decision record (human, 2026-10-15)
**Accepted, for the development distribution only.** v0.1 is built as a PyInstaller **one-folder** bundle (`FirewallAI.exe` and `firewallai-cli.exe` sharing `_internal`):
- built from the hash-locked lockfile in an isolated build environment, with reproducible settings;
- checked by an automated bundle verifier, with a CycloneDX SBOM and SHA-256 checksums;
- verified by CI on every pull request.

It may be distributed **only as an unsigned portable ZIP for development and testing**. **Public release is not approved.**

**Acceptance evidence:**
1. **CI:** met. PR #8's CI passed both jobs at `9af1f96` (after one fixed false positive).
2. **Manual GUI checks:** **basic 7/7 PASS**. Also PASS:
   - DPI scaling at 100/150/200 %;
   - keyboard-only navigation;
   - closing during an active collection;
   - the related firewall rules panel;
   - the N-04 timing indication (full rule scan 27.9 s against 10 s, warning shown);
   - the portable-folder check (no new files).

   The detailed matrix has **8 of 13 rows PASS**. **Rows 1, 3, 5, 8, and 9 are partly verified**, with sub-items **not independently confirmed**:
   - no console window and the window title;
   - cancel on the Rules tab and the cancelled status text;
   - resizing during an active collection;
   - cancel on the Network tab with partial results;
   - endpoint filters, sorting, and remote addresses in the GUI.

   See `packaging/BUILD.md`.
3. **Packaging defects:** resolved; no new defects reported.

The human accepted the development distribution **with these residual manual-verification gaps documented**. They are not claimed as passed and must be closed before any public release (gate 7).

**Public-release gates** (all required before any public release; none waived):
1. The Inno Setup per-user installer and uninstall flow (Sprint 4).
2. The §7 clean-VM validation: Windows 11 (required) and Windows 10 22H2 (best-effort, logged).
3. Code signing per [ADR 0007](0007-code-signing.md), or an explicitly approved unsigned-release decision with SmartScreen documentation.
4. Security review item SR-M1.5-01 (PowerShell module resolution) resolved or explicitly accepted.
5. A human decision on the N-04 performance gap (full rule scan about 27–30 s against 10 s) and the inconsistent endpoint cold-start timing. These remain **unmet and documented**, not waived.
6. The human publishes the release. Agents never publish.
7. The unverified sub-items of detailed checklist rows 1, 3, 5, 8, and 9 are verified (`packaging/BUILD.md`).
