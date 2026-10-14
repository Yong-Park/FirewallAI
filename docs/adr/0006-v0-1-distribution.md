# ADR 0006: v0.1 distribution: PyInstaller one-dir + Inno Setup per-user installer

- **Status:** Proposed · **Decision ID:** D6 · **Date:** 2026-10-14 · **Proposed by:** claude-code · **Decided by:** pending

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
