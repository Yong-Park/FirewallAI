# 14: Packaging, Installer, and Distribution

Status: Approved plan rev. 3, frozen snapshot. Covers deliverable (13) and rev. 2 requirement §2. Decisions: [ADR 0006](../adr/0006-v0-1-distribution.md), [0007](../adr/0007-code-signing.md), [0008](../adr/0008-windows-10-support.md).

## 1. Pipeline (v0.1)
```
GitHub Actions (windows-latest)
  uv sync --frozen  →  tests + security gates  →  PyInstaller one-dir (pinned spec)
  →  Inno Setup per-user installer  →  SHA-256 checksums + CycloneDX SBOM
  →  GitHub artifact attestation  →  draft GitHub Release (human publishes)
```
The human publishes every release. Agents never publish releases.

## 2. Bundling Python is not automatically secure or portable

| Concern | Mitigation |
|---|---|
| DLL search-order hijacking (CWE-427) in a user-writable per-user install directory | No elevated code ever runs from it; call `SetDefaultDllDirectories` early [VERIFY what PyInstaller's bootloader does]; privileged components install per-machine (v0.4+) |
| Missing VC++ runtime or Qt plugins (platforms, styles, imageformats) | PyInstaller PySide6 hooks; test on a **clean** VM, not the dev machine |
| Antivirus false positives (packed Python apps are common in malware) | One-dir (not one-file); signing when available; submit false positives to vendors; documented in the release notes |
| SmartScreen "unknown publisher" | Signing ([ADR 0007](../adr/0007-code-signing.md)); until then, document checksum and attestation verification |
| Long paths, non-ASCII usernames | Test with a user profile path that has spaces and non-ASCII characters (e.g. a test account such as `C:\Users\Test User Ñandú`) |
| High-DPI and mixed-DPI displays | Qt high-DPI settings; manual check at 100%, 150%, and 200% |
| LGPL compliance (PySide6) | Dynamic linking (the default with one-dir); ship license notices; document how to replace the Qt libraries |
| Reproducibility | Pinned Python, lockfile, and PyInstaller version; `SOURCE_DATE_EPOCH`; best-effort, limits documented |

## 3. Installer UX
- **Install:** per-user, no admin rights, Start Menu shortcut, optional desktop shortcut. No services, drivers, or firewall changes in v0.1.
- **First run (onboarding):** what FirewallAI collects; that it is read-only; that nothing leaves the PC; that AI is off and how to enable local AI later (v0.2); where data is stored.
- **Uninstall:** removes the program files and asks "Keep scan history and reports?" (`%LOCALAPPDATA%\FirewallAI`). Never touches firewall rules.
- **Updates:** none automatic in v0.1. Users check GitHub Releases.

## 4. Later versions
- **v0.4 (elevated helper)** and **v0.5 (service):** per-machine install under `Program Files`. Re-evaluate WiX MSI vs. Inno Setup at that point. The service installer must be signed.
- **Nuitka** evaluation in v0.3: compare start time, size, AV detection rate, and build time [NEEDS PROTOTYPE].
- **Tray app and auto-start** (v0.5): opt-in only.

## 5. Code signing
See [ADR 0007](../adr/0007-code-signing.md):
1. SignPath Foundation (free for OSI-licensed OSS; needs an existing release and an automated build).
2. An OV certificate from a CA that validates applicants in Guatemala [VERIFY].
3. Azure Artifact Signing is **not eligible** (the developer is in Guatemala; individuals must be in the US or Canada, and Guatemala is not on the organization country list).

## 6. Validation checklist (per release)
- [ ] Clean Windows 11 VM: install, scan, export (HTML and PDF), uninstall. Leftovers checked.
- [ ] Clean Windows 10 22H2 VM: same steps (best-effort; results logged).
- [ ] Checksums match. SBOM attached. Attestation verifiable (`gh attestation verify`).
- [ ] No network connections observed during the scan (Resource Monitor).
- [ ] Results recorded in the release notes and HANDOFF.md.
