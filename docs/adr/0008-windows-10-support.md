# ADR 0008: Windows 10 support level

- **Status:** Proposed · **Decision ID:** D8 · **Date:** 2026-10-14 · **Proposed by:** claude-code · **Decided by:** pending

## 1. Problem
Many users still run Windows 10. Mainstream support for Windows 10 ended in October 2025, after which only Extended Security Updates are available [VERIFY ESU terms]. Testing on two operating systems costs effort.

## 2. Decision (recommended)
- **Windows 11 is the primary, fully supported platform.**
- **Windows 10 22H2 is best-effort.** It is tested in a VM before each release, and results are logged. Failures are documented, not release-blocking.
- 32-bit and ARM64 are not supported in v0.1 [ASSUMPTION: Python, PySide6, and PyInstaller x64 only].

## 3. Alternatives considered
- **Windows 11 only.** Excludes a large user base for little saving, because the NetSecurity cmdlets and psutil behave the same on both [ASSUMPTION; verify in a VM].
- **Full Windows 10 support.** Gives a release-blocking commitment on an end-of-life OS.

## 4. Advantages and disadvantages
- **Advantages:** wider reach at low cost.
- **Disadvantages:** an extra VM test pass per release.

## 5. Security implications
FirewallAI should show an informational finding when the OS is out of mainstream support, since that is a host risk. The wording must be factual, not alarmist.

## 6. Performance implications
None expected.

## 7. Validation
Sprint 4 runs the packaging smoke test on Windows 10 22H2 and logs the results.

## 8. What to learn
- Windows servicing channels.
- Feature differences across Windows 10 and 11 for Windows Firewall and Security Center WMI.
