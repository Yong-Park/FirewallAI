# 04: Technology Stack Evaluation

Status: Approved plan rev. 3, frozen snapshot. Covers deliverable (6). The major decisions have full ADRs in the 8-point format. This page compares the options; the ADRs hold the reasoning.

## Summary table

| Area | Recommendation | Main alternatives | Why the recommendation | ADR |
|---|---|---|---|---|
| Language | Python 3.12 (pinned) | C#/.NET 8 (stronger Windows integration), Rust | Learning goals, AI ecosystem, P_proyect reuse. C# is reconsidered for privileged parts. | [0001](../adr/0001-python-pyside6.md), [0012](../adr/0012-native-component-language.md) |
| GUI | PySide6 (LGPL) | PyQt6 (GPL/commercial), WinUI 3, Tauri, Electron | Mature tables and model/view, accessibility, LGPL | [0001](../adr/0001-python-pyside6.md) |
| Firewall read | PowerShell NetSecurity on ActiveStore, bulk filters | COM `INetFwPolicy2`, WFP enumeration, `netsh` | Documented effective policy, JSON output | [0009](../adr/0009-firewall-read-path.md) |
| Network/process | psutil + pywin32 or WMI | `Get-NetTCPConnection`, `GetExtendedTcpTable` via ctypes | Fast, cross-tested, well maintained | — |
| Models/validation | pydantic v2 | dataclasses + manual checks, attrs | Validation at trust boundaries, JSON schema export (shared with AI structured output) | — |
| Storage | SQLite via stdlib `sqlite3`, WAL, hand-written migrations | SQLAlchemy/Alembic, DuckDB, SQLCipher | Zero dependency, adequate volume, transparent SQL for learning | — |
| Reports | Jinja2 → HTML; Qt `QPdfWriter` PDF (v0.1); python-docx (v0.3) | WeasyPrint (native GTK deps), ReportLab, Qt WebEngine | No new dependencies in v0.1 | [0005](../adr/0005-v0-1-report-formats.md) |
| AI | Ollama on loopback, provider-agnostic | Embedded llama.cpp, cloud APIs | Free, offline, private, already installed | [0002](../adr/0002-local-first-ai-ollama.md) |
| HTTP client (v0.2) | `httpx` (timeouts, streaming, size limits) or stdlib `urllib` with explicit caps | `requests` | Explicit timeouts and streaming; P_proyect's unbounded `urllib` reads are not reused | — |
| Secrets | `keyring` → Windows Credential Manager (DPAPI) | Config file, environment variables | OS-protected and per-user | — |
| Dependency mgmt | uv + `uv.lock` | Poetry, pip-tools | Fast, reproducible lockfile, manages Python versions | — |
| Lint/format/type | ruff, mypy (`--strict` on core), import-linter | black + flake8, pyright | One fast tool for lint and format; contracts for module boundaries | — |
| Tests | pytest, pytest-qt, hypothesis, pytest-benchmark | unittest | Ecosystem and fixtures; property tests for parsers | — |
| Security scanning | pip-audit, bandit, CodeQL, gitleaks, Dependabot, CycloneDX SBOM | Snyk (account required) | Free, CI-native | — |
| Packaging | PyInstaller one-dir | Nuitka (evaluate in v0.3), cx_Freeze, one-file | Mature, predictable | [0006](../adr/0006-v0-1-distribution.md) |
| Installer | Inno Setup, per-user | WiX MSI (v0.4+ for service), NSIS, MSIX | Simple, no admin rights needed | [0006](../adr/0006-v0-1-distribution.md) |
| Signing | SignPath Foundation (OSS) → OV certificate | Azure Artifact Signing (not eligible from Guatemala), self-signed (test only) | Free for OSS; Azure Public Trust is limited to US/Canada individuals and listed countries for organizations | [0007](../adr/0007-code-signing.md) |
| CI/CD | GitHub Actions on `windows-latest` | Azure Pipelines | Native to GitHub Releases and attestations | — |

## Is a privileged service or native component needed?

- **Not for v0.1.** Read-only auditing runs as a standard user [ASSUMPTION; the Sprint 1 spike lists which fields need admin rights].
- **v0.4 (rule changes):** an on-demand elevated helper is needed. A UAC prompt is required for each approved change set.
- **v0.5 (monitoring):** a Windows Service is needed. ETW kernel-network providers, Security log audit events, and WFP management APIs all need administrator or service rights.
- **Pre-connection authorization:** a driverless approximation is possible with user-mode WFP. True pend-and-decide needs a kernel callout driver. See [12](12-monitoring-research.md).

## Version notes

- Python 3.14 is installed as the system default, but the packaging toolchain may lag behind. Pin 3.12 via uv [VERIFY support matrices at Sprint 1].
- Ollama 0.34.4 is installed on the dev machine (observed 2026-10-14). Structured outputs via `format` have been available since 0.5 ([Ollama blog](https://ollama.com/blog/structured-outputs)).
