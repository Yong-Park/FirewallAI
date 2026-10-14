# Module map

Status: **planned**. No code exists yet. The rationale is in [../planning/03-architecture.md](../planning/03-architecture.md).

## Packages (`src/firewallai/`)

| Package | Responsibility | May import | Must NOT import | Status |
|---|---|---|---|---|
| `core` | Domain models, effective-policy evaluation, verdicts, correlation, findings engine and catalog, scan diff. Pure functions. | stdlib, pydantic | Qt, subprocess, sockets, `collectors`, `storage`, `ui`, `ai` | planned |
| `collectors` | Platform adapters behind Protocols: `windows/` (powershell_runner, firewall, network, process, service, securitycenter) and `fake/` (fixtures) | `core` models, psutil, pywin32 | `ui`, `ai`, `storage` | planned |
| `storage` | SQLite repository and migrations | `core` models | `ui`, `ai`, `collectors` | planned |
| `references` | Standards reference registry data and its loader | `core` models | `ui`, `ai` | planned (v0.3; minimal in v0.1) |
| `securitydocs` | Product-agnostic report model, Jinja2 templates, renderers (HTML, Qt PDF; DOCX later) | stdlib, jinja2, PySide6 (PDF renderer only) | **any FirewallAI-specific module** | planned |
| `ai` | LLM providers, redaction, consent, schemas, validator, eval | stdlib, pydantic, httpx or urllib | **any FirewallAI-specific module**, and anything privileged or write-capable | planned (v0.2) |
| `app` | Application services (scan, export, settings) shared by the GUI and CLI | all of the above except `ui` and `cli` | `ui`, `cli` | planned |
| `ui` | PySide6 views and models, theme, onboarding | `app`, `core` models | `collectors`, `storage` directly | planned |
| `cli` | Command-line entry point for dev and automation | `app` | `ui` | planned |
| `privileged` (separate process, v0.4+) | Allowlisted typed-operation executor | `core` operation schema only | `ai`, `ui` | planned (v0.4) |

## Enforced contracts (import-linter, from Sprint 1)

1. `core` is independent: it has no imports from other `firewallai` packages.
2. `ai` and `securitydocs` don't import FirewallAI-specific modules. This keeps them extractable ([ADR 0013](../adr/0013-shared-package-extraction.md)).
3. Nothing imports `privileged`, and `privileged` imports only the operation schema.
4. `ui` reaches data only through `app`.
