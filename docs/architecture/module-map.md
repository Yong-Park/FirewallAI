# Module map

Status as of M1.1 (2026-10-14). The rationale is in [../planning/03-architecture.md](../planning/03-architecture.md).

## Packages (`src/firewallai/`)

| Package | Responsibility | May import | Must NOT import | Status |
|---|---|---|---|---|
| `core` | Domain models, effective-policy evaluation, verdicts, correlation, findings engine and catalog, scan diff. Pure functions. | stdlib, pydantic | Qt, subprocess, sockets, `collectors`, `storage`, `ui`, `ai` | **M1.1:** `models` (FirewallProfile, enums, stable IDs), `results` (CollectorResult/Error), `sensitivity` (DataClass metadata). Rest planned |
| `collectors` | Platform adapters behind Protocols: `windows/` (powershell_runner, firewall, network, process, service, securitycenter) and `fake/` (fixtures) | `core` models, psutil, pywin32 | `ui`, `ai`, `storage` | **M1.1:** `protocols`, `windows/powershell_runner`, `windows/scripts`, `windows/profile_mapping`, `windows/firewall_profiles`, `windows/privilege`, `fake/firewall_profiles`. Rules, network, process, service, and securitycenter collectors planned (rules blocked on D9) |
| `storage` | SQLite repository and migrations | `core` models | `ui`, `ai`, `collectors` | planned |
| `references` | Standards reference registry data and its loader | `core` models | `ui`, `ai` | planned (v0.3; minimal in v0.1) |
| `securitydocs` | Product-agnostic report model, Jinja2 templates, renderers (HTML, Qt PDF; DOCX later) | stdlib, jinja2, PySide6 (PDF renderer only) | **any FirewallAI-specific module** | planned |
| `ai` | LLM providers, redaction, consent, schemas, validator, eval ([ADR 0021](../adr/0021-hybrid-ai-orchestration.md)) | stdlib, pydantic, httpx or urllib | **any FirewallAI-specific module**, and anything privileged or write-capable | planned (v0.2) |
| `app` | Application services (scan, export, settings) shared by the GUI and CLI | all of the above except `ui` and `cli` | `ui`, `cli`, Qt | **M1.1:** `profile_service` (ProfileService, ProfileReport, JSON report) |
| `ui` | PySide6 views and models, theme, onboarding | `app`, `core` models | `collectors`, `storage` directly | **M1.1:** `main_window`, `profiles_model`, `worker` (QThreadPool), `app` (entry point) |
| `cli` | Command-line entry point for dev and automation | `app` | `ui`, Qt | **M1.1:** `firewallai profiles [--json] [--fixture]` |
| `privileged` (separate process, v0.4+) | Allowlisted typed-operation executor | `core` operation schema only | `ai`, `ui` | planned (v0.4) |

## Enforced contracts (import-linter, `pyproject.toml`; run with `uv run lint-imports`)

Implemented in M1.1. All four pass ("4 kept, 0 broken", 2026-10-14):
1. **Layers:** `ui | cli` → `app` → `collectors` → `core`. Lower layers never import higher ones, and `ui` and `cli` are independent of each other.
2. **`core` is pure:** no `PySide6`, `subprocess`, `socket`, `urllib`, or `http`.
3. **Only `ui` imports Qt:** `core`, `collectors`, `app`, and `cli` must not import `PySide6`.
4. **No network modules anywhere in v0.1** (SB-05): `socket`, `urllib`, `http`, and `ssl` are forbidden for all of `firewallai`.

Still planned (added when the packages exist): `ai` and `securitydocs` must not import product modules ([ADR 0013](../adr/0013-shared-package-extraction.md)); nothing imports `privileged`.
