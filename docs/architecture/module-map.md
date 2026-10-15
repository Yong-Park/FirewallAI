# Module map

Status as of M1.4 (2026-10-15; first written for M1.1). The rationale is in [../planning/03-architecture.md](../planning/03-architecture.md).

## Packages (`src/firewallai/`)

| Package | Responsibility | May import | Must NOT import | Status |
|---|---|---|---|---|
| `core` | Domain models, effective-policy evaluation, verdicts, correlation, findings engine and catalog, scan diff. Pure functions. | stdlib, pydantic | Qt, subprocess, sockets, `collectors`, `storage`, `ui`, `ai` | **M1.1:** `models` (FirewallProfile, enums, stable IDs), `results` (CollectorResult/Error), `sensitivity` (DataClass metadata). **M1.3:** `rules` (FirewallRule, FilterResult, tokens, RuleCollection, ScanLimitation, ID scheme h1), `evidence` (verdict completeness guard). **M1.4:** `endpoints` (Endpoint, ProcessInfo, `Observed`, bind scope, `display_safe`), `correlation` (descriptive listener-to-rule correlation, SB-20). Rest planned |
| `collectors` | Platform adapters behind Protocols: `windows/` (powershell_runner, firewall, network, process, service, securitycenter) and `fake/` (fixtures) | `core` models, psutil, pywin32 | `ui`, `ai`, `storage` | **M1.1:** `protocols`, `windows/powershell_runner`, `windows/scripts`, `windows/profile_mapping`, `windows/firewall_profiles`, `windows/privilege`, `fake/firewall_profiles`. **M1.3:** streaming mode in `windows/powershell_runner`; `windows/scripts` (FIREWALL_RULES); `windows/rule_mapping` (raw→typed, ID allocation, assembler); `windows/firewall_rules` (single-flight `HEAVY_QUERY_LOCK`); `rule_collection` (shared progressive driver); `fake/firewall_rules`. **M1.4:** `endpoint_assembly` (best-effort two-snapshot PID-reuse check, platform-neutral), `windows/network_endpoints` (psutil sockets and processes; **the only module that imports psutil**, [ADR 0022](../adr/0022-psutil-endpoint-collection.md)), `windows/scripts` (`WIN32_SERVICES`), `fake/network_endpoints`. securitycenter collector planned |
| `storage` | SQLite repository and migrations | `core` models | `ui`, `ai`, `collectors` | planned |
| `references` | Standards reference registry data and its loader | `core` models | `ui`, `ai` | planned (v0.3; minimal in v0.1) |
| `securitydocs` | Product-agnostic report model, Jinja2 templates, renderers (HTML, Qt PDF; DOCX later) | stdlib, jinja2, PySide6 (PDF renderer only) | **any FirewallAI-specific module** | planned |
| `ai` | LLM providers, redaction, consent, schemas, validator, eval ([ADR 0021](../adr/0021-hybrid-ai-orchestration.md)) | stdlib, pydantic, httpx or urllib | **any FirewallAI-specific module**, and anything privileged or write-capable | planned (v0.2) |
| `app` | Application services (scan, export, settings) shared by the GUI and CLI | all of the above except `ui` and `cli` | `ui`, `cli`, Qt | **M1.1:** `profile_service` (ProfileService, ProfileReport, JSON report). **M1.3:** `rule_service` (RuleScanService, N-04 evaluation, evidence summary, `firewallai.rules/1`). **M1.4:** `endpoint_service` (EndpointScanService, 1 s snapshot target separate from N-04, `firewallai.endpoints/1`, rule index builder) |
| `ui` | PySide6 views and models, theme, onboarding | `app`, `core` models | `collectors`, `storage` directly | **M1.1:** `main_window`, `profiles_model`, `worker` (QThreadPool), `app` (entry point). **M1.3:** `main_window` tabs; `rules_tab` (worker, progress, cancel); `rules_model` (precomputed rows); `app.prepare_gc_for_gui`. **M1.4:** `network_tab` (worker collection, filter, cancel, related-rules panel), `network_model`, `table_model` (shared precomputed-rows model) |
| `cli` | Command-line entry point for dev and automation | `app` | `ui`, Qt | **M1.1:** `firewallai profiles [--json] [--fixture]`. **M1.3:** `firewallai rules [--json] [--summary] [--inventory-only] [--fixture]`. **M1.4:** `firewallai endpoints [--json] [--summary] [--listening] [--show-remote] [--fixture]` |
| `privileged` (separate process, v0.4+) | Allowlisted typed-operation executor | `core` operation schema only | `ai`, `ui` | planned (v0.4) |

## Packaging (outside `src/`, M1.5)
`packaging/` holds build tooling, not application code. It is never imported by `firewallai`:
- `firewallai.spec`: the PyInstaller spec with two executables;
- `entry_gui.py` and `entry_cli.py`;
- `buildinfo.py`: version single-sourced from `pyproject.toml`, and the commit read from `.git` without subprocesses;
- `make_icon.py`;
- `build.py`;
- `verify_build.py`;
- `smoke/`: frozen-bundle tests, run explicitly.

PyInstaller lives in the `build` dependency group. See [packaging/BUILD.md](../../packaging/BUILD.md).

## Enforced contracts (import-linter, `pyproject.toml`; run with `uv run lint-imports`)

Implemented in M1.1; contract 5 added in M1.4. All five pass ("5 kept, 0 broken", 2026-10-15):
1. **Layers:** `ui | cli` → `app` → `collectors` → `core`. Lower layers never import higher ones, and `ui` and `cli` are independent of each other.
2. **`core` is pure:** no `PySide6`, `subprocess`, `socket`, `urllib`, or `http`.
3. **Only `ui` imports Qt:** `core`, `collectors`, `app`, and `cli` must not import `PySide6`.
4. **No network modules anywhere in v0.1** (SB-05): `socket`, `urllib`, `http`, and `ssl` are forbidden for all of `firewallai`.
5. **psutil only in the Windows endpoint collector** (M1.4): `core`, `ui`, `cli`, `collectors.fake`, `collectors.endpoint_assembly`, and the firewall collectors must not import `psutil` (indirect imports through `app` are allowed). A security test also checks that only read-only psutil APIs are used.

Still planned (added when the packages exist): `ai` and `securitydocs` must not import product modules ([ADR 0013](../adr/0013-shared-package-extraction.md)); nothing imports `privileged`.
