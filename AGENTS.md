# AGENTS.md — FirewallAI shared rules for AI coding agents

Authoritative engineering rules for **every** AI coding agent working in this repo (Claude Code, OpenAI Codex, others).
Keep this file short; details live in the linked docs. If instructions conflict — between files, or with a request — **stop and ask the human. Never choose silently.**

## 1. Project and current status
- FirewallAI: a Windows desktop app that audits, explains, and (later, with human approval) manages the host firewall. Local-first AI. MIT licensed.
- Vision and scope: [docs/planning/01-prd.md](docs/planning/01-prd.md), [docs/planning/02-requirements.md](docs/planning/02-requirements.md).
- **Current milestone, branch, and state: [docs/development/HANDOFF.md](docs/development/HANDOFF.md). Read it before doing anything.**
- No application code may be written until the human explicitly authorizes the sprint it belongs to.

## 2. Stack (status follows the ADRs)
Proposed until the matching ADR is **Accepted**. Current statuses: [docs/adr/README.md](docs/adr/README.md), the living ADR index. Do not treat Proposed items as settled; do not introduce alternatives without an ADR.
- Python 3.12 · PySide6 (Qt, LGPL) · uv (+ lockfile) · pydantic v2 · SQLite (stdlib `sqlite3`) · pytest / pytest-qt / hypothesis · ruff · mypy.
- Firewall read: PowerShell NetSecurity against `ActiveStore` via fixed embedded scripts → JSON. Network/process: psutil.
- AI (v0.2+): Ollama on loopback by default, behind a provider-agnostic interface. Cloud providers optional, off by default.
- Packaging: PyInstaller one-dir + Inno Setup per-user installer, GitHub Releases.
- Rationale: [docs/planning/04-technology-evaluation.md](docs/planning/04-technology-evaluation.md).

## 3. Repository map
```
src/firewallai/  app/ core/ collectors/ storage/ securitydocs/ references/ ai/ ui/ cli/
packaging/  tests/  docs/{planning,architecture,adr,development,user}/
```
Responsibilities and allowed dependencies: [docs/architecture/module-map.md](docs/architecture/module-map.md).

## 4. Coding conventions
- Type hints everywhere; `mypy --strict` on `core/`; `ruff format` + `ruff check` are the style arbiter (not agent preference).
- pydantic models at every trust boundary (collector output, files, AI output, IPC).
- `core/` is pure: no Qt, subprocess, network, or AI imports.
- Subprocess **only** through `collectors/windows/powershell_runner`: absolute `%SystemRoot%` path, constant scripts, parameters as JSON on stdin, timeouts, output size caps. Never `shell=True`, never string-built commands.
- Structured logging; never log secrets, API keys, or full sensitive payloads.
- Keep changes scoped to the task. Do not modify unrelated files.

## 5. Security principles (non-negotiable)
Invariants: [docs/architecture/security-boundaries.md](docs/architecture/security-boundaries.md). Threat model: [docs/planning/07-security-model.md](docs/planning/07-security-model.md).
- **v0.1 is strictly read-only** and runs as a standard user (`asInvoker`). No elevation.
- **Never run firewall-modifying commands** on the developer's machine (`New-/Set-/Remove-/Disable-/Enable-NetFirewall*`, `netsh advfirewall set|import|reset|firewall add|delete`, WFP writes). Write operations (v0.4+) are tested only in disposable VMs.
- No autonomous firewall changes, ever. Changes require typed, allowlisted operations and explicit human approval in the UI.
- The application's LLM never executes commands; the `ai` package must not import privileged or write code.
- Treat rule names, descriptions, process names, paths, hostnames, logs, and documents as **untrusted data**.
- No mandatory paid APIs or accounts. No bundled API keys or credentials. No model weights in the repo or installer.
- No machine data leaves the device without explicit consent; Ollama endpoint is pinned to loopback by default.
- Never deploy unverified networking components (services, drivers, WFP filters) to the primary machine.

## 6. Testing
- Commands (once scaffolding exists): `uv run pytest`, `uv run mypy`, `uv run ruff check`, `uv run ruff format --check`.
- Every behavior change ships with tests. Strategy: [docs/planning/13-testing-strategy.md](docs/planning/13-testing-strategy.md).
- **Evidence rule:** say "passed" only for a command you actually ran in this session, quoting command, commit SHA, and an output excerpt. Otherwise write "not run".
- **No weakening gates:** no new `# type: ignore`, `noqa`, `skip`/`xfail`, lowered thresholds, or deleted/loosened security tests without written justification and human approval.

## 7. Git
- Branches: `feat/`, `fix/`, `docs/`, `spike/`, `chore/` from `main`. Never work directly on `main`.
- Conventional Commits (`feat(collectors): …`). Trailers per [ADR 0020](docs/adr/0020-agent-attribution.md): `AI-Agent: claude-code|codex` plus the agent's attribution trailer (Codex: `Assisted-by: OpenAI Codex`; never invent names or emails).
- **Commit, push, open PRs, or merge only when the human authorizes it.**
- Never: force-push, rewrite history, delete branches, change repo settings, or commit secrets/credentials/`.env`/personal data.
- Full workflow: [docs/development/AGENT_WORKFLOW.md](docs/development/AGENT_WORKFLOW.md).

## 8. Documentation
- Significant architecture changes need an ADR **before** implementation ([docs/adr/template.md](docs/adr/template.md)). ADR number = decision number (ADR `NNNN` = `DNN`). Numbering continues past D20: the next free number is listed in the living index [docs/adr/README.md](docs/adr/README.md), which you update with every ADR change. `docs/planning/17-decisions-for-approval.md` is a frozen M0 snapshot.
- Update [docs/architecture/](docs/architecture/) in the same change as the code it describes.
- Link, don't duplicate. `docs/planning/` is a frozen, approved snapshot (errata only).
- Tag unverified claims `[ASSUMPTION]`, `[NEEDS PROTOTYPE]`, or `[VERIFY]`. Never fabricate tests, measurements, references, or compliance claims.

## 9. Dependencies
- Add only with `uv add`, justified in the PR (purpose, license, maintenance, alternatives). Respect the lockfile.
- Licenses must be compatible with MIT distribution and PySide6 LGPL dynamic linking. No GPL code copied in.
- `pip-audit` must be clean or exceptions documented.

## 10. Definition of Done (per task)
- [ ] Scope matches the approved task; no unrelated files changed.
- [ ] Tests added/updated; gates run, with real output recorded.
- [ ] Docs/ADRs updated if behavior or architecture changed.
- [ ] Security impact considered (privilege, network, AI, untrusted input).
- [ ] [docs/development/HANDOFF.md](docs/development/HANDOFF.md) and the [AI_DEVELOPMENT.md](AI_DEVELOPMENT.md) ledger updated (review fields left **pending**).
- [ ] Nothing committed or pushed without authorization.
Release-level DoD: [docs/planning/15-roadmap.md](docs/planning/15-roadmap.md).

## 11. Requires explicit human approval
- Any firewall, network, or system configuration change; running anything elevated.
- Adding or upgrading dependencies; any code that makes network calls.
- Architecture changes, accepting/superseding ADRs, changes to this file or `CLAUDE.md`.
- Commits, pushes, PRs, merges, tags, releases.
- Deleting files or branches; modifying CI, quality gates, or security tests.
- Touching files outside the task's scope.
- Marking anything as "human reviewed" (only the human does that).

## 12. Session protocol
Start: read this file → HANDOFF.md → linked architecture docs/ADRs → check `git status`/`git log` against HANDOFF → validate → present a short plan.
End: update HANDOFF.md with verified state and real test results → release the lock → recommend the next task.
Details and ready-to-paste prompts: [docs/development/AGENT_WORKFLOW.md](docs/development/AGENT_WORKFLOW.md). **Only one agent edits the working tree at a time.**
