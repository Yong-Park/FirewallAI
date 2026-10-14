# 15: Roadmap, Sprint 1, and Definition of Done

Status: Approved plan rev. 3, frozen snapshot. Covers deliverables (15) the roadmap, (19) Sprint 1, and (20) the v0.1 Definition of Done.

## 1. Milestones

| Milestone | Content | Exit gate |
|---|---|---|
| **M0: Planning** | This documentation set. The human decides D1–D20. | ADRs accepted or amended. Human authorizes Sprint 1. |
| **v0.1: Read-only Firewall Auditor** (Sprints 1–4) | Collectors, verdict engine with Indeterminate, findings catalog (≥ 10), SQLite history and diff, GUI, CLI, JSON/HTML/basic PDF reports, unsigned per-user installer | v0.1 DoD (§4) |
| **v0.2: Local AI Advisor** | Ollama provider, detection and guided setup, model picker, explain-only advisor, validator, privacy controls, eval harness, model benchmark | Eval thresholds met, threat model updated |
| **v0.3: SecurityDocs + standards** | Full report suite, DOCX, richer PDF, reference registry, RAG (FTS5, then embeddings), Nuitka evaluation | Docs reviewed for claims and licensing |
| **v0.4: Human-approved rule management** | Elevated helper, typed operations, diff, drift detection, verification, audit chain, rollback | **VM test matrix passes.** Human sign-off ADR required before any real-system use. |
| **v0.5: Background monitoring** | Windows Service, tray, notifications, event correlation, reactive allow and block, temporary permissions | Fail-safe tests, performance budget |
| **Research** | R1 ETW, R2 dynamic WFP sessions, R3 driverless default-deny ([12](12-monitoring-research.md)) | Go/no-go ADR |

Every version starts by updating its ADRs and the threat model.

## 2. Sprint 1: walking skeleton with GUI (about 2 weeks) — **not yet authorized**

**Day 0: workflow setup (rev. 3)**
- [ ] Human: enable branch protection on `main` ([ADR 0018](../adr/0018-branch-protection.md)).
- [ ] Human: configure the Codex sandbox and approval settings ([ADR 0017](../adr/0017-codex-guardrails.md)). (Claude deny rules: done in M0, [ADR 0016](../adr/0016-claude-guardrails.md).)
- [ ] Human: **verify Hyper-V availability** (enabled feature, CPU virtualization, disk space for 3–5 VMs). This is a prerequisite for the clean-VM freeze test below.
- [ ] Update `docs/development/HANDOFF.md` with the real state.
- [ ] Set up pre-commit (ruff, mypy, gitleaks) and the CI skeleton on `windows-latest`.
- [ ] **Dry-run agent switch:** Claude → Codex → Claude on a small task. Record what was lost or unclear, then improve AGENT_WORKFLOW.md.

**Build tasks**
- [ ] Scaffolding: `pyproject.toml` (src layout), uv with Python 3.12, lockfile, ruff, mypy, pytest, import-linter contracts.
- [ ] Domain models (pydantic): Snapshot, FirewallProfile, FirewallRule plus filters, Endpoint, ProcessInfo, ServiceInfo, CollectorResult.
- [ ] `powershell_runner` with an injection test corpus and a test that scans scripts for read-only verbs.
- [ ] Profiles and rules collector (ActiveStore, bulk filters).
- [ ] psutil listeners and connections collector, plus process and service mapping.
- [ ] Fixture recorder and sanitizer script, plus the first sanitized fixtures.
- [ ] CLI: `firewallai scan --json`.
- [ ] **Minimal PySide6 window** showing profiles and listeners, loaded by a background worker.
- [ ] **PyInstaller one-dir freeze** of that window, installed and run on a clean Windows 11 VM.

**Spikes (results recorded with commands, numbers, and machine details)**
- [ ] PowerShell cold start and bulk query time at about 500 and about 1,500 rules.
- [ ] ActiveStore vs. COM `INetFwPolicy2` fidelity (GPO VM if available).
- [ ] Which fields fail without admin rights.
- [ ] Python 3.12 / 3.13 support matrix for PySide6, PyInstaller, and Nuitka.

**Sprint 1 exit:** CI green on `windows-latest`, `scan --json` works on the dev machine and a VM, the frozen GUI runs on a clean VM, the spike report is written, HANDOFF.md and AI_DEVELOPMENT.md are updated.

## 3. Sprints 2–4 (v0.1)
- **Sprint 2:** effective-policy evaluator, verdict engine plus truth table, correlation, findings catalog (≥ 10 rules, each with tests and benign conditions), SQLite storage, history, and diff, SecurityCenter2 detection.
- **Sprint 3:** full GUI (all v0.1 views, onboarding, light/dark themes, accessibility pass), SecurityDocs model, HTML and Qt PDF renderers, redaction.
- **Sprint 4:** Inno installer, uninstall flow, clean-VM validation (Windows 11 and 10), benchmarks, user documentation, limitations doc, release workflow → **v0.1 on GitHub Releases** (human publishes).

## 4. Definition of Done: v0.1
- [ ] Every v0.1 user story ([01](01-prd.md)) meets its acceptance criteria.
- [ ] Runs as a standard user. **Zero outbound network**, verified by the test suite and a manual check.
- [ ] Verdict truth table passes. `Indeterminate` is shown with its reasons. No finding is raised from an open port alone.
- [ ] `core` coverage ≥ 85%, `mypy --strict` on `core`, CI green, no high-severity findings from pip-audit, bandit, or CodeQL.
- [ ] Installer installs, runs, and uninstalls on clean Windows 11 (required) and Windows 10 22H2 (best-effort, logged).
- [ ] HTML and PDF reports separate facts, evidence, assessment, recommendations, and limitations.
- [ ] Scan time measured and recorded with the environment details.
- [ ] Threat model updated for v0.1. Each catalog rule documents when it is benign.
- [ ] README, user guide, and limitations doc written.
- [ ] **Multi-agent workflow (rev. 3):**
  - every merged feature has an AI_DEVELOPMENT.md row naming its agents and review status;
  - HANDOFF.md matches `git status` and `git log` at the release tag;
  - AGENTS.md reflects the accepted stack and rules;
  - every architecture change since approval has an ADR;
  - no PR was merged with failing or skipped security checks.

**Per-task DoD for an agent session:** see [AGENTS.md §10](../../AGENTS.md).
