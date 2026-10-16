# Architecture Decision Records: living index

This is the **living index and decision register** for FirewallAI. Update it in the same change that adds an ADR or changes an ADR's status.

- Process: [ADR 0000](0000-record-architecture-decisions.md). **ADR number = decision number** (ADR `NNNN` = decision `DNN`). New decisions continue at **D25 / 0025**.
- Template: [template.md](template.md).
- Only the human owner moves an ADR to Accepted, Rejected, or Superseded. Agents draft ADRs as **Proposed**.
- [docs/planning/17-decisions-for-approval.md](../planning/17-decisions-for-approval.md) is the **frozen M0 snapshot** of D1–D20 (2026-10-14), including the reasons each decision was then pending. From D21 on, and for every later status change, **this file is the source of truth**.

## Index

| ADR | Decision | Title | Status | Notes |
|---|---|---|---|---|
| [0000](0000-record-architecture-decisions.md) | — | Record architecture decisions | **Accepted** | ADR process |
| [0001](0001-python-pyside6.md) | D1 | Application language and UI: Python 3.12 + PySide6 | **Accepted** | Accepted 2026-10-14; implemented with `pyside6-essentials` |
| [0002](0002-local-first-ai-ollama.md) | D2 | Local-first AI with Ollama as default | **Accepted** | Extended by 0021 |
| [0003](0003-ai-in-v0-2.md) | D3 | AI advisor ships in v0.2 | **Accepted** | |
| [0004](0004-default-local-model.md) | D4 | Default recommended local model | Proposed | Benchmark-dependent |
| [0005](0005-v0-1-report-formats.md) | D5 | v0.1 report formats (JSON, HTML, basic Qt PDF) | Proposed | Qt PDF prototype |
| [0006](0006-v0-1-distribution.md) | D6 | v0.1 distribution (PyInstaller one-dir + Inno per-user) | **Accepted (development distribution only)** | Human, 2026-10-15: one-folder unsigned portable development build accepted (CI passed; basic GUI checks 7/7 PASS; detailed matrix 8/13 rows PASS, rows 1/3/5/8/9 partly verified and documented; no open packaging defects). **Public release NOT approved**; gates: installer, clean-VM Win11/Win10, signing, SR-M1.5-01, human decision on N-04, remaining manual sub-items |
| [0007](0007-code-signing.md) | D7 | Code signing (SignPath → OV; Azure not eligible from Guatemala) | Proposed | OV CA availability [VERIFY] |
| [0008](0008-windows-10-support.md) | D8 | Windows 10 best-effort | Proposed | |
| [0009](0009-firewall-read-path.md) | D9 | Firewall read path: ActiveStore, non-elevated; bulk inventory + per-rule restricted filters | **Accepted** (v0.1 direction) | **Implemented in M1.3** (production collector, streaming). Measured full scan about 29-35 s, so **N-04 (10 s) exceeded**. Win10, GPO, service-hardening, and EnforcementStatus checks pending; interface-alias access verified on TE-1 |
| [0010](0010-executable-hashing.md) | D10 | Executable hashing off by default | Proposed | |
| [0011](0011-change-rollback-model.md) | D11 | Rule-change rollback model (v0.4) | Proposed | |
| [0012](0012-native-component-language.md) | D12 | Privileged helper/service language | Proposed (deferred) | Decided at v0.4 |
| [0013](0013-shared-package-extraction.md) | D13 | Defer shared-package extraction | Proposed | |
| [0014](0014-cli-first-class.md) | D14 | CLI first-class alongside GUI | **Accepted** | |
| [0015](0015-documentation-split.md) | D15 | Planning snapshot vs. living architecture docs | **Accepted** | |
| [0016](0016-claude-guardrails.md) | D16 | Claude Code deny-only project settings | **Accepted** | Implemented |
| [0017](0017-codex-guardrails.md) | D17 | Codex sandbox and approval guardrails | Proposed | Human configures |
| [0018](0018-branch-protection.md) | D18 | Branch protection on `main` | **Accepted** | Ruleset 25123659 active: no deletion, no force-push, PR required, squash only, linear history. Required CI status checks are a future enhancement (no CI yet) |
| [0019](0019-merge-strategy.md) | D19 | Squash-merge PRs | Proposed | |
| [0020](0020-agent-attribution.md) | D20 | Agent attribution trailers | **Accepted** | |
| [0021](0021-hybrid-ai-orchestration.md) | D21 | Hybrid AI orchestration (v0.2+): Python-orchestrated, single-model first, optional Gemini/Groq | **Accepted (direction)** | Benchmark protocol, prototypes, and provider details pending; adds SB-15–SB-17 |
| [0022](0022-psutil-endpoint-collection.md) | D22 | psutil for local endpoint and process collection (M1.4), incl. psutil-only mypy settings | **Accepted** | Accepted by the human 2026-10-15 (psutil 7.2.2 pinned and hash-locked) |
| [0023](0023-beginner-first-ux.md) | D23 | Beginner-first, evidence-honest UX (guardrails UX-01…UX-10, new milestone UX0 before Sprint 3) | **Accepted** | Human requirement and approval 2026-10-15, with refinements (Windows profile names kept, possible-only rule relationships, attention vs. evidence confidence, comprehension checks C1–C3); current UI not redesigned until approved implementation |
| [0024](0024-local-policy-verdict-contract.md) | D24 | Local-policy verdict contract (SB-21), finding contract, `scan --json` schema, JSON fixtures | Proposed | M2.0 draft (2026-10-15). Specs: [verdict-contract.md](../architecture/verdict-contract.md), [findings-contract.md](../architecture/findings-contract.md). Architecture approved for refinement only (human, 2026-10-15), not accepted. No decision step verified or authorized; M20-Q1…Q9 directions recorded; errata E1–E5 proposed, not applied; precedence documented, not VM-verified |

**Totals:**
- Accepted: 0000, D1, D2, D3, D6 (development distribution only), D9 (v0.1 direction), D14, D15, D16, D18, D20, D21 (direction), D22, D23.
- Proposed or pending: D4, D5, D7, D8, D10–D13, D17, D19, D24.
