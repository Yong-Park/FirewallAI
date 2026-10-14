# 17: Decisions Requiring Human Approval

Status as of 2026-10-14 (end of M0). Covers deliverable (18). Each decision has an ADR with the same number.

**Status rules:**
- **Accepted** means the human explicitly directed or approved this decision. The evidence is quoted in the ADR.
- **Pending** means the decision is still open. The reason is given: it depends on a prototype, benchmark, or verification; the human asked only to "evaluate" it; or no explicit approval was given yet.
- Approving the overall planning proposal is **not** treated as approving every individual recommendation in it.

To decide: tell an agent, for example, "Accept D1, D5, D6; amend D7 to …". The agent updates the ADR status and records the decision in [AI_DEVELOPMENT.md](../../AI_DEVELOPMENT.md).

| # | Decision | Recommendation | ADR | Status | Why pending / evidence |
|---|---|---|---|---|---|
| D1 | Application language and UI | Python 3.12 + PySide6 | [0001](../adr/0001-python-pyside6.md) | **Pending** | PySide6 GUI was directed by the human. The Python version (3.12 vs. 3.13+) depends on the Sprint 1 toolchain check [VERIFY] |
| D2 | AI default | Ollama on loopback; cloud optional, off by default, bring-your-own key | [0002](../adr/0002-local-first-ai-ollama.md) | **Accepted** | "Make Ollama the default AI backend." Model benchmark still pending in D4 |
| D3 | AI timing | v0.2. v0.1 is deterministic with zero network | [0003](../adr/0003-ai-in-v0-2.md) | **Accepted** | Human roadmap: "V0.2: Local Ollama AI Advisor" |
| D4 | Default recommended model | `qwen2.5:7b-instruct` provisionally | [0004](../adr/0004-default-local-model.md) | **Pending** | Depends on the v0.2 benchmark and license verification |
| D5 | v0.1 report formats | JSON + HTML + basic Qt PDF | [0005](../adr/0005-v0-1-report-formats.md) | **Pending** | Human asked to "investigate" PDF in v0.1; Qt PDF quality [NEEDS PROTOTYPE] |
| D6 | v0.1 distribution | Unsigned PyInstaller one-dir + Inno per-user installer | [0006](../adr/0006-v0-1-distribution.md) | **Pending** | Human asked to "evaluate" PyInstaller, Nuitka, and Inno; clean-VM freeze test in Sprint 1 |
| D7 | Code signing | SignPath Foundation first, then an OV certificate; Azure Artifact Signing not eligible (Guatemala) | [0007](../adr/0007-code-signing.md) | **Pending** | Location given (Guatemala). OV CA availability [VERIFY]; SignPath requires a release first |
| D8 | Windows 10 | Best-effort on 22H2, VM-tested, not release-blocking | [0008](../adr/0008-windows-10-support.md) | **Pending** | Human said "where technically feasible"; the best-effort policy needs explicit confirmation |
| D9 | Firewall read path | PowerShell ActiveStore; COM and WFP as secondary sources | [0009](../adr/0009-firewall-read-path.md) | **Pending** | Prototype-dependent (Sprint 1 spike) |
| D10 | Executable hashing | Off by default, opt-in | [0010](../adr/0010-executable-hashing.md) | **Pending** | No explicit decision; performance [NEEDS PROTOTYPE] |
| D11 | Rollback model | Inverse operations on our own delta plus drift detection | [0011](../adr/0011-change-rollback-model.md) | **Pending** | v0.4 design. The human set the requirement ("Avoid unintentionally overwriting legitimate firewall changes"); the mechanism is not yet approved |
| D12 | Language for the privileged helper and service | Defer to a v0.4 ADR | [0012](../adr/0012-native-component-language.md) | **Pending (deferred)** | Decided at v0.4 |
| D13 | Shared-package extraction | Defer until a second project uses it | [0013](../adr/0013-shared-package-extraction.md) | **Pending** | Aligns with "Avoid … premature integration", but the mechanism is not explicitly approved |
| D14 | CLI | First-class for dev and automation; GUI is the primary product | [0014](../adr/0014-cli-first-class.md) | **Accepted** | "Keep the CLI for development, automation, and testing, but introduce a functional GUI early." |
| D15 | Documentation split | Planning frozen; `docs/architecture/` living; ADRs record changes | [0015](../adr/0015-documentation-split.md) | **Accepted** | "Add or organize `docs/architecture/` as the central location…" |
| D16 | Claude guardrails | Deny-only project `.claude/settings.json`; personal rules in the git-ignored local file | [0016](../adr/0016-claude-guardrails.md) | **Accepted** | Implementation explicitly authorized; validated by a blocked test command |
| D17 | Codex guardrails | `workspace-write` + `on-request`, network off; configured by the human | [0017](../adr/0017-codex-guardrails.md) | **Pending** | Needs human configuration and a Sprint 1 Day 0 check; project-config trust behavior [VERIFY] |
| D18 | Branch protection on `main` | Human enables: PR required, checks required, no force-push or deletion | [0018](../adr/0018-branch-protection.md) | **Pending** | The human required "No force-pushing to main"; enabling the GitHub ruleset is a human action not yet taken |
| D19 | Merge strategy | Squash-merge; branches not auto-deleted | [0019](../adr/0019-merge-strategy.md) | **Pending** | No explicit decision yet |
| D20 | Agent attribution | `AI-Agent:` trailer; Claude: session `Co-Authored-By`; Codex: `Assisted-by: OpenAI Codex` | [0020](../adr/0020-agent-attribution.md) | **Accepted** | Required by the human; Codex trailer policy set by the human |

**Summary:** Accepted: D2, D3, D14, D15, D16, D20 (plus ADR 0000, the ADR process). Pending: D1, D4–D13, D17–D19.

## Non-ADR inputs
| # | Item | Status |
|---|---|---|
| 1 | Developer location, for code signing (D7) | **Answered:** Guatemala. Azure Artifact Signing is not eligible. |
| 2 | Codex attribution (D20) | **Answered:** `Assisted-by: OpenAI Codex`, with no invented identity. |
| 3 | Hyper-V availability | **Pending verification.** VM testing remains a requirement ([13 §3](13-testing-strategy.md)). |
| 4 | Commit and PR for the documentation branch | **Authorized 2026-10-14:** commit, push, and PR. **Merge is not authorized.** |
