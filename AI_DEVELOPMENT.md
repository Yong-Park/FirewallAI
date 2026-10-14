# AI-Assisted Development Record

FirewallAI is built by a human developer, the project owner, with AI coding agents (Claude Code and OpenAI Codex). This file records **who did what** and **what has actually been verified**, so readers can tell AI-generated work from human decisions and see which work has been reviewed.

## Policy
- AI-generated code and docs must meet the **same quality and security requirements** as human-written work: same gates, same tests, same review.
- Nothing is recorded as "human reviewed", "tested", "measured", or "security reviewed" without evidence. **The default state is `pending`.**
- Agents may add rows, but only with review fields set to `pending`. **Only the human owner** changes a review field.
- Agent attribution is also recorded in commit trailers (`AI-Agent: claude-code|codex`, [ADR 0020](docs/adr/0020-agent-attribution.md)), so this ledger can be cross-checked against `git log`.

## 1. Contribution ledger

| Date | Feature / PR | Agent(s) | Scope of AI help | Human architectural decisions | Human review | Validation evidence | Security review | Known AI limitations | Corrections after review |
|---|---|---|---|---|---|---|---|---|---|
| 2026-10-14 | Planning rev. 1 (in-session plan, not committed) | claude-code | Drafted the full proposal | Human defined project vision, modules, constraints, and the required deliverables | Human read it and requested changes (see rev. 2) | none (documents only) | not done | Initially defaulted to a cloud AI provider (Claude API), which conflicted with the human's later local-first requirement | Human required local-first Ollama, early GUI/installer/PDF, and stricter analysis semantics → rev. 2 |
| 2026-10-14 | Planning rev. 2 (in-session plan) | claude-code | Revised the proposal; reviewed P_proyect's `llm_client.py` for reuse | Human set the local-first AI requirement, v0.1–v0.5 roadmap, Indeterminate state, standards scope, and documentation as a core goal | Human read it and requested the multi-agent workflow (rev. 3) | none | not done | — | Human added the multi-agent workflow → rev. 3 |
| 2026-10-14 | Planning rev. 3 + docs set on branch `docs/planning-v0` (`AGENTS.md`, `CLAUDE.md`, `docs/planning/*`, `docs/architecture/*`, `docs/adr/*`, `docs/development/*`) | claude-code | Wrote all documents; checked selected [VERIFY] items against official sources | Human approved the rev. 3 plan on 2026-10-14. **Individual decisions D1–D20 are still pending.** | **pending** (document contents not yet reviewed) | none (no code, no tests run; Mermaid diagrams not rendered by a tool) | not done | Some claims still tagged [VERIFY] or [ASSUMPTION]; see [tag register](docs/planning/00-README.md#tag-register) | Code-signing recommendation (D7) changed after verification: Azure Artifact Signing accepts individual developers only in the US and Canada, so SignPath Foundation is now recommended first. (Status as of rev. 3 drafting; later rows supersede it.) |
| 2026-10-14 | M0 finalization: `.claude` settings sanitization, D16 deny rules, recording human decisions (Guatemala, Codex trailer, Hyper-V pending) | claude-code | Config + docs | Human authorized the D16 implementation; human chose the Codex trailer policy (no invented identity) | **pending** | Deny-rule test: `git branch -D zz-nonexistent-deny-test` was blocked; both settings files pass JSON validation; `git check-ignore` confirms `settings.local.json` is ignored | self-review only (agent) | Deny rules are pattern-based and bypassable (ADR 0016 §4) | Session approvals had written two arbitrary-Python allow rules and absolute local paths into the project `settings.json`. Removed or moved to the git-ignored local file. |
| 2026-10-14 | M0 final review and documentation commit / PR | claude-code | Final review; recording decision statuses (D2, D3, D14, D15, D16, D20 Accepted per explicit human direction); test-environment labeling; commit, push, and PR as authorized by the human | Human authorized commit, push, and PR; **merge not authorized** | **pending** (PR review) | Pre-commit checks recorded in [HANDOFF.md](docs/development/HANDOFF.md) | self-review only (agent) | The agent decided which decisions counted as "explicitly approved"; the human should confirm in PR review | — |

## 2. Decision ledger

The ADR number matches the decision ID. Full list: [docs/planning/17-decisions-for-approval.md](docs/planning/17-decisions-for-approval.md).

| Decision | Origin | ADR status | Human decision |
|---|---|---|---|
| ADR process (0000) | AI-proposed | Accepted | Approved with the rev. 3 plan, 2026-10-14 |
| D2 local-first AI (Ollama) | Human requirement | Accepted | Explicitly directed, 2026-10-14 (quote in ADR 0002) |
| D3 AI in v0.2 | AI-proposed, matches the human roadmap | Accepted | Human roadmap, 2026-10-14 (quote in ADR 0003) |
| D14 CLI first-class | AI-proposed, matches a human requirement | Accepted | Explicitly directed, 2026-10-14 (quote in ADR 0014) |
| D15 documentation split | Human requirement | Accepted | Explicitly directed, 2026-10-14 (quote in ADR 0015) |
| D16 Claude deny rules | AI-proposed | Accepted | Human authorized the implementation, 2026-10-14 |
| D20 agent attribution | Human requirement; Codex trailer policy set by the human | Accepted | Explicitly directed, 2026-10-14 (quote in ADR 0020) |
| D1, D4–D13, D17–D19 | Mostly AI-proposed; the human supplied inputs (D7 location: Guatemala) | Proposed | **pending**. Reasons are listed per decision in [17](docs/planning/17-decisions-for-approval.md) (prototype- or benchmark-dependent, "evaluate" only, or not yet explicitly approved) |

## 3. Corrections log

Notable AI errors or weaknesses that were caught during review.

| Date | What the AI produced | Problem | Caught by | Fix |
|---|---|---|---|---|
| 2026-10-14 | Rev. 1 plan defaulted to a paid cloud LLM | Conflicted with the owner's cost, privacy, and offline goals | Human | Rev. 2: local-first Ollama |
| 2026-10-14 | Rev. 2 plan recommended Azure Artifact Signing as the first option | Individual eligibility is limited to the US and Canada | AI self-verification against Microsoft docs; confirmed when the human gave their location (Guatemala) | ADR 0007 now recommends SignPath Foundation first, then an OV certificate; Azure is marked not eligible |
| 2026-10-14 | The rev. 3 docs proposed a `Co-authored-by: Codex <…>` trailer | Would require inventing an identity or email address | Human | Changed to `Assisted-by: OpenAI Codex` (ADR 0020) |
| 2026-10-14 | Agent-session approvals wrote broad allow rules to the project `.claude/settings.json` | Arbitrary-Python allow rules would bypass the deny rules; absolute local paths would have been published | Human asked for an inspection; the agent identified the rules | Dropped or moved to the git-ignored `settings.local.json`; ADR 0016 and CLAUDE.md now require a deny-only project file |
| 2026-10-14 | ADR 0002 said "Measured on the dev box: RTX 3080…" | Nothing had been measured. The hardware was also easy to misread as a minimum requirement | Agent, during the final M0 review requested by the human | Reworded to "nothing measured yet"; dev machine documented as test environment TE-1 ([13 §4](docs/planning/13-testing-strategy.md)), explicitly not a product requirement |

## 4. Validation evidence index

No application code exists, and no application tests or benchmarks have been run. Configuration checks from M0 finalization (2026-10-14):
- the deny-rule test was blocked as intended;
- both settings files are valid JSON;
- the ignore rule was confirmed with `git check-ignore`.

## 5. Open items
- Human review of every planning document (status `pending`).
- Decisions D1, D4–D13, D17–D19.
- Hyper-V availability (pending verification).
