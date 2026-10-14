# Handoff: last updated 2026-10-14 by claude-code

Active agent lock: RELEASED

> **[Verified]** means it was checked by a command in the session that wrote this section, with the output pasted.
> **[Assumed]** means it was not checked.
> Protocol: [AGENT_WORKFLOW.md](AGENT_WORKFLOW.md).

## Position
- **M0 is merged into `main`.** It went in through squash merges of PR #1 (`12cd228`) and PR #2 (`c56129e`).
- **Current work:** integrating [ADR 0021](../adr/0021-hybrid-ai-orchestration.md) (hybrid AI orchestration, accepted as the v0.2+ direction) on branch `docs/adr-0021-hybrid-ai-v2`.
  - The human **approved the diff** on 2026-10-14 and authorized a separate commit for `AGENTS.md` and this file, plus a push of the branch.
  - Pull request: **not opened by the agent** (no `gh`; installing it is not authorized). The human opens it in the browser.
  - **Merge is not authorized.**
- **Sprint 1 is NOT authorized.** Do not write application code, install dependencies, run privileged operations, or change firewall or system settings.

## Git [Verified]
```
$ git fetch origin
   d602990..c56129e  main       -> origin/main
$ git log --oneline -3 origin/main
c56129e docs: add M0 planning, ADRs, and multi-agent workflow (#2)
12cd228 docs: add M0 planning, ADRs, and multi-agent workflow (#1)
d602990 Initial commit
$ git diff --stat 2235608 origin/main          # original M0 commit vs merged main
(empty: identical content)
$ git diff --stat 12cd228 c56129e              # what PR #2 changed
(empty: PR #2 is a no-op squash commit with the same message)
```
- `2235608` (the original M0 commit) is **not** an ancestor of `main`, as expected after a squash merge.
- Branch `docs/adr-0021-hybrid-ai-v2` was created from `origin/main` (`c56129e`), then `git cherry-pick 078f66f` was run.
  - **No conflicts.** It produced commit `71c7d5f`.
  - The branch's upstream tracking of `origin/main` was **removed** (`git branch --unset-upstream`), so a bare `git push` can't target `main`.
- This file and `AGENTS.md` are committed in a **separate second commit** on top of `71c7d5f`. `71c7d5f` was not amended. A commit can't record its own SHA; use `git log --oneline -3 docs/adr-0021-hybrid-ai-v2`.
- Push: `git push -u origin docs/adr-0021-hybrid-ai-v2` (authorized). Check the result with `git rev-parse docs/adr-0021-hybrid-ai-v2 origin/docs/adr-0021-hybrid-ai-v2`; the two SHAs should match.
- Earlier branches are **kept, not deleted**:
  - `docs/planning-v0` (`2235608`, also on origin);
  - `docs/adr-0021-hybrid-ai` (`078f66f`, local only). It is superseded by `-v2`; the human may delete it.

## Status
**Completed**
- [Verified] M0 merged. Content on `main` is identical to the reviewed M0 commit.
- [Verified] ADR 0021 commit cherry-picked onto `main` (`71c7d5f`). The diff against `origin/main` contains only ADR 0021 and its supporting docs (see below).
- [Verified] `AGENTS.md` now points to [docs/adr/README.md](../adr/README.md) as the living ADR index, and states that ADR numbering continues past D20.

**In progress**
- The PR for `docs/adr-0021-hybrid-ai-v2` → `main` (the human opens and reviews it; merge not yet authorized).

**Not started**
- Sprint 1 (all application code).

## Uncommitted work
- None expected. `AGENTS.md` (§2 and §8: link to the ADR index, numbering past D20) and this file are in the second commit on `docs/adr-0021-hybrid-ai-v2`.

## Decisions
- **Accepted:** ADR 0000, D2, D3, D14, D15, D16, D20, and **D21** (direction; benchmark protocol, prototypes, and provider endpoint details pending).
- **Pending:** D1, D4–D13, D17–D19. Live statuses are in [docs/adr/README.md](../adr/README.md).

## Known issues
- No code exists, so there are no bugs.
- **`main` contains two M0 squash commits** (#1, and an empty #2 with an identical message). They are harmless, and they are left as they are, because rewriting `main` would require a force-push, which is forbidden.
- Deny rules are bypassable guardrails (ADR 0016 §4). Check `git diff .claude/` before every commit.

## Security notes
- No firewall, system, or network configuration was changed.
- `.claude/settings.json` is unchanged on this branch. `.claude/settings.local.json` is git-ignored and not included.

## Tests run (this session)
| Check | Result |
|---|---|
| `git diff --stat 2235608 origin/main` | Empty (M0 content identical) |
| `git cherry-pick 078f66f` on `origin/main` | Clean, no conflicts |
| `git diff --name-status origin/main` | Only the 7 expected files (6 ADR files, plus `AGENTS.md` once committed) |
| Markdown relative-link check; secret and private-path scan | See the final review in the agent's report to the human |

No application tests exist.

## Tests not run
- Everything in [13-testing-strategy.md](../planning/13-testing-strategy.md); there is no code yet.
- Mermaid diagrams are not rendered by a tool (ADR 0021 adds none).

## Pending decisions needing the human
- Open the PR (`docs/adr-0021-hybrid-ai-v2` → `main`), review it, and authorize the merge (squash, per D19 if accepted).
- Inside ADR 0021: the benchmark protocol (primary metric, whether 15% is relative or absolute, run count, overhead limits), the prototypes, and provider endpoint allowlists.
- D1, D4–D13, D17–D19; Hyper-V verification.
- Before Sprint 1: branch protection (D18), Codex configuration (D17), and explicit Sprint 1 authorization.

## Next steps
1. The human opens the PR in the browser: https://github.com/Yong-Park/FirewallAI/compare/main...docs/adr-0021-hybrid-ai-v2
2. The human reviews it and squash-merges **only** when ready. Merge it once only, to avoid a repeat of the empty duplicate seen with M0's PR #2.
3. After merge: `git fetch origin`, confirm `main` contains ADR 0021, then resolve the remaining pre-Sprint 1 items above.

## Resume commands
```
git fetch origin
git switch docs/adr-0021-hybrid-ai-v2
git status --short
git log --oneline -3
git diff --name-status origin/main
```
