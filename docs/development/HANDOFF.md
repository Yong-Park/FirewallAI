# Handoff: last updated 2026-10-14 by claude-code

Active agent lock: RELEASED

## Post-M0 work: ADR 0021 on an isolated branch
- [Verified] Branch **`docs/adr-0021-hybrid-ai`** was created from `docs/planning-v0` at `2235608`. It carries **one local commit** with ADR 0021 and its supporting docs. **Not pushed; no PR.**
- [Verified] `docs/planning-v0` is untouched: local and `origin` both still point to `2235608`.
- ADR 0021 status: **Accepted as the v0.2+ direction** (human, 2026-10-14). Benchmark protocol, prototypes, and provider endpoint details stay pending.
- Contents of the ADR 0021 commit:
  - `docs/adr/0021-hybrid-ai-orchestration.md` (new)
  - `docs/adr/README.md` (new living ADR index and decision register)
  - `docs/architecture/security-boundaries.md` (SB-15, SB-16, SB-17)
  - `docs/architecture/interfaces.md` (AI orchestration sketch)
  - `AI_DEVELOPMENT.md` (ledger rows)
  - this file
- The frozen M0 planning docs are **unchanged**: `docs/planning/17-decisions-for-approval.md` was restored to byte-identical with `2235608`.

### Integrating ADR 0021 after M0 is merged (squash merge)
After the M0 PR is **squash-merged**, `main` gets a *new* commit (call it `S`) with the same content as `2235608`, but `2235608` is **not** an ancestor of `main`. If `docs/adr-0021-hybrid-ai` were pushed and PR'd as-is, the PR would show the M0 commit again. To avoid that, move only the ADR 0021 commit onto the new `main`. Each step needs the human's go-ahead:
1. `git fetch origin` and confirm the M0 PR is merged: `git log --oneline -3 origin/main` shows the squash commit.
2. Check that the squash commit's content equals the M0 branch, so the ADR commit applies cleanly: `git diff 2235608 origin/main --stat` should be empty. If M0 changed during review, expect conflicts in `AI_DEVELOPMENT.md`, `HANDOFF.md`, or `interfaces.md`.
3. **Option A (recommended, no history rewrite):** create a fresh branch from `main` and cherry-pick the ADR commit:
   ```
   git switch -c docs/adr-0021-hybrid-ai-v2 origin/main
   git cherry-pick <ADR-0021-commit-sha>
   ```
   **Option B (rewrites this local, unpushed branch; needs explicit approval per AGENTS.md):**
   ```
   git rebase --onto origin/main 2235608 docs/adr-0021-hybrid-ai
   ```
4. Resolve any conflicts. Then re-run the link check and `git diff origin/main --stat`, and confirm the diff contains only the ADR 0021 files above.
5. Update this HANDOFF with the new branch and SHA. With authorization, push and open a PR to `main`.
6. Leave the old local `docs/adr-0021-hybrid-ai` branch alone. Agents never delete branches; the human may delete it later.

If M0 is merged with a merge commit instead of a squash, `2235608` becomes an ancestor of `main`, and the branch can be PR'd directly.

> **[Verified]** means it was checked by a command in the session that wrote this section, with the output pasted.
> **[Assumed]** means it was not checked.
> Protocol: [AGENT_WORKFLOW.md](AGENT_WORKFLOW.md).

## Position
- Milestone: **M0, Planning: final.** The documentation is committed on `docs/planning-v0` (`2235608`) and pushed to `origin`. The agent could **not** open the PR (`gh` not installed). Whether the human has opened it is **[Assumed: unknown to the agent]**.
- **The PR is NOT merged. Merging is not authorized.**
- **Sprint 1 is NOT authorized.** Do not write application code, install dependencies, run privileged operations, or change firewall or system settings.

## Git
- Branch: `docs/planning-v0`, based on `main` at `d602990 Initial commit`. [Verified]
- Remote: `origin https://github.com/Yong-Park/FirewallAI.git`. [Verified]
- The commit containing this file is the single M0 documentation commit, authorized by the human on 2026-10-14. A commit can't record its own SHA. Get it with `git log -1 --oneline docs/planning-v0`. The PR URL is on GitHub (`docs/planning-v0` → `main`).
- The local-only file `.claude/settings.local.json` exists and is **git-ignored** (verified with `git check-ignore`). It is not part of the commit.

## Status
**Completed (M0)**
- [Verified] Planning set: `docs/planning/00–18`, `docs/architecture/*`, `docs/adr/` (template + 0000–0020), `docs/development/*`, `AGENTS.md`, `CLAUDE.md`, `AI_DEVELOPMENT.md`, `.github/pull_request_template.md`.
- [Verified] The project `.claude/settings.json` is **deny-only** (ADR 0016). The deny test `git branch -D zz-nonexistent-deny-test` was blocked.
- [Verified] Personal allow rules live only in the git-ignored `.claude/settings.local.json`. Arbitrary-Python allow rules were removed.
- [Verified] Decision statuses recorded in [17-decisions-for-approval.md](../planning/17-decisions-for-approval.md):
  - **Accepted:** D2, D3, D14, D15, D16, D20 (explicit human direction, quoted in each ADR) and ADR 0000.
  - **Pending:** D1, D4–D13, D17–D19, each with its reason.
- [Verified] The development machine is documented as **test environment TE-1** ([13 §4](../planning/13-testing-strategy.md)), not as a product requirement.

**In progress**
- PR review by the human.

**Not started**
- Sprint 1 (all application code).

## Known issues
- No code exists, so there are no bugs.
- Deny rules are bypassable guardrails (ADR 0016 §4).
- Approving Claude Code prompts with "don't ask again" may add `allow` rules to the project `settings.json`. Always check `git diff .claude/` before committing.

## Security notes
- No firewall, system, or network configuration was changed during M0.
- Before staging, a search for credentials, tokens, emails, and machine-specific user paths found nothing apart from generic `%LOCALAPPDATA%` placeholders (details in the PR description).

## Tests run (M0 configuration checks)
| Check | Result |
|---|---|
| Both settings files through `json.tool` | Valid |
| Deny-rule test (`git branch -D` on a nonexistent branch) | Blocked |
| `git check-ignore -v .claude/settings.local.json` | Ignored, via `.gitignore` |
| Markdown relative-link check across `*.md` | No broken links (re-run before commit) |

No application tests exist.

## Tests not run
- Everything in [13-testing-strategy.md](../planning/13-testing-strategy.md); there is no code.
- Mermaid diagrams have **not** been rendered by a tool [Assumed valid]. GitHub's PR preview will render them, so check it there.

## Pending decisions needing the human
- D1, D4–D13, D17–D19 ([17](../planning/17-decisions-for-approval.md)).
- Confirm that the agent's classification of Accepted decisions (D2, D3, D14, D15, D16, D20) matches your intent.
- Hyper-V availability (pending verification).
- PR review and merge (merge not yet authorized).

## Next steps
1. The human reviews the PR, including the Mermaid rendering, the decision statuses, and the `.claude/settings.json` deny list.
2. The human authorizes the merge, or requests changes.
3. Before Sprint 1:
   - verify Hyper-V;
   - enable branch protection on `main` (D18);
   - configure Codex (D17);
   - decide D1, D5, D6, and D9, or accept them as Sprint 1 spike inputs.
4. The human explicitly authorizes Sprint 1.

## Resume commands
```
git fetch origin
git switch docs/planning-v0
git status --short
git log -3 --oneline
gh pr view --web          # open the M0 PR
```
