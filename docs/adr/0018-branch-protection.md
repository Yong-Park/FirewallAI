# ADR 0018: Branch protection on GitHub `main`

- **Status:** Accepted. The human accepted D18 on 2026-10-14 "for the implemented main branch protection ruleset".
- **Decision ID:** D18 · **Date:** 2026-10-14 · **Proposed by:** claude-code · **Decided by:** human, 2026-10-14

## 1. Problem
Several agents can push to the same repository. `main` must not be force-pushed, deleted, or changed without passing checks.

## 2. Decision (recommended)
The **human** configures a branch protection rule or ruleset on `main`. Agents never change repository settings. The rule should:
- require a pull request before merging, with self-approval allowed (there is one human reviewer);
- require status checks to pass once CI exists in Sprint 1;
- block force pushes;
- block deletion.

## 3. Alternatives considered
- **No protection:** a single mistaken command could rewrite `main`.
- **Requiring a second reviewer:** impossible for a solo project.

## 4. Advantages and disadvantages
- **Advantages:** enforced on the server side, so no local agent can bypass it.
- **Disadvantages:** small hotfixes also need a PR.

## 5. Security implications
Protects release integrity and the audit trail of AI contributions.

## 6. Performance implications
None.

## 7. Validation
After setup, `git push --force` to `main` from a test clone is rejected. Record the result in HANDOFF.md.

## 8. What to learn
GitHub rulesets, required status checks, and why server-side controls beat client-side ones.

## Implementation (verified 2026-10-14)
The human created repository ruleset **25123659** on `main`. The agent verified it read-only through the public GitHub API (`/repos/Yong-Park/FirewallAI/rules/branches/main`, with `"protected": true` on `/branches/main`):

| Rule | Effect |
|---|---|
| `deletion` | `main` can't be deleted |
| `non_fast_forward` | Force-pushes are blocked |
| `pull_request` | Changes go through a PR. `required_approving_review_count: 0` (solo project; self-merge allowed); review threads must be resolved; **allowed merge method: squash only** |
| `required_linear_history` | No merge commits on `main` |

**Future enhancement, not yet in place:** required CI status checks. They can't be required until a CI workflow exists. Adding the workflow (with pinned third-party actions reviewed by the human) and then marking its checks as required on this ruleset is a separate, future change.

**Not verifiable by the agent:** the ruleset's bypass list, which the public API doesn't show.

The squash-only setting implements the merge strategy proposed in [ADR 0019](0019-merge-strategy.md). That ADR itself remains Proposed.
