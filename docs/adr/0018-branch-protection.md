# ADR 0018: Branch protection on GitHub `main`

- **Status:** Proposed · **Decision ID:** D18 · **Date:** 2026-10-14 · **Proposed by:** claude-code · **Decided by:** pending

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
