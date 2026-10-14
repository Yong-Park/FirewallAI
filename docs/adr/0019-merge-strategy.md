# ADR 0019: Squash-merge pull requests into `main`

- **Status:** Proposed · **Decision ID:** D19 · **Date:** 2026-10-14 · **Proposed by:** claude-code · **Decided by:** pending

## 1. Problem
Agent sessions produce many small or work-in-progress commits. `main` history should stay readable for a portfolio project while the full detail is still kept somewhere.

## 2. Decision (recommended)
- Squash-merge every PR into `main`, so each feature becomes one commit.
- The squash commit message keeps the PR title (in Conventional Commits form) and the `Co-authored-by` and `AI-Agent` trailers.
- The full commit history stays on the PR branch. Branches are **not** auto-deleted; the human may delete them manually.

## 3. Alternatives considered
- **Merge commits:** full history, but noisy.
- **Rebase-merge:** linear history, but keeps every work-in-progress commit.

## 4. Advantages and disadvantages
- **Advantages:** clean `main`, one revertible commit per feature.
- **Disadvantages:** per-commit detail lives only in the PR.

## 5. Security implications
Easy to revert whole features. Agent attribution is kept through the trailers.

## 6. Performance implications
None.

## 7. Validation
Check the first squash-merged PR: its trailers appear on `main` and can be found with `git log --grep "AI-Agent:"`.

## 8. What to learn
Git merge strategies, and commit trailers (`git interpret-trailers`).
