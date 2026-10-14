# Agent Workflow — switching between Claude Code and Codex

Status: Proposed (part of planning rev. 3). Rules here are referenced from [AGENTS.md](../../AGENTS.md); AGENTS.md wins on any conflict (and the agent must stop and ask).

FirewallAI is developed by one human owner with two AI coding agents (Claude Code and OpenAI Codex) used **in turns**, e.g. when one hits its usage limit. The goal: no lost context, no duplicated or conflicting edits, no weakened security rules, and full human ownership.

## 1. Single-writer rule

- Only **one agent edits the working tree at a time**.
- The lock line at the top of [HANDOFF.md](HANDOFF.md) says who holds it: `Active agent lock: <agent> since <time>`. When nobody holds it, it reads `RELEASED`.
- An agent that finds the lock held by another agent must **not edit**. It reports the situation to the human and waits.
- Only the human may override a stale lock, for example after an agent session crashed.

## 2. Ending a session (outgoing agent)

1. Run `git status`, `git branch --show-current`, and `git log -5 --oneline`, and paste the output into HANDOFF.md.
2. Summarize the work completed in this session.
3. List each uncommitted or modified file and what the change is for.
4. Record the test, lint, and type results **actually run**: command, commit SHA, and an output excerpt. Anything not run is listed as "not run" with the reason.
5. Update every section of [HANDOFF.md](HANDOFF.md), keeping Verified and Assumed separate.
6. List unresolved decisions and questions for the human.
7. Recommend the next task (one to three items).
8. Add or update rows in [AI_DEVELOPMENT.md](../../AI_DEVELOPMENT.md) with review fields set to **pending**.
9. Release the lock.
10. **Do not commit or push** unless the human authorized it in this session. The agent may *suggest* a commit message for the human to run.

## 3. Starting a session (incoming agent)

1. Read [AGENTS.md](../../AGENTS.md). Claude Code also gets `CLAUDE.md`.
2. Read [HANDOFF.md](HANDOFF.md).
3. Read the [docs/architecture/](../architecture/) pages and [ADRs](../adr/) relevant to the next task.
4. Run `git status`, `git branch --show-current`, and `git log -5 --oneline`, and **compare the output with HANDOFF.md**. Report every mismatch before doing anything else (unexpected files, a different branch, new commits).
5. Identify incomplete work from HANDOFF.md.
6. Validate the current state by running the test, lint, and type commands. Record the real output. If tooling doesn't exist yet, write "not applicable — no code yet".
7. Take the lock: set `Active agent lock: <agent> since <time>`.
8. Present a **short execution plan** (scope, files to touch, tests) and wait for the human's approval before making significant changes.

## 4. Ready-to-paste prompts

**Start (either agent):**
> Start a FirewallAI session following docs/development/AGENT_WORKFLOW.md §3. Read AGENTS.md and docs/development/HANDOFF.md, verify the git state against HANDOFF, run the validation commands, report any mismatches, then propose a short plan for the recommended next task. Do not edit files until I approve.

**End (either agent):**
> End this FirewallAI session following docs/development/AGENT_WORKFLOW.md §2. Update HANDOFF.md with verified git state and actual test results, add pending rows to AI_DEVELOPMENT.md, release the lock, and recommend the next task. Do not commit or push.

## 5. Git workflow (lightweight, solo + two agents)

- **`main`** is always releasable. It is protected on GitHub (the human configures this, see [ADR 0018](../adr/0018-branch-protection.md)): PRs only, required checks, no force-push, no deletion.
- **Branches:** short-lived, named `feat/<scope>`, `fix/<scope>`, `docs/<scope>`, `spike/<scope>`, or `chore/<scope>`, and created from `main`.
- **Commits:** Conventional Commits, with these trailers:
  ```
  feat(collectors): add ActiveStore rule collector

  AI-Agent: codex
  Assisted-by: OpenAI Codex
  ```
  Claude Code uses `AI-Agent: claude-code` plus the `Co-Authored-By` line its session provides. Never invent a name or email address ([ADR 0020](../adr/0020-agent-attribution.md)).
- **Pull requests:** opened only when the human says so, using the [PR template](../../.github/pull_request_template.md). Automated checks must pass before merge. The human reviews the diff, then squash-merges ([ADR 0019](../adr/0019-merge-strategy.md)).
- **Never:**
  - force-push;
  - rewrite history (`rebase -i`, `reset --hard` on shared branches, `commit --amend` on pushed commits) without explicit approval;
  - delete branches automatically;
  - commit credentials, `.env` files, personal data, or raw scan captures from a real machine (only sanitized fixtures);
  - make unauthorized firewall modifications.

## 6. Parallel work (not planned yet)

If two agents ever need to work at the same time:
- Each works on **its own branch** in **its own worktree**:
  `git worktree add ../FirewallAI-codex feat/<scope>`
- Tasks are split so that **no file is assigned to both agents**. The HANDOFF lock line lists the files each agent owns.
- The branches are integrated through separate PRs. Neither agent merges the other's branch.

## 7. Technical guardrails (back up the written rules)

| Guardrail | Status | Decision |
|---|---|---|
| Claude Code deny rules in the project `.claude/settings.json`: firewall writes, `netsh`, force-push, `reset --hard`, branch deletion, `.env*` reads. Deny-only; personal allow rules go in the git-ignored `.claude/settings.local.json`. | **Accepted, implemented 2026-10-14** | [ADR 0016](../adr/0016-claude-guardrails.md) |
| Codex: `sandbox_mode = "workspace-write"`, `approval_policy = "on-request"`, network off by default | Proposed; the human configures it | [ADR 0017](../adr/0017-codex-guardrails.md) |
| pre-commit: ruff, mypy, gitleaks | Sprint 1 | [15-roadmap.md](../planning/15-roadmap.md) |
| GitHub branch protection on `main` | Proposed; the human configures it | [ADR 0018](../adr/0018-branch-protection.md) |

**Before every commit, run `git diff --cached .claude/`.** Approving a Claude Code prompt with "don't ask again" can write `allow` rules into the project `settings.json`. Move personal rules to `settings.local.json`. Never approve broad interpreter rules such as `Bash(python *)`, because they bypass every deny rule.

Codex reads `AGENTS.md` natively and, by default, embeds up to 32 KiB of it (`project_doc_max_bytes`). Codex also supports a project-scoped `.codex/config.toml` ([Codex sample config](https://developers.openai.com/codex/config-sample), [sandboxing](https://developers.openai.com/codex/concepts/sandboxing.md)). Keep `AGENTS.md` well under that limit.
