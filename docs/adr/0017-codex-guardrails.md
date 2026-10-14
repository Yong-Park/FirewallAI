# ADR 0017: Codex technical guardrails

- **Status:** Proposed · **Decision ID:** D17 · **Date:** 2026-10-14 · **Proposed by:** claude-code · **Decided by:** pending

## 1. Problem
Codex needs backstops equivalent to the Claude Code guardrails.

## 2. Decision (recommended)
Run Codex with these settings:
- `sandbox_mode = "workspace-write"`: edits stay inside the workspace, and routine local commands are allowed.
- `approval_policy = "on-request"`: Codex asks before going beyond the sandbox.
- Network access off by default.

These keys are confirmed in the official Codex docs ([sample config](https://developers.openai.com/codex/config-sample), [sandboxing](https://developers.openai.com/codex/concepts/sandboxing.md)).

Codex supports both `~/.codex/config.toml` and a project-scoped `.codex/config.toml`. The project file applies only when the project is trusted [VERIFY trust behavior]. Recommendation:
- the human sets these values in **user-level** config;
- a project `.codex/config.toml` with the same values may be committed later, once its behavior is verified.

**Never** use `danger-full-access` or `approval_policy = "never"` for this repository.

## 3. Alternatives considered
- **Full autonomy:** unacceptable for a project that touches firewall tooling.
- **Read-only:** too restrictive for implementation work.

## 4. Advantages and disadvantages
- **Advantages:** OS-level sandboxing, which is stronger than pattern deny lists.
- **Disadvantages:** some commands will prompt, for example `uv sync`, which needs network access.

## 5. Security implications
The sandbox limits the damage a misdirected agent can do on the primary machine.

## 6. Performance implications
None.

## 7. Validation
Sprint 1 Day 0 dry-run switch: confirm Codex prompts before network access and cannot write outside the repository. Record the outcome in HANDOFF.md.

## 8. What to learn
OS-level sandboxing vs. pattern-based permissions. The `AGENTS.md` size cap (`project_doc_max_bytes`, 32 KiB by default).
