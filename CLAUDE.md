@AGENTS.md

# CLAUDE.md — Claude Code–specific notes

`AGENTS.md` (imported above) is **authoritative** for all engineering rules. This file only lists differences specific to Claude Code.

- If anything in this file, a skill, a memory, or a user request conflicts with `AGENTS.md`, **stop and ask**; do not pick one silently.
- Use plan mode for any multi-file or architecture-relevant change, and present the plan before editing.
- Any deny rules in `.claude/settings.json` are guardrails. Do not look for workarounds such as alternative shells, aliases, or encoded commands.
- Keep the project `.claude/settings.json` **deny-only**. Personal "don't ask again" approvals belong in the git-ignored `.claude/settings.local.json`. Check `git diff .claude/` before any commit, and never suggest broad interpreter allow rules such as `Bash(python *)` ([ADR 0016](docs/adr/0016-claude-guardrails.md)).
- On Windows, use the Bash tool (Git for Windows) or the PowerShell tool for read-only inspection. Never request elevation.
- Commit trailers: `AI-Agent: claude-code` plus the `Co-Authored-By` line given by the session.
