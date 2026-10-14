# ADR 0016: Claude Code technical guardrails (`.claude/settings.json` deny rules)

- **Status:** Accepted. The human authorized implementation of the D16 deny rules on 2026-10-14 ("If the approved D16 deny-rules configuration can be implemented safely, create a sanitized project-level `.claude/settings.json`").
- **Decision ID:** D16 · **Date:** 2026-10-14 · **Proposed by:** claude-code · **Decided by:** human, 2026-10-14

## 1. Problem
The rules in AGENTS.md are written policy only. A mistaken command, such as a firewall write on the primary machine, a force-push, or a branch deletion, should also be blocked by a technical control.

## 2. Decision
- Commit a **deny-only** project `.claude/settings.json`. Rule syntax was checked against the [Claude Code permissions docs](https://code.claude.com/docs/en/permissions) on 2026-10-14. It contains:
  - **Firewall writes:** `netsh` in Bash and in PowerShell (all subcommands, including read-only ones; agents use read-only `Get-NetFirewall*` cmdlets instead), and the `New-`, `Set-`, `Remove-`, `Enable-`, `Disable-`, `Rename-`, and `Copy-NetFirewall*` cmdlets, both as PowerShell rules and as substrings in Bash commands, which covers `powershell -Command …`.
  - **Destructive git:** force-push (`--force*`, `-f`, `+refspec`), `reset --hard`, branch deletion (`-d`, `-D`, `--delete`), and remote branch deletion (`push --delete`). Each is denied for both the Bash and PowerShell tools.
  - **Secrets:** `Read` of `.env` and `.env.*` at any depth. This also blocks `.env.example`, which is acceptable.
- The project file contains **no allow rules**. Personal or machine-specific approvals belong in `.claude/settings.local.json`, which is git-ignored by the repo's `.gitignore`.

## 3. Alternatives considered
- **Written rules only:** no backstop.
- **User-level settings only:** not versioned, so they don't travel with the repository.
- **Broader denies** (e.g. every command containing `advfirewall`): this would also block harmless searches of the docs.

## 4. Advantages and disadvantages
- **Advantages:**
  - Defense in depth, versioned with the repository.
  - Deny rules take precedence over any allow rule, so an exception can't override them.
  - PowerShell matching is case-insensitive and resolves aliases.
- **Disadvantages:**
  - This is a **guardrail, not a security boundary**. The docs warn that argument-constraining patterns are fragile.
  - The rules can be bypassed by any general-purpose interpreter or script (`python -c`, a `.ps1` file, encoded commands, variables).
  - Bash matching of `-D` vs `-d` may be case-sensitive, so both are listed.

## 5. Security implications
- **Never approve broad interpreter rules** such as `Bash(python *)` or `Bash(python -I -c *)`, because they let any command bypass every deny rule. Two such rules had been created by session approvals and were **removed** on 2026-10-14 (see §7).
- The real control for firewall writes is still **VM-only testing** ([security-boundaries.md](../architecture/security-boundaries.md) SB-11) plus human approval.
- Approving a prompt with "don't ask again" can add `allow` rules to settings. On this machine, rules were written to the **project** `.claude/settings.json` (observed 2026-10-14). Check `git diff .claude/settings.json` before every commit.

## 6. Performance implications
None.

## 7. Validation (actual results)
- 2026-10-14: `git branch -D zz-nonexistent-deny-test` was **blocked by Claude Code** ("Permission to use Bash with command git branch -D zz-nonexistent-deny-test has been denied"). The command did not run.
- Both settings files passed `python -I -m json.tool`.
- The other patterns have **not** been individually tested. Firewall-cmdlet denies are intentionally not exercised on the primary machine.
- Cleanup recorded: the pre-existing project `settings.json` contained allow rules with absolute user-profile paths, a stale session path, and two arbitrary-Python rules.
  - The personal, narrow rules moved to `settings.local.json`.
  - The session path and the Python rules were dropped.

## 8. What to learn
- Claude Code permission rules: evaluation order is deny → ask → allow.
- Compound-command splitting.
- Guardrails vs. security boundaries.
