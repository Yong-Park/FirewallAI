# Handoff: last updated 2026-10-14 by claude-code

Active agent lock: RELEASED

> **[Verified]** means it was checked by a command in the session that wrote this section, with the output pasted.
> **[Assumed]** means it was not checked.
> Protocol: [AGENT_WORKFLOW.md](AGENT_WORKFLOW.md).

## Position
- **Sprint 1, milestone M1.1 ("walking skeleton": read-only firewall profiles end to end) is implemented, tested, and approved by the human (2026-10-14)** for a reviewable commit and PR. It is committed in a single M1.1 commit on this branch (use `git log -1` for the SHA; a commit can't contain its own SHA), pushed to `origin`, and **the PR is to be opened by the human**. **Merge is not authorized.**
- Branch: **`feat/s1-m1-walking-skeleton`**, created from `origin/main` at `b18c97f` (PR #3, ADR 0021). It has no upstream configured.
- **Not authorized yet:** merging the M1.1 PR, and M1.2. Do not start the rules collector (blocked on D9).
- `main` history so far: M0 (PRs #1 and #2, the second an empty squash) and ADR 0021 (PR #3).

## Sprint 1 Day 0 findings [Verified, read-only, non-elevated, TE-1, 2026-10-14]
| Area | Finding |
|---|---|
| Python | CPython 3.12.6 x64 via `py -3.12`. The system default is 3.14; the project pins 3.12 (D1 accepted) |
| uv | Installed by the agent after human approval: WinGet `astral-sh.uv` (publisher Astral Software Inc.), **version 0.12.21** (released 2026-09-29, at least 2 weeks old). User scope, `--skip-dependencies` (VC++ 14.51 runtime already present), installer hash verified by WinGet. 0.13.1 (released the same day) was intentionally not used |
| Tools not installed | `gh`, `pyinstaller`; git is 2.37.2 (old; update recommended, human action) |
| PowerShell | 5.1.26100, FullLanguage. **LocalMachine execution policy = AllSigned.** Errors are localized (Spanish) |
| Hyper-V | Hypervisor present, `vmms` running, PowerShell module present. **`Get-VM` is denied when not elevated.** VM work needs the human (admin or Hyper-V Administrators membership) |
| VirtualBox | 7.2.20 installed, with one VM "WS2022" (Windows Server 2022: no SecurityCenter2, so not a client-SKU test target). It runs on the Hyper-V backend when Hyper-V is active |
| Windows Sandbox | Not enabled |
| Resources | C: 243 GB free, G: 1.46 TB free, RAM 15.9 GB |
| Branch protection | At Day 0, `main` was unprotected. **Update (later on 2026-10-14):** the human created a ruleset, verified via the public GitHub API (see "Branch protection" below) |
| Codex | codex-cli 0.162.1. The user `config.toml` has **no `sandbox_mode` or `approval_policy`** (D17 not configured). No repo `.codex/` |
| Firewall read access | Profiles and 1,586 rules are readable. **Bulk port and address filters are access denied for a standard user.** Details in [ADR 0009](../adr/0009-firewall-read-path.md) evidence §B |

## Branch protection on `main` [Verified, 2026-10-14]
The human reported creating the ruleset. The agent confirmed it read-only:
```
GET https://api.github.com/repos/Yong-Park/FirewallAI/branches/main  ->  "protected": true
GET https://api.github.com/repos/Yong-Park/FirewallAI/rules/branches/main  ->  ruleset_id 25123659 (Repository):
  deletion                 (branch deletion blocked)
  non_fast_forward         (force-push blocked)
  pull_request             (required_approving_review_count: 0, required_review_thread_resolution: true,
                            allowed_merge_methods: ["squash"])
  required_linear_history
```
- **No required status checks yet**, because there's no CI. Add them once a CI workflow exists.
- Bypass actors can't be seen through the public API [unknown to the agent].
- ADR 0018 (D18) is **Accepted** (human, 2026-10-14) for this ruleset. Required CI status checks remain a future enhancement.

## M1.1 status
**Completed [Verified]**
- `pyproject.toml`:
  - Python `==3.12.*`, build backend **uv_build** (approved by the human), `exclude-newer = 2026-09-30`, `python-downloads = "never"`.
  - Ruff, mypy (strict), pytest, and import-linter configuration.
- `uv.lock`: 37 packages. Direct pins:
  - runtime: `pydantic==2.13.5`, `pyside6-essentials==6.11.2` (core subset of PySide6, no Addons/WebEngine);
  - dev: `pytest==9.1.1`, `pytest-qt==4.5.0`, `ruff==0.16.9`, `mypy==2.3.1`, `import-linter==2.15`, `pre-commit==4.6.2`.
- `.pre-commit-config.yaml` has **local hooks only**: ruff, ruff-format, mypy, import-linter. No downloaded hooks; **gitleaks deliberately not added**. `pre-commit validate-config` exits 0. The git hook is **not installed** (`pre-commit install` not run).
- `src/firewallai/` layers:
  - core models, results, and sensitivity;
  - the secure PowerShell runner;
  - the profile script, mapping, and Windows collector;
  - the privilege check;
  - the fake collector;
  - the app service;
  - the CLI;
  - the PySide6 GUI.
- Tests in `tests/`: unit, security, Windows integration, UI. Fixtures are **synthetic**.
- Docs:
  - ADR 0001 is **Accepted** (D1);
  - ADR 0009 has the evidence and is **still Proposed**;
  - ADR index, module map, interfaces, and security boundaries updated;
  - this file and the AI_DEVELOPMENT.md row.

**In progress:** none. **Not started:** M1.2 (D9 read-path investigation), M1.3 rules collector, M1.4 network collector, M1.5 packaging.

## Tests run [Verified, 2026-10-14, on uncommitted tree based on `b18c97f`, TE-1, non-elevated]
| Command | Result |
|---|---|
| `uv run --frozen pytest -q -s` | **70 passed** in 4.90 s. **Re-run before commit review: 70 passed in 6.19 s** (security 33, integration/windows 4, unit 24, UI 10; ruff, format, mypy, and lint-imports clean again; `uv lock --check` OK) |
| `uv run --frozen pytest -q -m security` | 33 passed, 37 deselected |
| `uv run --frozen pytest -q -m integration` (real PowerShell, read-only) | 4 passed |
| `uv run --frozen pytest -q -m windows` | 4 passed |
| `uv run --frozen pytest -q tests/unit` | 24 passed |
| `uv run --frozen pytest -q tests/ui` (offscreen) | 10 passed |
| `uv run --frozen ruff check` | All checks passed |
| `uv run --frozen ruff format --check` | 39 files already formatted |
| `uv run --frozen mypy` (strict) | Success: no issues found in 25 source files |
| `uv run --frozen lint-imports` | Contracts: 4 kept, 0 broken |
| `uv run --frozen firewallai profiles` / `--json` (live) | Exit 0; 3 profiles; `elevated: false`; `ok: true` |
| Live GUI probe (scratch script, offscreen, real collector) | `refresh()` returned in 0.1 ms; collection 1.48 s; GUI heartbeat max gap 79 ms; 3 rows rendered |
| **Manual GUI launch by the human** on the Windows desktop: `uv run --frozen firewallai-gui` | The window opened and showed all three profiles (Domain, Private, Public). *Reported by the human, 2026-10-14.* No other interactions or error scenarios were tested manually |

- During development, one test failure was a test-data bug: lone surrogate escapes in the injection corpus. The corpus entry was corrected to a real code point and the assertion was left unchanged.
- Timing figures come from single informal runs, not benchmarks.

## Tests not run
- Packaging and clean-VM tests (M1.5). No VM was used.
- CI (no workflow yet; adding one is a proposed next step).
- `pre-commit run` through git hooks (hooks not installed; the same tools were run directly).
- Coverage measurement (no coverage tool approved).
- Mypy over `tests/` (only `src` is type-checked).

## Known limitations
- **D9 blocker:** bulk port and address filters are access denied for standard users. The rules collector is deferred until the M1.2 investigation is reviewed.
- Profiles only: no rules, listeners, findings, storage, or reports yet.
- GUI: verified offscreen by the agent, plus **one successful manual launch by the human** that displayed the 3 profiles. Not tested manually: Refresh, resizing, keyboard navigation, screen readers, high-DPI, and error or partial-data display on the real desktop.
- The fixtures are synthetic; there is no sanitized live capture yet.

## Security notes
- No firewall, system, or network configuration was changed. Every system query was read-only and non-elevated. The only network use was the approved uv/WinGet and PyPI package downloads.
- No AI, cloud, or network code exists in `src/`. An import-linter contract forbids network modules.
- `.claude/settings.json` is unchanged and still deny-only.

## Pending decisions and actions for the human
1. Open and review the M1.1 PR (`feat/s1-m1-walking-skeleton` -> `main`), then authorize the squash merge.
2. D18 is done and accepted. D17: Codex sandbox and approval settings. Hyper-V access, and a Windows 11 client VM.
3. Approve M1.2 (the D9 read-path investigation, read-only, no new dependencies expected).
4. Optional: a CI workflow, which needs pinned third-party actions for review; installing the pre-commit git hook; updating git.

## Resume commands
```
git fetch origin
git switch feat/s1-m1-walking-skeleton
git status --short
uv sync --frozen
uv run --frozen pytest -q
uv run --frozen ruff check && uv run --frozen ruff format --check && uv run --frozen mypy && uv run --frozen lint-imports
uv run --frozen firewallai profiles
uv run --frozen firewallai-gui
```
(If `uv` isn't on PATH in an old shell: `%LOCALAPPDATA%\Microsoft\WinGet\Links\uv.exe`.)
