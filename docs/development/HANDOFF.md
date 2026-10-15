# Handoff: last updated 2026-10-14 by claude-code

Active agent lock: RELEASED

> **[Verified]** means it was checked by a command in the session that wrote this section, with the output pasted.
> **[Assumed]** means it was not checked.
> Protocol: [AGENT_WORKFLOW.md](AGENT_WORKFLOW.md).

## Position
- **Sprint 1, M1.2: the D9 firewall read-path investigation is complete. D9 is ACCEPTED as the v0.1 read-path direction, with conditions** (human, 2026-10-14; see ADR 0009, "Accepted decision (v0.1)"). It is research only; no production collector exists.
- Branch: **`research/s1-m1-2-firewall-read-path`**, created from `main` at `eb221ba` (PR #4, M1.1 merged). The human approved the M1.2 changes and authorized **one commit** (the M1.2 documentation and research commit; get the SHA with `git log -1 --oneline research/s1-m1-2-firewall-read-path`) and a **push** of this branch. Verify the push with `git rev-parse research/s1-m1-2-firewall-read-path origin/research/s1-m1-2-firewall-read-path`. **The PR is to be opened by the human.**
- **Not authorized:** merging the M1.2 PR, and **M1.3** (rules collector with progressive collection). The next agent must not start M1.3 without explicit human authorization.
- `main` history: M0 (#1, #2), ADR 0021 (#3), M1.1 (#4, `eb221ba`). Branch protection ruleset 25123659 is active (ADR 0018 Accepted).

## Git [Verified]
```
$ git fetch origin   ->  b18c97f..eb221ba  main
$ git log --oneline -1 origin/main
eb221ba feat: add M1.1 read-only firewall profiles walking skeleton (#4)
$ git diff --stat af9befd origin/main      # reviewed M1.1 commit vs merged main
(empty)
$ git switch main && git merge --ff-only origin/main   # b18c97f..eb221ba
$ git switch -c research/s1-m1-2-firewall-read-path && git branch --unset-upstream
```
Earlier branches are kept: `docs/planning-v0`, `docs/adr-0021-hybrid-ai`, `docs/adr-0021-hybrid-ai-v2`, `feat/s1-m1-walking-skeleton`.

## M1.2 results (summary; details in the report)
- Report: [docs/research/2026-10-14-d9-firewall-read-path.md](../research/2026-10-14-d9-firewall-read-path.md).
- Sanitized evidence: [docs/research/evidence/d9-read-path-te1-2026-10-14.json](../research/evidence/d9-read-path-te1-2026-10-14.json).
- Probe: [scripts/research/d9_read_path_probe.py](../../scripts/research/d9_read_path_probe.py). It is read-only, uses the audited `PowerShellRunner`, and refuses to run elevated.
- [Verified, TE-1, non-elevated]
  - Bulk port/address/interface-type/interface filter enumeration is **denied**, even through raw CIM.
  - **Per-rule association works for all 1,586 rules with 0 errors.**
  - COM = PersistentStore (1,583). The 3-rule gap is the **Dynamic store**, which COM omits.
  - COM loses keywords: `RPC` and `PlayToDevice` appear as Any; `LocalSubnet6` appears as `LocalSubnet`.
  - 77 COM names are unresolved resource strings.
  - WFP filter enumeration is denied.
  - ActiveStore excludes the service-hardening stores (191 + 95 rules).
  - Rules + port + address association took **about 15.7 s** (median of 3). Running the pipelines in parallel is slower.
- **Accepted D9 (v0.1 direction)** (ADR 0009 **Accepted** with conditions):
  - ActiveStore: bulk rules plus application/service/security filters, and per-rule association for port/address/interface-type filters;
  - no COM, WFP, or registry as data sources;
  - explicit `Indeterminate` reasons for anything unreadable.
- **N-04 is kept at 10 s (human decision).** The detailed scan **currently exceeds N-04**: about 15.7 s measured for rules + port + address, about 20 s estimated with interface-type filters (TE-1, informal). This must be reported transparently until it is met.
- **M1.3 must evaluate progressive collection:** a fast inventory, background detailed filters, explicit progress/completeness/error states, and no final verdict before its evidence is available.
- **Verified only on TE-1:** per-rule access behavior. **Pending:** Windows 10 22H2, Group Policy, interface-name filters, service-hardening rules, `EnforcementStatus` semantics.

## Tests and checks run [Verified, 2026-10-14, uncommitted tree on `eb221ba`]
| Command | Result |
|---|---|
| `uv run --frozen python scripts/research/d9_read_path_probe.py --repeat 3 --out docs/research/evidence/d9-read-path-te1-2026-10-14.json` (final script version) | Completed; evidence written. Numbers matched two earlier runs (the counts were identical; timings within about 10%) |
| Evidence sanitization scan (regex for SIDs, paths, IPs, resource strings, user and host names; list of every string value) | Clean. String values are only Windows enum names, error IDs, versions, and the locale (`es-ES`). The only regex hit was the module version `2.0.0.0` |
| `uv run --frozen ruff check` / `ruff format --check` (whole repo, including `scripts/`) | All checks passed / 40 files already formatted |
| `uv run --frozen pytest -q` | 70 passed (no production code changed in M1.2) |
| `uv run --frozen mypy` / `lint-imports` / `uv lock --check` | Success: no issues in 25 source files / 4 kept, 0 broken / 37 packages resolved |

## Tests not run
- Windows 10 22H2 and Group Policy VM checks (Hyper-V access pending).
- Per-rule association of interface-alias filters; filters of the service-hardening stores.
- No unit tests for the research script (it isn't production code).

## Known limitations
- Single machine (TE-1), no GPO, informal timings.
- `docs/research/` and `scripts/research/` were added to the AGENTS.md repository map (human-approved, 2026-10-14).
- The M1.1 limitations still apply (profiles only; no CI; synthetic fixtures).

## Security notes
- All probe operations were read-only and non-elevated: Get-* cmdlets, COM property reads, WFP enumeration (denied), and registry `KEY_READ`.
- No firewall, rule, system, or network configuration was changed. No dependencies were installed.
- The committed evidence contains no rule names, paths, SIDs, addresses, or host identifiers.
- `.claude/settings.json` is unchanged.

## Pending decisions and actions for the human
1. D9 decided (accepted with conditions); N-04 kept at 10 s.
2. Open and review the M1.2 PR (`research/s1-m1-2-firewall-read-path` -> `main`), then authorize the squash merge.
3. Authorize M1.3 (rules collector with progressive collection) separately.
3. Hyper-V access, plus Windows 10 22H2 and GPO test VMs, to resolve the open items.
4. Still open: D17 (Codex settings), D4–D13, D19.

## Resume commands
```
git fetch origin
git switch research/s1-m1-2-firewall-read-path
git status --short
uv sync --frozen
uv run --frozen python scripts/research/d9_read_path_probe.py --repeat 3 --out <scratch>.json
uv run --frozen pytest -q
```
