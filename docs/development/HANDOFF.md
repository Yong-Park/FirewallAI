# Handoff: last updated 2026-10-14 by claude-code

Active agent lock: RELEASED

> **[Verified]** means it was checked by a command in the session that wrote this section, with the output pasted.
> **[Assumed]** means it was not checked.
> Protocol: [AGENT_WORKFLOW.md](AGENT_WORKFLOW.md).

## Position
- **Sprint 1, M1.3: the read-only ActiveStore rules collector is implemented, final-reviewed, and tested.**
- The human reviewed the final report (2026-10-14) and **authorized** the M1.3 commit, `git push -u origin feat/s1-m1-3-firewall-rules`, and opening a PR to `main` for review.
- Branch: **`feat/s1-m1-3-firewall-rules`**, created from `main` at `fa656ea` (PR #5, M1.2 merged).
- **Not authorized:** merging the PR, and **M1.4**.
- The N-04 gap must keep being reported explicitly.
- `main` history: M0 (#1, #2), ADR 0021 (#3), M1.1 (#4), M1.2 (#5, `fa656ea`). Ruleset 25123659 protects `main` (ADR 0018).

## Git [Verified]
```
$ git branch --show-current
feat/s1-m1-3-firewall-rules
$ git rev-parse --short HEAD
fa656ea
$ git status --short          # 17 modified, 16 untracked; .claude/ unchanged
```

## Human decisions for M1.3 (2026-10-14)
- **Q1, approved:** an opt-in JSON Lines streaming mode in the runner, conditional on the Step 0 prototype and security validation (both done; no unresolved security issue).
- **Q3, approved:** SHA-256 rule IDs, which must be stable, collision-detected, never merged, and versioned (`h1`).
- **Q4, approved:** collect enabled inbound rules first, with complete coverage.
- **Q9, deferred:** `--redact`. JSON exports carry a host-sensitive note instead.
- **N-04 stays at 10 s.** The human **accepted that M1.3 exceeds it** as an explicitly documented limitation. This is **not a waiver** and not a change to the requirement.
- **SB-18 and SB-19 approved** by the human as security invariants ([security-boundaries.md](../architecture/security-boundaries.md)).

## M1.3 status [Verified]
**Implemented:**
- `core.rules`: `FirewallRule`, `FilterResult` (collected / not_collected / unreadable; no defaults), typed tokens, ID scheme `h1`, `RuleCollection`, `ScanLimitation`.
- `core.evidence`: the completeness guard.
- Runner streaming mode.
- The `FIREWALL_RULES` script.
- `rule_mapping` (assembler, ID allocation, built-model cache).
- The shared progressive driver.
- The Windows collector, with a single-flight lock.
- The fixture collector.
- `RuleScanService`, with N-04 evaluation and `firewallai.rules/1`.
- The `firewallai rules` CLI.
- The GUI Rules tab: progress, cancel, limitations, timing/N-04, and rows precomputed on the worker.
- `prepare_gc_for_gui`.

**Docs updated:**
- `docs/architecture/interfaces.md`, `module-map.md`, and `security-boundaries.md` (SB-03 extended; SB-18 and SB-19 added and marked human-approved).
- ADR 0009 implementation notes (status unchanged: Accepted), the ADR index, README, and AI_DEVELOPMENT.md.

## Final review (2026-10-14) [Verified]

### 1. Streaming runner security review
Areas reviewed:
- process cleanup: kill, wait, and close in `finally`, and reader threads joined;
- cancellation, timeout, and the deadline loop;
- the strict line schema;
- per-line, total, and event-count caps;
- stdout and stderr handling;
- exception paths.

Three defects were found in the agent's own code. All three are **fixed in both the buffered and streaming paths**. Each has a regression test, and each test was shown to **fail on the unfixed code** (5 failed) and to pass after the fix.

| # | Defect | Fix | Test |
|---|---|---|---|
| F1 | A deeply nested JSON line within the caps raised an uncaught `RecursionError`, not a structured error | `RecursionError` → `parse_error` | `test_json_nesting_bomb_*` (both files) |
| F2 | After 64 KiB of stderr the reader stopped draining, so a chatty child could block on a full pipe until timeout | `_drain_stderr` keeps 64 KiB and drains and discards the rest | `test_*stderr_flood_does_not_block_the_child` |
| F3 | A child that closed stdout without exiting raised an uncaught `TimeoutExpired` from `wait(5)` | Reported as `execution_failed` (`exit_code=None`); child killed in `finally` | `test_child_closing_stdout_without_exiting_is_failed_and_killed` (marker file proves the kill) |

- Test-harness note: the venv's `python.exe` is a launcher that keeps its own copy of the pipe handle. F3's test therefore uses the base interpreter. Production runs `powershell.exe` directly.
- No other issues were found. Timeout, cancel, consumer exception, and the per-line, total, and event caps were already covered by tests.

### 2. `gc.freeze()` review
- **Why:** M1.3 probes showed generation-2 collections on the worker thread taking 35–91 ms while holding the GIL, which stalled the GUI. `prepare_gc_for_gui()` runs `gc.collect()` and then `gc.freeze()` **once at GUI start-up**, so full collections skip the roughly 40–63k start-up objects.
- **Memory implications:** frozen objects are still freed by reference counting. Only cyclic garbage that existed at start-up is never reclaimed, and the preceding `gc.collect()` minimizes that. Scan data is created later and stays collectable. It must be called **once per process**; calling it after each scan would pin that scan's results. All of this is documented in the docstring in `ui/app.py`.
- **Defect fixed:** the UI test froze the test process without unfreezing, which leaked state into later tests. It now calls `gc.unfreeze()` in `finally`.

### 3. Repeated-scan probe (scratch script; offscreen Qt; real `RulesTab`; non-elevated; no new dependencies; memory via `GetProcessMemoryInfo` through ctypes)
| Run | Scans | Private bytes after `gc.collect` (MB) | GC-tracked objects | Freeze count | Max GUI gap |
|---|---|---|---|---|---|
| Real ActiveStore, 1,586 rules | 4 (33.7 / 33.4 / 30.4 / 30.8 s) | 60.9 → 65.4 → 66.5 → 66.5 (start-up 35.8) | 1,660 constant | 40,714 constant | 62 / 67 / 74 / 59 ms |
| Fixture, 2,000 rules, CPU-saturated (0.02 s per chunk) | 10 | 70.8 → 77.0 → 74.9 … 76.1 | 2,038 constant | 62,922 constant | 41 → 77 ms |

- **Conclusion:** there is **no object growth across repeated scans**. Private memory settles after scan 2–3, a rise of about 5 MB that is consistent with allocator arena reuse rather than a leak.
- The probe's GUI gaps, 59–74 ms on real scans, are higher than the earlier live probe (35–49 ms). This probe drives the event loop with `processEvents()` plus a 5 ms sleep, not `app.exec()`. Every gap is under 100 ms.
- In the CPU-saturated fixture run, gaps rose from 41 to 77 ms over 10 scans while object counts stayed flat. This is unexplained timing variance, and it is recorded as a limitation, not a known cause. `[NEEDS PROTOTYPE]` if it matters.

### 4. The 19 incomplete rules (SB-18)
- No rule can become "unrestricted" or "safe":
  - `evidence_for_verdict` returns `IncompleteEvidence` for a non-`any` dynamic target or transport, dynamic keyword addresses, UNKNOWN tokens or protocol, an unknown policy source, and any filter that is not COLLECTED;
  - uncollected filters have `value=None`, never a default;
  - nothing produces a verdict in v0.1, and the GUI and CLI say "No verdicts".
- New live integration test `test_dynamic_or_unreadable_rules_are_never_complete` independently re-derives the risky rules and asserts each one is `IncompleteEvidence`. On TE-1: `[SB-18] rules forced to incomplete evidence: 19`.

### 5. Data locality and sensitivity
- There is no logging in `src/`: no `logging` and no `print` of rule data. The CLI writes only to the requested stdout. There is no network code, and SB-05 is enforced by import-linter plus the socket guard in the tests.
- A scratch scan collected live data from 1,586 rules and built 3,996 needles from raw IDs, hashed IDs, display names, program paths, interface aliases, and explicit addresses. It then searched every tracked and untracked repo file, 115 in all. Results:
  - only generic tokens matched: the Windows keywords `LocalSubnet4` and `LocalSubnet6`, and the product name "Visual Studio Code" in a `.gitignore` comment;
  - **no host-specific rule data** is in any file.
- Fixtures are synthetic (`tests/rule_builders.py`).

### 6. SB-19
- New test `test_concurrent_collections_never_run_heavy_queries_in_parallel` uses two threads and a blocking fake runner. It asserts:
  - the second collection returns BUSY without invoking PowerShell;
  - the runner had at most one active run and was called exactly once;
  - the lock is released afterwards.

## Tests and measurements [Verified, 2026-10-14, uncommitted tree on `fa656ea`, TE-1, non-elevated]
| Command / check | Result |
|---|---|
| `uv run --frozen pytest -q -s` | **185 passed in 81.19 s** (security 60, integration/windows 10, unit 96, UI 19) |
| `ruff check` / `ruff format --check` / `mypy` (strict) / `lint-imports` / `uv lock --check` | All checks passed / 56 files already formatted / no issues in 34 source files / 4 kept, 0 broken / resolved 37 packages |
| **Full rule scan (integration test, final run)** | total **32.81 s**, inventory 5.21 s, 1,586 rules, evidence 1,567 complete / 19 incomplete. **N-04 EXCEEDED by 22.8 s** |
| Full scans across all M1.3 runs (integration, CLI, GUI, repeated-scan probe) | **29.4–34.9 s** (inventory 4.6–6.3 s), about 3× the 10 s target |
| Live CLI `firewallai rules --summary` (earlier in M1.3) | exit 0; 1,586/1,586 rules; detail complete; 0 errors |
| Streamed output size | about 2.39 MB total (cap 16 MB); largest line about 1.52 MB (cap 8 MB) |
| Live GUI probe | **Before** fixes: max gap 439 ms. **After:** 35 ms and 49 ms; repeated-scan probe 59–74 ms |
| Security-test bound | The rules script was first set to timeout 180 s / output 64 MB, which **failed** the existing gate (≤ 120 s, ≤ 16 MB). The **script was adjusted; the test was not loosened** |
| New `# type: ignore` / `noqa` / skip / xfail | **None added** |

## GUI responsiveness history (for the next agent)
1. **439 ms stall:** the sort proxy re-sorted about 1,600 rows through Python `data()` on the GUI thread.
   - Fix: precompute display rows on the worker, and sort precomputed keys.
2. **100–125 ms stalls:** these overlapped full model rebuilds with generation-2 GC passes holding the GIL.
   - Fix: cache built models and rows, and call `gc.freeze()` at start-up.
3. **Tried and reverted:** cooperative `time.sleep(0)` yields made stalls worse (126–168 ms).
4. **Remaining:** a CPU-saturated synthetic stream measured 60–80 ms. GIL contention can't be fully removed in one Python process.

## Known limitations
- **N-04 not met (accepted by the human as a documented limitation, not a waiver):**
  - a full scan takes about 30 s against the 10 s target;
  - progressive results don't count as compliance;
  - inventory-only (about 5 s) is never reported as a full scan.
- Verified only on TE-1. Still pending (ADR 0009): Windows 10, Group Policy merge, service-hardening stores, and `EnforcementStatus` semantics. Non-firewall WFP filters can't be observed.
- 19 rules on TE-1 have incomplete evidence by design (non-`any` dynamic target/transport).
- Keyword vocabularies are `[VERIFY]`. Unknown values become UNKNOWN and incomplete, never ANY.
- Rule sets above about 11,000 rules may hit the 16 MB output cap. That fails explicitly with `output_too_large`.
- The GUI gap rises under CPU-saturated synthetic load, with an unexplained trend across 10 scans (see §3 of the final review).
- No CI yet. Fixtures are synthetic. No coverage tool. mypy doesn't check `tests/`.

## Security notes
- Read-only and non-elevated throughout. No firewall, system, or network configuration was changed. No dependencies were added. No AI, cloud, or network code.
- `.claude/settings.json` unchanged. Host-sensitive fields are marked, and the JSON export prints a sensitivity note. No host data is in the repo (§5).

## M1.3 commit (authorized by the human 2026-10-14; SHA reported in the session, see `git log`)
```
feat(collectors): add M1.3 read-only ActiveStore firewall rules collector

Progressive, non-elevated rule collection via an opt-in JSON Lines streaming
mode of the PowerShell runner; explicit per-filter evidence states; versioned
SHA-256 rule IDs; evidence guard (SB-18); single-flight heavy queries (SB-19);
CLI `rules` command and GUI Rules tab. N-04 (10 s) is not met: full scan
~30 s on TE-1, documented as a limitation.

AI-Agent: claude-code
Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
```

## Pending decisions and actions for the human
1. Open the M1.3 PR from the pushed branch, review the diff, and decide on the merge (agents never merge).
2. Hyper-V access and Windows 10 / Group Policy VMs (open compatibility items). D17 (Codex settings) is still open.
3. A plan for N-04. Ideas for a separately approved spike: profile the about 26 s of detail time inside PowerShell, and evaluate a persistent PowerShell session.

## Next steps
1. Human PR review and merge decision for M1.3.
2. Then plan M1.4 (do not start without authorization).

## Resume commands
```
git fetch origin
git switch feat/s1-m1-3-firewall-rules
git status --short
uv sync --frozen
uv run --frozen pytest -q
uv run --frozen firewallai rules --summary
uv run --frozen firewallai-gui
```
