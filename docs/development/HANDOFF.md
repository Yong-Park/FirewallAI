# Handoff: last updated 2026-10-15 by claude-code

Active agent lock: RELEASED

> **[Verified]** means it was checked by a command in the session that wrote this section, with the output pasted.
> **[Assumed]** means it was not checked.
> Protocol: [AGENT_WORKFLOW.md](AGENT_WORKFLOW.md).

## Position
- **Sprint 1, M1.4 (local endpoints, processes, descriptive correlation): implemented, final-reviewed, and verified** on `feat/s1-m1-4-network-endpoints` (from `main` `7e52e93`).
- The human reviewed the final report and **authorized the M1.4 commit and `git push -u origin feat/s1-m1-4-network-endpoints`** (2026-10-15). The commit SHA is reported in the session; see `git log`.
- **Not authorized:** merging, opening the PR (the human will authorize it separately), and **M1.5**.
- M1.3 is merged (PR #6, `7e52e93`). The full M1.3 handoff, including its final review, is in git: `git show 7e52e93:docs/development/HANDOFF.md`.
- `main` history: M0 (#1, #2), ADR 0021 (#3), M1.1 (#4), M1.2 (#5), M1.3 (#6). Ruleset 25123659 protects `main` (ADR 0018).

## Git after the M1.3 merge [Verified, 2026-10-15, normal user environment]
```
$ git status --short --untracked-files=all     # on feat/s1-m1-3-firewall-rules, before sync
(empty; no stash entries)
$ git fetch origin                     -> fa656ea..7e52e93  main
$ git rev-parse 79f7ac5^{tree} origin/main^{tree}
0bad8fd8...  0bad8fd8...               # merged tree identical to the reviewed commit
$ git switch main && git merge --ff-only origin/main     -> 7e52e93
$ git switch -c feat/s1-m1-4-network-endpoints
```
- `gh` is not installed. The merge was confirmed through git.
- All earlier local branches were kept. No `safe.directory` override was added.

## Codex session (2026-10-14/15) [reported by the human; local state Verified]
- Codex was tested. It **could not complete the repository audit** because Git reported dubious-ownership errors inside its Windows sandbox.
- Afterwards, in the normal user environment:
  - the tree was clean;
  - there were no stash entries;
  - HEAD was the reviewed M1.3 commit.
- **No security settings were changed** for Codex. **D17 remains open.**

## Human decisions for M1.4 (2026-10-15)
- **Q1, approved:** psutil (option A) as the single new runtime dependency, after verification (done; see below).
- **Q2, approved:** service names through the audited PowerShell runner, via a constant, registered, read-only `Win32_Service` query. Failures must not invalidate socket data.
- **Q3, approved:** descriptive correlation, with strict semantics:
  - no exposure or reachability verdicts;
  - a port match alone is never enough;
  - contradictions block a match;
  - missing or ambiguous data gives `cannot_evaluate`;
  - no restriction is silently ignored;
  - no automatic rule scan.
- **Q4, approved:** collect remote endpoints for active TCP connections and the process metadata Windows allows. Also:
  - **no command lines or process owners**;
  - remote addresses hidden by default in text output, with `--show-remote` to show them;
  - JSON documented as sensitive;
  - no telemetry and no logging of endpoint records.
- **Q5:** endpoint → interface → profile mapping **deferred to Sprint 2**. No profile is inferred from a local address.
- **Q6:** **SB-20 approved** ([security-boundaries.md](../architecture/security-boundaries.md)).
- **N-04** (the rule scan, 10 s) is unchanged and still unmet. It is **not** combined with the endpoint snapshot target.

## Human decisions after the M1.4 report (2026-10-15)
- **Decision 1:** the psutil-only mypy configuration is **conditionally approved**, under these conditions:
  - strict typing stays for all first-party code;
  - exceptions are limited to psutil;
  - the effect is verified and documented;
  - **no `types-psutil`**.
- **Decision 2:** PID 4 listeners against non-`System` program rules **stay `cannot_evaluate`**, with the reasons preserved. No artificial reduction.
- **Decision 3:** a short **Proposed ADR** for psutil. It is [ADR 0022](../adr/0022-psutil-endpoint-collection.md), the next free number from the index; no existing ADR was changed. It was drafted as Proposed and has since been **accepted** (see below).

## Final human decisions (2026-10-15)
- **ADR 0022 accepted:** psutil 7.2.2 as the M1.4 endpoint collection dependency, with its documented rationale, licensing, maintenance, privacy constraints, and typing limitations. The ADR index is updated.
- **PID 4 approved as implemented:** kernel-owned listeners stay `cannot_evaluate` when Windows semantics don't justify more. Uncertainty is not artificially reduced.
- **SB-20 approved:** correlation is descriptive only, with four categories:
  - `related`;
  - `related_with_unevaluated_conditions`;
  - `cannot_evaluate`;
  - `not_related`.
  None of them means firewall permission, network reachability, or a security finding.
- **M1.4 performance accepted as a documented development limitation:** the < 1 s endpoint target is not consistently met on cold starts. **N-04 remains unmet and unchanged.** This is **not a waiver and not a declaration of compliance**.

## psutil verification (before installing) [Verified, 2026-10-15]
- **PyPI metadata:**
  - psutil 7.2.2, released 2026-01-28 (inside `exclude-newer`);
  - **BSD-3-Clause**;
  - **no runtime dependencies** (only dev and test extras).
- **Compatibility:** a `cp37-abi3-win_amd64` wheel, which works with CPython 3.12. Its sha256 `eb7e8143…` matches the locked hash.
- **Advisories:**
  - PyPI's `vulnerabilities` field is empty for 7.2.2;
  - OSV's only entry is CVE-2019-18874 / GHSA-qfc5-mcwq-26q8 (double free), which affects ≤ 5.6.5 and was fixed in 5.6.6;
  - `pip-audit` is not installed, so it was **not run**. Adding it would be an unapproved dependency.
- **Install:**
  - `uv add psutil==7.2.2` resolved 38 packages (37 + psutil); **no other package changed**;
  - `uv lock --check` and `uv sync --frozen` are both clean.

## M1.4 status [Verified]
**Implemented:**
- **`core.endpoints`:**
  - `Endpoint` (TCP/UDP, IPv4/IPv6; kinds `listening` / `bound` / `connection`; TCP states preserved, unknown → `UNRECOGNIZED`; bind scope; dual-stack flag);
  - `ProcessInfo` and `Observed[T]` (explicit unavailable reasons; no defaults);
  - `EndpointSnapshot`, which has a 65,536-endpoint cap that fails explicitly;
  - `display_safe` for untrusted text.
- **`core.correlation`:** descriptive related / cannot-evaluate / not-related relations, and `RuleIndex` (SB-20).
- **`collectors.endpoint_assembly`:** the two-snapshot PID-reuse guard. It is platform-neutral and shared by both collectors.
- **`collectors.windows.network_endpoints`:**
  - psutil for sockets, plus name and path for each process;
  - `WIN32_SERVICES`, run in parallel through the runner;
  - `ENDPOINT_SNAPSHOT_LOCK` for single-flight.
- **`collectors.fake.network_endpoints`.**
- **`app.endpoint_service`:**
  - the 1 s snapshot target (`met` / `exceeded` / `not_evaluated`), separate from N-04;
  - the `firewallai.endpoints/1` export with a privacy note;
  - the rule index builder, which expands only system-wide path variables.
- **CLI:** `firewallai endpoints [--json] [--summary] [--listening] [--show-remote] [--fixture]`.
- **GUI:** the **Network** tab:
  - collection runs on a worker, with a filter, cancel, explicit process states, timing, and limitations;
  - the related-rules panel uses only a rule scan the user already ran (`RulesTab.collection_ready`);
  - indexing and correlation run on workers.
  - Shared `ui.table_model` (the Rules model was refactored onto it, with no behaviour change).
- **Import contract 5:** psutil only in the Windows endpoint collector. It was mutation-checked with a temporary probe file that was then deleted.

**Docs updated:**
- `docs/architecture/interfaces.md` (M1.4 section);
- `module-map.md` (M1.4 entries; 5 contracts);
- `security-boundaries.md` (**SB-20**, the SB-18 `*` fix, and the SB-19 note);
- README;
- AI_DEVELOPMENT.md.

## Deviations from the approved plan and new findings
1. **Best-effort PID-reuse check by double snapshot, not process creation time.** It is a consistency check, **not proof of process identity**.
   - The plan said "process started after the snapshot is not attributed". As a standard user, psutil's `create_time()` cost about 660 ms for about 87 processes, mostly protected ones that fall back to a whole-system query. That alone would break the 1 s target.
   - Instead, the socket table is read before and after the process lookups. A socket/PID pair that isn't present in both is `attribution_unverified`, and no process details are attached.
   - Residual risks are documented in `collectors/endpoint_assembly.py` and reported with **every** snapshot as the `attribution_best_effort` limitation:
     - (a) the owner exits, its PID is reused, and the new process binds the identical tuple within the window (about 0.1–0.3 s);
     - (b) inherited or duplicated socket handles `[VERIFY]`;
     - (c) PID 4 is never attributed.
2. **M1.3 defect fixed (SB-18): `*` in service and package filters had been mapped to "any".** For these filters `*` means "services only" or "app packages only", which is a restriction.
   - It is now preserved and handled in correlation.
   - TE-1 has no `*` values today (services: 1,406 any / 184 specific; packages: 1,561 empty / 29 specific), so no live result changed.
   - A regression test was added.
3. **Gate-config change (conditionally approved by the human, 2026-10-15; see "mypy configuration" below).** psutil ships no type information, so strict mypy rejected the import. Two overrides were added to `pyproject.toml`:
   - `[[tool.mypy.overrides]] module=["psutil","psutil.*"] follow_untyped_imports=true` (mypy reads psutil's own source rather than skipping it);
   - `untyped_calls_exclude=["psutil"]`.
   - **No `# type: ignore` and no `ignore_missing_imports`.** All psutil values are validated by strict pydantic models before use.
   - The alternative would be the `types-psutil` stub package, which would be a second dependency and was not added.
4. **Gate strengthened:** import-linter contract 5 (psutil confined). Security tests check read-only psutil API use and the service script's minimal fields.
5. **Shared table model.** The Qt boilerplate, including its 3 existing `noqa` lines, moved from `rules_model` to `table_model`.
   - The `noqa` count in `src` is 8, the same as HEAD.
   - The `type: ignore`, skip, and xfail counts are also unchanged.
6. **Correlation is conservative on purpose (human decision 2: keep it so).** On TE-1, about 17,000 relations are `cannot_evaluate`:
   - **8,711:** PID 4 (kernel) listeners against rules for a specific program. The image path for PID 4 isn't available, so these aren't treated as a mismatch.
   - **8,512:** rules with an app-container owner.
   - **1,792:** rules with an app package.
   - **194:** dynamic ports.
   - **123:** unresolved port keywords.
   - "PID 4 vs a non-`System` program" stays `cannot_evaluate`, with its reason, unless verified Windows semantics justify more (decision 2).
7. **NetTCPIP vs psutil row counts** (planning spike) are still unexplained `[VERIFY]`. psutil was chosen, so this no longer affects M1.4.

## Final review (2026-10-15) [Verified]
**PID attribution (additional review 1–2):**
- The implementation and docs no longer claim guaranteed identity:
  - `core.endpoints` and `endpoint_assembly` describe a best-effort consistency check;
  - the always-on limitation says "not a guarantee of process identity";
  - the correlation disclaimer says "process identity is best effort".
- Conservative handling:
  - **any** field reporting "process exited" now unattributes the whole process (before, both fields had to report it; regression test `exited-mid-lookup`);
  - access-denied or overlong values are explicit unavailable states;
  - unverified attribution, PID 0/4, and a missing PID carry no details;
  - program matching uses only the image path (never the name), and an unavailable path gives `cannot_evaluate`.

**Correlation (additional review 3–4):**
- `RELATED` (identity filters consistent and **no** network conditions) is now **separate from** `RELATED_WITH_UNEVALUATED_CONDITIONS` (identity consistent; profile, interface type or alias, remote address or port, edge traversal, or IPsec/authorization conditions listed as not evaluated).
- **Unevaluated conditions are never treated as satisfied.**
- Service-hosting ambiguity and app-container (package or owner) scopes give `cannot_evaluate`.
- Tests:
  - 12 parametrized cases assert that each condition alone prevents a plain `related`;
  - service-hosting and app-container scopes are tested;
  - the live integration test asserts that `related` has no conditions.
- The GUI panel lists the three groups separately.

**Wildcard fix (additional review 5):**
- `_optional_keep_wildcard` keeps `*` for service and package filters. Program filters keep `*` → any, because programs have no wildcard semantics.
- An 11-case mapping regression test was added.
- **Mutation-checked:** with the M1.3 mapping restored, exactly the 3 `*` cases failed (3 failed, 9 passed). The fix was then restored, and the file was confirmed identical.

**Privacy output (additional review 6):**
- `--show-remote` changes **text output only**. A test asserts that `--json` and `--json --show-remote` give identical endpoint data and an identical stderr warning.
- The JSON export now has an explicit `sensitivity` block:
  - `data_class=host_sensitive`;
  - the list of contained data;
  - `remote_addresses_included=true`;
  - `share_publicly=false`;
  - `not_collected` = command lines and owners;
  - plus the existing `note` and the stderr warning.

**No live or machine data (additional review 7):**
- A scan of 37 changed and new files against 131 live values (addresses, image paths, service names) matched only generic Windows service names. `Schedule` and `SharedAccess` appear only because this handoff and earlier research mention them.
- There are no user names, machine names, real SIDs, or credentials (the only SID in tests is a synthetic `S-1-5-21-0-0-0-1001`).
- `.claude/` is unchanged, and `settings.local.json` stays git-ignored.

**Performance (additional review 8):**
- **The < 1 s target is NOT consistently met.**
  - Warm: 0.69–0.94 s.
  - Cold first runs: 1.26, 1.26, 1.35, 1.67 s.
- The rule-scan N-04 limitation is unchanged and separate (27.2 s, over by 17.2 s).

## mypy configuration (decision 1) [Verified]
```toml
[tool.mypy]
strict = true
untyped_calls_exclude = ["psutil"]      # only calls into psutil's unannotated functions

[[tool.mypy.overrides]]
module = ["psutil", "psutil.*"]
follow_untyped_imports = true           # read psutil's source instead of rejecting the import
```
- **Effect, measured with a temporary probe module (deleted afterwards):**
  - `psutil.net_connections` is `def (kind: Any =) -> Any`, and `Process(…).name()` / `.exe()` are `Any`.
  - **First-party strict checks are all still reported:** `no-untyped-def`, first-party `no-untyped-call`, `assignment`, `arg-type`, `no-any-return`.
- **Limitation:** a psutil `Any` assigned to a typed variable is not checked by mypy.
  - The mitigation is runtime validation: every psutil value goes through `str()`/`int()` conversion and **strict** pydantic models (`RawSocket`, `RawField`, `RawProcess`), or an `isinstance` check, before use.
  - There is no `ignore_missing_imports`, and no `# type: ignore` in `src`.
- Documented in `pyproject.toml` and [ADR 0022](../adr/0022-psutil-endpoint-collection.md) §5.

## Tests and measurements [Verified, 2026-10-15, uncommitted tree on `7e52e93`, TE-1, non-elevated]
| Command / check | Result |
|---|---|
| `uv run --frozen pytest -q -s` (final run after the final review; repeated before the commit) | **382 passed in 106.98 s**; pre-commit re-run **382 passed in 115.46 s** (security 73, integration/windows 13, unit 269, UI 27). Pre-commit run: snapshots 1.16 s (cold, exceeds) / 0.86 / 0.79 s; rule scan 29.2 s (N-04 exceeded by 19.2 s); network tab max gap 77 ms |
| `ruff check` / `ruff format --check` / `mypy` (strict) / `lint-imports` / `uv lock --check` | All checks passed / 74 files already formatted / no issues in 43 source files / **5 kept, 0 broken** / resolved 38 packages |
| Network tab scale test (final run) | max GUI gap 71 ms |
| Suppressions vs HEAD | `noqa` src 8/8, tests 0/0; `type: ignore` src 0/0, tests 4/4; skip/xfail 1/1 (unchanged) |
| **Endpoint snapshot, end to end** (sockets + processes + service lookup) | **Target < 1 s NOT consistently met.** Warm, in-process (integration): **0.69–0.94 s**. Fresh CLI processes: **0.77–0.82 s** (6 runs). **Cold first runs: 1.26 s, 1.26 s, 1.35 s, 1.67 s, which EXCEEDS 1 s.** Breakdown: sockets 0.02 s (two tables), processes 0.10–0.19 s, service lookup 0.67–0.91 s warm and 1.2–1.6 s cold (PowerShell + CIM start-up, in parallel) |
| Live snapshot content (counts only) | about 657 endpoints: listening 141, bound 189, connections 327; IPv4 572, IPv6 85; process attributed 593, system pseudo (PID 0/4) 64; 0 access-denied (psutil has a fallback for protected processes), 0 unverified |
| Live correlation (counts only, final run) | endpoints: evaluated 211, not applicable (connections) 330, cannot evaluate (loopback) 107; relations: **related 81**, **related with unevaluated conditions 328**, cannot evaluate 16,860, not related 215,042. Index build 8 ms; per-endpoint correlation mean 2.7 ms, max 53 ms (on a worker) |
| GUI: `test_network_tab::test_gui_stays_responsive_at_realistic_scale` (5,000 synthetic endpoints + 2,000-rule index) | 8/8 runs passed, max gap **62–77 ms** (< 100 ms). The GUI-thread slots themselves are ≤ 7 ms; the gaps are the worker's CPU-bound row and index building contending for the GIL |
| Live GUI probe (real collectors, offscreen) | endpoint snapshot max gap 36–37 ms; rule scan 63 ms; filters plus 8 related-rules look-ups 24 ms; **overall max 63 ms** |
| Rule scan in the same suite (N-04) | 27.21 s, 1,590 rules. **N-04 EXCEEDED by 17.2 s** (unchanged limitation) |
| Data locality | No live addresses, process paths, or service names in any repo file (scratch scan of 133 files against 131 live values; only the generic Windows service names `Schedule` and `SharedAccess` matched). No logging in the M1.4 modules |

## Known limitations
- **N-04 not met (M1.3, unchanged):** a full rule scan takes about 27–35 s against the 10 s target. It is a documented limitation, not a waiver.
- **Endpoint snapshot target (< 1 s) is not consistently met:**
  - met warm, at 0.69–0.94 s;
  - **exceeded on cold first runs** (1.26–1.67 s), because of PowerShell + CIM start-up for the service lookup.
  - A persistent PowerShell session could fix both this and N-04 `[NEEDS PROTOTYPE]`, separately approved.
- **Profile per interface not mapped** (Sprint 2). Correlation lists profile, interface, remote-peer, and IPsec restrictions as *not evaluated*.
- **Snapshot is not atomic:** endpoints come from the first socket table, and sockets can change during the snapshot.
- **Process attribution is best effort:** a double-snapshot consistency check, not proof of identity. The residual PID-reuse risk is reported with every snapshot.
- **Typing:** psutil's API is `Any` to mypy. It is mitigated by runtime validation (ADR 0022 §5).
- **Loopback-bound endpoints aren't correlated** (`[VERIFY]` how firewall rules treat loopback traffic). TCP connections aren't correlated either.
- **Shared service hosts:** a service-specific rule against a process hosting several services is `cannot_evaluate`.
- **8.3 short names, device/UNC paths, and user-specific variables** in rule program paths are `cannot_evaluate`.
- `dual_stack_unknown`: whether a `::` socket also accepts IPv4 (`IPV6_V6ONLY`) can't be observed.
- **GUI gaps reach 62–77 ms** at a synthetic 5,000 endpoints + 2,000 rules (GIL contention). On TE-1 with real data the maximum was 63 ms.
- **Verified only on TE-1** (Windows 11). Windows 10 and VMs are still pending.
- **Process-access result is host-specific:** TE-1 showed 0 access-denied processes. Other machines and security products may differ, and that is handled explicitly.
- No CI yet; `pip-audit` was not run; fixtures are synthetic; mypy doesn't check `tests/`.

## Security and privacy notes
- **Read-only and non-elevated** throughout. No firewall, system, or network configuration was changed.
- **Read-only psutil APIs only** (`net_connections`, `Process.name/exe/oneshot`), enforced by an AST test. No command lines, owners, environment, or process control.
- The **service query** is local (no `-ComputerName`) and requests only `Name` and `ProcessId`.
- **No logging or printing** of endpoint records; the CLI writes only the requested output.
- Remote addresses are **hidden** in text output by default. JSON prints a privacy note to stderr and contains one in the document.
- Untrusted names are escaped for display (bidi, control, and zero-width characters).
- **No AI, cloud, or telemetry.** SB-05 is unchanged: psutil makes no network connections, and the socket guard plus the import contracts still pass.
- `.claude/` is unchanged.

## Pending decisions for the human
1. Open and review the M1.4 PR (human authorization required); the merge decision is the human's.
2. Review and authorize the M1.4 PR (separately). Do not merge without authorization.
3. Still open: Hyper-V / Windows 10 / Group Policy VMs, D17 (Codex settings), and an N-04 plan (persistent PowerShell session spike).

## M1.4 commit (authorized by the human 2026-10-15)
```
feat(collectors): add M1.4 read-only endpoint, process and service collection

Local TCP/UDP (IPv4/IPv6) listening, bound and connection endpoints via psutil
with a two-snapshot PID-reuse guard; explicit process states; service names via
a registered read-only CIM query in parallel; descriptive listener-to-rule
correlation (SB-20; related vs. related-with-unevaluated-conditions vs.
cannot-evaluate; no reachability claims); best-effort process attribution;
service/package '*' filters kept as restrictions (M1.3 fix); CLI `endpoints`
(remote addresses hidden by default) and GUI Network tab; ADR 0022 (psutil, accepted).
Endpoint snapshot 0.7-0.9 s warm but 1.3-1.7 s cold: the 1 s target is not
consistently met. N-04 for the rule scan remains unmet.

AI-Agent: claude-code
Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
```

## Next steps
1. Human authorization and review of the M1.4 PR.
2. Do not start M1.5 without authorization.

## Resume commands
```
git fetch origin
git switch feat/s1-m1-4-network-endpoints
git status --short
uv sync --frozen
uv run --frozen pytest -q
uv run --frozen firewallai endpoints --summary
uv run --frozen firewallai-gui
```
