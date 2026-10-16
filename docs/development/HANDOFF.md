# Handoff: last updated 2026-10-15 by claude-code

Active agent lock: RELEASED

> **[Verified]** means it was checked by a command in the session that wrote this section, with the output pasted.
> **[Assumed]** means it was not checked.
> Protocol: [AGENT_WORKFLOW.md](AGENT_WORKFLOW.md).

## Position
- **`main` = `9f590c6`** (PR #12: UX0 design package, **DRAFT, not validated**, usability study **not run**; tree identical to the reviewed `a4bbd33`).
- **PR-C branch `docs/sprint2-plan`** (from `9f590c6`), documentation only, uncommitted: [sprint-2-plan.md](sprint-2-plan.md). It covers:
  - milestones M2.0–M2.5, each needing separate authorization;
  - the SB-21 contract requirements (**SB-21 stays Proposed**; its precise contract is reviewed and approved in M2.0);
  - the decision-E outcomes;
  - the provisional catalog (9 entries) and the recorded F1-10 gap;
  - the privacy-design gate;
  - the N-04 investigation and the SR-M1.5-01 prerequisite review (P0, before M2.1).
- **Not authorized:**
  - any Sprint 2 implementation, including M2.0 ADR acceptance;
  - GUI implementation or redesign;
  - application code changes, new dependencies, publishing builds;
  - commits, pushes, PRs, or merges without approval.
- **Open:**
  - N-04 (rule scan about 27–35 s against 10 s);
  - inconsistent endpoint cold start;
  - unsigned development-only distribution;
  - Windows 10 and clean-VM validation;
  - the installer;
  - signing;
  - SR-M1.5-01;
  - the unverified manual sub-items (rows 1, 3, 5, 8, 9);
  - the UX0 usability round;
  - all VM validation requirements (S3: preserved, not moved or waived).
- `main` history: M0 (#1, #2), ADR 0021 (#3), M1.1 (#4), M1.2 (#5), M1.3 (#6), M1.4 (#7), M1.5 (#8), M1.5 closeout (#9), ADR 0023 (#10), M1.5 final acceptance (#11), UX0 draft (#12).

## Git after PR #12 [Verified, 2026-10-15]
```
$ git fetch origin                     -> be7316c..9f590c6  main
$ git rev-parse a4bbd33^{tree} origin/main^{tree}    # identical (a96b833e…)
$ git switch main && git merge --ff-only origin/main  -> 9f590c6
$ git switch -c docs/sprint2-plan
$ git show 'stash@{0}^3:docs/development/sprint-2-plan.md' > docs/development/sprint-2-plan.md
# only the Sprint 2 plan restored (byte-identical to the backup), then revised with decisions C–E and the refinements of 2026-10-15
```

## Sprint 2 plan (PR-C, draft) [human decisions C, D, E, 2026-10-15]
- **C:** M2.0–M2.5 are approved as a structure. Each milestone needs explicit authorization. **No engine implementation is authorized.** M2.0 must resolve the effective-policy evidence contract before M2.2.
- **D:** the SB-21 principle is approved; **SB-21 stays Proposed** until its precise contract is reviewed and approved in M2.0. `PermittedByPolicy` never means a real connection, internet reachability, that WFP/third-party/outside devices can't block, or that the PC is safe. Missing decisive evidence → Indeterminate. SB-18 and SB-20 are not weakened.
- **E:**
  - **S1:** JSON/TOML fixtures.
  - **S2:** `hypothesis` deferred.
  - **S3:** all VM validation requirements preserved; nothing moved, waived, or redefined; any schedule change only as a proposal for human approval.
  - **S4:** `scan --json` with evidence completeness.
  - **S5:** N-04 investigation planned, not started.
  - **S6:** SR-M1.5-01 is a separate prerequisite investigation (P0) before M2.1; a `Get-Command` origin check alone is not assumed sufficient; a narrowly scoped hardening design comes for separate approval; nothing implemented in PR-C.
  - **S7, S8:** FW-RULE-003 and FW-ENV-001 deferred.
  - **Q2:** unverified GPO merge → Indeterminate.
  - **Q3:** WFP limitation on every verdict.
  - **Q4:** Security Center readability investigated first.
  - **Q5:** M2.4 blocked on an approved privacy design; no automatic persistence, no 50-scan default, no DPAPI without a separate decision.
  - **Q6:** 9 supported frozen entries as a provisional catalog; FW-EXP-002 pending review of its port/process list and evidence; FW-RULE-003 and FW-ENV-001 deferred; **F1-10 (≥10) not waived**: the gap and safe options are recorded for a human decision before the M2.3 acceptance.
- **Refinements (human, 2026-10-15):** precedence (IPsec, Block/Allow, defaults, GPO merge, WFP) is not finalized and must be verified against authoritative Windows behaviour, otherwise Indeterminate; a local-policy verdict never implies real-world connectivity, internet reachability, or complete device security; loopback-only results describe the verified local binding and are never an unqualified "not exposed" (a label rename is only a proposal); every milestone M2.0–M2.5 needs separate authorization; six-field explanations plus complete technical evidence; UX0 stays DRAFT and not usability-validated; no generative AI in the verdict engine.

## Git after PR #11 [Verified, 2026-10-15]
```
$ git fetch origin                     -> d008ff0..be7316c  main
$ git rev-parse be065be^{tree} origin/main^{tree}    # identical (8296481c…)
$ git switch main && git merge --ff-only origin/main  -> be7316c
$ git switch -c docs/ux0-design-foundation
# UX0 files restored from stash "ux0-sprint2-drafts" only (6 ux/ docs + architecture index link);
# byte-identical to the preserved backup. sprint-2-plan.md stays in the stash for PR-C.
```

## UX0 design package (DRAFT) [human decisions B and F, 2026-10-15]
- **Location:** `docs/architecture/ux/`:
  - README: status, the four-way distinction, boundaries, decisions, recommendations R1–R4, exit criteria;
  - information-architecture.md;
  - wireframes.md;
  - status-and-tokens.md;
  - copy-guide.md;
  - usability-test-plan.md.
- **Applied:**
  - observed facts, verified findings, unknown/incomplete evidence, and **actual network reachability** (never shown as known) are kept apart;
  - Windows **Domain/Private/Public network profile** names stay correct, with plain descriptions and labelled examples, and the navigation label is "Network profiles";
  - the beginner Overview is the default, with optional technical details;
  - no GUI implementation.
- **Decisions R1–R4 (human, 2026-10-15), recorded as design requirements, not implemented:**
  - **R1:** Advanced view is session-only. It is not persisted until the storage/privacy design is separately approved, and the default is beginner-friendly.
  - **R2 (with refinements):**
    - first launch explains what is read and asks for **explicit authorization** before the first quick check;
    - after that, an automatic quick check (profiles and endpoints only) is allowed, under a user setting and with Cancel;
    - the full rule collection is always user-initiated, with an **estimated** duration (no exact promise);
    - a quick check is never "safe" and never a complete verdict;
    - SB-18/19/20 are respected.
    - **Dependency:** remembering the authorization or setting across launches needs persisted settings. Until the storage/privacy design is approved, it lasts for the session only.
  - **R3:** moderated walkthroughs of the text wireframes with synthetic data; a clickable Qt prototype with synthetic fixtures only as a separately authorized Sprint 3 activity.
  - **R4:** Domain/Private/Public with concise descriptions and explicitly labelled examples; never imply a location always maps to a profile.
- **Exit criteria:**
  1. Human design approval: structure approved as a draft; final approval after the usability round.
  2. **The usability round: NOT run.**
  3. R1–R4: decided.
- **UX0 stays DRAFT and NOT validated.** No GUI redesign implemented.

## Planning drafts
All drafts from the stash "ux0-sprint2-drafts" have now been used:
- UX0 → PR #12 (merged);
- the Sprint 2 plan → PR-C (`docs/sprint2-plan`).

The stash's older index/HANDOFF/ledger versions are superseded. The stash entry is kept until the human approves dropping it; agents do not delete it on their own.

## M1.5 final acceptance [reported by the human, 2026-10-15]
**Confirmed PASS:**
- the seven basic manual GUI checks;
- DPI scaling at 100/150/200 %;
- keyboard-only navigation;
- closing during an active collection;
- the related firewall rules panel (visual and functional inspection);
- the N-04 GUI timing indication (full rule scan 27.9 s against the 10 s target; exceeded-target warning displayed correctly);
- the portable folder (ran from a copied directory; no new files appeared).

No new defects were reported, and CI for PR #8 passed both jobs.

**Detailed matrix (`packaging/BUILD.md`): 8 of 13 rows PASS.** Rows 1, 3, 5, 8, and 9 are **partly verified**. Their basic evidence is preserved; these sub-items are **unverified and not marked PASS**:
- row 1: no console window; window title;
- row 3: cancel on the Rules tab; the cancelled-status text;
- row 5: resizing during an active collection;
- row 8: cancel on the Network tab; partial result with limitations;
- row 9: endpoint filters; sorting; remote addresses visible in the GUI.

**Decision (human, 2026-10-15):** ADR 0006 is **Accepted for the PyInstaller one-folder DEVELOPMENT distribution only**, with the residual manual-verification gaps documented. **Public release is NOT approved.**

**Public-release gates** (in ADR 0006):
1. installer;
2. clean-VM Windows 11/10;
3. signing;
4. SR-M1.5-01;
5. a human decision on N-04 and the endpoint cold start;
6. the human publishes;
7. the remaining manual sub-items.

## UX direction: human decisions (2026-10-15)
- **Decision 1:** ADR 0023, the beginner-first UX direction, is **approved** with refinements. FirewallAI must be understandable to non-experts while keeping full technical evidence for advanced users.
- **Decision 2:** UX-01 … UX-10 are **approved**, consistent with the security boundaries and with these refinements, all incorporated into [ux-principles.md](../architecture/ux-principles.md):
  1. Keep the Windows **Domain / Private / Public** profile names, with plain explanations; examples are labelled as examples.
  2. Rule relationships are described as **possible** only. A matching Allow rule does not guarantee a connection is permitted (SB-20).
  3. **Attention level is separate from evidence confidence.** Unknown or incomplete evidence never raises a warning. Green never means the whole device is safe. Icons and text accompany colour. No unsupported verdicts before Sprint 2.
  4. Usability tests add comprehension checks:
     - C1: a listening port is not necessarily exposure;
     - C2: an Allow rule is not necessarily permitted traffic;
     - C3: checked is not the same as unknown.

     There must be zero "completely safe" or "hacked" conclusions.
- **Decision 3:** milestone **UX0** (design only, before Sprint 3) is **approved**. Its deliverables: information architecture, low-fidelity wireframes, accessible design tokens, status/severity semantics, glossary and copy guidelines, the loading/empty/partial/cancelled/error states, and a usability-test plan with measurable criteria. Sprint 3 may implement the approved designs.
- **Decision 4:** the Sprint 2 plain-language finding fields are **approved**: observed; why it may matter; when it can be normal; supporting evidence; what is still unknown; what to review next. Analysis stays deterministic and evidence-based.
- **Decision 5:** **no redesign of the current UI now.** The existing functional M1.x UI stays intact until an approved implementation milestone.
- **Consistency check:**
  - The findings-catalog severity and confidence (planning 05 §6) are mapped, not redefined (ux-principles §5C).
  - The PRD's persona P1, N-07, and N-08 are reinforced, not contradicted.
  - SB-18 and SB-20 remain authoritative.
  - F1-15 view names may be refined in UX0 without removing any view.

## Git after the M1.5 closeout merge [Verified, 2026-10-15]
```
$ git fetch origin                     -> 6b150a3..3a26f56  main
$ git rev-parse a3781c4^{tree} origin/main^{tree}    # identical
$ git stash push --include-untracked   # UX drafts preserved
$ git switch main && git merge --ff-only origin/main  -> 3a26f56
$ git branch -m docs/ux-beginner-first docs/ux-beginner-first-old-base   # kept, no own commits
$ git switch -c docs/ux-beginner-first && git stash pop                  # re-applied cleanly
```

## Git after the M1.4 merge [Verified, 2026-10-15]
```
$ git status --short --untracked-files=all   # on feat/s1-m1-4-network-endpoints, before sync
(empty; no stash entries)
$ git fetch origin                     -> 7e52e93..5eb158e  main
$ git rev-parse c52ed77^{tree} origin/main^{tree}
6f0bff1a...  6f0bff1a...               # merged tree identical to the reviewed commit
$ git switch main && git merge --ff-only origin/main     -> 5eb158e
$ git switch -c feat/s1-m1-5-packaging
```

## CI failure on PR #8 and its correction (2026-10-15) [Verified locally; uncommitted, not pushed]
- **Status:** fix approved by the human, final-review hardening added, **commit and push authorized** (2026-10-15) to re-run CI on PR #8.
- **Symptom (reported by the human):** the first CI run on PR #8. "Gates and tests" passed. "Build and verify the portable bundle" built both executables, but `verify_build.py` failed the check "no build user, computer name, or source path in any file", only for `_internal/pydantic_core/_pydantic_core.cp312-win_amd64.pyd`.
- **Root cause (verified):**
  - The bundled pydantic-core binary contains **133 copies of one upstream path prefix**, `C:\Users\runneradmin\.cargo\registry\src\index.crates.io-…`. These are Rust crate source paths compiled in by **pydantic-core's own upstream build on GitHub Actions**.
  - GitHub's Windows runner account is `runneradmin`, and our CI build user is the same account, so the bare user-name search term matched.
  - The file is **byte-identical to the SHA-256 in the pydantic-core wheel's RECORD**, and the wheel is hash-locked in `uv.lock`. It holds no data from our build: no `D:\a\` checkout path and no "firewallai".
  - It passed locally only because the local user name differs.
  - **Reproduced locally** with `USERNAME=runneradmin`: the same check failed on the same single file.
  - No other bundled file contains the account name.
- **Correction:** the matching logic now distinguishes provenance (`packaging/privacy_scan.py`, used by `verify_build.py`):
  - **Source-path search terms fail in every file. No exception.**
  - User-name and computer-name terms fail in every file, except a file under `_internal/` whose bytes equal (SHA-256) the hash in the RECORD of an installed, locked **runtime** distribution (the SBOM set).
  - Every such match is **reported** in a separate check, `identity matches attributed to byte-identical locked upstream wheels`.
  - No exception for our executables, the base library archive, generated files, files missing from RECORD, modified wheel files, or non-runtime distributions.
  - `.pyd`, `.dll`, and `.exe` are not exempted by type; `_internal` is not ignored; the privacy check is not disabled; pydantic-core is unchanged.
  - Hardening found by a new test: malformed RECORD hashes are now rejected (strict base64 and exactly 32 bytes); before, they decoded to an empty digest, which could never match but was sloppy.
- **Evidence:**
  - verifier with `USERNAME=runneradmin`: exit 0, with the `.pyd` reported as attributed to `pydantic-core`;
  - verifier with the local user: exit 0;
  - mutation checks on a bundle copy, all failed as required: a tampered `.pyd` (exemption lost), a planted non-upstream file containing `runneradmin`, and a planted source path;
  - `tests/unit/test_packaging_privacy_scan.py`: **28 passed** (after the final-review hardening).
- **Final review hardening** (human conditions 1–5, 2026-10-15):
  - each wheel entry binds **one path to one hash**, and the bundled file is looked up by its own path, so a hash recorded for another file cannot authorize it;
  - unrecorded paths get no exemption;
  - only the locked **runtime** distributions can vouch for files (filtering moved into `privacy_scan.wheel_index(allowed=...)`, unit-tested; distribution names normalized);
  - a path recorded by two distributions with different hashes is dropped as ambiguous;
  - our executables and **top-level `_internal` files** (Python runtime, `base_library.zip`) are never exempt, even with a forged RECORD entry, because wheel files live inside a package directory;
  - source paths are never exempt;
  - every attributed match is reported.
  - **28 regression tests** (was 15).
- **Residual risk:**
  - A runtime wheel's own content could in principle contain *any* string. It is trusted only because its exact bytes are pinned by the hash-locked wheel; a dependency upgrade changes that content and is reviewed through the lockfile.
  - The check still cannot detect private data that **our build** might write into a file that also comes byte-identical from a wheel, but such a file would then no longer match its RECORD hash.
  - `COMPUTERNAME` on GitHub runners is random; it is scanned as before.

## Human decisions for M1.5 (2026-10-15)
- **Q1:** PyInstaller 6.22.3 as a development-only dependency, after verification.
- **Q2:** dependency audit and SBOM with uv tooling. Only public package names and versions may go out.
- **Q3:** a one-folder portable x64 development build. The installer is deferred to Sprint 4. **ADR 0006 stays Proposed**; the proposed Accepted wording is drafted for review.
- **Q4:** executable names `FirewallAI.exe` (GUI) and `firewallai-cli.exe` (CLI).
- **Q5:** automated launch/smoke tests plus a manual checklist. **No `--self-test` feature.**
- **Q6:** a local Microsoft Defender scan, as a standard user, with no setting changes and no uploads.
- **Q7:** narrowly scoped cleanup of PyInstaller-specific environment values for the PowerShell child.
- **Q8:** a minimal Windows CI workflow for pull requests:
  - least privilege;
  - SHA-pinned actions;
  - no secrets, artifacts, or releases;
  - required checks not enabled.
- **Q9:** a simple original provisional icon, without an image library.

## Human decisions after the M1.5 report (2026-10-15)
- **Decision 1:** the dedicated `build` dependency group and the isolated `.venv-build` are **approved**. PyInstaller and its build-only dependencies stay out of the runtime bundle.
- **Decision 2:** **ADR 0006 stays Proposed.** It may be accepted only after:
  - the first GitHub Actions CI run succeeds;
  - the manual GUI checklist is completed;
  - any packaging defects found by either are resolved.
  - The drafted Accepted wording stays in the ADR for later review.
- **Decision 3:** **no change to PowerShell module resolution in M1.5.** It is recorded as a separate security review item (below). The runner controls stay as they are.
- **Decision 4:** the manual GUI checklist is authorized but **not yet performed**. Its status is **PENDING**. Instructions and the exact repo-relative executable path (`dist\FirewallAI\FirewallAI.exe`) are in [packaging/BUILD.md](../../packaging/BUILD.md). It must not be marked passed without real results.
- **Decision 5:** commit and push authorized after the final checks.

## Security review item SR-M1.5-01: PowerShell module resolution (open; not changed in M1.5)
- **Observed** on TE-1 (2026-10-15), through the real runner:
  - the runner passes `PSModulePath` = System32 `WindowsPowerShell\v1.0\Modules` only;
  - Windows PowerShell 5.1 inserts `%ProgramFiles%\WindowsPowerShell\Modules` **before** it at start-up;
  - the user-profile module path is not added;
  - `Get-NetFirewallProfile` resolved to the NetSecurity module under System32.
- **Risk:** low. Program Files is admin-writable by default, so a standard-user process can't plant a module there. But a module placed there by an administrator or another installer would be searched first. This has been true since M1.1.
- **Proposed hardening (separate decision, not implemented):** import the required modules (NetSecurity, CimCmdlets) explicitly by full System32 path in the constant scripts, and test that the loaded module path is under System32.
- **Status:** open, for human review. SB-03 wording already corrected.

## Manual GUI acceptance [reported by the human, 2026-10-15; not agent-verified]
The human launched the locally built development bundle **as a standard user**. Basic checks:

| # | Check | Result |
|---|---|---|
| B1 | Application startup | **PASS** |
| B2 | Profiles tab | **PASS** |
| B3 | Rules tab and rule collection | **PASS** |
| B4 | Network tab and endpoint collection | **PASS** |
| B5 | Cancellation during collection | **PASS** |
| B6 | Window resizing and navigation | **PASS** |
| B7 | Application shutdown and restart | **PASS** |

**Result: 7 of 7 basic manual checks passed.** Nothing else is inferred.

**Detailed checks still PENDING** (`packaging/BUILD.md` rows 1–13 are cross-referenced there):
- DPI scaling at 100/150/200 %;
- keyboard-only operation;
- closing the window during a collection;
- the related-rules panel details;
- the N-04 line in the GUI timing;
- the read-only install folder checked by hand (the automated frozen smoke test verified it);
- clean-VM and Windows 10 testing.

## M1.5 status [Verified unless marked]
**Implemented:**
- **`pyproject.toml`:**
  - `pyinstaller==6.22.3` in a new **`build`** dependency group (not `dev`, so dev tools can never be bundled);
  - per-file lint ignores for `packaging/smoke/**` (S101, S603, S607, the same as `tests/**`).
- **`.gitignore`:** `.venv-build/`, and an exception for `packaging/firewallai.spec`.
- **`packaging/`:**
  - `firewallai.spec`: two executables sharing one `_internal`; `asInvoker`, `uiAccess=false`; no UPX; version resource; icon; excludes for network clients, async, multiprocessing, and dev tools;
  - `entry_gui.py`, `entry_cli.py`;
  - `buildinfo.py`: version single-sourced and checked against `firewallai.__version__`; the commit read from `.git` without subprocesses;
  - `make_icon.py`: an original slate tile with an amber brick wall and a teal dot; no shield; Qt and a hand-written `.ico`; deterministic;
  - `build.py`: refuses dev environments, `PYTHONPATH`, and non-reproducible settings; licenses, notices, README, build info, SBOM, deterministic ZIP, SHA-256;
  - `verify_build.py`: 28 checks;
  - `smoke/`: 11 frozen-binary tests;
  - `BUILD.md`, including the manual GUI checklist.
- **Runner hardening (Q7)** in `powershell_runner.build_environment`:
  - removes `_PYI_*` and `_MEIPASS2`;
  - when frozen, removes `PATH`, `QT_PLUGIN_PATH`, and `QML2_IMPORT_PATH` entries inside the bundle;
  - nothing else is changed.
- **CI:** `.github/workflows/ci.yml` (**prepared, not run**).
- **Tests:** `tests/unit/test_packaging_helpers.py` (12) and runner hardening tests in `tests/security/test_powershell_runner.py`.
- **Docs:**
  - ADR 0006 implementation notes and proposed Accepted wording (status **unchanged: Proposed**);
  - ADR index note;
  - `security-boundaries.md`: SB-02 implemented; SB-03 correction and hardening; SB-05; SB-13;
  - `module-map.md` (packaging section);
  - README;
  - AI_DEVELOPMENT.md.

## Dependency audit, SBOM, and toolchain [Verified, 2026-10-15]
- **uv 0.12.21:** `uv audit` and `uv export --format cyclonedx1.5` are available. `uv audit` is marked **experimental** by uv.
- **Audit before PyInstaller:** "no known vulnerabilities … in 37 packages".
- **Audit after PyInstaller:** "no known vulnerabilities … in 44 packages" (repeated in the final run).
- **PyInstaller 6.22.3:**
  - uploaded 2026-09-12;
  - GPLv2-or-later with the bootloader exception;
  - PyPI `vulnerabilities` empty; OSV advisories all fixed before 6.0;
  - locked wheel sha256 `500bd58c…` matches PyPI.
  - New transitive packages: altgraph 0.17.5 (MIT), pefile 2024.8.26 (MIT), pywin32-ctypes 0.2.3 (BSD-3-Clause), pyinstaller-hooks-contrib 2026.7 (GPLv2 / Apache-2.0), setuptools 84.0.0 (MIT).
  - `packaging` 26.3 was already locked.
  - **No existing package changed.** All are build-time only, except the bootloader.
- **SBOM:** CycloneDX 1.5 with **8 runtime components**: annotated-types, psutil, pydantic, pydantic-core, pyside6-essentials, shiboken6, typing-extensions, typing-inspection.
  - It contains no local paths or user names.
  - It is not byte-reproducible (random serial number).
- **CI action pins** (each release at least two weeks old):

  | Action | Version | Commit | Note |
  |---|---|---|---|
  | `actions/checkout` | v7.0.1 | `3d3c42e5…` | |
  | `actions/setup-python` | v7.0.0 | `5fda3b95…` | |
  | `astral-sh/setup-uv` | v10.2.0 | `c18668ad…` | v10.3.0 skipped: only 6 days old |

## Build, size, and start-up [Verified, TE-1, Windows 11, standard user]
| Measure | Result |
|---|---|
| Spike (dev environment) | 123 MiB, 289 files; it pulled in mypy, rich, pygments, hypothesis, setuptools, `ssl`, `http` (via pydantic's optional plug-ins). **This is why the isolated `.venv-build` and the excludes exist** |
| Final bundle | **108.1 MiB, 223 files**; ZIP **43.3 MiB** (`FirewallAI-0.1.0.dev0-g5eb158ec-win64-portable.zip`, sha256 `d294330c…`). The commit label is HEAD `5eb158e` plus uncommitted changes, so this artifact is **not** a committed build |
| Build time | 86–103 s |
| Reproducibility | Without fixed settings, 3 of 223 files differed. With `PYTHONHASHSEED=0` + `SOURCE_DATE_EPOCH`, **three builds, including the ZIP, were byte-identical** |
| CLI `--version` | 0.68 s first run from a fresh copy; 0.28–0.31 s warm |
| GUI window visible | 1.35 s first run from a fresh copy; 0.62–0.66 s warm. Not post-reboot cold starts |
| Frozen rule scan | 27.7–29.1 s. **N-04 EXCEEDED** (unchanged) |
| Frozen endpoint snapshot | 0.91–1.57 s across runs. **1 s target not consistently met** (unchanged) |

## Verification of the bundle [Verified]
- **`packaging/verify_build.py dist`: 28/28 checks passed.**
  - Layout.
  - Both executables: `asInvoker` with `uiAccess=false`, the right subsystem, a version resource, an icon, no UPX.
  - **All `firewallai` modules structurally identical to the source.**
  - Forbidden modules absent; no absolute paths; no user name, computer name, or source path in any file.
  - Licenses, notices, README, build info (`signed: false`), SBOM, SHA256SUMS, and the ZIP contents.
- **Mutation checks:**
  - a one-word change in a PowerShell script body in `src` (ActiveStore → PersistentStore) made the integrity check fail for both executables;
  - a planted file containing the user name made the local-data check fail.
  - Both were reverted, and the verifier passed again.

## Smoke tests against the frozen binaries [Verified: `pytest packaging/smoke --bundle dist/FirewallAI`, 11 passed]
- CLI version (no installed Python needed).
- `profiles --json` with `elevated: false`.
- Rules: N-04 reported (EXCEEDED).
- Endpoints: the text hides remote addresses (all connection rows `<hidden>`).
- JSON `sensitivity` block and the stderr privacy note, with and without `--show-remote`.
- Hostile process names escaped in frozen text output.
- **GUI launch (offscreen):** a PowerShell child observed with **no `_PYI_*` variables and no bundle entries in `PATH` or `QT_PLUGIN_PATH`**.
- GUI start to first collection: 0.47–0.49 s.
- **Install directory unchanged** after CLI and GUI runs.
- Runs from a path with spaces and non-ASCII characters (`Carpeta con espacios Ñandú`).
- No executable-name collision.

## Microsoft Defender [Verified, standard user, no settings changed]
- `MpCmdRun.exe -Scan -ScanType 3 -File <dist>`: **"found no threats"**, exit 0, 6.1 s.
- Engine 1.1.26090.9; signatures 1.461.40.0 (updated 2026-10-15); real-time protection on.
- Nothing was uploaded.

## New findings and deviations
1. **PyInstaller moved from `dev` to a dedicated `build` group, built from an isolated environment.** It is still development-only, and this is why the bundle contains no dev tools. **Approved by the human (decision 1).**
2. **PowerShell 5.1 rewrites `PSModulePath`.**
   - The runner passes only the System32 module path. A probe through the real runner showed that PowerShell sees `%ProgramFiles%\WindowsPowerShell\Modules` *before* System32. The user-profile path was not added, and NetSecurity loaded from System32.
   - This has been true **since M1.1**; SB-03's wording is corrected.
   - Risk is low: Program Files is admin-writable by default.
   - Not changed in M1.5 (decision 3). Tracked as **SR-M1.5-01** (above).
3. **Reading another process's environment** (psutil) gave an empty `PSModulePath` for the PowerShell child, so it is unreliable after PowerShell modifies its environment. The frozen smoke test therefore checks only the PyInstaller-related values.
4. **Reproducibility needs `PYTHONHASHSEED=0` and `SOURCE_DATE_EPOCH`**, which means running with `-s -P` instead of `-I`. `build.py` enforces this and refuses `PYTHONPATH`.
5. **`build-info.json` can't detect uncommitted changes** (no subprocess to git). Release builds must come from a clean checkout; CI does that.
6. **CI integration tests are excluded:** GitHub's Windows runners execute as admin, and the integration and frozen smoke tests assert standard-user execution. CI builds and verifies the bundle and runs a fixture-based frozen CLI check instead.

## Tests and quality gates [Verified, 2026-10-15, uncommitted tree on `5eb158e`, TE-1, non-elevated]
| Command | Result |
|---|---|
| `uv run --frozen pytest -q -s` (source) | **399 passed** in 118.28 s (security 78, integration/windows 13, unit 281, UI 27) |
| `ruff check` / `ruff format --check` / `mypy` / `lint-imports` / `uv lock --check` / `uv audit --frozen` | All checks passed / 83 files formatted / no issues in 43 source files / 5 kept, 0 broken / resolved 45 packages / no known vulnerabilities in 44 packages |
| `packaging/verify_build.py dist` (frozen bundle) | 28/28 checks passed |
| `pytest packaging/smoke --bundle dist/FirewallAI` (frozen binaries) | **11 passed** |
| **After the CI fix, first version** | Source suite **414 passed** in 108.49 s (399 + 15 new privacy-scan tests); ruff, format (86 files), mypy (43), 5 contracts, lock, audit (44 packages) clean; `verify_build.py` exit 0 locally **and with `USERNAME=runneradmin`** (30 checks); frozen smoke **11 passed** (frozen rule scan 26.9 s, N-04 EXCEEDED; frozen endpoints 0.78 s; GUI to first collection 0.45 s) |
| **Pre-commit re-run (2026-10-15, after the human's final decisions)** | Source suite **399 passed** in 109.50 s; ruff, format (84 files), mypy (43), 5 contracts, lock, audit (44 packages) clean; `verify_build.py` exit 0 (28/28); frozen smoke **11 passed** (frozen rule scan 27.9 s, N-04 EXCEEDED; frozen endpoints 0.90 s; GUI to first collection 0.43 s); source endpoint snapshot 1.00 s cold (EXCEEDS) / 0.75 / 0.79 s |
| Suppressions vs `main` | `noqa` src 8/8, tests 0/0, packaging 0; `type: ignore` src 0/0, tests 4/4; skip/xfail 1/1 (unchanged) |
| Source-run measurements in the same suite | rule scan 29.97 s (**N-04 EXCEEDED by 20.0 s**); endpoint snapshot 1.15 s cold (exceeds) / 0.78 / 0.82 s; network tab max GUI gap 72 ms |

**Not run / not executable here:**
- the **CI workflow** (only runs on a PR; local PowerShell 7 not installed, so its `pwsh` step wasn't executed locally);
- the **manual GUI checklist** (human);
- **clean Windows 11 VM** and **clean Windows 10 22H2** (Hyper-V pending);
- **SmartScreen** behaviour of a downloaded ZIP;
- a **post-reboot cold start**.
- No claim of clean-VM or Windows 10 compatibility is made.

## Known limitations and release blockers
- **N-04 not met** (rule scan about 27–30 s against 10 s). It is a documented limitation, not a waiver. The **endpoint snapshot** misses 1 s on cold starts.
- **Unsigned** (ADR 0007: SignPath after the first public release), so SmartScreen will warn on downloaded copies. **Not ready for public distribution.**
- **No installer yet** (Sprint 4). The portable folder is user-writable; no elevated component may ever run from it (SB-13).
- **Clean-VM and Windows 10 validation missing.** CI is prepared but not run.
- **v0.1 features still missing:** onboarding, reports, verdict engine, storage.
- The ZIP is about 43 MiB; Qt is about 73 MiB of the unpacked bundle.

## Pending items for the human
1. **ADR 0006: kept Proposed by the human (2026-10-15).** The original criteria are unchanged:
   - (1) a successful CI run: **MET**;
   - (2) the detailed manual GUI checklist completed: **PARTIALLY MET**;
   - (3) identified packaging defects resolved: **MET**.
   - It may be accepted only after the detailed checklist is completed and any newly found defects are resolved. The drafted wording stays in the ADR.
2. The remaining detailed manual checks (DPI, keyboard, close during collection, panel details, N-04 line in the GUI, manual install-folder check).
3. Review the closeout PR (commit and push authorized 2026-10-15; merging is the human's decision).
4. **SR-M1.5-01** (PowerShell module resolution): a separate security review.
5. Still open: Hyper-V / Windows 10 VMs, D17 (Codex), an N-04 plan, and whether to enable CI as a required check (repository settings: human only).

## M1.5 commit (authorized by the human 2026-10-15)
```
build(packaging): add M1.5 portable one-folder Windows development build

PyInstaller 6.22.3 (dedicated "build" group, isolated build env) producing
FirewallAI.exe (GUI) and firewallai-cli.exe (CLI) in one asInvoker, non-UPX
one-folder bundle with version resources, an original provisional icon,
third-party licenses, CycloneDX SBOM and SHA-256 sums; reproducible build
settings; bundle verifier (code identical to source, no network-client or dev
modules, no local data); frozen smoke tests; runner strips PyInstaller-specific
environment values from the PowerShell child; minimal SHA-pinned Windows CI
(pull requests, read-only). Unsigned development build, not a public release.
N-04 and the endpoint cold-start target remain unmet.

AI-Agent: claude-code
Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
```

## Next steps
1. The human's decision on ADR 0006 and on this closeout.
2. Do not start Sprint 2 without authorization.

## Resume commands
```
git fetch origin
git switch feat/s1-m1-5-packaging
git status --short
uv sync --frozen
uv run --frozen pytest -q
# packaging: see packaging/BUILD.md
```
