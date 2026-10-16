# Sprint 2 plan: deterministic, evidence-based analysis engine (PLAN; implementation not authorized)

**Status: PLAN, approved for documentation** (human, 2026-10-15). **No implementation is authorized.**
- The milestone structure M2.0–M2.5 is approved as a plan (decision C). **Every milestone, M2.0 through M2.5, requires its own explicit authorization.**
- **SB-21 stays PROPOSED.** The principle of a separate local-policy verdict is approved (decision D), but its precise security contract must be reviewed and approved in M2.0 before the policy evaluator (M2.2) starts.
- Scope decisions S1–S8 and Q2–Q6 are recorded in §5 (decision E), with the human's refinements of 2026-10-15.

**References:**
- frozen scope: [roadmap §3](../planning/15-roadmap.md), [requirements F1](../planning/02-requirements.md), [analysis model](../planning/05-firewall-analysis.md), [testing strategy](../planning/13-testing-strategy.md);
- binding boundaries: SB-18, SB-19, SB-20 ([security-boundaries.md](../architecture/security-boundaries.md));
- [ADR 0006](../adr/0006-v0-1-distribution.md): development distribution only;
- [ADR 0023](../adr/0023-beginner-first-ux.md) and the **UX0 design package, DRAFT and not usability-validated** ([ux/](../architecture/ux/README.md)), used only as a wording reference.

**Not part of Sprint 2:** a GUI redesign. Findings are exposed through the CLI/JSON. No generative AI anywhere in the engine.

## 1. Engine principles (binding for every milestone)
1. **Deterministic and reproducible:**
   - the same snapshot, catalog version, and engine version give byte-identical JSON verdicts and findings, in a stable order with stable IDs;
   - no randomness and no wall-clock dependence in results.
2. **No generative AI** in the verdict or findings engine (SB-15). An import-linter contract enforces it.
3. **Evidence-first:**
   - every verdict and finding lists its evidence IDs, the catalog ID and version, and the engine version;
   - **when decisive conditions are unknown or unsupported, the result is Indeterminate** with reasons (SB-18).
4. **Local policy only.** A verdict describes what this PC's Windows Firewall policy would do in a stated traffic scenario. It **never implies real-world connectivity, internet reachability, or complete device security** (SB-20, proposed SB-21, N-08).
5. **No finding from a listening port alone** (F1-11).
6. **Frozen contracts kept:**
   - the findings catalog ([planning 05 §6](../planning/05-firewall-analysis.md)) and its severity (Info/Low/Medium/High) and confidence (Low/Medium/High) definitions;
   - the verdict names of F1-09.
7. **Beginner fields:** every finding carries the six ADR 0023 fields **and** its complete technical evidence:
   - what was observed;
   - why it may matter;
   - when it can be normal;
   - what evidence supports it;
   - what is still unknown;
   - what the user can review next.

## 2. Milestones (each requires separate authorization)
### Prerequisite P0: SR-M1.5-01 module-resolution review (before M2.1)
This is a separate investigation and hardening design (§7.2), approved and done (or explicitly accepted) **before** any new PowerShell-based security evaluation is added. It is not implemented in this documentation PR.

### M2.0: Security contracts (documentation only)
- **Deliverables:**
  - **ADR 0024 (Proposed)** with the precise SB-21 contract (§3), including the **verified** precedence and merge semantics or explicit Indeterminate mappings;
  - the finding data contract;
  - the `scan --json` schema;
  - the fixture format (JSON or TOML);
  - the loopback wording (§3.4);
  - the F1-10 plan (§4).
- **Acceptance:**
  - the human reviews and accepts ADR 0024; **only then does SB-21 move from Proposed**;
  - every open question in §3.3 is decided or mapped to Indeterminate;
  - **M2.2 cannot start before this.**
- **Checks:**
  - the contract does not weaken SB-18 or SB-20 (a checklist in the ADR);
  - every verdict state has a defined Indeterminate path;
  - each precedence or merge statement cites authoritative Windows documentation or is marked `[VERIFY]` → Indeterminate.

### M2.1: Network-to-profile mapping and third-party firewall detection (evidence)
- **Precondition:** P0 done or explicitly accepted.
- **Investigations first** (results recorded before any design):
  - **Q4:** whether Windows Security Center (`root\SecurityCenter2`, `FirewallProduct`) is readable **without elevation** on TE-1;
  - which read-only cmdlets give the interface→profile mapping and interface addresses as a standard user.
- **Deliverables:** registered read-only scripts (SB-03 rules unchanged), typed models with explicit states, fixture collectors, and the bind-address-to-interface/profile coverage.
- **Acceptance:**
  - standard user, read-only;
  - an unreadable source gives **Unknown + limitation**, never "none" or "no third-party firewall";
  - Server SKUs without Security Center give a limitation;
  - unit, security, and non-elevated Windows integration tests.
- **Negative cases:**
  - Security Center access denied or the namespace missing → Unknown;
  - an interface without a profile → Unknown;
  - IPv6 link-local with scope IDs;
  - a disconnected adapter;
  - `::` and `0.0.0.0` binds covering several interfaces.

### M2.2: Effective-policy evaluator and local-policy verdict engine (`core`, pure)
- **Preconditions:** M2.0 accepted (SB-21 contract approved); M2.1 merged.
- **Deliverables:**
  - verdicts per **(endpoint, interface/profile, traffic scenario)** using the F1-09 names, with qualifiers, matched rule IDs, and Indeterminate reasons;
  - only `CompleteRuleEvidence` is consumed (SB-18);
  - the descriptive correlation (SB-20) stays unchanged and separate.
- **Truth table:** about 40 scenarios (planning 05 §5) as JSON or TOML fixtures. Scenario expectations follow the **approved** M2.0 contract, not a simplified ordering.
- **Acceptance:**
  - all truth-table scenarios and negative cases pass;
  - output is identical on repeat runs;
  - `core` is pure and imports no `ai`.
- **Negative cases (required):**
  - a loopback-only binding → the loopback verdict, with **accurate binding wording** (§3.4), and never an exposure finding;
  - a listening port without complete rule evidence → Indeterminate;
  - a rule scoped to another profile → not counted for the evaluated profile;
  - Block/Allow conflicts, default actions, and `AllowInboundRules` resolved **only per the verified M2.0 contract**, otherwise Indeterminate;
  - Group Policy merge behaviour that is unverified or unreadable where decisive → `Indeterminate(MERGE_SETTINGS_UNREADABLE)`;
  - IPsec/authenticated-bypass conditions unknown → `Indeterminate(AUTH_BYPASS_UNKNOWN)`;
  - an inaccessible process path on a program-scoped candidate → `Indeterminate(PROCESS_INFO_UNAVAILABLE)`;
  - dual-stack ambiguity → `Indeterminate(DUAL_STACK_AMBIGUOUS)`;
  - unsupported filters → `Indeterminate(UNSUPPORTED_FILTER)`;
  - third-party firewall active or Unknown where decisive → per the contract;
  - no text claims real traffic, reachability, exposure, or safety.

### M2.3: Findings engine, catalog, and `scan --json`
- **Deliverables:**
  - the versioned catalog as data (§4);
  - rule functions over snapshot + verdicts;
  - six beginner fields plus complete technical evidence per finding;
  - confidence lowered when related verdicts are Indeterminate (planning 05 §6);
  - **`firewallai scan --json`**.
- **`scan --json`:**
  - every section carries **evidence completeness** (complete / partial / unknown / not collected, with reasons);
  - verdicts carry `scope: "local_policy_only"`, the scenario, interface/profile, qualifiers, limitations, and Indeterminate reasons;
  - nothing implies reachability;
  - the privacy note and sensitivity metadata are included.
- **Acceptance:**
  - every entry has a positive, a benign-condition, and a negative test;
  - all six fields are non-empty and pass the forbidden-claims/jargon lint;
  - reproducible finding IDs;
  - never from a listening port alone;
  - no finding from incomplete evidence;
  - **the F1-10 gap decision is made by the human before the M2.3 acceptance decision** (§4).

### M2.4: Storage, history, and diff: BLOCKED
- **Blocked until a privacy design is approved** (§6).
- **No assumptions:** no automatic persistence, no default retention (50 scans is not approved), and no DPAPI without a separate human decision.

### M2.5: Integration and acceptance
- **Deliverables:**
  - one shared `scan` service;
  - limitations data (F1-16);
  - end-to-end tests on fixtures and TE-1 (non-elevated);
  - performance measured and reported (N-04 unchanged).
- **Acceptance:**
  - all gates and tests;
  - frozen smoke still green;
  - HANDOFF and AI_DEVELOPMENT updated;
  - **all VM validation requirements still listed as open** unless actually performed (§5 S3).

## 3. SB-21: local-policy verdict contract: **PROPOSED** (to be reviewed and approved in M2.0)
### 3.1 What a local-policy verdict must never mean
- that a real network connection was established, or that real-world connectivity exists;
- that a service is reachable from the internet or any other network;
- that the Windows Filtering Platform, other filtering layers, third-party products, routers, or other devices cannot block the traffic;
- that the computer, or any part of it, is completely secure or safe.

### 3.2 Elements M2.0 must define precisely
| Element | Planning position (to verify; not final) |
|---|---|
| Traffic scenario | An **inbound, unsolicited** connection attempt to (protocol, local address, local port) of one endpoint, from an unspecified remote peer, over one interface with one assigned profile. Remote-address restrictions become qualifiers. Outbound traffic is not evaluated in v0.1. |
| Applicable profile/interface | From M2.1 evidence only. Unknown → Indeterminate. Several active profiles → one verdict per (interface, profile). |
| Rule/filter evidence | Only rules with `CompleteRuleEvidence` (SB-18). Every filter relevant to the scenario must be evaluable. |
| Rule precedence and conflicts | **Not finalized.** Planning 05 §3 lists a simplified order (authenticated bypass → block → allow → default). That order is a **hypothesis to verify against authoritative Windows Firewall/WFP behaviour**, covering IPsec and authenticated bypass, explicit Block vs. Allow, default inbound actions, `AllowInboundRules`, and rule-specific options. Anything not verified or not supported → **Indeterminate**. |
| Group Policy merge | `AllowLocalFirewallRules` / `AllowLocalIPsecRules` semantics **to verify** (`[VERIFY]` ADR 0009). Unverified or unreadable merge behaviour where decisive → **Indeterminate** (Q2). |
| Windows Filtering Platform | Filters outside Windows Firewall rules are not observable. A **permanent limitation** on every verdict (Q3), and never asserted as absent. |
| Unknown/unsupported conditions | Package/owner/dynamic keywords, dynamic port targets, port keywords, unknown tokens, unreadable process paths, ambiguous shared service hosts, dual-stack ambiguity, unknown IPsec state → Indeterminate with reasons. |
| Forced Indeterminate | Any missing decisive evidence; third-party firewall active or Unknown where decisive (per the M2.0 decision); profile disabled with an unknown alternative control. |
| Provenance and reproducibility | Evidence IDs, matched and considered rule IDs, interface/profile, engine and catalog versions, and collector completeness on every verdict. Deterministic output. |

### 3.3 Open technical questions (M2.0)
1. Authoritative sources for precedence, IPsec bypass, and merge semantics, and which cases are verified vs. mapped to Indeterminate.
2. Presenting several active profiles (one per interface) without implying one answer for the PC.
3. Remote-address-restricted Allow rules: a qualifier (`REMOTE_SCOPE_DEPENDENT`, planning 05) or Indeterminate.
4. UDP "bound" endpoints: the same scenario (an unsolicited inbound datagram) or a separate one.
5. Third-party firewall Unknown: Indeterminate for every verdict, or a qualifier.
6. Validating merge behaviour on a GPO VM (§5 S3, Hyper-V pending).

### 3.4 Loopback wording (refinement 2)
- The frozen verdict name `NotExposed_LoopbackOnly` (F1-09) is kept in data. It is **never shown as an unqualified "not exposed"**.
- Display and finding text describe the **verified local binding** only: "This app accepts connections only from this PC (it is bound to the loopback address)."
- It must not generalize to other services, other ports of the same app, or other network paths, and it is never evidence about internet reachability.
- **Proposal for M2.0 (human decision):** whether to also rename or alias the data label (for example `LoopbackOnlyBinding`). That would be a change to frozen F1-09 wording and needs explicit approval.

## 4. Findings catalog: provisional v1 (frozen entries only) and the F1-10 gap
**Provisional v1: 9 supported candidates:**

| ID (frozen) | Evidence needed | Notes |
|---|---|---|
| FW-PROF-001 profile disabled, no third-party firewall detected | profiles + Security Center (M2.1) | Raised only if third-party detection **succeeded** and found none. Detection Unknown → no finding, plus an Unknown note (handling decided in M2.0) |
| FW-PROF-002 default inbound Allow on an active profile | profiles + profile mapping (M2.1) | "Active" requires mapping evidence |
| FW-PROF-003 dropped-packet logging disabled (Info) | profiles | — |
| FW-RULE-001 inbound Allow on Public, Any program/port/remote | complete rule evidence | — |
| FW-RULE-002 admin/file-sharing ports on Public, remote Any | complete rule evidence | Ports as frozen (3389, 445, 5985/5986, 22) |
| FW-RULE-004 duplicate rules (Info) | complete rule evidence | "Identical effective filters" defined in M2.0 |
| FW-RULE-005 edge traversal allowed | complete rule evidence | — |
| FW-EXP-001 all-interfaces listener, `PermittedByPolicy` on Public, remote Any | verdicts (M2.2) under the approved SB-21 | Local-policy wording only; never "exposed" or "reachable" |
| FW-AI-001 Ollama API on a non-loopback address (F1-17) | endpoints (+ verdict qualifiers) | "Listening on a non-loopback address"; reachability never claimed |

**Pending or deferred (not counted):**
- **FW-EXP-002** (dev-tool/database listener): **pending human review of its exact port/process list and evidence requirements**.
- **FW-RULE-003** (stale program path): **deferred** until a path-existence evidence contract exists. Access errors → Unknown; a missing path is never automatically a vulnerability.
- **FW-ENV-001** (OS support): **deferred** until a verified OS-version collection contract exists.

**F1-10 gap (recorded; not waived).** Frozen requirement F1-10 asks for **10 or more** catalog rules in v0.1. The provisional v1 has **9**. No weak or unsupported entry is added to reach 10. Safe options for the human, **decided before the M2.3 acceptance decision**:
1. **Approve FW-EXP-002** after reviewing a concrete, documented port/process list and its evidence requirements (proposal prepared in M2.0).
2. **Approve the FW-RULE-003 evidence contract:** a read-only existence check of rule program paths, with explicit Unknown on access errors and Info-level wording.
3. **Approve the FW-ENV-001 OS-version contract:** a verified read-only OS-version source and a documented support-status reference.
4. **A formal scope decision** to ship v0.1 with 9 entries (it changes F1-10 and needs explicit human approval).

## 5. Decision E outcomes (with the 2026-10-15 refinements)
| Item | Decision | Plan consequence |
|---|---|---|
| S1 | JSON or TOML fixtures, stdlib only; no YAML dependency | Format fixed in M2.0 |
| S2 | Defer `hypothesis` | Parametrized and seeded-random stdlib tests |
| S3 | **Preserve all VM validation requirements**; nothing moved, waived, or redefined | The two-VM real-behaviour check (planning 05 §5, 13), the clean-VM tests, and the GPO VM checks stay **open requirements**. Sprint 2 cannot claim behavioural validation without them. **Any schedule change is only a proposal for human approval** (none is made here) |
| S4 | `scan --json` with explicit evidence completeness; no misrepresented verdicts | M2.3. It also addresses the carried-over Sprint 1 exit criterion ("works on the dev machine and a VM"), whose VM part stays open |
| S5 | Separate N-04 investigation, planned and not started | §7.1 |
| S6 | SR-M1.5-01 review is a **separate prerequisite (P0) before M2.1** | §7.2: design for separate approval; not implemented here |
| S7 | Program-path existence only with reliable evidence | FW-RULE-003 deferred |
| S8 | OS-version findings need a verified contract | FW-ENV-001 deferred |
| Q2 | Unverified GPO merge → Indeterminate where decisive | §3.2 |
| Q3 | Document WFP and other filtering-layer limits | Permanent limitation on every verdict |
| Q4 | Investigate Security Center without elevation first | M2.1 |
| Q5 | No persistence assumptions | M2.4 blocked; §6 |
| Q6 | Catalog from approved entries | §4: 9 provisional; F1-10 gap recorded |

## 6. Privacy design required before M2.4 (no defaults assumed)
A separate design must be proposed and **approved by the human**. It covers:
1. opt-in vs. opt-out for saving history;
2. location and file permissions (a user-only folder, never the install folder);
3. retention (no default is approved; **50 is not approved**);
4. deletion (one scan, all history, the uninstaller choice);
5. which host-sensitive fields are stored or minimized;
6. encryption at rest. **Windows DPAPI is an option only.** It needs a separate decision:
   - *Pros:* user-bound, no key management, protects against other users and offline copies.
   - *Cons:* no protection against malware running as the same user, data lost with the profile, more complexity, and it needs `ctypes` work or a dependency approval;
7. persistence of the UX R1 (Advanced view) and R2 (quick-check authorization) settings.

## 7. Separate investigations (planned; each needs authorization)
### 7.1 N-04 performance investigation
Measure where the about 27–35 s goes (PowerShell start-up, inventory, per-rule detail queries). Evaluate a persistent session, batched bulk filter queries (respecting ADR 0009 / M1.2), and caching. It produces a measured report with options and changes no N-04 target.

### 7.2 SR-M1.5-01 module-resolution review (prerequisite P0 before M2.1)
**Threat recap (M1.5 finding):** Windows PowerShell 5.1 inserts `%ProgramFiles%\WindowsPowerShell\Modules` ahead of the System32 module path that the runner passes. NetSecurity currently loads from System32.

**The investigation must evaluate, and a single `Get-Command` origin check is not assumed to be sufficient:**
1. **Trusted module loading:** where NetSecurity, CimCmdlets, and NetTCPIP are loaded from in the runner's sessions, and whether explicit loading from a pinned System32 path is possible within the script-safety rules.
2. **Effective paths:** the runtime `PSModulePath`, module auto-loading (`$PSModuleAutoLoadingPreference`), and the impact of other module directories.
3. **Command resolution:** precedence of aliases, functions, cmdlets, and external commands, and whether **module-qualified names** (for example `NetSecurity\Get-NetFirewallRule`) close shadowing.
4. **Module integrity:** whether the loaded module files are the Windows-shipped ones (Authenticode/catalog signature, path under System32), and what is verifiable as a standard user.
5. **Validation vs. execution (time-of-check to time-of-use):** checking and executing in the **same** PowerShell session, against the **same** loaded module object, so that a check cannot pass while a different command later runs.

**Output:** a narrowly scoped hardening design with options, the tests to add, and any script-safety-test changes (which need approval), presented **for separate approval**. Nothing is implemented in this documentation PR.

## 8. Dependencies, risks, and approval gates
- **Order (each step separately authorized):**
  1. P0 (SR-M1.5-01 review and design) and M2.0 (contracts);
  2. M2.1;
  3. M2.2;
  4. M2.3 (with the F1-10 decision);
  5. the privacy design, then M2.4;
  6. M2.5.
- **Human approval gates:**
  - each milestone start;
  - ADR 0024 / SB-21 contract;
  - the P0 hardening design;
  - the loopback label proposal;
  - the FW-PROF-001 Unknown handling;
  - the F1-10 option;
  - the FW-EXP-002 list;
  - the privacy design;
  - the N-04 investigation;
  - any VM-validation schedule proposal.
- **Risks:**
  - **Precedence or merge semantics wrong** → incorrect verdicts. Mitigation: verification against authoritative behaviour, Indeterminate otherwise, the truth table, and the open VM validation.
  - **N-04** makes verdict-dependent output slow. Mitigation: honest progress and the separate investigation.
  - **False confidence from wording.** Mitigation: SB-21 wording rules, the six-field lint, loopback wording, and UX0 C1–C3 (later; UX0 is not yet validated).
  - **Scope creep or weak findings.** Mitigation: the frozen catalog only and the F1-10 gap decided explicitly.
  - **Security Center unreadable when unelevated.** Mitigation: Unknown plus limitation; FW-PROF-001 conditional.
