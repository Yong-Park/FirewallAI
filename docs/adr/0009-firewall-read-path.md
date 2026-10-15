# ADR 0009: Firewall read path

- **Status:** **Accepted (v0.1 read-path direction)**, decided by the human on 2026-10-14 after the M1.2 investigation. The accepted architecture is in **"Accepted decision (v0.1)"** at the end of this ADR. Implementation and compatibility questions there remain **unresolved**.
- **Decision ID:** D9 · **Date:** 2026-10-14 · **Proposed by:** claude-code · **Decided by:** human, 2026-10-14
- **Reading note:** §§1–8 are the original proposal. Their bulk-filter plan in §2 (`Get-NetFirewall*Filter -All` joined on `InstanceID`) **doesn't work for a standard user** (evidence §B) and is **superseded** by the accepted decision below. §5's `-ExecutionPolicy Bypass` example is superseded by evidence §A.

## 1. Problem
To produce accurate verdicts, FirewallAI needs the **effective** firewall policy: local rules merged with Group Policy, together with each rule's filters. It must read this without elevation, safely, and fast enough for a desktop app.

## 2. Decision (recommended)
- **Primary source: PowerShell NetSecurity** against `-PolicyStore ActiveStore`.
  - Use fixed, embedded, versioned scripts that emit JSON.
  - Fetch filters in bulk: run `Get-NetFirewallPortFilter -All` (and the other `*Filter` cmdlets) once each and join on `InstanceID`, instead of piping each rule separately.
- **Secondary sources, to be evaluated:**
  - COM `HNetCfg.FwPolicy2`, as a speed and fidelity comparison.
  - WFP filter enumeration (`FwpmFilterEnum0`), to detect filters that don't come from firewall rules. Those filters feed the `Indeterminate` verdict.

## 3. Alternatives considered
- **COM `INetFwPolicy2`:** in-process and probably faster. It may expose the local store rather than the effective merged policy [VERIFY in a GPO VM].
- **`netsh advfirewall` text parsing:** the output is localized and brittle. Rejected.
- **WFP only:** low-level and complete, but WFP filters map awkwardly back to user-facing rules. Better as a complement.

## 4. Advantages and disadvantages
- **Advantages:** PowerShell's ActiveStore is the documented path to the effective policy. Its JSON output is easy to validate.
- **Disadvantages:** process start-up cost of about 0.5–1.5 s [NEEDS PROTOTYPE]. Bulk filter queries need careful joins.

## 5. Security implications
- **Command injection (CWE-78) is the key risk.** Mitigations:
  - `%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe` is called by absolute path, with `-NoProfile -NonInteractive -NoLogo`.
  - Script text is a constant. Parameters go in as JSON on stdin.
  - No `shell=True`.
  - Timeouts, output size caps, and schema validation of the output.
- Read-only cmdlets only. A test asserts that the embedded scripts contain no `Set-`, `New-`, `Remove-`, `Enable-`, `Disable-`, or `netsh` verbs.

## 6. Performance implications
Target: a full scan in under 10 s with 1,500 rules [NEEDS PROTOTYPE].

## 7. Validation
**Sprint 1 spike:**
- Measure cold start and total time on the dev machine and in a VM with 500 and 1,500 rules.
- Compare ActiveStore vs. COM output on a VM that has GPO-applied rules.
- List which fields need admin rights.

Results are recorded in the spike report with the command lines used.

## 8. What to learn
- Firewall policy stores (PersistentStore, GPO stores, ActiveStore, RSOP).
- CIM/WMI classes (`MSFT_NetFirewallRule`).
- The WFP architecture: layers, sublayers, filters, and arbitration.

## Evidence recorded 2026-10-14 (Sprint 1 Day 0 and M1.1)

All observations come from read-only, non-elevated commands on test environment TE-1 (Windows 11 Pro build 26200, Windows PowerShell 5.1.26100, Spanish locale). These are informal single runs, not benchmarks.

### A. Execution policy: no `-ExecutionPolicy Bypass` (human-confirmed 2026-10-14)
- The machine's `LocalMachine` execution policy is **`AllSigned`**.
- Scripts passed via **`-Command`** (a string argument) or via stdin ran without any execution-policy override. Execution policy applies to script **files** (`-File`, `.ps1`), not to command text.
- Decision for the runner: **never** pass `-ExecutionPolicy Bypass`, `-EncodedCommand`, or `-File`.
  - They aren't needed.
  - `Bypass` and `-EncodedCommand` are common malware indicators that security products flag.
  - Least privilege applies.
- Implemented in M1.1. `powershell_runner.py` uses `-NoProfile -NonInteractive -NoLogo -Command <constant script>`, with parameters as JSON on stdin. Tests: `tests/security/test_powershell_runner.py` and `tests/integration/test_windows_powershell.py`.
- This **supersedes** the `-ExecutionPolicy Bypass` example in the frozen planning doc [06-windows-integration.md §2](../planning/06-windows-integration.md) and the "Security" bullet in §5 above, which no longer applies.

### B. Standard-user access to effective rules and filters (blocks the rules collector)
| Query (`-PolicyStore ActiveStore` unless noted) | Standard user result |
|---|---|
| `Get-NetFirewallProfile` | OK (3 profiles) |
| `Get-NetFirewallRule` | OK (**1,586 rules**) |
| `Get-NetFirewallApplicationFilter -All` | OK (1,586), about 0.2 s |
| `Get-NetFirewallServiceFilter -All` | OK (1,586), about 0.2 s |
| `Get-NetFirewallPortFilter -All` | **Access denied** (`PermissionDenied`) |
| `Get-NetFirewallAddressFilter -All` | **Access denied** |
| `Get-NetFirewallPortFilter -All`, PersistentStore and default store | **Access denied** |
| `Get-NetFirewallPortFilter -PolicyStore RSOP -All` | OK but **0** results (no GPO on TE-1) |
| Per-rule association (`Get-NetFirewallRule …` piped to `Get-NetFirewallPortFilter`), first 20 rules | OK, about 0.37 s for 20 (a linear guess for all rules is about 29 s, **too slow** unless batching helps) [NEEDS PROTOTYPE] |
| COM `HNetCfg.FwPolicy2.Rules` | OK, **1,583** rules **with ports/programs**, about 0.13 s. Store semantics vs. ActiveStore unverified (3-rule difference) [NEEDS PROTOTYPE] |

**Implications:**
1. The bulk-filter plan in §2 (`Get-NetFirewall*Filter -All` joined on `InstanceID`) **doesn't work as a standard user** for port and address filters, which the verdict engine needs most.
2. **Elevation is not an acceptable workaround** in v0.1 (SB-02).
3. The D9 investigation (milestone **M1.2**) must compare:
   - (a) the COM `INetFwPolicy2` rules API: fidelity vs. ActiveStore, GPO merge behavior, and the 3-rule gap;
   - (b) a batched per-rule association pipeline: measured timing;
   - (c) WFP enumeration, if it's readable without elevation;
   - (d) a combined approach (e.g. ActiveStore for the rule list plus app/service filters, COM for ports and addresses, cross-validated);
   - and the resulting `Indeterminate` reasons for anything that remains unreadable.
4. **No alternative is accepted by this evidence.** D9 stays Proposed until the M1.2 results are reviewed by the human.

### C. Other runner-relevant facts
- Error messages are **localized** (Spanish on TE-1). The runner classifies errors only by `CategoryInfo.Category`, `FullyQualifiedErrorId`, and HRESULT, never by message text (implemented and tested).
- NetSecurity enum values verified via reflection:
  - `GpoBoolean` is False=0, True=1, NotConfigured=2;
  - `Action` is NotConfigured=0, Allow=2, Block=4;
  - `DisabledInterfaceAliases` comes back as `[""]` when not configured.
- Cold start of an empty `powershell.exe -NoProfile` was about 0.34 s. Live profile collection through the runner took 1.5–2.2 s (integration-test output).

## M1.2 investigation results and proposed decision (2026-10-14)

Full report: [docs/research/2026-10-14-d9-firewall-read-path.md](../research/2026-10-14-d9-firewall-read-path.md). Sanitized evidence: [docs/research/evidence/d9-read-path-te1-2026-10-14.json](../research/evidence/d9-read-path-te1-2026-10-14.json). Everything was measured read-only and non-elevated on TE-1. This section supersedes the "about 29 s" estimate in evidence §B above.

**Verified on TE-1:**
- Bulk `-All` enumeration is **denied** for the **port, address, interface-type, and interface** filter classes in every store tried, including through raw `Get-CimInstance`. Application, service, and security filters enumerate fine.
- **Per-rule association returns all 1,586 port, address, and interface-type filters with 0 errors.**
- **COM = PersistentStore (1,583).** ActiveStore has 1,586 = 1,583 local + **3 Dynamic-store rules, which COM omits**.
- 77 per-user rules have **unresolved resource-string names** in COM.
- COM is **lossy**: the local-port keyword `RPC` appears as Any (28 rules), the remote-address keyword `PlayToDevice` as Any (5), and `LocalSubnet6` as `LocalSubnet` (10).
- COM has no rule IDs and no enforcement status.
- WFP filter enumeration is **denied** (`FwpmFilterCreateEnumHandle0` returns 5).
- ActiveStore **excludes** StaticServiceStore (191) and ConfigurableServiceStore (95) rules.
- Timing (median of 3): rules + port + address association in one process **about 15.7 s**. Parallel pipelines are slower (about 20 s wall). COM takes about 0.3–0.7 s.

**Proposed decision (as presented to the human; accepted with conditions below):**
1. ActiveStore through NetSecurity, non-elevated:
   - the rule list and the application, service, and security filters in **bulk**;
   - port, address, and interface-type filters by **per-rule association**, sequential, in one background PowerShell process.
2. Don't use COM, WFP enumeration, or the registry as data sources in v0.1.
3. Unreadable data becomes explicit `Indeterminate` reasons (report §5). This includes the new proposed reasons `SERVICE_HARDENING_NOT_EVALUATED` and `RULE_FILTERS_UNREADABLE`.
4. Accept completeness over speed. **The human must decide** whether to keep or relax the N-04 target of 10 s per scan. M1.3 measures the full read and a scoped variant (e.g. enabled inbound rules only).

**Still unverified:** behavior on Windows 10 22H2; Group Policy merge (needs a GPO VM); per-rule interface-alias timing; Microsoft definitions of `EnforcementStatus` values.

## Accepted decision (v0.1), 2026-10-14

Decided by the human after reviewing the [M1.2 report](../research/2026-10-14-d9-firewall-read-path.md). Wording follows the human's decision.

### Accepted architecture
1. **Primary source:** NetSecurity **ActiveStore**, read through **non-elevated** PowerShell (the audited `PowerShellRunner`).
2. **Collection pattern:**
   - read the rule inventory and the filter types that are bulk-readable (application, service, security) **in bulk**;
   - retrieve the restricted filter types (port, address, interface type; interface alias pending) **individually per rule** inside a **controlled background process**.
3. **Not authoritative in v0.1:** COM (`HNetCfg.FwPolicy2`), WFP enumeration, and direct registry parsing.
4. **Explicit `Indeterminate`** for anything unreadable, ambiguous, or unsupported.
   - FirewallAI **never** claims complete effective network reachability from ActiveStore alone.
   - Known gaps: non-firewall WFP filters, service-hardening stores, Group Policy merge, unreadable per-rule filters, interface-alias filters, and enforcement-status semantics.
5. **Correctness, scope accuracy, and security take precedence over speed.** Nothing may be sacrificed to reach a benchmark.

### Performance: N-04 is kept, and the current gap is reported
- **N-04 stays as written** (full scan under 10 s, [02](../planning/02-requirements.md)). It is **not** relaxed or redefined.
- **Current gap (TE-1, informal, median of 3):**
  - rules + port + address per-rule association: about **15.7 s**;
  - estimated with interface-type filters: about **20 s** [Assumption].
  - That is **about 1.6–2× the N-04 target**, so the detailed scan **does not currently meet N-04**.
- **Provisional allowance:** a slower detailed scan may be used during development, but every report, handoff, and release note must state that it **exceeds N-04**, with the measured time.
- **M1.3 evaluates progressive collection:**
  - (a) a fast initial inventory;
  - (b) detailed filter collection in the background;
  - (c) explicit progress, completeness, and error states in the UI, CLI, and reports;
  - (d) **no final security verdict until the evidence required for that verdict is available**.
  - Scoping per-rule association to the rules a verdict needs (e.g. enabled inbound: 1,100 of 1,586 on TE-1) is a candidate optimization, provided it doesn't reduce scope accuracy.

### Unresolved: implementation and compatibility (pending verification)
| Item | Status |
|---|---|
| Per-rule access behavior on other machines | Verified **only on TE-1** (Windows 11 Pro build 26200). Not verified on Windows 10 22H2 (a third-party report suggests elevation may be needed there) |
| Group Policy merge (`AllowLocalFirewallRules`, GPO rules in ActiveStore) | Pending a GPO VM |
| Interface-name (alias) filters | Bulk denied; per-rule timing and access not measured |
| Service-hardening rules (StaticServiceStore, ConfigurableServiceStore) | Readable but not in ActiveStore; effect on verdicts not evaluated |
| `EnforcementStatus` semantics | Microsoft definitions not verified; supporting evidence only |
| Meeting N-04 | Not met today; progressive collection to be evaluated in M1.3 |
| Root cause of bulk-enumeration denial | Undocumented by Microsoft; current explanation is an interpretation |

Any change to the accepted architecture needs a new ADR that supersedes this one.
