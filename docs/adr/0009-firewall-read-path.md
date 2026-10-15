# ADR 0009: Firewall read path

- **Status:** Proposed · **Decision ID:** D9 · **Date:** 2026-10-14 · **Proposed by:** claude-code · **Decided by:** pending (final choice after the Sprint 1 prototype)

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

## Evidence recorded 2026-10-14 (Sprint 1 Day 0 and M1.1). Status remains **Proposed**

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
