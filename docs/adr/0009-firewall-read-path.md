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
