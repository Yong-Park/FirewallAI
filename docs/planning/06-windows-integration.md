# 06: Windows Integration Strategy

Status: Approved plan rev. 3, frozen snapshot. Covers deliverable (7). Monitoring research is in [12](12-monitoring-research.md).

## 1. Data sources (v0.1, read-only)

| Data | Mechanism | Privilege (expected) | Notes |
|---|---|---|---|
| Profiles | `Get-NetFirewallProfile -PolicyStore ActiveStore` | Standard user [ASSUMPTION] | Effective merged settings |
| Network → profile | `Get-NetConnectionProfile` | Standard user | Maps interface index to NetworkCategory |
| Rules + filters | `Get-NetFirewallRule -PolicyStore ActiveStore`, plus each `Get-NetFirewall{Address,Port,Application,Service,InterfaceType,Interface,Security}Filter -PolicyStore ActiveStore -All` joined on `InstanceID` | Standard user [ASSUMPTION] | Bulk queries avoid per-rule pipeline cost |
| Listeners and connections | `psutil.net_connections(kind="inet")` | Standard user; some PIDs are hidden or 0 for system endpoints | IPv4 + IPv6 |
| Process details | `psutil.Process(pid)`: name, exe, cmdline (cmdline is opt-in for privacy) | Access denied for protected processes and other users' elevated processes | Record as "unavailable" |
| Services per PID | `psutil.win_service_iter()` | Standard user | Shared svchost |
| Signer | `WinVerifyTrust` / `Get-AuthenticodeSignature` (batched) | Standard user | Best-effort and optional |
| Third-party firewall | CIM `root\SecurityCenter2` → `FirewallProduct` | Standard user | **Client SKUs only.** Absent on Server. |
| OS version | `platform`, registry `CurrentVersion` | Standard user | For FW-ENV-001 |

**Sprint 1 spike:** list exactly which fields fail without admin rights, on Windows 11 and in a VM. Record the results with the commands used.

## 2. PowerShell runner design (security-critical)

- Executable: `%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe`, resolved by absolute path. This avoids `PATH` hijacking (CWE-427).
- Arguments: `-NoProfile -NonInteractive -NoLogo -ExecutionPolicy Bypass -Command -`. The script is passed on stdin. `Bypass` applies only to this process, and the script text is our own constant [ASSUMPTION: no AppLocker/WDAC constrained-language issues on typical home PCs; detect and report otherwise].
- Scripts: constant `.ps1` resources shipped with the app and versioned. Parameters, when any are needed, go in as JSON that the script parses (`$input | ConvertFrom-Json`). **No string interpolation of untrusted data into script text.**
- Output: `ConvertTo-Json -Depth N -Compress`. The output is size-capped, parsed, and validated with pydantic.
- `subprocess.run([...], shell=False, timeout=…, capture_output=True, creationflags=CREATE_NO_WINDOW)`.
- Encoding: force UTF-8 output (`[Console]::OutputEncoding`) and handle localized Windows. Rule display names are localized, so match on stable fields (`Name`, `InstanceID`), never on display text.
- **Read-only guarantee:** a unit test fails if any embedded script contains a write verb (`Set-`, `New-`, `Remove-`, `Enable-`, `Disable-`, `Rename-`, `Copy-NetFirewall`, `netsh`, `Invoke-Expression`, `iex`).
- Performance: measure cold start. If it's too slow, keep one long-lived PowerShell process with a framed request/response protocol [NEEDS PROTOTYPE].

## 3. Windows 10 / 11 support

- Windows 11 x64 is primary. Windows 10 22H2 x64 is best-effort ([ADR 0008](../adr/0008-windows-10-support.md)). The NetSecurity module exists on both (introduced in Windows 8 / Server 2012).
- Windows PowerShell 5.1 is the target (present by default). PowerShell 7 is not required.
- Server SKUs are not targeted in v0.1. If run there, SecurityCenter2 is missing and FirewallAI reports that as a limitation.

## 4. Things FirewallAI must NOT do (v0.1)

- Call any firewall or network write API, cmdlet, or `netsh` set/add/delete/import/reset.
- Request elevation or install services or drivers.
- Read other users' files, browser data, or any data unrelated to network and firewall state.
- Make network connections. Collecting data is local only.

## 5. What to learn

- Windows Firewall with Advanced Security concepts: profiles, rule types, GPO merge.
- CIM/WMI and the NetSecurity module (`MSFT_NetFirewallRule` and the related filter classes).
- psutil internals on Windows (`GetExtendedTcpTable`).
- Protected processes (PPL) and access tokens.
- PowerShell execution policy vs. AppLocker/WDAC constrained language mode.
