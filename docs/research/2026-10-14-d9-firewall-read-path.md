# Research M1.2: D9 firewall read path for a standard (non-elevated) user

- **Date:** 2026-10-14 · **Milestone:** Sprint 1, M1.2 (investigation only; no production collector)
- **Author:** claude-code (AI-generated research). **Human review:** pending.
- **Decision affected:** D9, [ADR 0009](../adr/0009-firewall-read-path.md). This report proposed a decision.
- **Outcome (2026-10-14):** the human **accepted the v0.1 read-path direction with conditions**. See ADR 0009, "Accepted decision (v0.1)":
  - ActiveStore, non-elevated: bulk inventory plus per-rule restricted filters in a controlled background process;
  - no COM, WFP, or registry as authoritative sources;
  - explicit `Indeterminate`, and no claims of complete reachability;
  - **N-04 (10 s) is kept; the detailed scan currently exceeds it and must be reported as such**;
  - progressive collection is to be evaluated in M1.3.

  The report below is unchanged from what was reviewed, apart from this note and §4a.
- **Reproduce** (standard user, repository root):
  ```
  uv run --frozen python scripts/research/d9_read_path_probe.py --repeat 3 --out docs/research/evidence/<name>.json
  ```
  The probe ([scripts/research/d9_read_path_probe.py](../../scripts/research/d9_read_path_probe.py)) is read-only. It runs PowerShell only through FirewallAI's audited `PowerShellRunner`, reads WFP through enumeration calls only, reads the registry with `KEY_READ`, and refuses to run elevated.
- **Evidence:** [evidence/d9-read-path-te1-2026-10-14.json](evidence/d9-read-path-te1-2026-10-14.json). It is **sanitized**: counts, timings, rates, and categories only. There are no rule names, paths, SIDs, addresses, or host identifiers. The only literal strings are Windows enum names, error IDs, and Windows keyword vocabulary (e.g. `rpc`, `localsubnet6`).

Labels: **[Verified]** = measured by the probe on TE-1 · **[Interpretation]** = inferred from verified data · **[Assumption]** / **[Needs prototype]** / **[Verify]** = not established.

## 1. Environment
TE-1 (dev machine; [13 §4](../planning/13-testing-strategy.md)): Windows 11 Pro build 26200, Windows PowerShell 5.1.26100, NetSecurity module 2.0.0.0, culture es-ES, **non-elevated**. There is no Group Policy firewall configuration: the RSOP store is empty, the GPO registry key is absent, and COM `LocalPolicyModifyState = 0`. Timings are the median of 3 runs on one machine. They are **not** benchmarks.

## 2. Findings

### F1. Which queries a standard user can run [Verified]
| Query | Result |
|---|---|
| `Get-NetFirewallRule` (ActiveStore / PersistentStore / SystemDefaults / StaticServiceStore / ConfigurableServiceStore / RSOP) | OK: 1,586 / 1,583 / 413 / 191 / 95 / 0 |
| Bulk `-All`: **Application, Service, Security** filters (ActiveStore) | OK: 1,586 each |
| Bulk `-All`: **Port, Address, InterfaceType, Interface** filters | **Access denied** (`PermissionDenied`, "Windows System Error 5") in ActiveStore, PersistentStore, and SystemDefaults |
| Raw CIM `Get-CimInstance` on `MSFT_NetProtocolPortFilter` / `MSFT_NetAddressFilter` | **Access denied** (same error, raised in the CIM layer) |
| Raw CIM on `MSFT_NetApplicationFilter` / `MSFT_NetFirewallRule` | OK: 1,583 (default store = PersistentStore) |
| **Per-rule association** (`$rules` piped to `Get-NetFirewallPortFilter` / `…AddressFilter` / `…InterfaceTypeFilter`), ActiveStore | **OK for all 1,586 rules, 0 errors**, for port, address, and interface-type filters |
| `-AssociatedNetFirewallRule` with an array of rules | Not supported (`ParameterArgumentTransformationError`) |

**Why the bulk queries fail:**
- [Verified] The denial comes from the CIM provider's **bulk enumeration** of four specific filter classes (port, address, interface type, interface). It also happens through raw `Get-CimInstance`, so it isn't a cmdlet quirk. The same data **is** returned when it is reached through each rule's association.
- [Interpretation] The provider applies a stricter access check to class-wide enumeration of these classes than to association traversal. Microsoft documents neither behavior.
- A third-party blog ([wiert.me, 2022](https://wiert.me/2022/10/26/powershell-working-around-get-netfirewallrule-not-showing-all-the-fields-that-set-netfirewallrule-allows-you-to-set/)) reports the same bulk denial and claims the per-rule direction also needs elevation. **That is contradicted on TE-1.** The behavior may differ by Windows build [Verify on Windows 10 22H2].

### F2. COM (`HNetCfg.FwPolicy2`) vs ActiveStore [Verified]
- **Coverage.** COM returns **1,583** rules. That equals PersistentStore (1,583), the local registry rule key (1,583 values), and raw CIM in the default store (1,583). ActiveStore has **1,586 = 1,583 local + 3 `Dynamic`**. **The 3-rule gap is entirely the Dynamic store**, which COM doesn't expose. The 3 Dynamic rules are allow rules with a program: 2 inbound (status "ProfileInactive Enforced") and 1 outbound ("OptimizedOut").
- **Naming.** 77 further rules didn't match by key. **All 77 are per-user rules** (owner SID set) for which **COM returns an unresolved resource-string name** (`@…`), while ActiveStore returns the resolved display name. They are the same rules, so this is not a coverage gap. It does mean COM can't be reliably joined with other data by name.
- **Identity.** COM has no stable rule ID (no `InstanceID`). By (name, direction, action, enabled, program, service), 295 keys are duplicated in ActiveStore and 292 in COM, so a one-to-one join is ambiguous for many rules.
- **Field fidelity** (415 unambiguous pairs; 705 duplicate groups compared as multisets, 646 identical):

  | Field | Agreement |
  |---|---|
  | protocol, local address | 100% |
  | remote port | 99.8% |
  | remote address | 96.4% |
  | local port | 91.8% |

  The disagreements:
  - **Lossy to "Any"** (COM shows a *broader* value than the effective rule):
    - local port keyword `RPC` shown as Any (28);
    - remote address keyword `PlayToDevice` shown as Any (5).
  - **Broadened:** `LocalSubnet6` shown as `LocalSubnet` (10, including 2 mixed with explicit addresses).
  - **Spelling only** (normalizable): `RPCEPMap`↔`RPC-EPMap` (4), `IPHTTPSIn`/`IPHTTPSOut`↔`IPHTTPS` (2), `PlayToDiscovery`↔`Ply2Disc` (1).
- **Missing metadata.** COM exposes no `PolicyStoreSourceType`, `EnforcementStatus`, `PrimaryStatus`, or owner SID.
- [Interpretation] Using COM would make some restricted rules look like "allowed from Any". That is exactly the over-claiming the verdict model must avoid (05 §1).

### F3. Per-rule association performance (non-elevated) [Verified, informal]
| Step (median of 3) | Time |
|---|---|
| ActiveStore rule list | 1.8 s |
| Application and service filters (bulk) | 0.4 s |
| Port filters, per-rule pipeline | 6.0 s |
| Address filters, per-rule pipeline | 5.6 s |
| Whole process: rules + port + address (one PowerShell process) | **15.7 s** |
| Port + address + interface-type pipelines **in parallel** (3 processes) | 20.3 s wall; each pipeline about 17 s, versus about 5.5–6 s alone |
| COM full rule list (for comparison) | 0.3 s (0.7 s process wall) |

- [Interpretation] Parallel pipelines don't help: they slow each other down roughly threefold, which suggests they are serialized in the WMI/CIM provider.
- [Assumption] A full read including interface-type filters takes about **20 s** sequentially (about 15.7 s measured plus one more pipeline of roughly 5.5 s). That **exceeds the 10 s target in N-04** ([02](../planning/02-requirements.md)).
- 1,100 of the 1,586 rules are enabled inbound rules. Limiting per-rule association to them would save roughly 30% [Assumption: cost proportional to rule count; Needs prototype].

### F4. Windows Filtering Platform [Verified]
`FwpmEngineOpen0` succeeds as a standard user, but `FwpmFilterCreateEnumHandle0` returns **`ERROR_ACCESS_DENIED` (5)**. WFP filter enumeration is **not available without elevation**, so non-firewall WFP filters (third-party filters, boot-time filters, and so on) **can't be observed** in v0.1.

### F5. Registry [Verified]
- The local rule key (`…\SharedAccess\Parameters\FirewallPolicy\FirewallRules`) is readable: 1,583 values in rule-string formats v2.10–v2.33. The GPO rule key (`HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules`) is absent on TE-1.
- [Interpretation] The registry duplicates the PersistentStore (local) view. It excludes Dynamic rules, applies no merge logic, and would need a parser for a versioned string grammar [Verify: documented in MS-FASP]. It is not an improvement on ActiveStore.

### F6. Rules outside ActiveStore [Verified counts; Interpretation of effect]
StaticServiceStore (191 rules) and ConfigurableServiceStore (95) are readable but **not included** in ActiveStore's 1,586 (1,583 local + 3 dynamic). [Interpretation/Verify] These are Windows Service Hardening rules, which restrict what Windows services may do. They may therefore affect effective behavior for service-hosted listeners without appearing in ActiveStore. Their filters weren't probed [Needs prototype].

### F7. ActiveStore exposes enforcement metadata [Verified]
Every ActiveStore rule carries `EnforcementStatus`. Values seen on TE-1: Enforced, ProfileInactive, OptimizedOut, Duplicate, Disabled, NoLocalPort, NoRemoteAddress, NoDynamicTransport, and combinations of these. This could strengthen verdicts (e.g. a rule present but not enforced) [Verify: Microsoft's definitions of each value before relying on them].

## 3. Comparison of approaches

| Approach | Completeness (effective policy) | Fidelity | Permissions | Speed (TE-1) | Verdict |
|---|---|---|---|---|---|
| **ActiveStore rules + bulk app/service/security filters + per-rule port/address/interface-type association** | Local + Dynamic (1,586); **excludes** service-hardening stores; GPO merge unverified | Native values incl. keywords, stable `InstanceID`, enforcement status | Standard user ✔ | about 16–20 s | **Recommended (authoritative)** |
| Bulk `-All` port/address filters | Would be complete | Native | **Denied** ✘ | n/a | Not possible |
| COM `HNetCfg.FwPolicy2` | Local only (**misses Dynamic**) | **Lossy**: RPC/PlayToDevice shown as Any; LocalSubnet6 shown as LocalSubnet; unresolved names; no IDs or enforcement status | Standard user ✔ | 0.3–0.7 s | Not as source of truth. Optional "quick preview" only if clearly labeled (not recommended for v0.1) |
| WFP enumeration | Would include non-firewall filters | Low-level | **Denied** ✘ | n/a | Not possible in v0.1 (elevation forbidden) |
| Registry rule strings | Local (+GPO key if present) only; no Dynamic; no merge | Raw format, must be parsed | Standard user ✔ | not measured | Not recommended |
| Elevated query | Complete | Native | Admin ✘ | n/a | Excluded by SB-02 |

## 4. Proposed D9 decision (as reviewed; accepted with conditions; see Outcome at the top)
1. **Source of truth:** NetSecurity **ActiveStore**, non-elevated:
   - the rule list in bulk (including `PolicyStoreSourceType`, `EnforcementStatus`, owner, profile, group);
   - application, service, and security filters in bulk;
   - port, address, and interface-type filters by **per-rule association**, sequentially, in one PowerShell process, run in the background worker.
2. **Do not use COM, WFP, or the registry as data sources** in v0.1, for the reasons in §3. COM may be revisited only as an explicitly labeled preview, and only with a separate decision.
3. **Per-rule errors become data:** a rule whose filters can't be read is excluded from matching and creates an `Indeterminate` reason. It is never silently treated as matching or as not matching.
4. **Performance:** accept a slower complete read over a fast lossy one. M1.3 should measure:
   - (a) the full read including interface-type filters;
   - (b) limiting association to rules the analysis needs (e.g. enabled inbound);
   - (c) a progress indicator.

   **Human decision needed on N-04:** keep the 10 s target (and design for it), or relax it for a complete, read-only scan.
5. **Interface (alias) filters:** bulk is denied, and per-rule association wasn't measured. Measure in M1.3, or report as `Indeterminate` when a rule restricts by interface alias.

## 4a. Performance gap against N-04 (recorded after the decision)
| Measurement (TE-1, non-elevated, median of 3, informal) | Time | vs N-04 (10 s) |
|---|---|---|
| ActiveStore rule inventory (bulk) | 1.8 s | within |
| Application and service filters (bulk) | 0.4 s | within |
| Rules + port + address per-rule association, one process (wall) | **15.7 s** | **exceeds by about 5.7 s (about 1.6×)** |
| Plus interface-type filters (sequential estimate) | **about 20 s** [Assumption] | **exceeds by about 10 s (about 2×)** |

- **N-04 stays at 10 s** (human decision). Until it is met, every scan result, handoff, and release note must say the detailed scan exceeds N-04 and give the measured time.
- M1.3 evaluates **progressive collection**:
  - a fast inventory first (about 2 s on TE-1);
  - detailed filters in the background;
  - explicit progress, completeness, and error states;
  - **no final verdict until its evidence is collected**.
- These measurements are from one machine. Other hardware, rule counts, and Windows builds may differ.

## 5. What must remain Indeterminate (never claimed)
| Condition | Why | Indeterminate reason (05 §3) |
|---|---|---|
| Non-firewall WFP filters (third-party, boot-time) | WFP enumeration is denied to standard users (F4) | `NON_FIREWALL_WFP_FILTERS` (always noted as a scan limitation) |
| Service-hardening rules (StaticServiceStore / ConfigurableServiceStore) | Not in ActiveStore; effect on listeners not evaluated (F6) | new: `SERVICE_HARDENING_NOT_EVALUATED` (proposed) |
| Group Policy merge | No GPO on TE-1; ActiveStore merge behavior with GPO unverified | `MERGE_SETTINGS_UNREADABLE` / GPO-specific reason until verified in a GPO VM |
| Rules whose filter association fails | Possible on other builds (third-party report) | `PROCESS_INFO_UNAVAILABLE`-style per-rule reason (new: `RULE_FILTERS_UNREADABLE`, proposed) |
| Interface-alias-restricted rules | Bulk denied; per-rule not yet measured | `UNSUPPORTED_FILTER` until measured |
| Meaning of `EnforcementStatus` values | Not yet verified against Microsoft documentation | Use only as supporting evidence, not as a verdict basis, until verified |

## 6. Open items
- [Verify] Per-rule association as a standard user on **Windows 10 22H2** (third-party report suggests elevation may be needed there).
- [Needs prototype] **GPO VM** (Hyper-V access pending): confirm that ActiveStore includes GPO rules and honors `AllowLocalFirewallRules=False`.
- [Needs prototype] Per-rule interface-alias filter timing; association for service-hardening stores.
- [Verify] Microsoft definitions of `EnforcementStatus` values; the registry rule grammar (MS-FASP), if it's ever needed.
- Human decision: the N-04 performance target vs. completeness.
