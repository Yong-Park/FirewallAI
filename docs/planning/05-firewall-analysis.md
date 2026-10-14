# 05: Firewall Analysis: Effective Policy, Verdicts, Correlation, Findings

Status: Approved plan rev. 3, frozen snapshot. Implements rev. 2 requirement §3 (analysis accuracy).

## 1. Principles

1. **An open port alone is not a vulnerability.** A listener is a fact. Exposure is a question about policy. Risk depends on context.
2. **Verdicts describe local policy only.** FirewallAI cannot see NAT, routers, upstream or cloud firewalls, or ISP filtering. The UI and reports always say *"permitted by local firewall policy"* and never say *"exposed to the internet"*.
3. **When the evidence is insufficient, the verdict is `Indeterminate`, with the reasons listed.** Guessing is a bug.

## 2. Inputs the evaluator must model

| Area | What matters | Source |
|---|---|---|
| Profiles | Domain, Private, and Public. **Several can be active at once (one per network interface).** Enabled state, default inbound and outbound action, `AllowInboundRules` ("block all incoming connections, including those in the list of allowed apps"), `DisabledInterfaceAliases`. | `Get-NetFirewallProfile -PolicyStore ActiveStore`, `Get-NetConnectionProfile` |
| Policy merge | Local rules apply only if `AllowLocalFirewallRules` is true. Group Policy can set it to false, in which case local rules are ignored. Same for `AllowLocalIPsecRules`. | Profile settings in ActiveStore |
| Rule precedence | Windows Firewall evaluates **authenticated-bypass allow rules** (`OverrideBlockRules`, which require IPsec) first, then **block** rules, then **allow** rules, then the **profile default action** [VERIFY exact ordering against Microsoft docs; document the citation]. | Rule `Action`, `OverrideBlockRules` |
| Rule filters | Direction, enabled state, profiles, protocol (TCP, UDP, ICMPv4/v6 type and code, other), local and remote ports including keywords (`RPC`, `RPC-EPMap`, `IPHTTPS`, `Teredo`…), local and remote addresses including keywords (`LocalSubnet`, `DNS`, `DHCP`, `DefaultGateway`, `Intranet`, `Internet`…), program path (with environment variables), service (service-SID filtering), interface alias and interface type, edge traversal, package (AppContainer) and owner, authentication and encryption requirements. | `Get-NetFirewall*Filter -All`, joined on `InstanceID` |
| Endpoints | Protocol, address family, bind address (`0.0.0.0`, `::`, a specific IP, loopback), port, PID, and **dual-stack** behavior (a `::` listener may also accept IPv4 unless `IPV6_V6ONLY` is set; this is often not visible). | psutil |
| Processes | Image path. Inaccessible for protected processes (PPL), some system processes, and other users' elevated processes when running unelevated. | psutil, Win32 APIs |
| Services | One `svchost` PID can host many services. Rules may be scoped to a service SID. | `psutil.win_service_iter()` / SCM |
| Other controls | Third-party firewall products registered with Security Center. WFP filters not created by Windows Firewall rules (Windows Service Hardening, third-party filters, boot-time filters). | `root\SecurityCenter2` (client SKUs only), WFP enumeration (spike) |

## 3. Verdict model

For each pair of (listener, active profile/interface):

```
NotExposed_LoopbackOnly   bound only to 127.0.0.0/8 or ::1
BlockedByPolicy           an applicable block rule matches, or no allow rule matches and the default inbound action is Block,
                          or AllowInboundRules=False, with no indeterminate condition present
PermittedByPolicy         an applicable allow rule matches, and no applicable block rule matches
                          (or an authenticated-bypass rule applies and its IPsec requirements are known)
Indeterminate(reasons[])  any condition below prevents a determination
```

**Rules are matched conservatively.** If a rule *might* match but a filter can't be evaluated (for example, the program path for the PID is inaccessible), the result is `Indeterminate`. It is never silently treated as matching or as not matching.

### Indeterminate reasons (initial set)
| Code | Meaning |
|---|---|
| `THIRD_PARTY_FIREWALL` | A third-party firewall is registered as active, so Windows Firewall may not be the effective control |
| `PROFILE_DISABLED_UNKNOWN_ALT` | Windows Firewall profile is disabled and no other firewall was identified, so whether a control exists is unknown |
| `PROCESS_INFO_UNAVAILABLE` | A program- or service-scoped rule could match, but the PID's image or services are unreadable |
| `UNSUPPORTED_FILTER` | A matching candidate uses a filter type FirewallAI cannot evaluate yet (e.g. package or owner, some interface types) |
| `AUTH_BYPASS_UNKNOWN` | A matching authenticated-bypass rule depends on the IPsec state, which is unknown |
| `NON_FIREWALL_WFP_FILTERS` | WFP filters from other sources may affect this traffic (after the spike) |
| `MERGE_SETTINGS_UNREADABLE` | Policy-merge flags could not be read |
| `DUAL_STACK_AMBIGUOUS` | A `::` listener's IPv4 acceptance is unknown, and the IPv4 and IPv6 verdicts differ |
| `REMOTE_SCOPE_DEPENDENT` | The allow rule is limited to remote addresses (e.g. `LocalSubnet`), so the verdict holds only for those sources. Reported as `PermittedByPolicy` with a scope qualifier, not as indeterminate, where possible |

Qualifiers attached to `PermittedByPolicy` include: remote scope (Any, LocalSubnet, specific ranges), the interface types involved, edge traversal, and the matched rule IDs.

## 4. Correlation algorithm (outline)

1. Build the snapshot: profiles, interfaces with their assigned profiles, rules with joined filters, endpoints, processes, and services.
2. Expand the effective rule set for each profile, applying merge flags and dropping disabled rules.
3. For each listening endpoint:
   1. If it is bound only to loopback, the verdict is `NotExposed_LoopbackOnly`.
   2. Otherwise, for each active profile whose interfaces the bind address covers, collect the inbound rules that match on protocol and local port. Then narrow by program, service, interface, and the other filters, tracking any filter that can't be evaluated.
   3. Apply precedence: auth-bypass, then block, then allow, then default.
   4. Emit the verdict with its matched rule IDs and any Indeterminate reasons.
4. Findings rules consume the verdicts plus profile and rule facts.

## 5. Validation strategy

- **Truth table:** about 40 synthetic scenarios, kept as YAML fixtures under `tests/fixtures/verdicts/`. Examples:
  - loopback-only;
  - an allow rule on Private only, while the active profile is Public;
  - a block rule overriding an allow rule;
  - `AllowInboundRules=False`;
  - GPO with `AllowLocalFirewallRules=False` plus a local allow rule;
  - a program-scoped rule with an inaccessible PID;
  - a dual-stack `::` listener;
  - an active third-party firewall;
  - a `LocalSubnet` scope;
  - an edge traversal rule.
- **Real-behavior check** [NEEDS PROTOTYPE]: two Hyper-V VMs on an internal switch. The target VM runs listeners and specific rules. The probe VM attempts connections. Observed reachability is compared with FirewallAI's verdict, and every mismatch becomes a test case.

## 6. Findings catalog (v0.1 draft)

Each entry contains: ID, title, severity (Info, Low, Medium, High), confidence (Low, Medium, High), condition, evidence fields, *why it matters*, *when it is benign*, recommendation, and references (registry IDs, worded "relates to").

| ID | Finding | Severity (default) | Benign when |
|---|---|---|---|
| FW-PROF-001 | A firewall profile is disabled and no third-party firewall is detected | High (Public) / Medium | A managed third-party control exists that FirewallAI can't see |
| FW-PROF-002 | Default inbound action is Allow on an active profile | High | Rarely benign; isolated lab networks |
| FW-PROF-003 | Dropped-packet logging is disabled | Info | Logging is centralized another way |
| FW-RULE-001 | An inbound Allow rule applies on Public with Any program, Any local port, and Any remote address | High | Deliberately exposed host behind other controls |
| FW-RULE-002 | An inbound Allow rule for a remote-administration or file-sharing port (e.g. 3389, 445, 5985/5986, 22) on Public with remote scope Any | Medium | Server roles that require it, behind upstream controls |
| FW-RULE-003 | A rule references a program path that no longer exists (stale) | Low | Path on a removable drive or a temporarily unmounted volume |
| FW-RULE-004 | Duplicate rules (identical effective filters) | Info | Created by different installers; harmless apart from clutter |
| FW-RULE-005 | Edge traversal is allowed on an inbound rule | Medium | Required by specific apps that use Teredo |
| FW-EXP-001 | A listener bound to all interfaces has verdict `PermittedByPolicy` on Public with remote scope Any | Medium | Intentional services; context decides |
| FW-EXP-002 | A development-tool or database listener is `PermittedByPolicy` on any non-Domain profile (port and process heuristics) | Low–Medium | Intentional LAN sharing |
| FW-AI-001 | The Ollama API is listening on a non-loopback address (e.g. `OLLAMA_HOST=0.0.0.0`): an unauthenticated model API reachable per local policy | Medium | Deliberate LAN model server with other controls in place |
| FW-ENV-001 | The OS is out of mainstream support (informational) | Info | ESU-covered systems [VERIFY wording] |

Confidence drops when any related verdict is `Indeterminate`, and the finding says so.
