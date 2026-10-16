# Local-policy verdict contract (SB-21): **PROPOSED**

**Status: PROPOSED and not binding.** It is drafted in M2.0 under [ADR 0024](../adr/0024-local-policy-verdict-contract.md), which is **Proposed**, and it becomes binding only when the human accepts ADR 0024. Until then:
- SB-18, SB-19, and SB-20 ([security-boundaries.md](security-boundaries.md)) are the only binding rules;
- no verdict engine exists;
- **no decision step is authorized** to produce policy verdicts (§9).

**Contract version:** `sb21/0-draft.2`.

**Frozen inputs, refined and not replaced:**
- the verdict model and reason codes in [planning 05 §3](../planning/05-firewall-analysis.md);
- requirements F1-09 and F1-11 and N-08 ([planning 02](../planning/02-requirements.md)).

Proposed changes to frozen identifiers are listed as **errata proposals** in §16. None of them has been applied to the planning documents.

## 1. Two separate layers
| Layer | What it describes | Possible results in v0.1 |
|---|---|---|
| **Windows Firewall local configuration** (`windows_policy`) | What the Windows Firewall configuration that FirewallAI could read would do with the scenario in §3 | `LoopbackOnlyBinding` (pending erratum E1), `PermittedByPolicy`, `BlockedByPolicy`, `Indeterminate` |
| **Overall traffic filtering** (`overall_filtering`) | Whether the traffic would actually be let through, by all filtering layers together | **Always `not_determined`** in v0.1, with reasons |

**Rules that keep the two layers apart:**
- A `windows_policy` result is a truthful statement about Windows Firewall's own readable configuration. It is **never** promoted to a statement about overall filtering.
- Unknown or active third-party firewalls, filters from the Windows Filtering Platform (WFP) outside Windows Firewall rules, Windows Service Hardening, routers, NAT, and other devices are recorded in `overall_filtering` and in `limitations`.

## 2. What a result never means
- That a connection was attempted, made, or observed.
- That the socket is **reachable from the internet** or from any other network or device.
- That a matching Allow rule **guarantees** that traffic is actually permitted.
- That other filtering layers (§1) would let the traffic through, or would block it.
- That the PC, the application, or any part of the device is secure, safe, protected, vulnerable, or compromised.
- Anything about other sockets, ports, services, or network paths.

## 3. Traffic scenario `in-unsolicited/1` (precise semantics)
### 3.1 Fixed dimensions
| Dimension | Fixed value in v0.1 |
|---|---|
| Direction | Inbound |
| Kind | **Unsolicited:** a new TCP connection attempt to a socket in `LISTEN` state. Replies to outbound traffic are excluded |
| Protocol | **TCP only.** UDP endpoints are `NotEvaluated` (§4, M20-Q4) |
| **Address family** | **Exactly one per record:** IPv4 or IPv6 (`scope.address_family`). A record never makes a statement about the other family. §12 defines which families a socket gets records for |
| **Local destination port** | The endpoint's own `local_port`, a single known value. It is matched against the rule's `local_ports` and is the only port a rule can be excluded on (§8) |
| **Remote source port** | **Every** remote port (quantified, §3.2). A rule's `remote_ports` never excludes it. Any value other than `any` is a remote restriction |
| **Interface and profile** | **Exactly one interface per record**, chosen as follows: an interface that has an address of the record's family that the bind address covers (`0.0.0.0` or `::` cover every such interface; a specific or link-local address covers only the interface that owns it, using the IPv6 scope ID for link-local). The record's profile is the one Windows assigned to that interface (M2.1 evidence). Interfaces without an address of the record's family get no record. The loopback pseudo-interface is never evaluated (§7) |
| Remote authentication | IPsec-authenticated peers are among "every remote address". A candidate whose effect depends on IPsec authentication therefore makes the result Indeterminate (`AUTH_BYPASS_UNKNOWN`, `SECURE_ALLOW_UNKNOWN`) |
| Not covered | Outbound traffic, ICMP, UDP, forwarded traffic, loopback-to-loopback traffic, and delivery through edge traversal (Teredo). A rule's edge-traversal value is recorded as a fact and not interpreted |

### 3.2 The remote-peer quantifier (`all_remote_addresses_and_ports`, unchanged)
- **Meaning within one record.** The quantifier ranges over **every remote address of the record's address family** combined with **every remote source port**.
  - `PermittedByPolicy` means the readable configuration would allow the attempt from **every** such (remote address, remote port) pair.
  - `BlockedByPolicy` means it would block the attempt from **every** such pair.
- **Per family.** An IPv4 record quantifies over all IPv4 remote addresses. An IPv6 record quantifies over all IPv6 remote addresses. The two are separate statements and are never merged.
- **No silent change.** The quantifier string is the same constant in every record. It is never switched to "a specific address" or "some address".
- **Only for complete evidence.** A universal Permitted or Blocked result is given only when the evidence supports that exact quantified statement for that family, interface, and profile. Otherwise the result is Indeterminate.

### 3.3 Effects on the result
| Situation | Result |
|---|---|
| A non-excluded candidate restricts remote addresses (keyword or explicit list, of either family) or remote ports, and that restriction could change the outcome for some (address, port) pair | `Indeterminate(REMOTE_SCOPE_DEPENDENT)`, with a descriptive remote-scope observation. No address-set arithmetic is done in v0.1, so a restriction that names only the other family is still treated as a restriction |
| A remote restriction cannot change the outcome (for example, a remote-restricted Allow when a complete Any-scope Block decides) | No effect |
| A non-excluded candidate has an unsupported filter that could change the outcome | `Indeterminate(UNSUPPORTED_FILTER)` |
| Socket family acceptance is ambiguous (dual-stack, §12) | `Indeterminate(DUAL_STACK_AMBIGUOUS)` on the affected IPv4 record |
| Bind address cannot be classified | `Indeterminate(BIND_ADDRESS_UNPARSEABLE)` |
| Interface, address, or profile evidence is missing | `Indeterminate(INTERFACE_EVIDENCE_UNKNOWN)`, with one record per endpoint and family and `interface_ref = null` |
| Any other part of the scenario cannot be evaluated completely | `Indeterminate` with the specific reason |

## 4. Outcome and collection states (kept strictly separate)
| State | Level | Meaning | Example | JSON |
|---|---|---|---|---|
| Collection failure | Evidence source | The collector ran and produced no usable data | Security Center access denied | `collection.<source>.status = "failed"` + `errors` |
| Incomplete collection | Evidence source | The collector ran, and part of the data is missing | Rule detail phase timed out | `status = "partial"` + `reasons` |
| Not collected | Evidence source | The collector did not run | Interface mapping before M2.1 | `status = "not_collected"` + `reasons` |
| **NotEvaluated** | Verdict | The subject is **outside the contract's scope**, so the evaluator deliberately gives no answer | A UDP endpoint; a TCP endpoint in a connection state | `evaluation = "not_evaluated"`, `not_evaluated_reason`, `windows_policy = null` |
| **Indeterminate** | Verdict | The subject is in scope and was evaluated, but the evidence is insufficient or unsupported, or the result depends on a step that is not authorized | An incomplete candidate rule; the deciding step is not authorized | `windows_policy.verdict = "Indeterminate"` + `reasons` |

Collection problems never appear as `NotEvaluated`. When they matter, they appear as `Indeterminate`, with a reason that points to the collection status.

## 5. Unit of evaluation
- One record per (TCP listening endpoint, address family, interface, profile), as defined in §3.1 and §12.
- Several interfaces or profiles mean several records. There is never a PC-wide result, and nothing is combined across interfaces or address families.
- Loopback-bound endpoints get one record each, with no interface or profile (§7).
- UDP and connection endpoints get one `NotEvaluated` record each.

## 6. Required evidence and completeness
| Evidence | Source | Completeness requirement | If not met |
|---|---|---|---|
| Profile settings (`enabled`, `default_inbound_action`, `allow_inbound_rules`, `disabled_interface_aliases`) | `core.models.FirewallProfile` (ActiveStore) | Read for the profile, with no `not_configured` value in a field the deciding step uses | `PROFILE_SETTINGS_UNAVAILABLE` / `PROFILE_SETTINGS_UNRESOLVED` |
| Merge flags (`allow_local_firewall_rules`, `allow_local_ipsec_rules`) | Same | Read and not `not_configured` whenever a local-source rule could decide | `MERGE_SETTINGS_UNREADABLE` (frozen) |
| Interfaces: identity, addresses with IPv6 scope IDs, type, assigned profile | **M2.1** | Every interface the bind address covers is known | `INTERFACE_EVIDENCE_UNKNOWN` |
| Third-party firewall state | **M2.1** (Security Center) | Collected or failed. Either way it affects **only** `overall_filtering` (M20-Q3) | — |
| Rules | `RuleCollection` + `core.evidence.evidence_for_verdict` | `detail_requested` and `detail_complete`. Each candidate is `CompleteRuleEvidence` or excluded (§8) | `INCOMPLETE_RULE_EVIDENCE` |
| Endpoint | `core.endpoints.Endpoint` | `bind_scope` parsed; `dual_stack_unknown` known | `BIND_ADDRESS_UNPARSEABLE` |
| Process image and hosted services | `ProcessInfo` (`Observed`) | Needed when a candidate has a program or service filter, and for the service-host check (§11) | `PROCESS_INFO_UNAVAILABLE` (frozen) |

**Purity of the engine:**
- it **never starts a collection**, runs PowerShell, or uses the network;
- it is pure, deterministic, and read-only, and it is independent of generative AI (SB-15, SB-19, `core` purity);
- the SB-20 correlation stays separate, and a "related" correlation result is **never** read as "applicable".

## 7. Loopback-only endpoints
- **When:** `bind_scope = loopback` (`127.0.0.0/8`, `::1`, or IPv4-mapped loopback).
- **Result:** `LoopbackOnlyBinding` (erratum E1; frozen name `NotExposed_LoopbackOnly`). It carries the qualifier `local_binding_observed_at_snapshot` and the limitation `binding_may_change_after_snapshot`. No rules are evaluated.
- **Meaning:** this one socket was observed bound only to loopback when the snapshot was taken. Other software **on this PC** can still connect to it.
- **It is never:**
  - displayed as "not exposed", "safe", or "protected";
  - generalized to other sockets, ports, services, or paths;
  - used as evidence about internet reachability.

## 8. Candidate rules and exclusion
A rule is a **candidate** for one (endpoint, interface, profile) unless a **collected** value contradicts the scenario. Only these contradictions exclude a rule:

| Exclusion ground | Field | Available for incomplete rules? |
|---|---|---|
| Not inbound | `direction` (inventory) | Yes |
| Disabled | `enabled` (inventory) | Yes |
| Profile not included | `profiles` (inventory) | Yes |
| Protocol excludes TCP | `port.protocol` (collected) | Only if `port` is collected |
| Local port excludes the endpoint's port (numbers, ranges, `any`; keywords cannot exclude) | `port.local_ports` | Only if collected and without UNKNOWN tokens |
| Local address excludes the bind address (explicit addresses only) | `address.local_addresses` | Only if collected |
| Program differs from the **collected** image path (after `%VAR%` expansion) | `application.program` | Only if both are collected |
| Interface alias or type excludes the evaluated interface | `interface`, `interface_type` | Only if collected and the interface evidence (M2.1) is known |

**What follows from these grounds:**
- A rule that is not excluded and has an unsupported filter (package, owner, SDDL user or machine, port or address keyword, `local_only_mapping`/`loose_source_mapping` not `false`, multi-service host) contributes `UNSUPPORTED_FILTER`.
- A rule that is not excluded and has incomplete evidence contributes `INCOMPLETE_RULE_EVIDENCE`.
- **A non-excluded candidate that could change the outcome always makes the result Indeterminate.** Each decision step says exactly which candidates "could change the outcome" (§10).
- Matching is conservative. A filter that cannot be evaluated is never treated as matching or as not matching.

## 9. Decision steps
### 9.1 Three independent attributes per step
| Attribute | Question it answers | Values | Current state |
|---|---|---|---|
| **Documentation status** | Does authoritative documentation support the behaviour? | `documented` (more than one source, consistent); `single_source` (one source only, or its wording is ambiguous); `undocumented` (no authoritative source, or the sources conflict) | Per step, below |
| **Verification status** | Has the behaviour been tested independently against real Windows traffic? | `not_verified`; `vm_verified` (two-VM real-behaviour test) | **`not_verified` for every step** |
| **Authorization status** | Has the human approved using this step to produce a policy verdict in the evaluator? | `not_authorized`; `authorized` (recorded human decision, with a date) | **`not_authorized` for every step** |

**How the attributes relate:**
- They are independent. **`documented` never implies `vm_verified`, and neither implies `authorized`.** A step can be documented and still not authorized. Authorization is a separate human decision for each step, taken after its dossier (§10) is reviewed (M20-Q1).
- **Only an `authorized` step may produce `PermittedByPolicy` or `BlockedByPolicy`.** Where a step that is not authorized would decide, the result is `Indeterminate(PRECEDENCE_UNVERIFIED)` with the detail `step:<id>`.
- Steps whose only possible result is Indeterminate need no authorization: Indeterminate is always allowed.
- An authorized step that is still `not_verified` adds the limitation `precedence_documented_not_vm_verified` to every result it produces, and caps finding confidence at Medium.
- **No step is authorized to produce policy verdicts.** P0 is a socket-binding observation, not a policy step (§7).

### 9.2 Step table
| Step | Condition | Result if authorized | Source | Documentation | Verification | Authorization |
|---|---|---|---|---|---|---|
| P0 | Loopback-bound endpoint | `LoopbackOnlyBinding` (§7) | Socket facts | n/a (observation) | n/a | n/a (not a policy step) |
| P1 | Profile `enabled = false` | `Indeterminate(PROFILE_DISABLED_UNKNOWN_ALT)` (frozen) | [S3] | single_source | not_verified | n/a (Indeterminate only) |
| P1a | A needed profile setting is `not_configured` in the ActiveStore | `Indeterminate(PROFILE_SETTINGS_UNRESOLVED)` | — | undocumented | not_verified | n/a (Indeterminate only) |
| P1b | The interface is in `disabled_interface_aliases` | `Indeterminate(INTERFACE_EXCLUDED_FROM_PROFILE)` | [S3] (effect on traffic not stated) | undocumented | not_verified | n/a (Indeterminate only) |
| P3 | `allow_local_firewall_rules = false`, and a local-source candidate could decide | `Indeterminate(MERGE_BEHAVIOUR_UNVERIFIED)` | [S3] says "ignored"; whether the ActiveStore still lists such rules is unknown | single_source | not_verified | n/a (Indeterminate only) |
| P4 | An Allow candidate has `override_block_rules = true` | `Indeterminate(AUTH_BYPASS_UNKNOWN)` (frozen) | [S2] (archived) | single_source | not_verified | n/a (Indeterminate only) |
| P4a | `allow_inbound_rules = false` | The default action decides | [S3]; interplay with bypass rules undocumented | single_source | not_verified | **not_authorized** (not proposed for v0.1) |
| **P5** | Complete, applicable Block candidate (dossier §10.1) | `BlockedByPolicy` | [S1] rule 2, [S2] | documented | not_verified | **not_authorized** |
| **P6** | Complete, applicable plain Allow candidate (dossier §10.2) | `PermittedByPolicy` (Windows configuration only) | [S1] rule 1, [S2], [S3] | documented | not_verified | **not_authorized** |
| P6a | An "allow if secure" candidate could decide | `Indeterminate(SECURE_ALLOW_UNKNOWN)` | [S1] rule 3 does not settle this | undocumented | not_verified | n/a (Indeterminate only) |
| **P7** | No candidate rule; default inbound action Block (dossier §10.3) | `BlockedByPolicy` | [S2], [S3] | documented | not_verified | **not_authorized** |
| P7a | No candidate rule; default inbound action Allow | `PermittedByPolicy` | [S3] only | single_source | not_verified | **not_authorized** (not proposed for v0.1) |
| P7b | Default Allow **and** a Block candidate | `Indeterminate(PRECEDENCE_UNVERIFIED)` | [S1] and [S3] wording conflicts | undocumented | not_verified | n/a (Indeterminate only) |

**JSON.** Every record names its deciding step together with all three attributes, so documentation is never mistaken for verification or authorization:
```json
"deciding_step": {"id": "P5", "documentation": "documented", "verification": "not_verified", "authorization": "not_authorized"}
```
**Specificity.** [S1] says "More specific rules take precedence over less specific rules, except if there are explicit block rules". How specificity is measured is not documented, so the contract never resolves an outcome by specificity. Wherever specificity could matter, the result is Indeterminate.

## 10. Decision dossiers (the material for M20-Q1; none of these steps is authorized)
### 10.1 P5: Block candidate → `BlockedByPolicy`
1. **Documentation:**
   - [S1] rule 2: "Explicit block rules take precedence over any conflicting allow rules."
   - [S2] rule priority 2: "Block connection. These rules block all matching inbound network traffic", processed after authenticated bypass. It adds: "As soon as a network packet matches a rule, that rule is applied, and processing stops."
2. **Required fields** (all `collected`):
   - **Profile:**
     - `enabled = true`;
     - `allow_inbound_rules = true` (if it is `false`, rules are ignored per [S3], so P5 does not apply);
     - the merge flag is `true` when the Block rule's `policy_source_type = local`.
   - **Interface:** evidence known (M2.1), including the alias and type if the rule filters on them.
   - **Rule:**
     - `CompleteRuleEvidence`, inbound, enabled, action `block`, the profile included;
     - protocol `tcp`, `6`, or `any`;
     - local port matching by number, range, or `any`, and dynamic target `any`;
     - local address `any`, or explicit and containing the bind address;
     - **remote addresses and remote ports exactly `any`** (the §3 quantifier);
     - program `any`, or equal to the collected image path;
     - no package or owner;
     - service `any`, or one unambiguous collected service;
     - no SDDL user or machine;
     - no local-only or loose-source mapping.
   - **Endpoint:** TCP `LISTEN`, parsed bind address, and process attribution collected if the rule has a program or service filter.
3. **Competing rules:**
   - Per [S2], only an authenticated-bypass Allow is processed before Block rules. So **every non-excluded candidate** must have a collected `security` filter with `override_block_rules = false`.
   - A candidate whose security filter is not collected gives `INCOMPLETE_RULE_EVIDENCE`. A bypass candidate gives `AUTH_BYPASS_UNKNOWN`.
   - Other Allow rules (complete or not) cannot change a Block outcome per [S1] rule 2, which also excepts explicit Block rules from the specificity principle.
4. **Inputs that force Indeterminate:**
   - the profile is disabled or unresolved;
   - `allow_inbound_rules` is not `true`;
   - local-source Block with merge `false` or unreadable;
   - interface evidence unknown;
   - a bypass candidate, or a candidate with an unknown security filter;
   - the Block rule restricts remote addresses or ports, so the outcome is not uniform → `REMOTE_SCOPE_DEPENDENT`;
   - the service-host condition (§11);
   - dual-stack mismatch (§12);
   - the step is not authorized.
5. **Fixtures:**
   - positive: Any Block + Any Allow;
   - contradictory: Block + bypass Allow → `AUTH_BYPASS_UNKNOWN`;
   - contradictory: Block + an Allow with an uncollected security filter → `INCOMPLETE_RULE_EVIDENCE`;
   - negative: a `LocalSubnet` Block → `REMOTE_SCOPE_DEPENDENT`;
   - negative: local-source Block with merge off → `MERGE_BEHAVIOUR_UNVERIFIED`;
   - negative: `AllowInboundRules=False` → Indeterminate;
   - negative: a Block rule for another profile → excluded, so P5 does not apply;
   - negative: the step not authorized → `PRECEDENCE_UNVERIFIED`.
6. **Still unverified:**
   - whether the archived order [S2] still holds on Windows 10/11;
   - whether the ActiveStore shows every effective rule (ADR 0009 found a 3-rule gap between COM and the ActiveStore; Windows Service Hardening; boot-time and other WFP filters);
   - real traffic behaviour.

### 10.2 P6: plain Allow candidate → `PermittedByPolicy` (Windows configuration only)
1. **Documentation:**
   - [S1] rule 1: "Explicitly defined allow rules take precedence over the default block setting."
   - [S2] priority 3.
   - [S3] `AllowInboundRules` True: "Inbound firewall rules are allowed."
2. **Required fields:** as for P5, with these differences for the deciding rule:
   - action `allow`;
   - **`authentication` and `encryption` show no IPsec requirement** (the exact raw tokens are fixed in M2.2 from fixtures [VERIFY]);
   - `override_block_rules = false`;
   - no SDDL user or machine;
   - remote addresses and ports exactly `any`.
3. **Competing rules.** Any non-excluded **Block** candidate could override the Allow, so the step requires:
   - **no** non-excluded Block candidate, complete or incomplete. Otherwise the result is `INCOMPLETE_RULE_EVIDENCE`, `UNSUPPORTED_FILTER`, or, for a remote-restricted Block, `REMOTE_SCOPE_DEPENDENT`;
   - **no** non-excluded "allow if secure" candidate, because specificity could matter. Otherwise the result is `SECURE_ALLOW_UNKNOWN`.

   Other plain Any-scope Allow candidates do not change the outcome.
4. **Inputs that force Indeterminate:** the P5 list, plus:
   - a program-scoped Allow with the image unavailable → `PROCESS_INFO_UNAVAILABLE`;
   - a local-source Allow with merge off or unreadable;
   - the service-host condition (§11).
5. **Fixtures:**
   - positive: an Any Allow with no Block, default Block;
   - contradictory: Allow + an incomplete Block → `INCOMPLETE_RULE_EVIDENCE`;
   - contradictory: Allow + a remote-restricted Block → `REMOTE_SCOPE_DEPENDENT`;
   - contradictory: Allow + a secure Allow → `SECURE_ALLOW_UNKNOWN`;
   - negative: a `LocalSubnet`-only Allow → `REMOTE_SCOPE_DEPENDENT`;
   - negative: a program-scoped Allow with the image unavailable → `PROCESS_INFO_UNAVAILABLE`;
   - negative: a service-hosting process → `SERVICE_HARDENING_UNKNOWN`;
   - negative: `AllowInboundRules=False` → Indeterminate;
   - negative: the step not authorized → `PRECEDENCE_UNVERIFIED`.
6. **Still unverified:**
   - everything in P5;
   - the effect of the specificity principle among Allow rules;
   - Windows Service Hardening;
   - whether an Allow rule actually leads to accepted traffic. **A Permitted result never guarantees that.**

### 10.3 P7: no candidate rule, default Block → `BlockedByPolicy`
1. **Documentation:**
   - [S2] priority 4: "The default behavior is to block unsolicited inbound network traffic".
   - [S3] `DefaultInboundAction` Block: "Blocks inbound network traffic that does not match an inbound rule."
2. **Required fields:**
   - profile `enabled = true`;
   - `default_inbound_action = block`;
   - `allow_inbound_rules` collected, `true` or `false`;
   - interface evidence known;
   - the rule scan with `detail_complete = true`.
3. **Competing rules:**
   - **Every** enabled inbound rule for the profile must be **excluded** by a collected contradiction (§8). Any non-excluded rule, complete or not, means P7 does not apply. Such a rule is either a real candidate (P5/P6 logic) or gives `INCOMPLETE_RULE_EVIDENCE` or `UNSUPPORTED_FILTER`.
   - A rule with an unsupported filter **can** still be excluded by a collected port or protocol contradiction.
4. **Inputs that force Indeterminate:**
   - default action `not_configured` or unreadable;
   - any non-excluded rule;
   - an incomplete or inventory-only scan;
   - interface evidence unknown or excluded;
   - the service-host condition (§11);
   - the step is not authorized.
5. **Fixtures:**
   - positive: no candidates, default Block;
   - positive: rules only for other profiles or ports;
   - negative: one incomplete rule that is not excluded;
   - negative: an unsupported-filter rule whose port matches;
   - negative: default `not_configured`;
   - negative: an inventory-only scan;
   - contradictory: the interface in `DisabledInterfaceAliases` → `INTERFACE_EXCLUDED_FROM_PROFILE`.
6. **Still unverified:** hidden or other WFP filters, Windows Service Hardening, the completeness of the ActiveStore listing, and real traffic.

## 11. Windows service hosts (M20-Q6)
The result is `Indeterminate` **only** when the service identity or rule applicability cannot be determined reliably:
- **A candidate rule has a service filter:**
  - if the hosted services are unavailable → `PROCESS_INFO_UNAVAILABLE`;
  - if the process hosts several services and the rule names one of them → `UNSUPPORTED_FILTER` (shared host).
- **The process hosts at least one collected service.** Windows Service Hardening restrictions may apply and are not observable [VERIFY]. Any Permitted or Blocked result becomes `SERVICE_HARDENING_UNKNOWN`.
- **Whether the process hosts services is unknown** (services `unavailable`) → `SERVICE_HARDENING_UNKNOWN`.
- **Processes whose services were collected as empty** (fully identified, non-service processes) are **not** affected.
- **PID 4 (System)** follows SB-20: a program- or service-scoped candidate → `PROCESS_INFO_UNAVAILABLE`.

## 12. Address families and dual-stack
- **IPv4 binds** (`0.0.0.0`, or a specific IPv4 address) get IPv4 records only.
- **IPv6 binds** (`::`, or a specific IPv6 address) get IPv6 records.
- **A `::` socket with `dual_stack_unknown = true`** also gets IPv4 records. Each carries the qualifier `ipv4_acceptance_by_socket_unknown`, because whether the socket accepts IPv4 at all is not known.
  - For each interface, the IPv4 record keeps its result **only if** it equals the IPv6 record's result on the same interface.
  - Otherwise, including when there is no IPv6 record on that interface, the IPv4 record is `Indeterminate(DUAL_STACK_AMBIGUOUS)` (frozen).
  - The IPv6 record is not affected.
- **A `::` socket with `dual_stack_unknown = false`** gets IPv6 records only. [VERIFY] the collector semantics of `dual_stack_unknown` before M2.2.
- A record never uses evidence or results from the other family to claim anything about its own family. The only cross-family check is the equality test above, and it can only make a result less certain.

## 13. Indeterminate reason codes
**Frozen** (planning 05, unchanged): `THIRD_PARTY_FIREWALL`, `PROFILE_DISABLED_UNKNOWN_ALT`, `PROCESS_INFO_UNAVAILABLE`, `UNSUPPORTED_FILTER`, `AUTH_BYPASS_UNKNOWN`, `NON_FIREWALL_WFP_FILTERS`, `MERGE_SETTINGS_UNREADABLE`, `DUAL_STACK_AMBIGUOUS`, `REMOTE_SCOPE_DEPENDENT`.
- `NON_FIREWALL_WFP_FILTERS` stays reserved until the WFP spike.
- Proposed placement changes for `THIRD_PARTY_FIREWALL` (E2) and `REMOTE_SCOPE_DEPENDENT` (E4) are in §16.

**JSON form of every reason:**
```json
{"code": "<CODE>", "detail": "<stable technical detail>", "refs": ["<entity ids>"]}
```

**Proposed additions** (pending compatibility review, M20-Q8). The 13 codes of the first draft became **11**:
- `RULE_SCAN_INCOMPLETE` was merged into `INCOMPLETE_RULE_EVIDENCE` (detail `scan` vs. `rule`);
- `PROFILE_MAPPING_UNKNOWN` and `INTERFACE_CONDITION_UNKNOWN` were merged into `INTERFACE_EVIDENCE_UNKNOWN`.

| Code | Meaning | Trigger (evidence condition) | Overlapping frozen code and how it is kept distinct | Beginner explanation | JSON example |
|---|---|---|---|---|---|
| `PROFILE_SETTINGS_UNAVAILABLE` | The profile's settings could not be read at all | Profile collection failed or the profile is missing | `MERGE_SETTINGS_UNREADABLE` covers only the merge flags of a profile that was read | "FirewallAI couldn't read the settings for this network type." | `{"code":"PROFILE_SETTINGS_UNAVAILABLE","detail":"profile:public","refs":[]}` |
| `PROFILE_SETTINGS_UNRESOLVED` | A needed non-merge setting reads `not_configured` | `enabled`, `default_inbound_action`, or `allow_inbound_rules` = `not_configured` | Merge flags → `MERGE_SETTINGS_UNREADABLE` | "A setting that decides this answer has no clear value." | `{"code":"PROFILE_SETTINGS_UNRESOLVED","detail":"field:default_inbound_action","refs":["fw_profile:public"]}` |
| `INTERFACE_EVIDENCE_UNKNOWN` | The network-interface facts needed are missing | Mapping, addresses, alias, or type not collected or failed | `UNSUPPORTED_FILTER` means FirewallAI cannot evaluate a filter *type*; this code means the *facts* are missing | "FirewallAI doesn't know which network this connection would arrive on." | `{"code":"INTERFACE_EVIDENCE_UNKNOWN","detail":"interfaces:not_collected","refs":[]}` |
| `INTERFACE_EXCLUDED_FROM_PROFILE` | The interface is listed as excluded from the profile's settings | Interface alias in `disabled_interface_aliases` | — | "Firewall settings are switched off for this network adapter, and FirewallAI can't tell what that means here." | `{"code":"INTERFACE_EXCLUDED_FROM_PROFILE","detail":"","refs":["interface:h1-…"]}` |
| `THIRD_PARTY_STATE_UNKNOWN` | Whether another firewall product is active is unknown (**`overall_filtering` only**) | Security Center collection failed or is not available | `THIRD_PARTY_FIREWALL` means one is *known* to be active | "FirewallAI couldn't check whether another firewall program is also in use." | `{"code":"THIRD_PARTY_STATE_UNKNOWN","detail":"security_center:access_denied","refs":[]}` |
| `MERGE_BEHAVIOUR_UNVERIFIED` | The settings were read, but their effect on a deciding local rule is unverified | `allow_local_firewall_rules = false` and a local-source candidate could decide | `MERGE_SETTINGS_UNREADABLE` means the flags were not read | "Your organization's policy may ignore this rule, and FirewallAI can't confirm whether it does." | `{"code":"MERGE_BEHAVIOUR_UNVERIFIED","detail":"","refs":["fw_rule:h1-…"]}` |
| `INCOMPLETE_RULE_EVIDENCE` | Rule details needed for the answer are missing | `detail:scan` = inventory-only, cancelled, or failed scan; `detail:rule` = a non-excluded candidate with `IncompleteEvidence` | SB-18 gate; no frozen equivalent | "Some rule details weren't read completely, so FirewallAI won't guess." | `{"code":"INCOMPLETE_RULE_EVIDENCE","detail":"rule","refs":["fw_rule:h1-…"]}` |
| `SECURE_ALLOW_UNKNOWN` | An "allow only if secure (IPsec)" rule could decide | Non-excluded Allow candidate with an authentication or encryption requirement and no bypass | `AUTH_BYPASS_UNKNOWN` is for override-block (bypass) rules, whose effect differs | "This rule allows only specially secured connections, and FirewallAI can't see that security setup." | `{"code":"SECURE_ALLOW_UNKNOWN","detail":"","refs":["fw_rule:h1-…"]}` |
| `PRECEDENCE_UNVERIFIED` | The deciding step is not authorized, or it is undocumented or conflicting, or rule specificity could matter | §9 | — | "How Windows decides between these settings hasn't been confirmed and approved yet, so FirewallAI doesn't give an answer." | `{"code":"PRECEDENCE_UNVERIFIED","detail":"step:P5","refs":[]}` |
| `BIND_ADDRESS_UNPARSEABLE` | The socket's local address could not be interpreted | `bind_scope = unparseable` | — | "FirewallAI couldn't read which address this app is using." | `{"code":"BIND_ADDRESS_UNPARSEABLE","detail":"","refs":["endpoint:h1-…"]}` |
| `SERVICE_HARDENING_UNKNOWN` | Windows service restrictions may apply and are not visible | §11 | `PROCESS_INFO_UNAVAILABLE` is for program- or service-scoped *rules*; this code is for hidden service restrictions | "This is a Windows service, and Windows can apply extra hidden restrictions to services that FirewallAI can't read." | `{"code":"SERVICE_HARDENING_UNKNOWN","detail":"services:collected","refs":["endpoint:h1-…"]}` |

## 14. NotEvaluated reasons
| Code | Meaning | Beginner explanation |
|---|---|---|
| `PROTOCOL_UDP_OUT_OF_SCOPE` | UDP endpoints are collected and shown but not evaluated in v0.1 (M20-Q4) | "FirewallAI doesn't check firewall settings for this kind of connection (UDP) yet." |
| `ENDPOINT_NOT_LISTENING` | TCP endpoint in a connection state, so no unsolicited inbound scenario applies | "This is an existing connection, not an app waiting for new connections." |

## 15. Limitations on every non-loopback record
- `local_policy_only`
- `wfp_filters_not_observable`
- `service_hardening_not_evaluated`
- `group_policy_merge_unverified`
- `enforcement_status_uninterpreted`
- `precedence_documented_not_vm_verified`, whenever an authorized step that is not VM-verified decides the result

These match the existing `ScanLimitationCode` values where one exists.

## 16. Errata proposals for frozen contracts (none applied; each needs explicit approval)
| ID | Frozen text | Proposal | Migration |
|---|---|---|---|
| **E1** | F1-09 / planning 05: `NotExposed_LoopbackOnly` | Use `LoopbackOnlyBinding` in `firewallai.scan/1` | The frozen documents stay unchanged until approval; then an erratum note is added and the old text is kept. No verdict output exists yet, so no consumer breaks. The schema documentation carries the mapping `NotExposed_LoopbackOnly` → `LoopbackOnlyBinding` (same meaning, narrower wording). Records do not emit the old name. If the erratum is rejected, the frozen name is emitted unchanged and the display rules in §7 still apply |
| **E2** | Planning 05: `THIRD_PARTY_FIREWALL` is a verdict Indeterminate reason | It becomes an `overall_filtering` reason. The `windows_policy` result is kept, with the qualifier `windows_firewall_enforcement_not_verified` (M20-Q3) | If rejected: an active third party forces the `windows_policy` result to Indeterminate (frozen behaviour). `THIRD_PARTY_STATE_UNKNOWN` stays in `overall_filtering` either way |
| **E3** | F1-09 lists four verdict values | Add a record-level `evaluation = not_evaluated` state (not a fifth verdict value) for out-of-scope endpoints | The verdict value set is unchanged |
| **E4** | Planning 05: `REMOTE_SCOPE_DEPENDENT` reported as Permitted plus a qualifier "where possible" | Under the fixed quantifier (§3), it is always an Indeterminate reason, and the remote scope is listed as a descriptive observation | It narrows "where possible" to "never in v0.1". The frozen wording allowed this |
| **E5** | Planning 05 §5: YAML truth-table fixtures | JSON (decision S1) | Test data only |

## 17. Sources (accessed 2026-10-15; documentation only, not behaviour verification)
- **[S1]** Microsoft Learn, "Windows Firewall rules", section "Rule precedence for inbound and outbound rules" (page dated 2025-06-06): https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/rules
- **[S2]** Microsoft Learn (archived; applies to Windows 7 / Windows Server 2008 R2), "Understanding Firewall Rules", section "Firewall rule priority": https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/dd421709(v=ws.10). The current page [S1] does not restate this fixed order, so whether it holds on Windows 10/11 is `[VERIFY]`.
- **[S3]** Microsoft Learn, `Set-NetFirewallProfile` parameter reference (Windows Server 2025 docset): https://learn.microsoft.com/en-us/powershell/module/netsecurity/set-netfirewallprofile. It describes the ActiveStore as including the Windows Service Hardening stores. Whether `Get-NetFirewallRule -PolicyStore ActiveStore` returns those restrictions is `[VERIFY]`.

None of these sources has been checked against observed traffic. That requires the two-VM real-behaviour test ([planning 05 §5](../planning/05-firewall-analysis.md), [planning 13](../planning/13-testing-strategy.md)), which is still open.
