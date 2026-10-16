# Findings, `scan --json`, and fixture contracts: **PROPOSED**

**Status: PROPOSED and not binding.** It is drafted in M2.0 under [ADR 0024](../adr/0024-local-policy-verdict-contract.md), which is Proposed. Nothing here is implemented. The verdict rules are in [verdict-contract.md](verdict-contract.md) (SB-21, proposed), and section references of the form "verdict §N" point there.

**Frozen inputs:**
- the catalog and the severity and confidence definitions in [planning 05 §6](../planning/05-firewall-analysis.md);
- requirements F1-10, F1-11, F1-14, and F1-16;
- the six plain-language fields of [ADR 0023 §2.3](../adr/0023-beginner-first-ux.md);
- [ux-principles §5](ux-principles.md);
- the UX0 package, which is a **DRAFT and not usability-validated** ([ux/status-and-tokens.md](ux/status-and-tokens.md)).

**All examples are synthetic:**
- addresses come from the documentation ranges `192.0.2.0/24` and `2001:db8::/32`;
- IDs are made up;
- no data comes from any real machine.

## 1. Finding data contract
### 1.1 When a finding may exist
1. **One rule function per catalog entry.** It lives in `core` and is pure, deterministic, read-only, and AI-free (SB-15).
2. **Declared required evidence.** Each rule function lists the evidence it needs (§3). If any of it is not `complete`, there is **no finding**. The check reports `insufficient_evidence` with reasons (§2.5). A missing piece of evidence never produces a weaker finding (SB-18).
3. **Never from a listening port alone** (F1-11). A finding that depends on a verdict uses only `windows_policy` results from **authorized** steps (verdict §9).
4. **"No finding" is never "fine".** The `checks` section always states what was evaluated, and what was not and why.

### 1.2 Record
```json
{
  "id": "finding:fw-rule-002:h1-3f9c2a7b01d4e6a8",
  "catalog_id": "FW-RULE-002",
  "catalog_version": "catalog/0.1-draft",
  "title": "Remote-administration port allowed on Public networks from any address",
  "severity": "medium",
  "confidence": "high",
  "confidence_reasons": [],
  "scope": {"layer": "windows_firewall_local_configuration"},
  "subjects": ["fw_rule:h1-0000000000000a01"],
  "evidence": [
    {"ref": "fw_rule:h1-0000000000000a01", "kind": "firewall_rule", "source": "rules",
     "collection_status": "complete", "evidence_state": "complete",
     "facts": {"direction": "inbound", "action": "allow", "enabled": true, "profiles": ["public"],
               "policy_source_type": "local", "protocol": "tcp", "local_ports": ["3389"],
               "remote_addresses": ["any"]}}
  ],
  "verdict_refs": [],
  "explanation": {
    "observed": "An enabled Windows Firewall rule on this PC allows incoming connections to TCP port 3389 (Remote Desktop) on the Public network profile, from any address.",
    "why_it_may_matter": "Remote-administration services are often targeted. On Public networks, such as many shared Wi-Fi networks, a rule like this lets more devices try to connect, if the network itself lets them.",
    "when_it_can_be_normal": "You use Remote Desktop on purpose, or your organization manages this PC and needs it.",
    "evidence": "This rule's settings, read from the PC's active firewall configuration: direction, action, network profile, protocol, port, and allowed remote addresses. All details are in the technical view.",
    "still_unknown": "Whether anything is actually listening on this port, and whether other devices or networks would let such a connection through. A rule that allows traffic does not prove that traffic is accepted. FirewallAI does not test connections.",
    "review_next": "Check whether you need Remote Desktop on Public networks. If you are unsure, ask whoever manages this PC before changing anything."
  },
  "benign_when": ["catalog:FW-RULE-002:benign:server-role"],
  "references": [{"registry_id": "[VERIFY] registry entry", "relation": "relates_to"}],
  "limitations": ["local_policy_only", "wfp_filters_not_observable", "group_policy_merge_unverified"],
  "provenance": {"engine_version": "0.2.0-draft", "contract_version": "sb21/0-draft.2",
                 "catalog_version": "catalog/0.1-draft", "analysis_digest": "sha256:…",
                 "source_digests": {"rules": "sha256:…"}}
}
```
This example is a rule-configuration finding, so it needs no verdict and no decision step, and its confidence can be `high`.

### 1.3 Field rules
| Field | Rule |
|---|---|
| `id` | `finding:<catalog id lower-case>:h1-<16 hex>`, where the hex is SHA-256 over the catalog ID and the sorted subject IDs. Stable for the same snapshot |
| `severity` | Catalog default (`info` / `low` / `medium` / `high`). It is lowered only where the catalog says so, and never raised because evidence is missing |
| `confidence` | `high` / `medium` / `low`. **At most `medium`** when the finding depends on an authorized step whose verification status is `not_verified`. Lowered when related verdicts are Indeterminate (planning 05 §6). Every step down lists a `confidence_reasons` code |
| `scope.layer` | Always `windows_firewall_local_configuration` in v0.1. A finding never states overall filtering or reachability |
| `evidence` | Every fact used, with its `ref`, `source`, `collection_status`, and `evidence_state`. **The complete technical evidence is always included**: the plain text summarizes it and never replaces it |
| `explanation` | The **six ADR 0023 fields** (§1.4), all required |
| Attention level | Not in the JSON. The UI derives it from severity, confidence, and evidence state ([ux-principles §5](ux-principles.md), Sprint 3) |
| Sensitivity | `subjects`, `facts` values, and explanation text that contains host values are `host_sensitive`. The rest is `derived_abstract` |

### 1.4 The six plain-language fields (ADR 0023)
| JSON key | Field | Content rule |
|---|---|---|
| `observed` | What was observed | Facts only, with no judgement words |
| `why_it_may_matter` | Why it may matter | Conditional wording only. No claim that harm happened or will happen |
| `when_it_can_be_normal` | When it can be normal | Taken from the catalog's benign conditions |
| `evidence` | What evidence supports it | Names the evidence sources, and points to the technical view |
| `still_unknown` | What is still unknown | **Always** states the Windows-configuration-only limitation. For Allow-related findings it adds "an Allow rule does not prove that traffic is accepted". It also lists the related reasons and limitations in plain words |
| `review_next` | What the user can review next | Review steps only. **Never a command, script, or firewall change** |

**Text rules:**
- **Templates.** Text comes from versioned catalog templates. Host values (rule names, paths, ports) are inserted only as escaped data in named placeholders, and they are untrusted (SB-04).
- **Lint tests** run over every template with synthetic values:
  - every field must be non-empty, and length limits apply;
  - forbidden claims: "reachable from the internet", "exposed", "safe", "secure", "protected", "hacked", or "vulnerable" as statements of fact, and "is allowed" or "is permitted" without "by this PC's firewall settings";
  - the UX0 copy-guide jargon rules, where the draft defines them.

## 2. `firewallai scan --json`: schema `firewallai.scan/1`
### 2.1 Top level
```json
{
  "schema": "firewallai.scan/1",
  "app_version": "0.2.0-draft",
  "engine_version": "0.2.0-draft",
  "contract_version": "sb21/0-draft.2",
  "catalog_version": "catalog/0.1-draft",
  "started_at": "2026-01-01T00:00:00+00:00",
  "read_only": true,
  "elevated": false,
  "evaluation_scope": {
    "layer": "windows_firewall_local_configuration",
    "scenario": "in-unsolicited/1",
    "direction": "inbound",
    "protocols_evaluated": ["tcp"],
    "address_families": ["ipv4", "ipv6"],
    "remote_quantifier": "all_remote_addresses_and_ports",
    "remote_quantifier_scope": "per_record_address_family",
    "authorized_steps": [],
    "overall_filtering": "not_determined"
  },
  "note": "Contains host-sensitive data. Results describe this PC's readable Windows Firewall configuration only. They are not connection tests, do not show whether anything is reachable from the internet, and an Allow rule does not prove that traffic is accepted.",
  "sensitivity": {"data_class": "host_sensitive"},
  "collection": { "...": "§2.2" },
  "analysis": {
    "verdicts": [ "...§2.3" ],
    "checks": [ "...§2.5" ],
    "findings": [ "...§1.2" ],
    "limitations": ["local_policy_only", "wfp_filters_not_observable", "service_hardening_not_evaluated",
                    "group_policy_merge_unverified", "enforcement_status_uninterpreted",
                    "precedence_documented_not_vm_verified"]
  },
  "verdict_label_mapping": {"NotExposed_LoopbackOnly": "LoopbackOnlyBinding"},
  "analysis_digest": "sha256:…",
  "timing": {"profiles_s": 0.0, "rules_s": 0.0, "endpoints_s": 0.0, "analysis_s": 0.0}
}
```
- **Determinism.** `analysis` is canonical JSON, with sorted keys and arrays sorted by `id`. It is **byte-identical** for the same input snapshots and the same engine, contract, catalog, and authorized-step set. `analysis_digest` is its SHA-256. `started_at` and `timing` lie outside it.
- **`verdict_label_mapping`** appears only if erratum E1 is approved (verdict §16).
- **Existing schemas** (`firewallai.profiles/1`, `firewallai.rules/1`, `firewallai.endpoints/1`) stay unchanged.

### 2.2 `collection`: evidence provenance and completeness (one entry per source)
```json
"collection": {
  "profiles":   {"status": "complete", "reasons": [], "errors": [], "digest": "sha256:…"},
  "rules":      {"status": "partial", "reasons": ["detail_incomplete"], "errors": [{"code": "timeout", "source": "rules.detail"}],
                 "rules_total": 412, "rules_complete": 380, "digest": "sha256:…"},
  "endpoints":  {"status": "complete", "reasons": ["attribution_best_effort"], "errors": [], "digest": "sha256:…"},
  "interfaces": {"status": "not_collected", "reasons": ["not_implemented_before_m2_1"], "errors": []},
  "third_party_firewall": {"status": "failed", "reasons": [], "errors": [{"code": "access_denied", "source": "security_center"}]}
}
```
- **`status`** is one of four values. There is no default, and a missing source is `not_collected`:
  - `complete`;
  - `partial` (ran; part missing);
  - `failed` (ran; no usable data);
  - `not_collected` (did not run).
- **`reasons` and `errors`** use the existing codes (`ScanLimitationCode`, `EndpointLimitationCode`, `CollectorErrorCode`).
- **`digest`** is the SHA-256 of the canonical snapshot that the analysis consumed.

### 2.3 Verdict record
```json
{
  "id": "verdict:h1-5b0e9d2c41a7f380",
  "evaluation": "evaluated",
  "not_evaluated_reason": null,
  "scope": {"layer": "windows_firewall_local_configuration", "scenario": "in-unsolicited/1",
            "direction": "inbound", "address_family": "ipv4",
            "remote_quantifier": "all_remote_addresses_and_ports"},
  "subject": {"endpoint_ref": "endpoint:h1-0000000000000e01", "protocol": "tcp", "family": "ipv4",
              "bind_scope": "all_interfaces", "local_port": 8080,
              "interface_ref": "interface:h1-0000000000000f01", "profile": "public"},
  "windows_policy": {
    "verdict": "Indeterminate",
    "reasons": [{"code": "PRECEDENCE_UNVERIFIED", "detail": "step:P5", "refs": ["fw_rule:h1-0000000000000a02"]}],
    "deciding_step": {"id": "P5", "documentation": "documented", "verification": "not_verified", "authorization": "not_authorized"},
    "qualifiers": []
  },
  "overall_filtering": {"status": "not_determined",
                        "reasons": [{"code": "THIRD_PARTY_STATE_UNKNOWN", "detail": "security_center:access_denied", "refs": []}]},
  "remote_scope_observations": [],
  "provenance": {
    "candidate_rule_refs": ["fw_rule:h1-0000000000000a02"],
    "excluded_rules": {"count": 409, "by_ground": {"profile": 301, "local_port": 104, "protocol": 4}},
    "evidence_sources": {"profiles": "complete", "rules": "complete", "endpoints": "complete",
                         "interfaces": "complete", "third_party_firewall": "failed"},
    "documentation": ["S1:rule-2", "S2:priority-2"]
  },
  "limitations": ["local_policy_only", "wfp_filters_not_observable", "service_hardening_not_evaluated",
                  "precedence_documented_not_vm_verified"]
}
```
**A UDP endpoint (NotEvaluated):**
```json
{"id": "verdict:h1-…", "evaluation": "not_evaluated",
 "not_evaluated_reason": {"code": "PROTOCOL_UDP_OUT_OF_SCOPE", "detail": "", "refs": []},
 "scope": {"layer": "windows_firewall_local_configuration", "scenario": "in-unsolicited/1",
           "direction": "inbound", "address_family": "ipv4",
           "remote_quantifier": "all_remote_addresses_and_ports"},
 "subject": {"endpoint_ref": "endpoint:h1-0000000000000e03", "protocol": "udp", "family": "ipv4",
             "bind_scope": "all_interfaces", "local_port": 5353, "interface_ref": null, "profile": null},
 "windows_policy": null, "overall_filtering": {"status": "not_determined", "reasons": []},
 "remote_scope_observations": [], "provenance": {}, "limitations": ["local_policy_only"]}
```
**A loopback-bound endpoint** (`LoopbackOnlyBinding` if E1 is approved; otherwise the frozen name):
```json
{"id": "verdict:h1-…", "evaluation": "evaluated", "not_evaluated_reason": null,
 "scope": {"layer": "windows_firewall_local_configuration", "scenario": "in-unsolicited/1",
           "direction": "inbound", "address_family": "ipv4",
           "remote_quantifier": "all_remote_addresses_and_ports"},
 "subject": {"endpoint_ref": "endpoint:h1-0000000000000e02", "protocol": "tcp", "family": "ipv4",
             "bind_scope": "loopback", "local_port": 11434, "interface_ref": null, "profile": null},
 "windows_policy": {"verdict": "LoopbackOnlyBinding", "reasons": [],
                    "deciding_step": {"id": "P0", "documentation": "n/a", "verification": "n/a", "authorization": "n/a"},
                    "qualifiers": ["local_binding_observed_at_snapshot"]},
 "overall_filtering": {"status": "not_determined", "reasons": []},
 "remote_scope_observations": [], "provenance": {"evidence_sources": {"endpoints": "complete"}},
 "limitations": ["binding_may_change_after_snapshot"]}
```
**A remote-scope observation**, descriptive only, attached when the result is `REMOTE_SCOPE_DEPENDENT`:
```json
{"rule_ref": "fw_rule:h1-0000000000000a03", "action": "allow", "remote_addresses": ["keyword:localsubnet"], "remote_ports": ["any"]}
```
The schema has **no** `reachable`, `exposed`, `safe`, or `permitted_traffic` field.

### 2.4 States: evaluation outcomes versus collection status
Defined in verdict §4. In this schema:
- **Collection status** lives in `collection.<source>.status` and in `provenance.evidence_sources`.
- **`NotEvaluated`** is `evaluation = "not_evaluated"` with `windows_policy = null`.
- **`Indeterminate`** is `windows_policy.verdict = "Indeterminate"` with `reasons`.

### 2.5 `checks`: what was and was not evaluated
```json
{"catalog_id": "FW-PROF-001", "status": "insufficient_evidence", "reasons": [{"code": "third_party_firewall:failed"}]}
{"catalog_id": "FW-RULE-002", "status": "finding_raised", "finding_refs": ["finding:fw-rule-002:h1-3f9c2a7b01d4e6a8"]}
{"catalog_id": "FW-RULE-005", "status": "condition_not_met", "reasons": []}
{"catalog_id": "FW-EXP-002",  "status": "not_evaluated", "reasons": [{"code": "catalog_entry_pending_review"}]}
```
- **`status`** is one of:
  - `finding_raised`;
  - `condition_not_met`: the condition was not found in complete evidence. It must never be shown as "safe" or "no problem";
  - `insufficient_evidence`: required evidence is not complete;
  - `not_evaluated`: the entry is pending or deferred, or out of scope.

### 2.6 CLI behaviour
- **Sequential collection.** `scan --json` collects through the existing services **sequentially** (SB-19).
- **Honest failure states.** A cancelled or failed source gives `partial`, `failed`, or `not_collected`. It never gives an invented value.
- **Exit codes.** Findings never change the exit code. Exit codes are aligned with the existing commands in M2.3.

## 3. Catalog evidence contracts (provisional v1: 9 entries; F1-10 still unmet)
| ID | Required evidence (all complete) | Result when evidence is not complete |
|---|---|---|
| FW-PROF-001 | Profile `enabled = false`; **successful** third-party detection showing no product; interface mapping showing the profile active | `insufficient_evidence` (third-party state is never assumed to be "none") |
| FW-PROF-002 | `default_inbound_action = allow`; the profile shown active by the mapping | `insufficient_evidence` |
| FW-PROF-003 | `log_blocked` | `insufficient_evidence` |
| FW-RULE-001 | Complete rule: inbound, allow, enabled, Public, program any, local port any, remote any | `insufficient_evidence` |
| FW-RULE-002 | Complete rule; ports 3389, 445, 5985, 5986, 22 (frozen); Public; remote any | `insufficient_evidence` |
| FW-RULE-004 | §3.1 | §3.1 |
| FW-RULE-005 | Complete rule; an `edge_traversal` value from a reviewed list of values that allow traversal | Unknown value → `insufficient_evidence` |
| FW-EXP-001 | A `PermittedByPolicy` `windows_policy` result from an **authorized** step, on Public, bound to all interfaces | No such result → `insufficient_evidence` |
| FW-AI-001 | Listener with a collected process image name equal to the documented Ollama binary name; non-loopback bind | Image unavailable → `insufficient_evidence`. Text: "listening on a non-loopback address", never "reachable" |

**Pending or deferred (not counted):**
- **FW-EXP-002** is pending. Before it can be approved, the human reviews its exact port and process list, its evidence requirements, its benign cases, and its false-positive risks (for example, development servers deliberately shared on a LAN, or reused ports).
- **FW-RULE-003** is deferred until a path-existence evidence contract exists.
- **FW-ENV-001** is deferred until an OS-version evidence contract exists.

**F1-10** (10 or more entries) **remains unmet**, at 9. No entry is invented to meet the count (M20-Q7).

### 3.1 FW-RULE-004: duplicate rules (M20-Q9)
- **Exact duplicate.** Two or more rules form an exact duplicate when **all** of the following are **collected and identical** after token normalization:
  - direction, action, enabled state, profiles;
  - `policy_source_type` (the policy origin);
  - all seven filters: application, service, security, port, address, interface type, interface;
  - edge traversal, owner presence, `local_only_mapping`, `loose_source_mapping`;
  - no dynamic keyword addresses.
- **Effective applicability.** If the rules are local-source and `allow_local_firewall_rules` is not `true` on every listed profile, whether the rules are effective is unknown. The check gives `insufficient_evidence`, not a confirmed duplicate.
- **Possible overlap** (filters that intersect but are not identical) is **not** a duplicate and is **not** a v0.1 finding, because it would need set arithmetic.
- **Incomplete evidence** for any rule in a group means no duplicate is reported for that group (`insufficient_evidence`).
- Display names and descriptions are **not** compared. They are untrusted and do not affect filtering.

## 4. Determinism and purity requirements (tests)
- **Same output:** the same snapshots and authorized-step set give the same `analysis` bytes. The test runs repeatedly and across processes with different `PYTHONHASHSEED` values.
- **No hidden inputs:** no wall clock, randomness, locale, environment variables, or file reads inside the engine. `%VAR%` expansion uses a mapping provided with the snapshot.
- **import-linter:** `core` never imports `ai`, `ui`, `collectors`, `subprocess`, or network modules.
- **Read-only:** the engine never calls the PowerShell runner (SB-19). This is tested with a runner that fails if it is invoked.
- **AI independence (SB-15):** results are the same with AI off, unavailable, or failing.

## 5. Fixture format and truth-table strategy
**Format: JSON** (decision S1 allows JSON or TOML).
- TOML has **no null**, while the evidence states depend on null being representable.
- `tomllib` cannot write, so recording fixtures would need a new dependency.
- The existing fake collectors already read JSON.

**Layout:** `tests/fixtures/verdicts/<id>.json`, schema `firewallai.verdict-fixture/1`:
```json
{
  "fixture_schema": "firewallai.verdict-fixture/1",
  "id": "p5-block-and-allow-any-scope",
  "description": "Complete Any-scope Block and Allow candidates for TCP 8080 on Public",
  "basis": ["S1:rule-2", "S2:priority-2"],
  "contract_version": "sb21/0-draft.2",
  "input": {
    "profiles": "…same shape as the fake profile collector fixtures…",
    "interfaces": [{"ref": "interface:h1-0000000000000f01", "addresses": ["192.0.2.10"], "type": "wired", "profile": "public"}],
    "third_party_firewall": {"status": "complete", "active_products": []},
    "rules": "…same shape as the fake rule collector fixtures…",
    "endpoints": "…same shape as the fake endpoint collector fixtures…"
  },
  "expect": {
    "no_steps_authorized": [{"subject": "…", "verdict": "Indeterminate", "reasons": ["PRECEDENCE_UNVERIFIED"], "deciding_step": "P5"}],
    "if_authorized": {"P5": [{"subject": "…", "verdict": "BlockedByPolicy", "deciding_step": "P5"}]}
  },
  "vm_observation": null
}
```
**Rules for fixtures:**
- **Hand-written expectations.** They are derived from the contract and reviewed by the human. They are never regenerated from engine output, and every change to an expectation is justified in the PR.
- **`no_steps_authorized` is mandatory** and describes today's state. `if_authorized` keys name single steps. A step's expectation is used only after the human authorizes that step. Authorization never changes a fixture's documentation or verification status.
- **`vm_observation` stays `null`** until the two-VM test produces a recorded observation. No fixture claims observed behaviour before then.
- **Synthetic data only.** Real captures go through the existing sanitizer and never into this folder.

### 5.1 Scenario list (42 scenarios; all expectations follow the verdict contract)
**Loopback, binding, and scope:**
1. A loopback IPv4 listener gives `LoopbackOnlyBinding`, with no rules evaluated and no finding, even when an Allow-Any rule exists.
2. An `::1` listener gives the same result.
3. An IPv4-mapped loopback listener gives the same result.
4. An unparseable bind address gives `BIND_ADDRESS_UNPARSEABLE`.
5. A specific-address bind is evaluated on its own interface only.
6. A link-local bind with a scope ID is evaluated on that interface only.
7. A UDP endpoint gives `not_evaluated` (`PROTOCOL_UDP_OUT_OF_SCOPE`), and its collection data stays in the snapshot.
8. A TCP connection-state endpoint gives `not_evaluated` (`ENDPOINT_NOT_LISTENING`).

**Incomplete evidence and collection states:**
9. An inventory-only scan gives `INCOMPLETE_RULE_EVIDENCE` (`detail:scan`).
10. A cancelled or timed-out detail phase gives the same result, with `collection.rules.status = partial`.
11. A failed profile collection gives `PROFILE_SETTINGS_UNAVAILABLE`, with `status = failed`.
12. Interfaces not collected give `INTERFACE_EVIDENCE_UNKNOWN`.
13. An incomplete candidate that is not excluded gives `INCOMPLETE_RULE_EVIDENCE` (`detail:rule`).
14. An incomplete rule excluded by its profile does not affect the result.
15. A missing filter is never treated as Any (SB-18 regression).

**Unsupported filters and uncertain applicability:**
16. A package-scoped candidate gives `UNSUPPORTED_FILTER`, and so does an owner-scoped one.
17. A local-port keyword (`RPC`) gives `UNSUPPORTED_FILTER`, but a port contradiction still excludes the rule.
18. A program-scoped candidate with the image unavailable gives `PROCESS_INFO_UNAVAILABLE`.
19. A service-scoped candidate on a multi-service host gives `UNSUPPORTED_FILTER`.
20. A process with collected services gives `SERVICE_HARDENING_UNKNOWN`. A fully identified non-service process is unaffected.
21. An SDDL user- or machine-scoped candidate gives `UNSUPPORTED_FILTER`.

**Precedence (dossiers P5, P6, P7):**
22. P5 positive, P5 contradictory (a bypass Allow; an uncollected security filter), and P5 negatives (verdict §10.1).
23. P6 positive, P6 contradictory (an incomplete Block; a remote-restricted Block; a secure Allow), and P6 negatives (verdict §10.2).
24. P7 positive, and P7 negatives and contradictions (verdict §10.3).
25. Default Allow plus a Block candidate gives `PRECEDENCE_UNVERIFIED`.
26. `AllowInboundRules=False` gives Indeterminate (P4a is not authorized).

**Remote scope (fixed quantifier):**
27. A `LocalSubnet`-only Allow with default Block gives `REMOTE_SCOPE_DEPENDENT`, with a remote-scope observation.
28. A remote-restricted Block plus an Any Allow gives `REMOTE_SCOPE_DEPENDENT`.
29. A remote-restricted Allow plus an Any Block gives `BlockedByPolicy` if P5 is authorized, because the restriction cannot change the outcome.
30. A remote-port-restricted Allow behaves like case 27.

**Profiles, Group Policy, and third parties:**
31. A disabled profile gives `PROFILE_DISABLED_UNKNOWN_ALT`.
32. A `not_configured` setting gives `PROFILE_SETTINGS_UNRESOLVED`. A `not_configured` merge flag gives `MERGE_SETTINGS_UNREADABLE`.
33. A local-source deciding rule with merge off gives `MERGE_BEHAVIOUR_UNVERIFIED`.
34. The same as case 33 with only `group_policy`-source candidates is evaluated normally.
35. An interface listed in `DisabledInterfaceAliases` gives `INTERFACE_EXCLUDED_FROM_PROFILE`.
36. An active third-party firewall keeps the `windows_policy` result with the qualifier `windows_firewall_enforcement_not_verified`, and `overall_filtering` lists `THIRD_PARTY_FIREWALL` (E2; if E2 is rejected, the result is Indeterminate).
37. A third-party state that is unknown leaves the `windows_policy` result unchanged, and `overall_filtering` lists `THIRD_PARTY_STATE_UNKNOWN`.
38. Two interfaces on different profiles give two records.

**Dual-stack:**
39. A `::` listener with dual-stack unknown gets IPv6 records plus IPv4 records with the qualifier `ipv4_acceptance_by_socket_unknown`. An IPv4 record equal to the IPv6 record on the same interface keeps its result.
40. The same listener with differing results, or with no IPv6 record on that interface, gives `DUAL_STACK_AMBIGUOUS` on the IPv4 record only. The IPv6 record is unchanged.
41. A remote-address restriction that names only IPv6 ranges still counts as a restriction on an IPv4 record (no address-set arithmetic), giving `REMOTE_SCOPE_DEPENDENT` where it could change the outcome.
42. A remote source-port restriction gives `REMOTE_SCOPE_DEPENDENT`. A local-port mismatch excludes the rule.

**Findings (in addition to the 42):**
- each entry has a positive case, a benign case, and an `insufficient_evidence` negative;
- FW-RULE-004 has an exact-duplicate case, a near-duplicate that differs only in profile (not a duplicate), and an incomplete-member case (not reported);
- the text lint and forbidden-claims tests run over every template and over the CLI JSON;
- a listener alone never produces a finding (F1-11).
