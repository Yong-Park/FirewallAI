# ADR 0024: Local-policy verdict contract (SB-21), finding contract, and `scan --json` schema

- **Status:** Proposed
- **Decision ID:** D24 (living index: [README.md](README.md))
- **Date:** 2026-10-15
- **Proposed by:** claude-code (M2.0, documentation only)
- **Decided by:** pending. On 2026-10-15 the human approved the general architecture for refinement only. That is **not** acceptance, and it does not authorize implementation.

## 1. Problem
Sprint 2 adds a deterministic engine that turns collected evidence into per-listener verdicts (F1-09) and catalog findings (F1-10). The main product risk is a wrong or overconfident result. A beginner could be told something is "blocked" or "allowed" when Windows behaves differently, or could read a result as a statement about the internet.

The constraints:
- **SB-18:** no verdict from incomplete evidence.
- **SB-19:** single-flight heavy queries.
- **SB-20:** correlation is descriptive only.
- **N-08:** no claims about external exposure.
- **ADR 0023:** beginner fields and evidence-honest status.
- **The approved Sprint 2 plan:** no generative AI, and every milestone is authorized separately.
- **The evidence available today:** Microsoft documentation describes rule precedence only partly, and nothing has been checked against real traffic. The two-VM test is open. The interface mapping and third-party detection do not exist yet (M2.1).

## 2. Decision (proposed)
1. **Adopt SB-21** as specified in [verdict-contract.md](../architecture/verdict-contract.md):
   - **Two layers.** A *Windows Firewall local configuration* result is kept strictly separate from *overall traffic filtering*, which is always `not_determined` in v0.1.
   - **One scenario** with fixed semantics: inbound, unsolicited, TCP only, **one address family**, one interface and profile, the endpoint's local destination port, and the remote quantifier "all remote addresses and ports". The quantifier ranges over every remote address **of the record's family** and every remote **source** port (verdict §3).
   - **Separate states.** `Indeterminate`, `NotEvaluated`, incomplete collection, and collection failure are distinct.
   - **Conservative matching.** Candidates are matched conservatively, and only enumerated collected contradictions exclude a rule.
   - **Decision steps.** Each step has a source and **three independent attributes**: documentation status, verification status (against real Windows traffic), and authorization status (human approval to use it in the evaluator). Documented never implies verified or authorized. **No step is verified or authorized.** A step that is not authorized can only give `Indeterminate` (verdict §9).
2. **Adopt the finding contract, the `firewallai.scan/1` schema, and the JSON fixture format** from [findings-contract.md](../architecture/findings-contract.md). They include the six ADR 0023 fields with complete technical evidence, per-source collection status and digests, per-verdict provenance and scope, a `checks` section, and deterministic output.
3. **Keep SB-20 unchanged and separate.** A "related" correlation result is never read as "applicable".
4. **Change no code.** M2.2 and M2.3 start only after this ADR is accepted, the relevant steps are authorized, and each milestone is separately authorized.

## 3. Alternatives considered
- **A fixed precedence order (planning 05 §3).** Rejected. Only an archived Windows 7 / Server 2008 R2 page states it, and nothing has been verified against real traffic.
- **A verdict that merges the Windows configuration with third-party and other layers.** Rejected (M20-Q3). It would either hide truthful Windows observations or overstate the overall effect.
- **A remote quantifier that varies between results ("from some address").** Rejected (M20-Q5). The meaning of Permitted would change silently.
- **Treating UDP like TCP.** Rejected for v0.1 (M20-Q4).
- **Authorizing P5, P6, and P7 straight away.** Rejected (M20-Q1). Each step needs a reviewed dossier and an explicit authorization decision.

## 4. Advantages and disadvantages
**Advantages:**
- Every result is traceable to evidence, a step, a source, and the step's documentation, verification, and authorization status.
- No result silently relies on documentation that has not been verified.
- Fixtures already contain the expectation for each step, so authorizing a step changes configuration, not tests.

**Disadvantages:**
- Until steps are authorized, every non-loopback TCP result is Indeterminate. This is honest, but less useful.
- The output needs careful wording (UX0 is a DRAFT and not usability-validated).

## 5. Security implications
- **Wrong certainty.** Mitigated by the unauthorized-by-default steps, the per-step dossiers, the exclusion list, and Indeterminate defaults.
- **Misleading wording.** Mitigated by:
  - the "never means" list;
  - the separate overall-filtering layer;
  - a schema without reachability or permitted-traffic fields;
  - the text lint;
  - "an Allow rule does not prove traffic is accepted" in every Allow-related explanation.
- **Untrusted strings** appear only as escaped data (SB-04).
- **No new privileges, queries, network access, or dependencies.** The engine is pure and read-only (SB-15, SB-19).
- **SR-M1.5-01.** The verdict inputs come from PowerShell NetSecurity output, so their integrity depends on module resolution. P0 (a separate design for approval) comes before M2.1. Until then, that risk applies to every result.

## 6. Performance implications
- Evaluation is expected to be small next to collection [ASSUMPTION; measured in M2.2].
- `scan --json` inherits N-04 (about 27–35 s against the 10 s target). The investigation is separate.

## 7. Validation
- **Fixtures:** about 40 truth-table fixtures (findings-contract §5.1). The expectations are reviewed by hand and given per step, plus the dossier fixtures for P5, P6, and P7.
- **Tests:** text lint, forbidden-claims tests, determinism, import-linter purity, and a runner that fails if the engine calls it.
- **Real-behaviour checks (all open and preserved):**
  - the two-VM test (planning 05 §5, planning 13), the only way to reach `vm-verified`;
  - a GPO VM for P3 and merge behaviour;
  - clean-VM tests;
  - Hyper-V availability is still pending.
- **Exit:** the human accepts this ADR, decides M20-Q1…Q9 and the errata E1–E5, and authorizes any steps one by one.

## 8. What the developer needs to learn
- Rule precedence:
  - [S1] https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/rules
  - [S2] https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/dd421709(v=ws.10)
- Profile settings and policy stores: [S3] https://learn.microsoft.com/en-us/powershell/module/netsecurity/set-netfirewallprofile
- IPsec authenticated bypass, Windows Service Hardening, and the Windows Filtering Platform: to study before the VM test.

## 9. Decisions (human direction, 2026-10-15; still Proposed)
| ID | Human direction | How the contract implements it | Still open |
|---|---|---|---|
| **M20-Q1** Verdicts before VM verification | Conditionally approved in principle. P5, P6, and P7 are **not** authorized automatically | No step is authorized, and none is verified. Each of P5, P6, and P7 has a dossier (verdict §10): the documentation, required fields and completeness, how competing rules are excluded, the inputs that force Indeterminate, the negative and contradictory fixtures, and what is still unverified. P4a and P7a are not proposed for v0.1 | The human decides, per step, whether to authorize it |
| **M20-Q2** Loopback label | Approved to propose `LoopbackOnlyBinding` | Erratum E1 with a migration strategy (verdict §16). Frozen documents are unchanged until approval | Approval of E1 |
| **M20-Q3** Third-party firewall | An unknown state must not support conclusions about overall filtering; Windows observations are kept | `overall_filtering` is always `not_determined`, and `THIRD_PARTY_STATE_UNKNOWN` appears only there. Erratum E2 moves `THIRD_PARTY_FIREWALL` there too | Approval of E2 (otherwise the frozen behaviour applies) |
| **M20-Q4** UDP | Approved: excluded from the evaluator; collection stays | `evaluation = not_evaluated` with `PROTOCOL_UDP_OUT_OF_SCOPE` (erratum E3: a record state, not a fifth verdict value) | Approval of E3 |
| **M20-Q5** Remote restrictions | No address-set arithmetic; state the quantifier | A fixed quantifier, `all_remote_addresses_and_ports`, applied per record address family and over all remote source ports. Results that depend on the remote address or port are Indeterminate (`REMOTE_SCOPE_DEPENDENT`), with descriptive observations (E4) | Approval of E4 |
| **M20-Q6** Service hosts | Indeterminate only when the service identity or applicability is unreliable; no broader rule | Verdict §11. Fully identified processes with no services are unaffected | [VERIFY] Windows Service Hardening semantics |
| **M20-Q7** Catalog | Nine entries stay provisional; FW-EXP-002 stays pending; F1-10 stays unmet | Findings-contract §3. Nothing is invented | Review of FW-EXP-002 (port/process list, evidence, benign cases, false positives) |
| **M20-Q8** Reason codes | Proposed codes stay pending compatibility review | Verdict §13 maps each code to its meaning, trigger, overlap, beginner text, and JSON. **13 were consolidated to 11** to remove overlaps | Compatibility review |
| **M20-Q9** Duplicate rules | Not by filter values alone; exact duplicates are separate from possible overlaps; no confirmed duplicate from incomplete evidence | Findings-contract §3.1 | — |

**Errata proposals E1–E5** (verdict §16) need explicit approval. Nothing in `docs/planning/` has been changed.

## Dependencies (not decided here)
- **SR-M1.5-01 (P0):** a prerequisite for M2.1. The design is for separate approval (Sprint 2 plan §7.2).
- **VM validation:** every requirement is preserved, and any schedule change would only be proposed to the human.
- **M2.1:** interface mapping and third-party detection are needed for any non-loopback result other than Indeterminate.

## Open items
- [VERIFY] whether the [S2] order holds on Windows 10/11.
- [VERIFY] whether the ActiveStore lists ignored local rules when merge is off, and Windows Service Hardening restrictions.
- [VERIFY] the meaning of `not_configured` in the ActiveStore.
- [VERIFY] the effect of `DisabledInterfaceAliases`.
- [VERIFY] the interplay of `AllowInboundRules=False` with bypass rules.
- [VERIFY] default Allow combined with a Block rule.
- [VERIFY] the raw tokens for "no IPsec requirement".
- [VERIFY] Windows Service Hardening semantics.
- [NEEDS PROTOTYPE] the two-VM real-behaviour test.
