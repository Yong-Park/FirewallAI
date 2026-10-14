# ADR 0021: Hybrid AI orchestration: Python-orchestrated tasks, local-first, optional cloud (v0.2+)

- **Status:** Accepted as the **architectural direction for v0.2+**. Implementation details that depend on benchmarks or prototypes remain **pending** (see "Pending items" at the end).
- **Decision ID:** D21 · **Date:** 2026-10-14 · **Proposed by:** human requirement (architecture direction), drafted by claude-code · **Decided by:** human, 2026-10-14
- **Human decisions recorded at acceptance (2026-10-14):**
  1. "Accept ADR 0021 as the future architectural direction for v0.2+, while keeping implementation details that require benchmarks or prototypes explicitly pending."
  2. "Host-sensitive data must NEVER have standing cloud-upload permission. Require per-request authorization showing the exact payload and destination provider. No automatic cloud fallback."
  3. "Start with a single-model workflow. Specialized agents should only be introduced if reproducible benchmarks demonstrate at least a 15% improvement in an agreed quality metric, without regressions in security, correctness, or privacy. The benchmark methodology and acceptable overhead must be defined before evaluation."
  4. Clarification: "AI agents must not have arbitrary shell, filesystem, privileged, or network tools. Explicitly approved cloud provider requests may use a restricted provider adapter with allowlisted endpoints and user consent."
- **Relationship:**
  - Extends [ADR 0002](0002-local-first-ai-ollama.md) (Accepted). Ollama stays the default. This ADR names **Groq** as a second optional cloud provider next to Gemini.
  - Depends on [ADR 0003](0003-ai-in-v0-2.md) (Accepted). No AI ships in v0.1.
  - Builds on the secure-AI design in [09-ai-integration.md](../planning/09-ai-integration.md) and the threat model in [07](../planning/07-security-model.md) (T7–T10). Neither document is modified.
- **v0.1 impact:** none to scope. v0.1 stays deterministic, read-only, and has zero network access. §9 lists only *design-for* considerations for Sprint 1 interfaces.

## 1. Problem

From v0.2, FirewallAI wants AI help with several distinct jobs: explaining findings, retrieving standards references, deeper reasoning about rule interactions, and drafting report text. These jobs differ in context size, reasoning depth, and data sensitivity. Some users have a capable local GPU, some don't, and some will accept cloud processing for some data.

Three questions follow:
- how to coordinate these jobs without giving an LLM control of the application;
- how to use optional cloud providers without leaking host data;
- how to avoid multi-agent complexity that doesn't pay for itself.

Human requirements (2026-10-14):
1. Python is the deterministic orchestrator. No LLM has unrestricted control.
2. Ollama stays the default.
3. Gemini and Groq are optional cloud providers, subject to configuration, explicit consent, and quotas.
4. Specialized agents *may* handle analysis, standards retrieval, advanced reasoning, and reporting.
5. Structured outputs, schema validation, strict tool permissions, execution limits, and auditable results.
6. No autonomous firewall changes by an LLM.
7. Detection and future enforcement work without AI.
8. No sensitive host data goes to the cloud without explicit authorization.
9. Offline operation and graceful fallback.
10. Compare a simple single-model workflow with specialized agents before choosing.

## 2. What the existing architecture already covers

| # | Requirement | Already covered by | Gap |
|---|---|---|---|
| 1 | Python orchestrates; no LLM control | 09 §1 (AI explains only), 09 §6 (no side-effect tools), `app` service layer ([module-map](../architecture/module-map.md)), SB-06 | No explicit **orchestrator / task-runner** component; multi-step flows not specified |
| 2 | Ollama default | ADR 0002 (Accepted), SB-07 | None |
| 3 | Gemini/Groq optional, consent, quotas | ADR 0002 and 09 §5 cover Gemini and a generic OpenAI-compatible cloud provider, off by default, with consent and keys in Credential Manager | **Groq not named**; **no quota or rate-limit handling**; consent is per send, not per data class |
| 4 | Specialized agents | — | Not addressed. Single advisor only |
| 5 | Structured outputs, validation, tool permissions, limits, audit | 09 §6 (schema + validator), 09 §7 (eval), `ai_interactions` table (08), LLM10 limits | **Per-task tool allowlists** and **step/tool-call budgets** not specified |
| 6 | No autonomous firewall changes | SB-10, 07 §2 (typed proposals only, human approval), import-linter contract (`ai` cannot reach privileged code) | None |
| 7 | Detection/enforcement independent of AI | SB-12 (LLM never in the packet path), ADR 0003 (deterministic v0.1), 12 §1 | Not stated as a general invariant for detection |
| 8 | No sensitive data to the cloud without authorization | SB-07, 09 §6 (consent dialog showing payload, redaction), T10 | No **data-sensitivity classification** that decides what may leave the machine |
| 9 | Offline and graceful fallback | AI optional (02 N-14), v0.1 offline | **Fallback chain** not specified |
| 10 | Compare simple vs. multi-agent | — | Not addressed |

**Conclusion:** the security core (AI explains only, validator, no write path, consent, loopback default) is already in place. The gaps are orchestration structure, cloud-provider policy (Groq, quotas, data classes), the fallback chain, and the single-model vs. multi-agent decision.

## 3. Options considered

### Option A: single-model task pipeline
One configured model. Python runs fixed task types: `explain_finding`, `summarize_scan`, `draft_report_section`, `lookup_references`. Each task has its own prompt template, output schema, and limits, and runs as **one model call** (or one retrieval followed by one model call).
- **Pros:** simplest; easy to test, evaluate, and audit; lowest latency and quota use; works on modest local hardware with one loaded model.
- **Cons:** one model must be good at everything. Larger context needs can't be routed to a stronger model.

### Option B: specialized agents (role-based), orchestrated by Python
Separate "agents" (Security Analyst, Standards Retriever, Reasoner, Report Writer). Each has its own model choice, prompt, tool allowlist, and budget. A Python state machine sequences them, for example: retrieve → analyze → write → validate.
- **Pros:** the right model for each job (small local model for retrieval and formatting, stronger model for reasoning); narrower tool permissions per role; clearer per-role evaluation.
- **Cons:**
  - More calls, so more latency and more quota use.
  - Errors compound across steps.
  - More prompts to maintain and evaluate.
  - Several local models may compete for VRAM.
  - More components in the audit trail.
  - Inter-agent data passing can **carry prompt injection** from one step into the next.

### Option C: LLM-driven orchestration (autonomous agent loop or planner)
An LLM decides which tools or agents to call and when it is done.
- **Rejected.** It violates requirement 1, makes behavior non-deterministic and hard to audit, and maps directly to OWASP LLM06 (Excessive Agency). P_proyect's tool-calling loop is the pattern being avoided.

## 4. Decision (proposed)

**Adopt Option A as the default implementation. Design it so Option B becomes a configuration of the same machinery, enabled only when the evaluation shows it pays off.**

Concretely:
1. **"Agents" are declarative task profiles, not autonomous actors.** A `TaskSpec` holds: task ID, prompt template version, input schema, output schema, allowed read-only tools, model requirements, data-sensitivity ceiling, budgets (max tokens, timeout, max steps, max tool calls), and allowed providers. A role-based "agent" in Option B is just a set of TaskSpecs that may name different models.
2. **The Python `TaskRunner` is the only orchestrator.**
   - Flows are fixed, versioned sequences written in Python.
   - No LLM chooses the next step, adds steps, or calls another agent.
   - Data between steps passes as **validated structured objects**, never as free text, and is re-validated at every step boundary.
3. **Tools are read-only and allowlisted per task.**
   - The AI tool registry contains only lookups: snapshot entities by ID, the reference registry, and retrieved documents.
   - The registry **has no arbitrary shell, file-system, privileged, or network tools at all**, so a misconfigured allowlist still can't produce a side effect.
   - Tool calls count against the task budget.
   - **The provider adapter is not a tool.** It is Python transport code that the `TaskRunner` calls, never the model. Cloud adapters may contact only **allowlisted endpoints** for the specific enabled provider (fixed scheme and host, no redirects to other hosts). They are used only for requests the user explicitly approved under §5. The model can't choose a URL, host, or provider.
4. **ProviderRouter (deterministic policy)** selects a provider for each task:
   - The default and preferred provider is **Ollama on loopback**.
   - A cloud provider (Gemini, Groq) is used only if *all* of these hold:
     - (a) the user enabled that provider and stored a key;
     - (b) the task's data-sensitivity ceiling allows cloud processing;
     - (c) the user has given consent covering this data class and provider (§5);
     - (d) the local quota tracker says budget remains;
     - (e) the provider meets the task's model requirements (e.g. strict structured output).
   - The router never escalates to the cloud silently. If local fails, the user sees the fallback (§6) and may *choose* cloud for that request.
5. **Every AI result is advisory and validated.** Validation includes schema, evidence-ID existence, citation existence, and proposals that are typed and non-widening (09 §6). Each result is stored in `ai_interactions` with provider, model, digest when available, prompt-template version, TaskSpec version, consent ID, token usage, and validation status.
6. **AI cannot change anything.** Firewall changes remain typed proposals that require explicit human approval through the v0.4 flow (SB-10). Detection, findings, verdicts, and any future enforcement run entirely without AI (§7).

**Gate to enable Option B (specialized agents), decided by the human 2026-10-14.** Single-model (Option A) is the default. A specialized-agent flow may be introduced only if **all** of these hold:
1. **Methodology defined first.** Before any evaluation run, a written benchmark protocol is approved by the human and committed. It names:
   - the **agreed primary quality metric** (candidates: validated-output rate, factual-error rate on the golden set, citation validity);
   - the golden-set and injection-corpus versions;
   - the models and hardware (TE-1 and a CPU-only VM);
   - the number of repeated runs and seeds/temperature;
   - the statistical treatment;
   - the **acceptable overhead** limits (latency, token/quota use, peak RAM/VRAM).
2. **Reproducible:** the results can be re-run from the committed protocol and recorded raw data.
3. **≥ 15% improvement** in the agreed primary metric over the Option A baseline [the protocol defines whether this is relative or absolute; human to confirm].
4. **No regressions** in security (injection success rate, data-class violations), correctness (hallucinated-ID rate after validation), or privacy (no extra data leaving the machine), and overhead within the pre-agreed limits.

Without that evidence, FirewallAI stays on Option A.

## 5. Data sensitivity classes and cloud consent

| Class | Examples | Local (Ollama) | Cloud (Gemini/Groq) |
|---|---|---|---|
| `PUBLIC_REFERENCE` | Public standards text, generic security concepts, catalog descriptions | Yes | Yes, once the provider is enabled |
| `DERIVED_ABSTRACT` | A finding type plus redacted context, e.g. "inbound allow, any port, Public profile, remote scope Any", with no names, paths, IPs, or hostnames | Yes | Only with explicit consent for this class and provider |
| `HOST_SENSITIVE` | Rule names and descriptions, process paths, usernames, hostnames, IP/MAC addresses, service lists, full snapshots | Yes | **Never by default and never as a standing permission** (human decision, 2026-10-14). Each upload needs **per-request** explicit authorization that shows the **exact payload and the destination provider**. The approval covers that one request only and isn't remembered |

- The class of each field is declared on the data models (§9) and used for **mechanical redaction**, so it doesn't depend on prompt wording.
- The payload preview shows exactly what would leave the machine, after redaction.
- Consent records (`consents` table) store the provider, data class, scope, and payload hash.
  - Scope may be "session" only for `DERIVED_ABSTRACT`.
  - `HOST_SENSITIVE` consent is always `single_request` and is bound to the payload hash and destination provider (SB-16).

## 6. Offline operation and fallback chain

```
task requested
  → local Ollama available and model meets TaskSpec? → run locally
  → else: deterministic fallback (catalog explanation text, rule-based summary,
          template report section) clearly labeled "AI unavailable – standard text"
  → user may explicitly choose an enabled cloud provider for this request
          (only if data class + consent + quota allow)
  → cloud quota exhausted / rate-limited / offline → deterministic fallback, never a retry loop
```
- **There is no automatic cloud fallback** (human decision, 2026-10-14). When local AI fails, the result is deterministic text. Cloud use always starts with an explicit user action for that request.
- Scans, findings, verdicts, reports, and (later) monitoring and enforcement **never wait on AI**. AI enrichment runs asynchronously after deterministic results already exist.
- Rate-limit responses (HTTP 429) → limited backoff within the task budget, then fallback.
- Quota counters are tracked locally per provider and per day. Provider consoles remain authoritative.

## 7. Independence of detection and enforcement (proposed invariant)

Added to [security-boundaries.md](../architecture/security-boundaries.md) on acceptance (2026-10-14), together with SB-16 and SB-17 for the cloud-data and tool rules:

> **SB-15:** Detection (collection, verdicts, findings, alerts) and any enforcement (v0.4+ changes, v0.5+ blocking) must produce identical outcomes whether AI is enabled, disabled, unavailable, slow, or returning invalid output. AI output is never an input to a detection or enforcement decision.

## 8. Provider notes (verified 2026-10-14; terms change, re-verify before v0.2)

| Provider | Role | Data handling (official source) | Structured output | Quotas |
|---|---|---|---|---|
| **Ollama** (local) | Default | Stays on the machine. Loopback API has no authentication (T9) | `format` JSON schema (since Ollama 0.5) | Local hardware only |
| **Gemini API** (optional) | Cloud | **Unpaid tier:** content may be used to improve Google products, and human reviewers may read it. Google advises not to submit sensitive data. Paid tier: not used for improvement. EEA, Switzerland, and the UK get paid-tier data terms ([terms](https://ai.google.dev/gemini-api/terms)) | JSON schema supported [VERIFY current API details at v0.2] | Free-tier limits vary by model and change. Read from the provider console |
| **Groq** (optional) | Cloud, OpenAI-compatible API | By default inference data is not retained. Logs for reliability or abuse may be kept up to 30 days. **Zero Data Retention can be enabled self-serve** in Data Controls ([Groq: Your Data](https://console.groq.com/docs/your-data)). Training use is not stated on that page [VERIFY in Groq's terms] | `json_schema` with `strict: true` only on some models. Not combinable with streaming or tool use ([Groq structured outputs](https://console.groq.com/docs/structured-outputs)) | Per-organization, per-model RPM/RPD/TPM/TPD limits. The console's Limits page is authoritative. Third-party figures conflict |

- Implications:
  - Even with consent, `HOST_SENSITIVE` data should not go to the **Gemini unpaid tier**. The UI must state this.
  - For Groq, the docs recommend enabling ZDR and say how.
- Groq is implemented through the existing `OpenAICompatibleCloudProvider` (09 §2), with provider-specific capability metadata. No new provider type is needed.

## 9. Implications for Sprint 1 interfaces (design-for only; no AI code)

These are cheap to do now and expensive to retrofit. **None of them add AI functionality, dependencies, or network access to v0.1.**

1. **Stable, typed IDs for every entity** (rule, endpoint, process, finding, verdict) in `core` models. The AI validator checks `evidence_refs` against these later, and reports and diffs need them anyway.
2. **Data-sensitivity metadata on model fields.** Example: `Field(json_schema_extra={"sensitivity": "host_sensitive"})` on rule names and descriptions, paths, hostnames, IPs, and usernames. v0.1 uses it immediately for **report redaction** (US-08). v0.2 reuses it for cloud gating.
3. **Findings carry deterministic explanation text** (catalog "why it matters", "when benign", recommendation). This is the AI-unavailable fallback, and it already exists in the catalog design (05 §6).
4. **The `app` scan pipeline must not need an AI hook to finish.** Design `ScanService` so that post-scan enrichers *could* be added later as optional, asynchronous consumers of a completed `ScanResult`. In v0.1 there are none.
5. **Keep the import-linter contracts.** `core`, `collectors`, and `storage` must never import `ai`. The `ai` package must never import privileged or write paths.
6. **The settings schema reserves an `ai.*` namespace** (enabled providers, data-class consents, budgets) with **no secrets** in settings. Keys go to Credential Manager. In v0.1 only the schema reservation is needed, if any.
7. **The SecurityDocs `AIInterpretation` block** already exists (10 §2) and stays unused in v0.1.
8. **The zero-egress test (SB-05) stays** in v0.1. In v0.2 it becomes an allowlist test: loopback Ollama plus explicitly enabled provider hosts only.

The detailed interface sketch is recorded in [interfaces.md](../architecture/interfaces.md#ai-task-orchestration-v02-adr-0021).

## 10. Advantages and disadvantages
- **Advantages:**
  - Deterministic control; one execution path to secure and audit.
  - Simplest default; multi-agent only on evidence.
  - Clear rules for what can leave the machine.
  - Offline-first, with graceful degradation.
  - Groq fits without a new provider type.
- **Disadvantages:**
  - The data-class model adds engineering and UI work.
  - Deterministic flows are less flexible than autonomous agents (intentional).
  - Quota tracking is approximate; provider consoles are the source of truth.
  - Option B may never be justified, so some flexibility goes unused.

## 11. Security implications
- **OWASP Top 10 for LLM Applications 2025 mapping:**
  - LLM01 (prompt injection): untrusted data in typed fields; structured hand-off between steps.
  - LLM02 (sensitive info disclosure): data classes, redaction, consent.
  - LLM05 (improper output handling): validator.
  - LLM06 (excessive agency): no LLM orchestration; tool registry has no write tools.
  - LLM09 (misinformation): evidence and citation checks.
  - LLM10 (unbounded consumption): budgets and quotas.
- **New risk: multi-step injection propagation (Option B).** Mitigated by re-validating structured objects at each step and never forwarding raw model text as instructions.
- **New risk: cloud key exposure.** Mitigated by Credential Manager, gitleaks, and no keys in logs or settings (SB-08).
- **New risk: provider-terms drift.** Mitigated by a provider metadata file with a `verified_on` date, and a UI warning when it is older than N days.
- **Threat model update when v0.2 starts:** add T18 (cross-step injection) and T19 (quota/rate-limit denial of service against AI features), and extend T10 (Groq).

## 12. Performance implications
- Option A: one call per task. Latency equals one model response.
- Option B: N calls, so roughly N× latency and quota.
- Locally, multiple model sizes can force model swaps (load and unload) on limited VRAM, as on TE-1 with 10 GB [NEEDS PROTOTYPE].
- Cloud reduces local load but adds network latency and quota limits.
- Enrichment runs asynchronously, so it never delays scan results.

## 13. Validation
1. **v0.2 eval harness:** first, write and get approval for the benchmark protocol (§4 gate, item 1). Then compare the Option A baseline with at least one Option B flow (e.g. retrieve → explain) on the golden set and the injection corpus, recording metrics, latency, and token or quota use on TE-1 and a CPU-only VM. Option B is enabled only if the ≥ 15% / no-regression gate is met, and the human confirms it.
2. **Consent and data-class tests:**
   - `HOST_SENSITIVE` fields never appear in a cloud request without per-request authorization (unit and integration tests with a fake provider);
   - the payload preview matches the bytes sent.
3. **Fallback tests:** Ollama down, model missing, cloud 429, cloud offline, invalid JSON. Each must give deterministic fallback text with no retry storm, and scan results must be unaffected.
4. **Independence test (SB-15):** findings and verdicts are identical with AI enabled, disabled, or failing.
5. **Network allowlist test (v0.2):** only loopback plus enabled provider hosts are contacted.

## 14. What the developer needs to learn
- Agent design patterns and their failure modes (planner loops vs. fixed pipelines).
- Structured/constrained decoding.
- Data classification and redaction.
- Consent UX.
- Rate limiting and backoff.
- Evaluating multi-step LLM systems.
- OWASP LLM Top 10 2025.

## Pending items (implementation details not decided by this acceptance)
- [PENDING: protocol] The benchmark protocol for the Option B gate: primary metric, whether 15% is relative or absolute, run count, statistics, and overhead limits. It must be written and human-approved **before** any evaluation (§4).
- [NEEDS PROTOTYPE] Single-model baseline quality and latency on TE-1 and a CPU-only VM (v0.2 eval harness).
- [NEEDS PROTOTYPE] VRAM model-swapping cost on TE-1 for Option B with two local models.
- [NEEDS PROTOTYPE] Consent and payload-preview UX for per-request `HOST_SENSITIVE` uploads.
- [VERIFY] Groq's training-use statement (terms of service) and current ZDR behavior, at v0.2 start.
- [VERIFY] Gemini structured-output parameters and current free-tier limits, at v0.2 start.
- [VERIFY] The exact endpoint allowlists (hosts and paths) for each cloud provider adapter, at v0.2 start.
- The default local model choice remains in [ADR 0004](0004-default-local-model.md) (pending).

**Resolved at acceptance:** the `HOST_SENSITIVE` policy (§5), no automatic cloud fallback (§6), the Option B gate threshold and conditions (§4), and the tool/adapter boundary (§4 item 3).
