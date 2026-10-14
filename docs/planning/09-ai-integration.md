# 09: AI Integration, Privacy, and Secure AI Engineering

Status: Approved plan rev. 3, frozen snapshot. Covers deliverable (11) and rev. 2 requirements §1 and §8. Implementation target: **v0.2**. Decisions: [ADR 0002](../adr/0002-local-first-ai-ollama.md), [0003](../adr/0003-ai-in-v0-2.md), [0004](../adr/0004-default-local-model.md).

## 1. Role of the AI

**The AI advises and explains. It is never the final authority and never acts.**

| AI may | AI may not |
|---|---|
| Explain a finding in plain language | Discover or invent findings, measurements, or vulnerabilities |
| Describe consequences and tradeoffs of allow/block | Execute commands or call any tool with side effects |
| Suggest least-privilege alternatives as **typed proposals** | Produce executable commands; approve changes |
| State assumptions and missing evidence | Cite references that aren't in the local registry |
| Summarize reports, with output labeled "AI-generated" | Run in any real-time connection-decision path |

## 2. Provider architecture

```
LLMProvider (Protocol)
├─ OllamaProvider                  default; loopback http://127.0.0.1:11434
├─ OpenAICompatibleLocalProvider   LM Studio / llama.cpp server (loopback)
├─ GeminiProvider                  optional, OFF by default, BYO key
└─ OpenAICompatibleCloudProvider   optional, OFF by default, BYO key
```
Interface: [../architecture/interfaces.md](../architecture/interfaces.md).

**Reuse from P_proyect** (`modules/llm_client.py`, rewritten with types and tests):
- The `/api/tags` probe, the installed-model list, and `name:tag` matching.
- `keep_alive`, streaming chat, and role-based models (`chat`, `embed`).
- Rules first, with the LLM as optional enrichment.

**Deliberately not reused:**
| P_proyect behavior | Why not |
|---|---|
| Silent fallback to the first installed model | Could pick a vision or abliterated model |
| Host from an environment variable without validation | Exfiltration risk |
| Unbounded `urllib` reads | Memory exhaustion |
| Tool-executing chat loop | Excessive agency (LLM06) |
| Offensive-security system prompt | Wrong posture for a defensive tool |
| OWASP LLM Top 10 **2023** list | Superseded by the 2025 edition |

## 3. Ollama detection and guided setup

1. Probe `GET /api/version` on the configured endpoint (2 s timeout). For reference, the dev machine reported `{"version":"0.34.4"}` on 2026-10-14.
2. If there is no response, check the default install location (`%LOCALAPPDATA%\Programs\Ollama\ollama.exe`, observed on the dev machine).
   - Installed but not running: tell the user to start Ollama.
   - Not installed: show a guided screen with a link to the official download page. **Never download or execute installers automatically.**
3. `GET /api/tags` lists installed models. `POST /api/show` returns details (family, parameter size, quantization, context length, license, digest).
4. Model picker:
   - The user picks a model explicitly.
   - A capability check runs a tiny structured-output test with the `format` JSON schema, available since Ollama 0.5 ([Ollama blog](https://ollama.com/blog/structured-outputs)).
   - Vision-only and embedding-only models are rejected for chat.
   - Abliterated (safety-removed) models trigger a warning.
5. Pull a new model only on user request, via `POST /api/pull` with streamed progress. Show the size and license before downloading.
6. Embeddings (v0.3 RAG): `nomic-embed-text` (already installed) via `/api/embed`. That endpoint superseded `/api/embeddings` [VERIFY in official Ollama API docs].

**Endpoint policy:** loopback only by default. A non-loopback endpoint needs an explicit settings override and shows a persistent warning.

## 4. Model guidance (to be benchmarked)

| Hardware | Suggested size | Examples (license [VERIFY] before recommending) |
|---|---|---|
| GPU with ≥ 8 GB VRAM | 7–8B Q4_K_M (about 4.5–5 GB) | `qwen2.5:7b-instruct` (Apache-2.0), Llama 3.1 8B (Llama Community License) |
| GPU with 4–6 GB VRAM, or a strong CPU | 3–4B | Phi-4-mini (MIT [VERIFY]), Llama 3.2 3B |
| CPU only, 16 GB RAM | 3–4B at Q4 | same as above; slow, so set expectations |
| Not recommended as default | — | Qwen2.5-3B/72B (Qwen-specific licenses), any `abliterated` model |

**Quantization basics to document:**
- GGUF Q4_K_M is a common quality/size balance.
- IQ3 trades quality for size.
- A model larger than VRAM partially offloads to CPU and runs much slower. For example, a 13 GB model on a 10 GB GPU, as in test environment TE-1.

The hardware table above is **draft guidance to be validated by benchmarks**, not a set of minimum product requirements. The v0.1 auditor has no GPU requirement, and AI is optional.

**Benchmark plan** [NEEDS PROTOTYPE]: for each candidate on test environment TE-1 (the development machine, [13 §4](13-testing-strategy.md)) and on a CPU-only VM, measure time to first token, tokens/s, peak RAM and VRAM, schema-valid %, hallucinated-ID rate, and latency for a typical "explain finding" request.

**Licensing:**
- FirewallAI never redistributes weights. Ollama downloads them, and the license is shown before every pull.
- Qwen2.5: all sizes are Apache-2.0 except 3B and 72B ([Ollama qwen2.5 page](https://ollama.com/library/qwen2.5)).

## 5. Optional cloud providers

- **Gemini API:**
  - Free ("unpaid") usage may be used by Google to improve products, and human reviewers may read inputs and outputs. Google says not to submit sensitive or personal information to unpaid services.
  - Paid usage is not used for product improvement.
  - In the EEA, Switzerland, and the UK, the paid-service data terms apply to all services.
  - Source: [Gemini API Additional Terms](https://ai.google.dev/gemini-api/terms). Rate limits and model availability change, so the docs link to the live pages instead of copying numbers.
- **Other OpenAI-compatible services:** many have free tiers with changing terms. FirewallAI treats them all the same way: off by default, bring your own key, consent required, redaction applied.
- Keys are stored only in Windows Credential Manager (via `keyring`). Never in a file, the database, or logs.

## 6. Secure AI engineering

**Input construction:**
- System instructions are constant.
- The evidence bundle is a JSON object. Untrusted strings sit in data fields, are never concatenated into instructions, and are length-capped.
- The system prompt tells the model that data fields may contain adversarial text and must not be followed.

**Output schema** (pydantic, exported as JSON schema to `format`):
```
summary: str
explanation: str
evidence_refs: list[EvidenceRef]      # must exist in snapshot
assumptions: list[str]
missing_evidence: list[str]
confidence: Literal["low","medium","high"]
citations: list[ReferenceId]          # must exist in registry
proposed_changes: list[TypedOperationProposal]  # optional, proposals only
```

**Deterministic validator.** It rejects:
- unknown evidence references;
- findings that the snapshot doesn't contain;
- unknown citations;
- proposals that widen access or touch protected connectivity;
- oversized output.

On failure the UI shows "AI response failed validation". There is no silent repair.

**Further rules:**
- **No tools with side effects.** The `ai` package cannot import collectors' write paths or privileged code (import-linter).
- **Labeling:** every AI block shows "AI-generated", the model name and digest, and a timestamp. Reports keep it in a separate `AIInterpretation` section.
- **Privacy controls:**
  - AI is off until enabled.
  - Local endpoints still go through redaction settings.
  - Cloud sends require a consent dialog that shows the exact redacted payload.
  - A consent record is stored.
- **Resource limits:** timeouts, max tokens, response size caps, and one request at a time per finding (LLM10, Unbounded Consumption).

## 7. Evaluation harness

- A **golden set** of about 30 findings with expected properties (required references, required uncertainty statements, prohibited claims).
- An **injection corpus**: rule names, descriptions, and process names containing instructions, fake citations, or fake findings.
- **Metrics:** schema-valid %, hallucinated-ID rate (before and after the validator), citation validity, whether uncertainty is stated, and how often an injection succeeds.
- **CI:** runs offline against recorded responses. **Local:** live runs, with results logged together with the model digest and date. Only executed runs are reported.

## 8. Reusability

`firewallai.ai` has no FirewallAI-specific imports ([ADR 0013](../adr/0013-shared-package-extraction.md)). The provider layer, redaction, consent, validator, and eval harness are written to work with any domain schema, so SentinelAI or SecureCode AI could use them later.

## 9. What to learn
- LLM inference basics: tokens, context, sampling.
- Quantization, structured or grammar-constrained decoding, embeddings, and RAG.
- Prompt injection and the OWASP Top 10 for LLM Applications 2025.
- Evaluation design for non-deterministic systems.
