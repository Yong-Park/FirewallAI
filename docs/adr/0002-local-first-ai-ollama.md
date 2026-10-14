# ADR 0002: Local-first AI with Ollama as the default provider

- **Status:** Accepted. Explicit human requirement (rev. 2 feedback, 2026-10-14): "Make Ollama the default AI backend", "No mandatory API subscriptions, cloud accounts, or per-token charges", "Keep the architecture provider-agnostic".
- **Decision ID:** D2 · **Date:** 2026-10-14 · **Proposed by:** human requirement, drafted by claude-code · **Decided by:** human, 2026-10-14
- **Still pending inside this decision:** the model benchmark ([NEEDS PROTOTYPE], §6) and the default model choice ([ADR 0004](0004-default-local-model.md)).

## 1. Problem
FirewallAI must not depend on paid AI APIs. The AI features have to work offline, and sensitive host data must stay on the machine by default.

## 2. Decision (recommended)
- A provider-agnostic `LLMProvider` interface. **`OllamaProvider` is the default**, on a loopback endpoint (`http://127.0.0.1:11434`).
- Optional providers: `OpenAICompatibleLocalProvider` (LM Studio, llama.cpp server), plus optional cloud providers (Gemini, a generic OpenAI-compatible service). Cloud providers ship **disabled**. They are bring-your-own-key, with the key stored in Windows Credential Manager, and every send needs consent and redaction.
- The firewall audit works fully with AI turned off.
- Details: [09-ai-integration.md](../planning/09-ai-integration.md).

## 3. Alternatives considered
- **A paid cloud API by default.** Rejected because of cost, privacy, and the offline requirement.
- **Embedding llama.cpp or llama-cpp-python inside the app.** Rejected: huge installer, GPU/driver complexity, and duplicated model storage. Ollama already manages the models.
- **Gemini free tier as the default.** Rejected. Under Google's terms, content submitted to unpaid services may be used to improve Google products and may be read by human reviewers ([Gemini API Additional Terms](https://ai.google.dev/gemini-api/terms)). In the EEA, Switzerland, and the UK, the paid-service data terms apply to all services.

## 4. Advantages and disadvantages
- **Advantages:** free, private, works offline, and the developer already has Ollama 0.34.4 and several models installed. Models can be swapped.
- **Disadvantages:** output quality depends on the user's hardware and model choice. Ollama is a separate install. Small models produce invalid structured output more often.

## 5. Security implications
- The Ollama HTTP API has **no authentication**. Any local process can call it or swap models.
- Setting `OLLAMA_HOST=0.0.0.0` exposes the API to the network. FirewallAI will ship a **catalog finding** for an Ollama API listening on a non-loopback interface.
- FirewallAI refuses a non-loopback endpoint unless the user explicitly overrides it and sees a warning. This prevents silent data exfiltration through an environment variable. P_proyect read `OLLAMA_BASE_URL` with no host validation.
- Log the model digest with every AI interaction.
- Response size limits and timeouts are enforced.

## 6. Performance implications
- **Nothing has been measured yet.** The first benchmark environment will be the development machine (test environment TE-1 in [13 §4](../planning/13-testing-strategy.md)). Its hardware describes a *test environment*, **not a minimum requirement**.
- Expected on TE-1: a 7B Q4_K_M model (about 4.7 GB) fits in VRAM, and a 13 GB model partially offloads to CPU [NEEDS PROTOTYPE: tokens/s, time to first token, peak RAM/VRAM].
- Machines without a GPU will likely need 3B–4B models [ASSUMPTION]. Product hardware guidance is published only after benchmarks on several environments.

## 7. Validation
The v0.2 benchmark harness records tokens/s, time to first token, peak memory, schema-valid rate, and hallucinated-ID rate for each candidate model on the dev machine and on a CPU-only VM.

## 8. What to learn
- The Ollama REST API (`/api/version`, `/api/tags`, `/api/show`, `/api/chat`, `/api/embed`, `/api/pull`).
- Quantization (GGUF, Q4_K_M, IQ3), context windows, GPU offload, and structured outputs (JSON schema passed in `format`; supported since Ollama 0.5 per the [Ollama blog](https://ollama.com/blog/structured-outputs)).
