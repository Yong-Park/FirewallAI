# ADR 0004: Default recommended local model

- **Status:** Proposed · **Decision ID:** D4 · **Date:** 2026-10-14 · **Proposed by:** claude-code · **Decided by:** pending

## 1. Problem
Users need a sensible default model that runs locally, follows a JSON schema reliably, explains security concepts accurately, and has a license that allows our use. FirewallAI **does not redistribute weights**. Ollama downloads them under their own license.

## 2. Decision (recommended)
- Provisional default: **`qwen2.5:7b-instruct`**. It is already installed on test environment TE-1 ([13 §4](../planning/13-testing-strategy.md)). That is a convenience for benchmarking, not a reason it suits all users.
- The Qwen2.5 family is Apache-2.0 **except the 3B and 72B sizes**, which use Qwen-specific licenses (per the [Ollama qwen2.5 library page](https://ollama.com/library/qwen2.5)) [VERIFY against the Hugging Face LICENSE file for 7B].
- The final choice comes after the v0.2 benchmark.
- **No silent fallback.** The user explicitly picks a model, and FirewallAI checks that the model supports what's needed (structured output, context length).

## 3. Alternatives considered
| Candidate | License (verify before recommending) | Notes |
|---|---|---|
| Llama 3.1 8B / 3.2 3B | Llama Community License (attribution, acceptable use policy) | Good quality; license is not OSI-approved [VERIFY] |
| Phi family (e.g. Phi-4-mini) | MIT [VERIFY per model] | Small; good for CPU-only machines |
| Gemma family | Gemma Terms of Use | Custom terms [VERIFY] |
| Qwen2.5 3B | Qwen Research License | Restricted; **not** recommended as default |
| `*-abliterated` models | Varies | Safety-removed. **Never recommended as default** for a security tool |

## 4. Advantages and disadvantages
- **Advantages:** Qwen2.5-7B is already installed (zero setup for the developer) and is commonly reported to handle structured output well [ASSUMPTION until benchmarked].
- **Disadvantages:** 7B needs about 5 GB of VRAM or a slow CPU fallback.

## 5. Security implications
- Model files are third-party artifacts. Record the model digest from `/api/show` or `/api/tags`.
- The UI shows the model's license and size before any `ollama pull`.

## 6. Performance implications
See [ADR 0002](0002-local-first-ai-ollama.md). Candidates are measured on GPU and CPU-only machines.

## 7. Validation
The v0.2 eval harness (golden set of about 30 findings plus an injection corpus) runs against each candidate. Selection criteria:
- schema-valid rate ≥ 95%;
- hallucinated-ID rate = 0 after validation;
- acceptable latency (threshold set in v0.2).

## 8. What to learn
- Model licensing (OSI vs. custom licenses).
- Benchmark design.
- Why we evaluate on *our* task rather than relying on public leaderboards.
