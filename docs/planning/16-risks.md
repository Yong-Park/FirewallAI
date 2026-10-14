# 16: Technical Risk Register

Status: Approved plan rev. 3, frozen snapshot. Covers deliverable (17). L = likelihood, I = impact (H/M/L). The human owns every risk; the "Trigger" column is the signal to act on.

| # | Risk | L | I | Mitigation | Trigger |
|---|---|---|---|---|---|
| R01 | PowerShell start-up or query latency makes scans slow | M | M | Bulk filter queries; persistent PowerShell session; COM as a fallback | Spike shows a scan > 10 s |
| R02 | Key data unreadable without admin rights | M | M | Explicit "unavailable" values; Indeterminate verdicts; Limitations panel | Spike list of fields that fail |
| R03 | Verdicts over-claim exposure | M | H | Local-policy-only wording; truth table; two-VM real-behavior tests | Any truth-table mismatch |
| R04 | `Indeterminate` too common to be useful | M | M | Measure the rate on VMs and real machines; add WFP enumeration as a source | > 30% of listeners indeterminate [ASSUMPTION threshold] |
| R05 | False-positive fatigue | M | M | Confidence levels, benign conditions, suppressions, conservative defaults | Owner dismisses most findings |
| R06 | AV or SmartScreen flags the unsigned build | H | M | One-dir build, documentation, SignPath, vendor false-positive submissions | First release |
| R07 | Python / PySide6 / PyInstaller version drift | M | M | Pinned versions, lockfile, Dependabot with CI | Build breaks |
| R08 | Local models too heavy for user hardware | M | M | AI optional; hardware-tiered model guidance | Benchmark results |
| R09 | Small models produce invalid or hallucinated output | H | M | Structured `format`, validator, eval harness, "failed validation" UX | Schema-valid rate < 95% |
| R10 | Ollama API exposure or model tampering | L | M | Loopback pin, digest logging, FW-AI-001 finding | — |
| R11 | Cloud free-tier terms change | M | L | Off by default, never required, docs link to live terms | — |
| R12 | Firewall changes lock users out (v0.4) | M | H | VM-only testing, protected connectivity, auto-revert, disaster-recovery export | VM matrix failures |
| R13 | Rollback overwrites other admins' changes (v0.4) | M | H | Delta-only inverse operations plus drift detection ([ADR 0011](../adr/0011-change-rollback-model.md)) | Drift test failure |
| R14 | Per-user install vulnerable to DLL hijacking | M | M | No elevated code from user-writable paths; safe DLL directories | Packaging review |
| R15 | WFP/driver work exceeds Python's reach | H | M | Research track with gates; native component ADR | R1–R3 results |
| R16 | Standards licensing violations | L | H | Reference-by-ID for restricted frameworks; `license_class` in the registry | — |
| R17 | Scope creep across FirewallAI, SentinelAI, SecureCode AI | M | M | Defer package extraction ([ADR 0013](../adr/0013-shared-package-extraction.md)); milestone gates | — |
| R18 | **Context lost on agent switch** | M | M | Mandatory HANDOFF update, start-up checklist, Sprint 1 dry-run switch | Mismatch found at session start |
| R19 | **Instruction drift** between AGENTS.md, CLAUDE.md, and docs | M | M | AGENTS.md is authoritative; CLAUDE.md only imports it; stop-and-ask on conflict; milestone doc review | Conflicting instructions reported |
| R20 | **Two agents editing at once** | L | H | Single-writer lock; worktrees and branches for any parallel work; never the same files | Lock held unexpectedly |
| R21 | **Fabricated "tests passed" claims** | M | H | Evidence rule (command + SHA + output); CI is the source of truth | Claim without evidence in a PR |
| R22 | **Agent weakens a gate to get green** | M | H | CI blocks new skips in security tests; PR checklist; human diff review | New skip, ignore, or noqa in a diff |
| R23 | **Agent runs a firewall write on the primary machine** | L | H | AGENTS.md prohibition, Claude deny rules, Codex sandbox, VM guard in code from v0.4 | Any such command proposed |
| R24 | **Inconsistent style between agents** | H | L | ruff and mypy as the arbiter | Formatting churn in diffs |
| R25 | **AGENTS.md grows too long to be useful context** | M | M | Under about 150 lines, links instead of copies; Codex default embed cap of 32 KiB (`project_doc_max_bytes`) | File > 150 lines |
