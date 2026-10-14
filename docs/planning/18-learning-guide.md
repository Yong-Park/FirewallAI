# 18: Learning Guide

Status: Approved plan rev. 3. Concepts to understand for each component, with suggested study order. Prefer official sources.

| When | Topic | Why it matters here | Resources |
|---|---|---|---|
| Before Sprint 1 | Windows Firewall with Advanced Security: profiles, rule types, rule precedence, GPO merge, authenticated bypass | Basis of the verdict engine | Microsoft Learn "Windows Firewall" docs; NIST SP 800-41 Rev. 1 |
| Sprint 1 | NetSecurity PowerShell module, CIM/WMI (`MSFT_NetFirewallRule`, filter classes), policy stores (ActiveStore, RSOP) | Read path | Microsoft Learn `Get-NetFirewallRule`, `Get-NetFirewallPortFilter` |
| Sprint 1 | Secure subprocess use, command injection (CWE-78), PATH and DLL search order (CWE-427) | PowerShell runner | MITRE CWE entries; Python `subprocess` docs |
| Sprint 1 | Qt model/view, signals and slots, `QThreadPool` | Responsive GUI | Qt for Python docs |
| Sprint 1 | uv, `pyproject.toml`, src layout, lockfiles | Reproducibility | uv docs; Python Packaging User Guide |
| Sprint 2 | TCP/UDP sockets, bind addresses, dual-stack IPv6 (`IPV6_V6ONLY`), loopback | Correlation correctness | RFC 3493; Microsoft dual-stack sockets docs |
| Sprint 2 | Windows services, svchost grouping, service SIDs | Process-to-service mapping | Microsoft Learn: Service Control Manager |
| Sprint 2 | SQLite: WAL, migrations, foreign keys | Storage | sqlite.org docs |
| Sprint 3 | Output encoding and autoescaping (CWE-79), CSP | Safe reports | OWASP XSS Prevention Cheat Sheet |
| Sprint 4 | PyInstaller internals, Authenticode, SmartScreen, SBOMs (CycloneDX), artifact attestations, SLSA | Distribution and supply chain | PyInstaller docs; Microsoft Authenticode docs; slsa.dev; GitHub attestations docs |
| v0.2 | LLM inference: tokens, context, sampling, quantization (GGUF), structured outputs, embeddings | Local AI | Ollama docs and blog; llama.cpp docs |
| v0.2 | Prompt injection, excessive agency, insecure output handling | Secure AI | OWASP Top 10 for LLM Applications 2025 (genai.owasp.org) |
| v0.2 | Evaluating non-deterministic systems | Eval harness | — |
| v0.3 | RAG: BM25 (SQLite FTS5), vector search, chunking; standards licensing | Docs and references | SQLite FTS5 docs; NIST CSRC |
| v0.4 | UAC, integrity levels, named-pipe security (DACLs), confused deputy, compensating transactions, hash chains | Privileged helper | Microsoft Learn: Named Pipe Security and Access Rights |
| v0.5 / Research | ETW, Windows Filtering Platform (layers, sublayers, filters, arbitration, ALE, dynamic sessions, callout drivers) | Monitoring and authorization | Microsoft Learn: Windows Filtering Platform; ETW docs |
| Throughout | Threat modeling (STRIDE), ADRs, secure SDLC | Engineering practice | Microsoft Threat Modeling docs; adr.github.io; NIST SSDF (SP 800-218) |
| Throughout | Multi-agent AI-assisted development: context handoff, verifying AI output | Workflow | [AGENT_WORKFLOW.md](../development/AGENT_WORKFLOW.md) |

**Suggested practice:** for each sprint, write a short "what I learned and decided" note in the PR description. It records your own engineering ownership for AI_DEVELOPMENT.md.
