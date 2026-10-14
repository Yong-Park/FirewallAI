# FirewallAI Planning Documentation

**Status:** Approved plan rev. 3 (2026-10-14). M0 documentation is complete. Accepted: D2, D3, D14, D15, D16, D20. Pending: D1, D4–D13, D17–D19 ([17](17-decisions-for-approval.md)).

This folder is the **frozen, approved rationale**. Current implementation references live in [../architecture/](../architecture/). Decisions live in [../adr/](../adr/). Live project state is in [../development/HANDOFF.md](../development/HANDOFF.md).

## Reading order
1. [01-prd.md](01-prd.md): vision, personas, user stories
2. [02-requirements.md](02-requirements.md): requirements, MVP scope, deferred features
3. [17-decisions-for-approval.md](17-decisions-for-approval.md): **what you need to decide**
4. [03-architecture.md](03-architecture.md) → [05-firewall-analysis.md](05-firewall-analysis.md) → [07-security-model.md](07-security-model.md)
5. [15-roadmap.md](15-roadmap.md): milestones, Sprint 1, Definition of Done
6. Everything else as needed

## Documents
| # | File | Content |
|---|---|---|
| 01 | [01-prd.md](01-prd.md) | PRD, personas, user stories with acceptance criteria |
| 02 | [02-requirements.md](02-requirements.md) | Functional and non-functional requirements, MVP scope, deferred features |
| 03 | [03-architecture.md](03-architecture.md) | Architecture, Mermaid diagrams, folder structure |
| 04 | [04-technology-evaluation.md](04-technology-evaluation.md) | Stack evaluation |
| 05 | [05-firewall-analysis.md](05-firewall-analysis.md) | Effective policy, verdict model, correlation, findings catalog |
| 06 | [06-windows-integration.md](06-windows-integration.md) | Windows integration strategy |
| 07 | [07-security-model.md](07-security-model.md) | Privilege separation, change safety, STRIDE threat model |
| 08 | [08-data-model.md](08-data-model.md) | SQLite schema and ER diagram |
| 09 | [09-ai-integration.md](09-ai-integration.md) | Local-first AI, providers, secure AI engineering, evaluation |
| 10 | [10-securitydocs.md](10-securitydocs.md) | Report engine |
| 11 | [11-standards-references.md](11-standards-references.md) | Standards registry and licensing |
| 12 | [12-monitoring-research.md](12-monitoring-research.md) | Monitoring and connection authorization feasibility |
| 13 | [13-testing-strategy.md](13-testing-strategy.md) | Testing, quality gates, VM plan |
| 14 | [14-packaging-distribution.md](14-packaging-distribution.md) | Packaging, installer, signing, releases |
| 15 | [15-roadmap.md](15-roadmap.md) | Roadmap, Sprint 1, Definition of Done |
| 16 | [16-risks.md](16-risks.md) | Risk register |
| 17 | [17-decisions-for-approval.md](17-decisions-for-approval.md) | Open decisions |
| 18 | [18-learning-guide.md](18-learning-guide.md) | Learning guide |

## Traceability

### Original 20 deliverables
| # | Deliverable | Location |
|---|---|---|
| 1 | PRD | 01 |
| 2 | Functional and non-functional requirements | 02 §1–2 |
| 3 | MVP scope and deferred features | 02 §3 |
| 4 | Software architecture | 03 §1, §3 |
| 5 | Mermaid diagrams | 03 §2, 08 §2 |
| 6 | Technology stack evaluation | 04 + ADRs |
| 7 | Windows integration strategy | 06 |
| 8 | Privilege separation and security model | 07 §1–2 |
| 9 | Initial threat model | 07 §3 |
| 10 | Database and data model | 08 |
| 11 | AI integration and privacy | 09 |
| 12 | Testing strategy (incl. VMs) | 13 |
| 13 | Packaging and installer | 14 |
| 14 | Repository folder structure | 03 §4, [module-map](../architecture/module-map.md) |
| 15 | Roadmap with milestones | 15 §1 |
| 16 | User stories and acceptance criteria | 01 §6 |
| 17 | Risks and mitigations | 16 |
| 18 | Decisions requiring approval | 17 |
| 19 | First sprint | 15 §2 |
| 20 | Definition of Done v0.1 | 15 §4 |

### Rev. 2 requirements
| § | Requirement | Location |
|---|---|---|
| 1 | Local-first AI (Ollama) | 09, ADR 0002/0004 |
| 2 | Desktop app and distribution | 14, ADR 0006/0007/0008 |
| 3 | Firewall analysis accuracy | 05 |
| 4 | Human-approved firewall management | 07 §2, ADR 0011 |
| 5 | Monitoring and connection authorization | 12 |
| 6 | Professional documentation | 10 |
| 7 | Standards and frameworks | 11 |
| 8 | Secure AI engineering | 09 §6–7, 07 T7–T10 |
| 9 | Engineering quality and portfolio | 13, [AI_DEVELOPMENT.md](../../AI_DEVELOPMENT.md) |
| 10 | Revised roadmap | 15 |
| 11 | Approval workflow | 17, ADR 0000 |

### Rev. 3 requirements (multi-agent workflow)
| § | Requirement | Location |
|---|---|---|
| 1 | AGENTS.md | [AGENTS.md](../../AGENTS.md) |
| 2 | CLAUDE.md | [CLAUDE.md](../../CLAUDE.md) |
| 3 | HANDOFF.md | [HANDOFF.md](../development/HANDOFF.md) |
| 4 | Agent switching protocol | [AGENT_WORKFLOW.md](../development/AGENT_WORKFLOW.md) §1–4 |
| 5 | Architecture documentation | [../architecture/](../architecture/), ADR 0015 |
| 6 | AI development transparency | [AI_DEVELOPMENT.md](../../AI_DEVELOPMENT.md) |
| 7 | Git workflow | [AGENT_WORKFLOW.md](../development/AGENT_WORKFLOW.md) §5, ADR 0018–0020 |
| 8 | Security boundaries preserved | [security-boundaries.md](../architecture/security-boundaries.md), AGENTS.md §5, ADR 0016/0017 |
| 9 | Plan updates (gates, Sprint 1, DoD, risks, decisions) | 13 §2, 15, 16 R18–R25, 17 D15–D20 |
| 10 | Approval workflow | 17; Sprint 1 not authorized ([HANDOFF](../development/HANDOFF.md)) |

## Tag register

Unverified items that remain open, and the step that resolves each.

| Tag | Item | Where | Resolve in |
|---|---|---|---|
| NEEDS PROTOTYPE | PowerShell cold start and scan time at 500 and 1,500 rules | 06, ADR 0009 | Sprint 1 spike |
| NEEDS PROTOTYPE | ActiveStore vs. COM fidelity | ADR 0009 | Sprint 1 spike |
| ASSUMPTION | Most rule and profile data is readable by a standard user | 01, 04, 06 | Sprint 1 spike |
| VERIFY | Python 3.13/3.14 support in PySide6, PyInstaller, and Nuitka | ADR 0001 | Sprint 1 |
| PENDING VERIFICATION | Hyper-V available on the dev machine (VM testing remains required) | 13 §3, 15 §2 | Before Sprint 1 (human) |
| VERIFY | OV code signing CAs that validate applicants in Guatemala | ADR 0007, 14 | Before the first signed release |
| VERIFY | Windows Firewall rule precedence ordering (citation) | 05 §2 | Sprint 2 |
| NEEDS PROTOTYPE | Two-VM real-behavior verdict validation | 05 §5 | Sprint 2 |
| NEEDS PROTOTYPE | Qt PDF layout quality and speed | ADR 0005, 10 | Sprint 3 |
| VERIFY | PyInstaller bootloader DLL directory behavior | 14, ADR 0006 | Sprint 4 |
| NEEDS PROTOTYPE | Bundle size and start time | ADR 0006 | Sprint 1/4 |
| VERIFY | `/api/embed` superseding `/api/embeddings` | 09 | v0.2 |
| VERIFY | Model licenses (Qwen2.5-7B HF LICENSE file, Llama, Phi, Gemma) | ADR 0004, 09 | v0.2 |
| NEEDS PROTOTYPE | Local model benchmark | ADR 0002/0004 | v0.2 |
| VERIFY | NIST SP 800-53 control titles, CSF PR.PS-01 / PR.IR-01 text, CWE titles, OWASP LLM 2025 on official site, CIS Controls v8.1 and ISO titles | 11 | v0.3 (registry `reviewed` flag) |
| VERIFY | Codex project-config trust behavior | ADR 0017 | Sprint 1 Day 0 |
| VERIFY | WFP dynamic-session semantics | 12 | Research R2 |
| VERIFY | Windows 10 ESU terms wording | ADR 0008, 05 FW-ENV-001 | Sprint 2 |

**Verified on 2026-10-14** (sources cited inline):
- NIST SP 800-41 Rev. 1 is the latest revision found.
- Azure Artifact Signing eligibility for individual developers (US/Canada only) and its pricing.
- SignPath Foundation's terms.
- Gemini API unpaid-tier data use.
- The CIS Benchmarks CC BY-NC-SA 4.0 license (as reproduced by NIST NCP).
- Codex `project_doc_max_bytes` (32 KiB default), sandbox and approval keys, and project-scoped config.
- Ollama structured outputs (`format`, since 0.5).
- Qwen2.5 licensing split by size.
- CSF 2.0 text for DE.CM-01, ID.AM-02, PR.PS-02, PR.PS-04, and PR.PS-06.
- Claude Code permission-rule syntax (Bash/PowerShell wildcards, deny precedence, `Read(./…)`). The ADR 0016 deny rules are implemented, and one was tested: a branch-deletion command was blocked.

**Resolved by the human on 2026-10-14:**
- Developer location: Guatemala.
- Codex attribution trailer: `Assisted-by: OpenAI Codex`.
- D16 implementation authorized.
