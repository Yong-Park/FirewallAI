# 07: Security Model, Privilege Separation, and Threat Model

Status: Approved plan rev. 3, frozen snapshot. Covers deliverables (8) and (9). The invariants that must hold right now live in [../architecture/security-boundaries.md](../architecture/security-boundaries.md).

## 1. Privilege model over time

| Version | Components | Privilege | IPC |
|---|---|---|---|
| v0.1 | GUI/CLI + collectors, one process | Standard user, `asInvoker` | none |
| v0.2 | Adds the AI layer (same process) talking to Ollama | Standard user | HTTP to loopback |
| v0.4 | Adds an **on-demand elevated helper**: a UAC prompt for each approved change set | Admin, short-lived | Named pipe with a DACL limited to the invoking user's SID; per-session nonce; message size limits; schema validation |
| v0.5 | Adds a **Windows Service** under a virtual service account (`NT SERVICE\FirewallAI`) with only the privileges it needs, plus a tray UI | Service | Named pipe, same controls |

**Rules:**
- The UI and AI processes are never elevated.
- Privileged code installs per-machine under `Program Files` and never loads from a user-writable path.
- The language for privileged code is decided in [ADR 0012](../adr/0012-native-component-language.md).

## 2. Change-management safety (v0.4 design)

- **Allowlisted typed operations:** `CreateRule`, `UpdateRule`, `DeleteRule`, `ExportPolicy`, `RestorePolicy`. These are the only operations. No free-form commands. **The AI can produce proposals only, never operations ready to execute.**
- **Validator** (it runs in the UI process *and* is repeated inside the helper):
  - fields come from an allowlist;
  - least privilege: narrowest program, port, remote scope, and profile;
  - rejects proposals that widen access beyond what was approved;
  - **protected connectivity:** never block DNS, DHCP, loopback, RDP when the session is remote, or FirewallAI's own IPC.
- **UX:** before/after diff, explicit approval, then verification by reading the rules back, a hash-chained audit log, and an auto-revert timer.
- **Conflict safety** ([ADR 0011](../adr/0011-change-rollback-model.md)): drift detection through rule hashes, rollback of FirewallAI's own changes only, FirewallAI-owned rule `Group`, and a second confirmation for changing rules FirewallAI didn't create.
- **VM-only:** `FIREWALLAI_ALLOW_WRITES=1` plus VM detection in dev builds. Exit criteria for real-system use: the full VM test matrix passes and the human signs off in an ADR.

## 3. Threat model (STRIDE)

**Assets:**
- firewall policy integrity;
- user's host data: rules, processes, network endpoints, hostnames;
- scan history and reports;
- AI API keys (optional);
- the audit log;
- release artifacts.

**Trust boundaries:** TB1 untrusted external strings → TB2 FirewallAI user process; TB2 ↔ TB3 local Ollama; TB2 → TB4 privileged helper or service; TB2 → TB5 cloud LLM (opt-in); the build/release pipeline → user. Diagram: [03 §2.6](03-architecture.md).

| # | Component / boundary | STRIDE | Threat | Mitigation | Verification |
|---|---|---|---|---|---|
| T1 | PowerShell runner (TB1→TB2) | T, E | Command injection via rule names, paths, or parameters (CWE-78) | Constant scripts, JSON via stdin, no `shell=True`, absolute exe path | Injection corpus tests; bandit |
| T2 | Executable resolution | E, T | PATH or DLL search-order hijack of `powershell.exe` or bundled DLLs (CWE-427) | Absolute `%SystemRoot%` paths; `SetDefaultDllDirectories`; privileged parts installed per-machine | Packaging review; Process Monitor check in a VM |
| T3 | Collector output parsing | T, D | Malformed or huge output crashes the app or exhausts memory | Size caps, timeouts, pydantic validation | Fuzz/property tests (hypothesis) |
| T4 | Reports (HTML/PDF) | T, I | A rule name containing `<script>` causes XSS when the report is opened (CWE-79) | Jinja2 autoescape, CSP, no remote resources | Escaping tests |
| T5 | SQLite and reports at rest | I | Another local user reads scan data | `%LOCALAPPDATA%` with user-only ACL; optional redaction on export | ACL test |
| T6 | Logs | I | Secrets or sensitive data logged (CWE-532) | Structured logging with redaction filters; no payload logging | Log tests |
| T7 | AI input (TB1→TB3) | T | **Prompt injection** through attacker-controlled strings, e.g. a rule named "ignore instructions…" (OWASP LLM01) | Untrusted data JSON-encoded in data fields; system prompt marks it as data; output schema plus deterministic validator; AI has no tools | Injection eval corpus |
| T8 | AI output (TB3→TB2) | T, E | Hallucinated findings, IDs, or citations; unsafe proposals (LLM05, LLM06, LLM09) | Schema validation; ID and citation existence checks; proposals only; human approval | Eval harness metrics |
| T9 | Ollama endpoint (TB3) | S, T, I | Unauthenticated API: another local process swaps models; a non-loopback endpoint leaks data | Loopback pin; record model digest; FW-AI-001 finding when Ollama is exposed | Settings tests |
| T10 | Cloud LLM (TB5) | I | Sensitive data sent externally; free-tier data used for training | Off by default; consent per send; payload preview; redaction | Consent flow tests |
| T11 | API keys | I | Key leakage from config, logs, or the repo (CWE-312) | Windows Credential Manager via keyring; gitleaks | gitleaks in CI |
| T12 | Elevated helper IPC (TB2→TB4) | S, E | Confused deputy: another process sends operations to the helper | Pipe DACL limited to the invoking SID; nonce; schema validation; helper re-validates; UAC per change set | VM tests |
| T13 | Firewall changes | D | Lockout or loss of connectivity | Protected-connectivity rules; auto-revert timer; disaster-recovery export | VM matrix |
| T14 | Audit log | R, T | Tampering hides changes | Append-only, hash-chained entries | Chain verification test |
| T15 | Supply chain | T | Malicious dependency or tampered release | Lockfile; pip-audit; Dependabot; SBOM; GitHub attestations; signing (ADR 0007) | CI gates |
| T16 | AI coding agents (dev-time) | T, E | An agent runs a destructive or firewall-modifying command, weakens tests, or fabricates results | AGENTS.md rules; deny rules and sandbox (ADR 0016/0017); branch protection; the evidence rule | Dry-run switch; PR review |
| T17 | Monitoring service (v0.5) | D, E | Service crash or misconfiguration blocks traffic; the service is a privilege-escalation target | Fail-safe defaults; minimal privileges; no LLM in the decision path | Research gate |

## 4. Mapping to weakness catalogs

These apply to the security of FirewallAI itself and are listed as references, not compliance claims: CWE-78, CWE-79, CWE-269, CWE-312, CWE-427, CWE-532; OWASP Top 10 for LLM Applications 2025: LLM01, LLM02, LLM05, LLM06, LLM09, LLM10. See [11](11-standards-references.md).
