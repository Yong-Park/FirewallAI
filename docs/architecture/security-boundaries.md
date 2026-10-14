# Security boundaries and invariants

Every change must preserve these invariants. Weakening any of them requires a new ADR that the human accepts. The threat model is in [../planning/07-security-model.md](../planning/07-security-model.md).

| ID | Invariant | Applies from | How it is enforced (planned) |
|---|---|---|---|
| SB-01 | v0.1 is **read-only**. No code path modifies firewall, network, or system configuration. | v0.1 | Test that scans embedded scripts for write verbs; code review; [AGENTS.md](../../AGENTS.md) §5 |
| SB-02 | The UI and AI processes **never run elevated**. The manifest uses `asInvoker`. | v0.1 | PyInstaller manifest; startup check that warns if elevated |
| SB-03 | Subprocess runs only through `powershell_runner`: absolute path, constant scripts, JSON over stdin, no `shell=True`, timeouts and output caps. | v0.1 | bandit rule, unit tests, injection corpus |
| SB-04 | All external data is **untrusted** (rule names, descriptions, process names, paths, hostnames, logs, documents) and is validated at trust boundaries. | v0.1 | pydantic models; escaping tests |
| SB-05 | v0.1 makes **zero outbound network** connections. | v0.1 | Test suite fails on socket use; manual check before release |
| SB-06 | The AI **explains only**. It cannot execute commands, call privileged code, or modify state. Its output is schema-validated, and IDs and citations are checked against local data. | v0.2 | import-linter; validator tests; eval harness |
| SB-07 | The AI endpoint is **loopback by default**. A non-loopback or cloud endpoint requires explicit opt-in, consent per send, and redaction. | v0.2 | Settings validation; tests |
| SB-08 | No API keys or credentials in the repository, installer, logs, or database. Keys live only in Windows Credential Manager. | v0.1 | gitleaks; log-redaction tests |
| SB-09 | No model weights are bundled. Models come from Ollama under their own licenses. | v0.2 | Packaging check |
| SB-10 | Firewall changes need typed, allowlisted operations, a before/after diff, **explicit user approval**, drift detection, verification, an audit log, and rollback. | v0.4 | Helper-side validation; VM test matrix |
| SB-11 | Firewall write operations are tested **only in disposable VMs** until the safety exit criteria pass. | v0.4 | `FIREWALLAI_ALLOW_WRITES` + VM detection in dev builds |
| SB-12 | The LLM is **never** in a real-time packet or connection decision path. | v0.5 / research | Architecture review |
| SB-13 | No elevated component loads code from a user-writable directory. | v0.4 | Per-machine install for privileged components |
| SB-14 | Reports separate observed facts, evidence, AI interpretation, recommendations, and limitations. No compliance claims. | v0.1 | Report model types; template tests |
