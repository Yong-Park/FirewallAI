# 02: Requirements and MVP Scope

Status: Approved plan rev. 3, frozen snapshot. Covers deliverables (2) functional and non-functional requirements and (3) MVP scope and deferred features.

## 1. Functional requirements

ID prefix by version: **F1** = v0.1, **F2** = v0.2, and so on.

### Audit engine (v0.1)
| ID | Requirement |
|---|---|
| F1-01 | Collect firewall profiles: enabled, default inbound and outbound action, `AllowInboundRules`, `AllowLocalFirewallRules`, `AllowLocalIPsecRules`, notifications, logging settings, `DisabledInterfaceAliases`. |
| F1-02 | Identify the active network connections and the profile assigned to each. |
| F1-03 | Collect effective rules from `ActiveStore` together with their address, port, application, service, interface, interface-type, security, and package filters. Record each rule's policy source (local or GPO). |
| F1-04 | Collect listening TCP and UDP endpoints (IPv4 and IPv6), including the bind address. |
| F1-05 | Collect active TCP connections with remote addresses. |
| F1-06 | Map endpoints to PID, process name, and image path, plus Authenticode signer on a best-effort basis. Record inaccessible fields explicitly. |
| F1-07 | Map PIDs to the Windows services they host (handles shared `svchost` processes). |
| F1-08 | Detect third-party firewall products via `root\SecurityCenter2` where available (client SKUs). |
| F1-09 | Compute a per-listener, per-profile verdict: `NotExposed_LoopbackOnly`, `PermittedByPolicy`, `BlockedByPolicy`, or `Indeterminate(reasons)` ([05](05-firewall-analysis.md)). |
| F1-10 | Run a versioned findings catalog (10 or more rules in v0.1). Each finding has evidence references, severity, confidence, explanation, benign conditions, recommendations, and references. |
| F1-11 | Never raise a finding solely because a port is open or listening. |
| F1-12 | Store scan snapshots in SQLite and diff any two scans. |
| F1-13 | Export JSON, HTML, and basic PDF reports with a provenance header and a Limitations section. Offer optional redaction. |
| F1-14 | Provide a CLI (`firewallai scan --json`, `firewallai report`) that uses the same services as the GUI. |
| F1-15 | Provide a GUI with these views: Overview, Profiles, Rules, Listening Ports, Connections, Findings, Scan History, Reports, Settings. Include onboarding. |
| F1-16 | Show collector failures and partial data in a Limitations panel. |
| F1-17 | Ship a catalog finding when the Ollama API listens on a non-loopback interface. This is detectable from listener data, with no AI involved. |

### Later versions (summary; detailed in the respective docs)
- **F2:** Ollama detection, guided setup, model picker, explain-only advisor with structured output and validation, privacy controls, optional cloud providers that are off by default, and an AI evaluation harness. See [09](09-ai-integration.md).
- **F3:** full SecurityDocs suite (DOCX, rich PDF), standards registry, RAG. See [10](10-securitydocs.md) and [11](11-standards-references.md).
- **F4:** typed rule operations, diff, approval, elevated helper, drift detection, verification, audit chain, rollback. See [07](07-security-model.md).
- **F5:** Windows Service, tray notifications, event correlation, reactive allow and block, temporary permissions. See [12](12-monitoring-research.md).

## 2. Non-functional requirements

| ID | Category | Requirement |
|---|---|---|
| N-01 | Privilege | v0.1 runs entirely as a standard user (`asInvoker`) and never requests elevation. |
| N-02 | Network | v0.1 makes zero outbound network connections. |
| N-03 | Privacy | No telemetry. Data stays in `%LOCALAPPDATA%\FirewallAI`. Retention is configurable. |
| N-04 | Performance | A full scan completes in under 10 s with 1,500 rules [NEEDS PROTOTYPE]. The UI never blocks for more than 100 ms. |
| N-05 | Reliability | A failure in one collector does not abort the scan. Partial results are labeled as partial. |
| N-06 | Security | No `shell=True` and no string-built commands. All external data is validated. Report output is autoescaped. |
| N-07 | Accessibility | Full keyboard navigation and accessible names on controls. Status is shown with text and icons as well as color. Light and dark themes. |
| N-08 | Honesty | No single security score. Confidence is shown on findings. External exposure is never claimed. |
| N-09 | Compatibility | Windows 11 x64 is primary. Windows 10 22H2 x64 is best-effort ([ADR 0008](../adr/0008-windows-10-support.md)). |
| N-10 | Maintainability | Type hints throughout, `mypy --strict` on `core`, ruff, import-linter contracts. Core test coverage is 85% or higher. |
| N-11 | Logging | Structured JSON logs, rotated, with no secrets or full sensitive payloads. |
| N-12 | Distribution | The installer requires neither Python nor admin rights. Releases carry SHA-256 checksums and an SBOM. |
| N-13 | Licensing | All dependencies are compatible with MIT distribution. PySide6 is used under the LGPL. |
| N-14 | AI cost | Nothing requires a paid API or account (v0.2 and later). |

## 3. MVP (v0.1) scope

**In scope:** F1-01 through F1-17 and N-01 through N-13, an unsigned per-user installer, and GitHub Releases.

**Explicitly deferred:**
| Feature | Target | Reason |
|---|---|---|
| AI advisor | v0.2 | Build it on validated deterministic findings ([ADR 0003](../adr/0003-ai-in-v0-2.md)) |
| DOCX, rich PDF, RAG, full standards registry | v0.3 | Scope; the PDF toolchain needs a prototype |
| Code signing | When eligible ([ADR 0007](../adr/0007-code-signing.md)) | SignPath requires an existing release |
| Rule create, modify, delete | v0.4 | Needs a privileged helper and VM-validated safety controls |
| Background monitoring and notifications | v0.5 | Needs a service and a privileged design |
| Pre-connection authorization, WFP integration, IPS | Research | Needs a feasibility prototype and a go/no-go ADR |
| Deep packet inspection | Not planned | Privacy, TLS, complexity |
| Auto-updater | Post-v0.1 | Update channels are an attack surface. Needs a design. |
