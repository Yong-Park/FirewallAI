# Interfaces and contracts

Status: mixed. Sections marked **implemented** reflect the code. Everything else is a planned, illustrative signature. Rationale: [../planning/03-architecture.md](../planning/03-architecture.md), [../planning/09-ai-integration.md](../planning/09-ai-integration.md).

## Implemented in M1.1 (2026-10-14)

**Core** (`firewallai.core`)
- `FirewallProfile` (frozen, `extra="forbid"`) with stable ID `fw_profile:<domain|private|public>`. The enums are `ProfileName`, `TriState` (true / false / not_configured), and `FirewallAction` (allow / block / not_configured).
- `CollectorResult[T]` has `data`, `errors: tuple[CollectorError, ...]`, and `partial`. It enforces: no data requires an error, and data plus errors requires `partial`.
- `CollectorError` has `code`, `source`, and `detail`. The codes are `access_denied`, `not_found`, `timeout`, `output_too_large`, `parse_error`, `invalid_value`, `execution_failed`, and `unsupported_platform`. `detail` holds stable identifiers only, never localized text or raw host data.
- `DataClass` sensitivity metadata is declared on every field (`json_schema_extra={"sensitivity": ...}`). Unclassified fields are treated as `host_sensitive`.

**Collectors** (`firewallai.collectors`)
```python
class FirewallProfileCollector(Protocol):          # protocols.py
    @property
    def source_id(self) -> str: ...
    def collect_profiles(self) -> CollectorResult[tuple[FirewallProfile, ...]]: ...

class PowerShellRunner:                            # windows/powershell_runner.py
    def run(self, script: PowerShellScript, params: Mapping[str, JsonValue] | None = None,
            *, source: str) -> RunOutcome: ...     # data or structured CollectorError
```
- Implementations: `WindowsFirewallProfileCollector` (read-only ActiveStore query) and `FixtureFirewallProfileCollector`. Both use the same parser, `profile_mapping.parse_profiles_payload`.
- Scripts are constant `PowerShellScript` objects registered in `windows/scripts.py`. Each has an allowlist of read-only commands, a timeout, and an output cap.
- Wire format between script and Python: one JSON envelope, `{"ok": true, "data": …}` or `{"ok": false, "error": {"category", "error_id", "hresult"}}`.

**App** (`firewallai.app.profile_service`)
- `ProfileService.get_profiles() -> ProfileReport`. The report holds the result, `source_id`, `collected_at` (UTC), and `elevated`.
- `report_to_dict()` produces JSON schema `firewallai.profiles/1` with `scope: "local_policy_only"` and `read_only: true`.
- `create_profile_service(fixture=None)`.

**CLI:** `firewallai profiles [--json] [--fixture PATH]`. Exit codes: 0 complete, 1 failed, 2 usage error, 3 partial.
**GUI:** `firewallai-gui [--fixture PATH]`. Collection runs in a `QThreadPool` worker and results come back through Qt signals.

## Implemented in M1.3 (2026-10-14): read-only ActiveStore rules ([ADR 0009](../adr/0009-firewall-read-path.md))

**Core** (`firewallai.core.rules`, `firewallai.core.evidence`)
- **`FirewallRule`** (frozen). Each of its 7 filters (application, service, security, port, address, interface_type, interface) is a **`FilterResult[T]`** in exactly one state:
  - `COLLECTED` (value);
  - `NOT_COLLECTED` (reason: `pending`, `not_requested`, `cancelled`, `phase_failed`, `missing_from_source`);
  - `UNREADABLE` (structured `CollectorError`).

  **There is no default value**: a missing filter is never "Any".
- **Typed tokens.** Ports, addresses, and ICMP types are parsed into `ANY | NUMBER | RANGE | KEYWORD | ADDRESS | UNKNOWN`. Unrecognized values become `UNKNOWN`, never `ANY`.
- **Rule ID scheme `h1`:** `fw_rule:h1-` + the first 16 hex chars of SHA-256(raw Windows rule ID).
  - The raw ID is kept in `instance_id`, which is host-sensitive.
  - On a 64-bit prefix collision, the affected rules use the full 64-hex digest.
  - Duplicate raw IDs are excluded and reported, never merged.
  - IDs were verified identical across scans on TE-1.
- **Evidence guard:** `evidence_for_verdict(rule) -> CompleteRuleEvidence | IncompleteEvidence(reasons)`. Any non-collected filter, unknown token, unknown policy source, non-`any` dynamic target or transport, or dynamic keyword addresses yields `IncompleteEvidence`.
  - **Future verdict code may only consume `CompleteRuleEvidence`.**
  - No verdicts exist in M1.3.
- `RuleCollection` holds rules, `total_in_source`, `detail_requested`, `detail_complete`, and `limitations` (`ScanLimitation` codes, always including local-policy-only, WFP filters not observable, service hardening not evaluated, GPO merge unverified, and enforcement status uninterpreted).

**Runner streaming mode** (`collectors.windows.powershell_runner`, opt-in, `PowerShellScript.streaming=True`)
- Protocol: zero or more `{"type":"event","data":…}` lines, then exactly one `{"type":"result",…}` line, then EOF.
- The script body calls `FwaiEmit $obj` to emit events.
- `PowerShellRunner.run_stream(script, params, *, source, on_event, cancel)`.
- Limits:
  - per-line cap and total cap, both enforced in the reader thread;
  - an event-count cap;
  - a timeout and cancellation;
  - the child process is always killed and reaped;
  - schema violations, truncation, and non-UTF-8 become structured errors.
- The non-streaming path is unchanged.

**Collectors**
```python
class FirewallRuleCollector(Protocol):
    @property
    def source_id(self) -> str: ...
    def collect_rules(self, *, detail: bool = True,
                      observer: RuleCollectionObserver | None = None,
                      cancel: threading.Event | None = None) -> CollectorResult[RuleCollection]: ...

class RuleCollectionObserver(Protocol):          # called on the collecting (worker) thread
    def inventory_ready(self, rules: tuple[FirewallRule, ...]) -> None: ...
    def detail_progress(self, done: int, total: int, updated: tuple[FirewallRule, ...]) -> None: ...
```
- `WindowsFirewallRuleCollector` runs **one** streaming PowerShell process (`FIREWALL_RULES`):
  - first, an inventory event (rules plus bulk application, service, and security filters);
  - then detail events in 100-rule chunks (per-rule port, address, interface-type, and interface-alias filters; **enabled inbound rules first**; every rule is still collected).
- A process-wide `HEAVY_QUERY_LOCK` means a second concurrent collection returns `BUSY`.
- `FixtureFirewallRuleCollector` replays fixture events, with optional delays and injected failures.
- Both collectors go through the shared driver `collectors.rule_collection.collect_progressively` and the `RuleAssembler` (`collectors.windows.rule_mapping`).

**App** (`app.rule_service`)
- `RuleScanService.scan(detail=True, observer=None, cancel=None) -> RuleScanReport` returns: result, inventory and total seconds, **N-04 status** (`met` / `exceeded` / `not_evaluated`), an evidence summary, and elevation status.
- N-04 is evaluated **only** for a complete full scan, measured end to end.
- `rules_report_to_dict()` produces JSON schema **`firewallai.rules/1`**. It includes a note that the export may contain host-sensitive data.

**CLI:** `firewallai rules [--json] [--summary] [--inventory-only] [--fixture PATH]`
- Progress goes to stderr.
- Exit codes: 0 complete, 3 partial or incomplete, 1 failed.

**GUI:** the **Rules** tab (`ui.rules_tab`, `ui.rules_model`)
- Collect and Cancel buttons, progress bar, and phase text.
- A sortable table in which uncollected filters show "Pending…", "Not collected (reason)", or "Unreadable".
- An evidence column, timing with N-04 status, and the limitations panel.
- Display rows (`RuleRow`) are **precomputed on the worker thread** and cached per rule. The model sorts precomputed keys.
- `ui.app.prepare_gc_for_gui()` (`gc.freeze()` at startup) keeps full GC passes short.

## Collectors, planned (`collectors`, v0.1)
The rules collector is **implemented** (M1.3, section above). The signatures below are the earlier planned sketch, kept for the network, process, and service collectors that remain planned.
```python
class FirewallCollector(Protocol):
    def profiles(self) -> CollectorResult[list[FirewallProfile]]: ...
    def rules(self) -> CollectorResult[list[FirewallRule]]: ...   # ActiveStore, filters joined

class NetworkCollector(Protocol):
    def endpoints(self) -> CollectorResult[list[Endpoint]]: ...   # listeners + connections

class ProcessCollector(Protocol):
    def process(self, pid: int) -> CollectorResult[ProcessInfo]: ...

class ServiceCollector(Protocol):
    def services(self) -> CollectorResult[list[ServiceInfo]]: ...
```
`CollectorResult` carries either data or a structured error (`access_denied`, `timeout`, `unsupported`, `parse_error`), plus a `partial` flag. Errors are surfaced as limitations; they never disappear silently.

## Core (v0.1)
- `evaluate(snapshot: Snapshot) -> list[Verdict]`. Verdict values: `NotExposed_LoopbackOnly | PermittedByPolicy | BlockedByPolicy | Indeterminate(reasons)`.
- `run_findings(snapshot, verdicts, catalog) -> list[Finding]`, where every finding carries `evidence_refs`, `severity`, `confidence`, and `catalog_version`.
- `diff(a: Snapshot, b: Snapshot) -> SnapshotDiff`.

## SecurityDocs (v0.1)
- `ReportDocument`, built from typed blocks: `ObservedFact`, `Evidence`, `Finding`, `RiskAssessment`, `Recommendation`, `AIInterpretation`, `StandardReference`, `Limitation`.
- `Renderer.render(doc) -> bytes`, with implementations `HtmlRenderer`, `QtPdfRenderer` (v0.1), and `DocxRenderer` (v0.3).

## AI provider (v0.2)
```python
class LLMProvider(Protocol):
    def health(self) -> ProviderHealth: ...
    def list_models(self) -> list[ModelInfo]: ...
    def capabilities(self, model: str) -> ModelCapabilities: ...
    def generate_structured(self, req: StructuredRequest) -> StructuredResponse: ...  # JSON schema enforced + validated
    def embed(self, texts: list[str]) -> list[list[float]]: ...
```

## AI task orchestration (v0.2+, ADR 0021)
Status: **direction accepted** ([ADR 0021](../adr/0021-hybrid-ai-orchestration.md), 2026-10-14). Signatures are illustrative and **not implemented**; details that depend on benchmarks or prototypes are still pending. Nothing here ships in v0.1.
```python
class DataClass(StrEnum):            # declared on model fields via json_schema_extra
    PUBLIC_REFERENCE = "public_reference"
    DERIVED_ABSTRACT = "derived_abstract"
    HOST_SENSITIVE  = "host_sensitive"

@dataclass(frozen=True)
class TaskSpec:                      # an "agent" = one or more TaskSpecs; never autonomous
    task_id: str; template_version: str
    input_schema: type[BaseModel]; output_schema: type[BaseModel]
    allowed_tools: frozenset[str]    # read-only lookups only; registry has no write tools
    max_sensitivity: DataClass; allowed_providers: frozenset[str]
    budget: Budget                   # max_tokens, timeout_s, max_steps, max_tool_calls

class ProviderRouter(Protocol):      # deterministic policy; NO automatic cloud fallback (SB-16)
    def select(self, spec: TaskSpec, payload_class: DataClass) -> RouteDecision: ...

class ProviderAdapter(Protocol):     # transport called by TaskRunner, never exposed to the model as a tool
    endpoint_allowlist: frozenset[str]   # fixed scheme+host(+path) per provider; no cross-host redirects (SB-17)
    def complete(self, req: StructuredRequest, authorization: RequestAuthorization) -> StructuredResponse: ...
    # cloud adapters require a RequestAuthorization; for HOST_SENSITIVE it is per-request and
    # binds the exact payload hash + destination provider (SB-16)

class TaskRunner(Protocol):          # the only orchestrator; fixed Python flows
    def run(self, spec: TaskSpec, inputs: BaseModel) -> TaskResult: ...  # validated or fallback
```
`TaskResult` is `Validated(output, audit_id)`, `Fallback(deterministic_text, reason)`, or `Rejected(validation_errors, audit_id)`. Detection and enforcement never consume a `TaskResult` ([SB-15](security-boundaries.md)).

**Design-for items in Sprint 1** (no AI code; see [ADR 0021 §9](../adr/0021-hybrid-ai-orchestration.md)):
- stable typed entity IDs;
- field sensitivity metadata (used in v0.1 for report redaction);
- deterministic explanation text in the findings catalog;
- a `ScanService` that completes without any enrichment hook;
- import-linter contracts kept.

## Typed firewall operations (v0.4, design only)
`CreateRule | UpdateRule | DeleteRule | ExportPolicy | RestorePolicy`. Each operation carries its target rule hashes for drift detection, plus a pre-computed inverse. See [ADR 0011](../adr/0011-change-rollback-model.md).
