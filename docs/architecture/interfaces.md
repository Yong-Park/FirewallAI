# Interfaces and contracts

Status: **planned**. Signatures are illustrative until implemented, and this page will be filled in as code lands. Rationale: [../planning/03-architecture.md](../planning/03-architecture.md), [../planning/09-ai-integration.md](../planning/09-ai-integration.md).

## Collectors (`collectors`, v0.1)
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
