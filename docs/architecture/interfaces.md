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

## Typed firewall operations (v0.4, design only)
`CreateRule | UpdateRule | DeleteRule | ExportPolicy | RestorePolicy`. Each operation carries its target rule hashes for drift detection, plus a pre-computed inverse. See [ADR 0011](../adr/0011-change-rollback-model.md).
