# 03: Software Architecture

Status: Approved plan rev. 3, frozen snapshot of the *rationale*. The current implementation reference lives in [../architecture/](../architecture/). Covers deliverables (4) architecture, (5) Mermaid diagrams, and (14) folder structure.

## 1. Architectural style

- **Layered, ports-and-adapters architecture with dependencies pointing inward.**
- `core` is pure. It holds the domain models and the logic for policy evaluation, verdicts, findings, and diff, and it has no I/O.
- Platform access sits behind `Protocol` interfaces in `collectors`. A fixture-backed fake implementation lets most logic be tested without Windows.
- The GUI and CLI both call one application-service layer (`app`).
- Privileged operations (v0.4+) run in a **separate process** and never in the UI or AI process.

Why: the core is testable, platform quirks are isolated, the AI and docs packages can be extracted later, and the privilege boundary is clear.

## 2. Diagrams

### 2.1 System context (C4 level 1)
```mermaid
flowchart LR
  user([User: P1/P2/P3])
  fwai[FirewallAI desktop app]
  win[(Windows Firewall / WFP<br/>Network stack / SCM / WMI)]
  ollama[Ollama local server<br/>v0.2+, optional]
  cloud[Optional cloud LLM<br/>off by default, consent required]
  gh[GitHub Releases]
  user -->|uses| fwai
  fwai -->|read-only queries v0.1| win
  fwai -.->|loopback HTTP v0.2| ollama
  fwai -.->|opt-in, redacted| cloud
  user -->|downloads installer| gh
```

### 2.2 Containers (all versions)
```mermaid
flowchart TB
  subgraph UserSession[Standard user session - never elevated]
    ui[PySide6 GUI]
    cli[CLI]
    app[App services]
    core[Core: policy eval, verdicts, findings]
    coll[Collectors: PowerShell runner, psutil, WMI]
    docs[SecurityDocs renderer]
    ai[AI advisor v0.2: providers, validator]
    db[(SQLite in %LOCALAPPDATA%)]
    ui --> app
    cli --> app
    app --> core
    app --> coll
    app --> docs
    app --> ai
    app --> db
  end
  subgraph Elevated[Elevated / service context - v0.4+]
    helper[Privileged helper v0.4<br/>typed allowlisted ops]
    svc[Monitoring service v0.5]
  end
  app -.->|named pipe, typed ops, user approval| helper
  svc -.->|alerts via named pipe| app
  ai -.->|loopback| ollama[(Ollama)]
```

### 2.3 v0.1 components
```mermaid
flowchart LR
  subgraph collectors
    psr[powershell_runner] --> fwc[FirewallCollector]
    netc[NetworkCollector psutil]
    procc[ProcessCollector]
    svcc[ServiceCollector]
    scc[SecurityCenter collector]
  end
  subgraph core
    snap[Snapshot model]
    eff[Effective policy evaluator]
    ver[Verdict engine]
    fnd[Findings engine + catalog]
    dif[Diff]
  end
  fwc & netc & procc & svcc & scc --> snap
  snap --> eff --> ver --> fnd
  snap --> dif
  fnd --> rep[SecurityDocs: HTML / Qt PDF / JSON]
  snap --> store[(SQLite)]
  fnd --> store
```

### 2.4 Scan sequence (v0.1)
```mermaid
sequenceDiagram
  actor U as User
  participant UI as GUI (main thread)
  participant W as Worker (QThreadPool)
  participant S as ScanService
  participant C as Collectors
  participant K as Core
  participant D as SQLite
  U->>UI: Click "Scan"
  UI->>W: start scan job
  W->>S: run_scan()
  S->>C: profiles(), rules(), endpoints(), services(), securitycenter()
  C-->>S: CollectorResults (data or structured errors)
  S->>K: build Snapshot -> evaluate -> findings
  K-->>S: verdicts, findings, limitations
  S->>D: persist scan
  S-->>W: ScanResult
  W-->>UI: signal finished(result)
  UI-->>U: Overview + Findings + Limitations
```

### 2.5 Future change request (v0.4, design)
```mermaid
sequenceDiagram
  actor U as User
  participant AI as AI advisor
  participant V as Validator (deterministic)
  participant UI as GUI
  participant H as Elevated helper
  participant FW as Windows Firewall
  AI->>V: proposed typed operation (proposal only)
  V->>V: allowlist, least privilege, protected connectivity
  V-->>UI: valid proposal + before/after diff
  U->>UI: explicit approval
  UI->>H: signed change set + target rule hashes (named pipe)
  H->>H: re-validate, drift check (abort if changed)
  H->>FW: apply operations
  H->>FW: read back and verify
  H->>H: append hash-chained audit entry, store inverse ops
  H-->>UI: result, auto-revert timer starts
  U->>UI: "Keep changes" (otherwise auto-rollback)
```

### 2.6 Trust boundaries
```mermaid
flowchart LR
  subgraph TB1[TB1: untrusted external data]
    rn[Rule names / descriptions]
    pn[Process names / paths]
    hn[Remote hosts]
    rd[Reference documents]
  end
  subgraph TB2[TB2: FirewallAI user process]
    val[Validation - pydantic]
    corez[Core]
    aiz[AI layer]
  end
  subgraph TB3[TB3: local model server]
    ol[Ollama - unauthenticated API]
  end
  subgraph TB4[TB4: privileged - v0.4+]
    hp[Helper / Service]
  end
  subgraph TB5[TB5: external services - opt-in]
    cl[Cloud LLM]
  end
  rn & pn & hn & rd --> val --> corez
  corez --> aiz
  aiz <-->|loopback| ol
  aiz -.->|consent + redaction| cl
  corez -.->|typed ops + approval| hp
```

## 3. Key design rules

- `core` imports nothing platform-specific. Collectors return validated pydantic models.
- `CollectorResult` carries data or structured errors, so partial data is explicit.
- The UI does all long work in `QThreadPool` workers and communicates through signals. No blocking calls run on the main thread.
- The `ai` and `securitydocs` packages don't depend on FirewallAI-specific modules ([ADR 0013](../adr/0013-shared-package-extraction.md)).
- The privileged component is a separate process, and its operation schema is shared ([07](07-security-model.md)).

## 4. Repository folder structure (target)

```
FirewallAI/
├─ AGENTS.md  CLAUDE.md  AI_DEVELOPMENT.md  README.md  LICENSE
├─ pyproject.toml  uv.lock                         (Sprint 1)
├─ src/firewallai/
│  ├─ app/          application services
│  ├─ core/         models/, effective_policy/, verdicts/, findings/ (catalog YAML + rules), diff/
│  ├─ collectors/   windows/ (powershell_runner, firewall, network, process, service, securitycenter, scripts/*.ps1), fake/
│  ├─ storage/      repository, migrations/
│  ├─ securitydocs/ model, templates/, renderers/
│  ├─ references/   registry data + loader
│  ├─ ai/           (v0.2) providers/, redaction, consent, schemas, validator, eval/
│  ├─ ui/           views/, models/, theme/, onboarding/
│  └─ cli/
├─ tests/  unit/ integration/ ui/ security/ ai_eval/ fixtures/ benchmarks/
├─ packaging/  pyinstaller/ inno/ manifest/
├─ scripts/    fixture recorder + sanitizer, benchmarks
├─ docs/  planning/ architecture/ adr/ development/ user/
└─ .github/  workflows/ pull_request_template.md
```
