# 13: Testing Strategy and Quality Gates

Status: Approved plan rev. 3, frozen snapshot. Covers deliverable (12) and the rev. 3 quality gates.

## 1. Test layers

| Layer | Scope | Where it runs | Tools |
|---|---|---|---|
| Unit | `core` (policy eval, verdicts, findings, diff), parsers, validators | CI + local | pytest, hypothesis |
| Fixture-driven | Collectors' parsing from **recorded, sanitized** JSON captures (real machines and VMs), plus synthetic edge cases: GPO-merged, third-party firewall, IPv6-only, multi-NIC/multi-profile, about 3,000 rules | CI + local | pytest |
| Verdict truth table | About 40 scenarios ([05 §5](05-firewall-analysis.md)) | CI + local | pytest (parametrized YAML) |
| Contract / integration (read-only) | Real collectors return schema-valid data on a real Windows host | GitHub `windows-latest` runner + local | pytest |
| UI | Views load, workers don't block, accessibility names exist | CI (offscreen) + local | pytest-qt |
| Security | Injection corpus (PowerShell params, report HTML, AI prompts), read-only script verb scan, log redaction, zero-egress test | CI | pytest, bandit |
| AI eval (v0.2) | Golden set + injection corpus ([09 §7](09-ai-integration.md)) | CI (recorded) + local (live) | pytest |
| Performance | Scan time, report rendering time, AI latency (v0.2) | Local + VM, results recorded | pytest-benchmark + scripts |
| Packaging smoke | Install → scan → export → uninstall on clean VMs | Hyper-V VMs | Manual checklist (later scripted) |
| Real-behavior | Verdicts vs. actual reachability, two-VM topology | Hyper-V | Scripted probes |

**Fixture hygiene:** the fixture recorder runs a sanitizer that replaces hostnames, usernames, domain names, MACs, and public IPs before anything is committed. Raw captures never enter the repository. gitleaks and a custom check scan the fixtures.

## 2. Quality gates (identical for human and AI-generated code)

- **pre-commit (local):** `ruff format --check`, `ruff check`, `mypy` (strict on `core`), `gitleaks`.
- **CI (required before merge):**
  - ruff, mypy, pytest (unit + fixtures + security + UI), coverage (`core` ≥ 85%);
  - import-linter contracts, pip-audit, bandit, CodeQL, gitleaks;
  - CycloneDX SBOM;
  - Dependabot alerts reviewed.
- **No weakening:** new `skip`/`xfail`, `type: ignore`, or `noqa` entries, or lowered thresholds, require written justification and human approval. CI rejects new skip/xfail markers under `tests/security/` and `tests/ai_eval/` unless the PR carries a label the human applies.
- **Evidence rule:** a result is reported as "passed" only for commands actually run, citing the command, the commit SHA, and an output excerpt. CI is the source of truth for merges.

## 3. Windows VM testing

| VM | Purpose |
|---|---|
| `fwai-win11-clean` (Hyper-V, baseline checkpoint) | Packaging smoke tests, read-only scans |
| `fwai-win10-22h2-clean` | Best-effort compatibility |
| `fwai-win11-gpo` (optional: local GPO or a small AD lab) | GPO merge scenarios |
| `fwai-win11-3pfw` | Third-party firewall installed |
| `fwai-probe` | Probe client for real-behavior tests (internal switch) |
| Windows Sandbox | Fast disposable read-only runs |

- Revert to the baseline checkpoint after every run.
- **All firewall write tests (v0.4+) and monitoring prototypes run only in these VMs.**
- Dev builds refuse writes unless `FIREWALLAI_ALLOW_WRITES=1` is set *and* VM detection passes.
- **[PENDING VERIFICATION] Hyper-V availability on the dev machine** has not been confirmed (human, 2026-10-14). VM testing **remains a requirement**. If Hyper-V turns out to be unavailable, choose an alternative (e.g. VirtualBox or VMware Workstation, or a second physical test machine) and record it in a new ADR before any VM-dependent task. Windows 11 Pro supports Hyper-V, but the feature, CPU virtualization, and disk space have not been checked.

## 4. Test environments

These are **test-environment descriptions, not product minimum requirements.** Product requirements live in [02 §2](02-requirements.md) (N-09, Windows 10/11 x64). Hardware guidance for local AI is published only after benchmarking ([09 §4](09-ai-integration.md)).

| ID | Environment | Observed specs (2026-10-14, read-only queries) | Used for |
|---|---|---|---|
| TE-1 | Development machine (primary; **never** used for firewall writes or networking components) | Windows 11 Pro (build 26200), NVIDIA RTX 3080 10 GB VRAM, 16 GB RAM, Ollama 0.34.4, Python 3.12 available | Read-only scans, local AI benchmarks (v0.2), development |
| TE-2… | Hyper-V VMs in §3 | Defined when created; Hyper-V **pending verification** | Packaging, compatibility, all write and monitoring tests |
| CI | GitHub `windows-latest` runner | Per GitHub's runner image documentation | Automated gates and read-only contract tests |

## 5. Benchmarks
Record the hardware, OS build, rule count, command, commit SHA, and the raw numbers. **A number that wasn't measured is never written into docs or the README.**
