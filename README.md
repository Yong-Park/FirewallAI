# FirewallAI
An AI-powered Windows firewall security manager for auditing network connections, analyzing firewall rules, detecting suspicious activity, and providing explainable security recommendations with human-approved remediation.

## Status

Pre-alpha (Sprint 1, milestone M1.1). Today FirewallAI shows the effective Windows Firewall **profile** settings, **read-only** and as a **standard user**, with no network access. Rules, listening ports, findings, and reports come in later milestones. See the [roadmap](docs/planning/15-roadmap.md) and the [current handoff](docs/development/HANDOFF.md).

## Development

Requires Windows 10/11 x64, Python 3.12, and [uv](https://docs.astral.sh/uv/).

```
uv sync --frozen
uv run --frozen firewallai profiles          # text output (add --json for machine-readable)
uv run --frozen firewallai-gui               # desktop window
uv run --frozen pytest -q                    # tests (unit, security, Windows integration, UI)
uv run --frozen ruff check && uv run --frozen mypy && uv run --frozen lint-imports
```

Contributor and AI-agent rules: [AGENTS.md](AGENTS.md). Architecture decisions: [docs/adr/README.md](docs/adr/README.md).
