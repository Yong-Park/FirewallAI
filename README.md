# FirewallAI
An AI-powered Windows firewall security manager for auditing network connections, analyzing firewall rules, detecting suspicious activity, and providing explainable security recommendations with human-approved remediation.

## Status

Pre-alpha (Sprint 1, milestone M1.3). FirewallAI runs **read-only**, as a **standard user**, with no network access. Today it shows:
- the effective Windows Firewall **profile** settings;
- the **rules** in the effective policy (ActiveStore), with their filters. Each filter is marked as collected, not collected, or unreadable, and is never assumed to be "Any".

It makes **no security verdicts yet**. It shows only the local firewall policy, not real-world reachability.

**Performance:** a complete rule scan currently takes about **30 s** on the development machine (about 1,600 rules). That **exceeds the 10 s target (N-04)**, and the app reports this on every full scan. The rule inventory appears after about 5 s, and the window stays responsive during collection.

Listening ports, findings, and reports come in later milestones. See the [roadmap](docs/planning/15-roadmap.md) and the [current handoff](docs/development/HANDOFF.md).

## Development

Requires Windows 10/11 x64, Python 3.12, and [uv](https://docs.astral.sh/uv/).

```
uv sync --frozen
uv run --frozen firewallai profiles          # text output (add --json for machine-readable)
uv run --frozen firewallai rules --summary   # rule scan summary (takes ~30 s; progress on stderr)
uv run --frozen firewallai rules --json      # full rule export (see the note below)
uv run --frozen firewallai-gui               # desktop window (Profiles and Rules tabs)
uv run --frozen pytest -q                    # tests (unit, security, Windows integration, UI)
uv run --frozen ruff check && uv run --frozen mypy && uv run --frozen lint-imports
```

**Note:** `firewallai rules --json` exports may contain host-sensitive information: rule names, program paths, addresses, and interface names. FirewallAI never uploads or logs them automatically. Review any export before sharing it.

Contributor and AI-agent rules: [AGENTS.md](AGENTS.md). Architecture decisions: [docs/adr/README.md](docs/adr/README.md).
