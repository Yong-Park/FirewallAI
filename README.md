# FirewallAI
An AI-powered Windows firewall security manager for auditing network connections, analyzing firewall rules, detecting suspicious activity, and providing explainable security recommendations with human-approved remediation.

## Status

Pre-alpha (Sprint 1, milestone M1.4). FirewallAI runs **read-only**, as a **standard user**, with no network access. Today it shows:
- the effective Windows Firewall **profile** settings;
- the **rules** in the effective policy (ActiveStore), with their filters. Each filter is marked as collected, not collected, or unreadable, and is never assumed to be "Any";
- local **listening TCP and bound UDP endpoints and TCP connections** (IPv4 and IPv6), with the owning process and its services where Windows allows reading them. Unavailable details are shown with the reason;
- for a selected listening/bound endpoint, the **related firewall rules**, described only: a related rule's filters are consistent with the endpoint, which does **not** mean that traffic is permitted or that the endpoint is reachable.

It makes **no security verdicts yet**. It shows only the local firewall policy, not real-world reachability.

**Performance:** a complete rule scan currently takes about **30 s** on the development machine (about 1,600 rules). That **exceeds the 10 s target (N-04)**, and the app reports this on every full scan. The rule inventory appears after about 5 s, and the window stays responsive during collection.

An endpoint snapshot takes about 0.7-0.9 s when warm, but 1.3-1.7 s on a cold first run, so the 1 s target is **not consistently met**. Firewall profiles per network interface are not mapped yet. Findings and reports come in later milestones. See the [roadmap](docs/planning/15-roadmap.md) and the [current handoff](docs/development/HANDOFF.md).

## Development

Requires Windows 10/11 x64, Python 3.12, and [uv](https://docs.astral.sh/uv/).

```
uv sync --frozen
uv run --frozen firewallai profiles          # text output (add --json for machine-readable)
uv run --frozen firewallai rules --summary   # rule scan summary (takes ~30 s; progress on stderr)
uv run --frozen firewallai rules --json      # full rule export (see the note below)
uv run --frozen firewallai endpoints         # local sockets (remote addresses hidden)
uv run --frozen firewallai endpoints --show-remote --listening   # explicit options
uv run --frozen firewallai-gui               # desktop window (Profiles, Rules, Network)
uv run --frozen pytest -q                    # tests (unit, security, Windows integration, UI)
uv run --frozen ruff check && uv run --frozen mypy && uv run --frozen lint-imports
```

**Note:** `firewallai rules --json` exports may contain host-sensitive information: rule names, program paths, addresses, and interface names. FirewallAI never uploads or logs them automatically. Review any export before sharing it.

**Note:** `firewallai endpoints --json` contains host-sensitive data: local and remote IP addresses (including the peers of active connections), process names and paths, and service names. Keep it local and do not share it publicly. Text output hides remote addresses unless you pass `--show-remote`. Process command lines and owners are never collected.

Contributor and AI-agent rules: [AGENTS.md](AGENTS.md). Architecture decisions: [docs/adr/README.md](docs/adr/README.md).
