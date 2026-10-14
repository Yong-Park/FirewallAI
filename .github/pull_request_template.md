## Summary
<!-- What and why. Link the task, issue, or ADR. -->

## AI assistance
- Agent(s): <!-- claude-code / codex / none -->
- Scope of AI help: <!-- design / code / tests / docs -->
- [ ] Commits carry `AI-Agent:` trailers ([ADR 0020](../docs/adr/0020-agent-attribution.md))
- [ ] An `AI_DEVELOPMENT.md` ledger row was added or updated (review fields stay **pending** until the human reviews)

## Tests and evidence
<!-- Paste only commands actually run, with the commit SHA and an output excerpt. Write "not run" otherwise. -->
```
$ uv run pytest -q        # SHA:
$ uv run mypy             # SHA:
$ uv run ruff check       # SHA:
```
- [ ] No new `skip`/`xfail`, `type: ignore`, or `noqa`, and no lowered thresholds (or each one is justified below)

## Security impact
- [ ] Touches privilege, network, AI, subprocess, or untrusted input → explain below
- [ ] Preserves all invariants in [security-boundaries.md](../docs/architecture/security-boundaries.md)
- [ ] No secrets, credentials, or unsanitized machine data committed
- [ ] No firewall or system modification outside a disposable VM

## Docs
- [ ] `docs/architecture/` updated if interfaces or structure changed
- [ ] ADR added if architecture changed
- [ ] `docs/development/HANDOFF.md` updated

## Human review (filled in by the human only)
- [ ] Diff reviewed by the human owner
