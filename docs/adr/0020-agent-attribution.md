# ADR 0020: Agent attribution in commits

- **Status:** Accepted. Explicit human requirements, 2026-10-14:
  - rev. 3: "Track: Which AI agent contributed to a feature";
  - M0 finalization: "For Codex commits, use an appropriate AI attribution trailer documenting Codex assistance. Do not invent a personal identity or email address."
- **Decision ID:** D20 · **Date:** 2026-10-14 · **Proposed by:** human requirement, drafted by claude-code · **Decided by:** human, 2026-10-14

## 1. Problem
`AI_DEVELOPMENT.md` has to record which AI agent contributed to each change, and that record should be checkable against Git.

## 2. Decision (recommended)
Every commit an agent assists with carries an `AI-Agent` trailer plus that agent's attribution trailer:

**Claude Code**
```
AI-Agent: claude-code
Co-Authored-By: <the co-author line provided by the Claude Code session>
```

**Codex**. The human decided on 2026-10-14 not to invent a personal identity or email address.
```
AI-Agent: codex
Assisted-by: OpenAI Codex
```
- **Why `Assisted-by` for Codex:** GitHub's `Co-authored-by` convention expects a name *and email address*. Making one up would create a fake identity. `Assisted-by` is a plain informational trailer that tools such as `git interpret-trailers` and `git log --format='%(trailers)'` can still parse. GitHub does not show it as a co-author, which is acceptable.
- If OpenAI publishes an official Codex attribution identity, a superseding ADR can adopt it.
- Commits the human writes alone carry no `AI-Agent` trailer.
- The ledger is cross-checked with `git log --format='%h %s %(trailers:key=AI-Agent,valueonly)'`.

## 3. Alternatives considered
- **Recording attribution only in AI_DEVELOPMENT.md:** can't be verified against the history.
- **Separate Git identities per agent:** clutters authorship and conflicts with the human owning every commit.

## 4. Advantages and disadvantages
- **Advantages:** verifiable, greppable, and good portfolio evidence.
- **Disadvantages:** it relies on each agent remembering the trailer. A PR checklist item covers that.

## 5. Security implications
Supports accountability. No secrets go in the trailers.

## 6. Performance implications
None.

## 7. Validation
Spot-check the ledger rows against `git log` at each milestone.

## 8. What to learn
Commit trailers, and provenance tracking.
