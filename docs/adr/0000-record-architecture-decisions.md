# ADR 0000: Record architecture decisions

- **Status:** Accepted. Accepted as part of the planning rev. 3 approval; the human approved the plan, including the ADR structure, on 2026-10-14.
- **Date:** 2026-10-14
- **Proposed by:** claude-code

## 1. Problem
Two AI coding agents (Claude Code and Codex) and one human make decisions in turns. If decisions live only in chat transcripts, the reasoning is lost between sessions and agents.

## 2. Decision
- Record every significant architecture, security, technology, or process decision as an ADR in `docs/adr/`, using [template.md](template.md).
- **ADR number = decision number.** ADR `NNNN` records decision `DNN` from [17-decisions-for-approval.md](../planning/17-decisions-for-approval.md). New decisions continue from D21 / 0021.
- Only the human can move an ADR to **Accepted**, **Rejected**, or **Superseded**. Agents may draft ADRs as **Proposed**.
- Accepted ADRs are never rewritten. A change requires a new ADR that supersedes the old one.
- A significant implementation change needs an Accepted ADR first.

## 3. Alternatives considered
- Decisions recorded only in planning docs: these become stale and have no per-decision status.
- GitHub issues or discussions: not versioned with the code, and not visible to agents offline.

## 4. Advantages and disadvantages
- **Advantages:** a lightweight, reviewable decision history that fits in a PR. It gives both agents the same context.
- **Disadvantages:** small writing overhead. It needs discipline to keep statuses current.

## 5. Security implications
Security decisions, such as privilege boundaries, become explicit and reviewable. Weakening one requires a visible superseding ADR.

## 6. Performance implications
None.

## 7. Validation
At each milestone, review: every architecture change merged since the previous milestone has an ADR. This is in the v0.1 Definition of Done.

## 8. What to learn
- Michael Nygard, "Documenting Architecture Decisions" (2011).
- adr.github.io.
