# ADR 0015: Documentation organization: planning snapshot vs. living architecture

- **Status:** Accepted. Explicit human requirement (rev. 3 feedback, 2026-10-14): "Maintain the existing planning documentation and ADR structure. Add or organize `docs/architecture/` as the central location for implementation-oriented architectural references. Avoid copying the same information into multiple files… Architecture changes must be documented through ADRs before significant implementation changes."
- **Decision ID:** D15 · **Date:** 2026-10-14 · **Proposed by:** human requirement, drafted by claude-code · **Decided by:** human, 2026-10-14

## 1. Problem
Two agents and a human need one place for the *current* architecture without duplicating the planning documents, because duplicated docs drift apart.

## 2. Decision (recommended)
| Location | Holds | How it changes |
|---|---|---|
| `docs/planning/` | The approved proposal and the *why* | Frozen after approval; errata only |
| `docs/adr/` | Individual decisions | New ADR per change; old ones are superseded, never deleted |
| `docs/architecture/` | The *current how*: module map, invariants, interfaces | Updated in the same PR as the code |
| `docs/development/` | Process and live state (HANDOFF, AGENT_WORKFLOW) | Every session |
| `AGENTS.md` / `CLAUDE.md` | Agent rules, made of links to the above | Only with human approval |

Rule: a fact lives in exactly one place. Everywhere else links to it.

## 3. Alternatives considered
- **Keep updating the planning docs:** history gets lost and the planning docs mix intent with the current state.
- **A wiki:** not versioned with the code, and not visible to agents.

## 4. Advantages and disadvantages
- **Advantages:** clear ownership, and agents load small, current docs.
- **Disadvantages:** some navigation overhead.

## 5. Security implications
[security-boundaries.md](../architecture/security-boundaries.md) is the one authoritative list of invariants.

## 6. Performance implications
None.

## 7. Validation
At the milestone review, grep for content duplicated between `AGENTS.md` and `docs/`, and check for broken links.

## 8. What to learn
Docs-as-code and the C4 model's levels of documentation.
