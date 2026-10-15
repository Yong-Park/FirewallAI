# Architecture reference (living)

This folder describes **how FirewallAI is built right now**. It changes in the same pull request as the code it describes.

| You want… | Go to |
|---|---|
| Why the architecture looks like this (the approved rationale, frozen) | [../planning/03-architecture.md](../planning/03-architecture.md) and the related planning docs |
| An individual decision and its status | [../adr/](../adr/) |
| Packages, responsibilities, and allowed dependencies | [module-map.md](module-map.md) |
| Invariants every change must keep | [security-boundaries.md](security-boundaries.md) |
| User-experience guardrails (beginner-first, evidence-honest; ADR 0023) | [ux-principles.md](ux-principles.md) |
| Interfaces and contracts between layers | [interfaces.md](interfaces.md) |
| Current project state and handoff | [../development/HANDOFF.md](../development/HANDOFF.md) |

**Status (2026-10-14):** no code exists yet. These pages describe the **intended** structure from the approved plan, and every item is marked *planned*. When code lands, each item is changed to *implemented*, or the page is corrected to match reality.

Rules:
- A fact lives in exactly one place ([ADR 0015](../adr/0015-documentation-split.md)). Every other mention links to it.
- If the code and these docs disagree, the docs are a bug. Fix one or the other in the same PR.
- A significant architectural change needs an ADR before the code.
