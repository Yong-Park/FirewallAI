# UX0: beginner-first design foundation

**Status: DRAFT, design only. Not complete and not validated.** UX0 was started with human approval on 2026-10-15, and the package was approved as a design draft (decision B). UX0 is **not** complete until the human has reviewed the wireframes **and** the beginner usability results (the usability test has **not been run**). No GUI code changes until the human approves UX0 and an implementation milestone (Sprint 3 per [ADR 0023](../../adr/0023-beginner-first-ux.md)).

It implements [ADR 0023](../../adr/0023-beginner-first-ux.md) and the guardrails **UX-01 … UX-10** in [ux-principles.md](../ux-principles.md). It does not repeat them: the glossary and status rules live there, and these documents apply them.

| Deliverable (ADR 0023 §2.4) | Document |
|---|---|
| 1. Information architecture and screen inventory | [information-architecture.md](information-architecture.md) |
| 2. Low-fidelity wireframes | [wireframes.md](wireframes.md) |
| 3. Accessible visual design tokens | [status-and-tokens.md](status-and-tokens.md) |
| 4. Status semantics (attention vs. evidence confidence) | [status-and-tokens.md](status-and-tokens.md) |
| 5. Glossary and copywriting guidelines | [copy-guide.md](copy-guide.md) (extends [ux-principles §4](../ux-principles.md)) |
| 6. Loading, empty, partial, cancelled, and error states | [copy-guide.md §4](copy-guide.md), [wireframes.md §7](wireframes.md) |
| 7. Beginner usability-test plan with measurable criteria | [usability-test-plan.md](usability-test-plan.md) |

## Four things the design always keeps apart
| Kind of statement | Meaning | How it looks | Example |
|---|---|---|---|
| **Observed fact** | Something FirewallAI read on this PC | Information `[i]`, or "Matches recommendation" `[✓]` for one completely read setting; evidence "Checked" | "The firewall is on for the Public network profile." |
| **Verified finding** (Sprint 2) | A catalog rule's conclusion from complete evidence | Review suggested `[!]` / Problem `[×]` plus the six fields | "This PC's own firewall settings would let incoming connections reach {app} on the Public network profile." |
| **Unknown / incomplete evidence** | FirewallAI could not read or evaluate everything | Evidence "Unknown" or "Partly checked" `[?]`, never a warning | "19 rules couldn't be checked completely." |
| **Actual network reachability** | Whether another device or the internet can really connect | **Never shown as known.** It is always named as outside what local firewall evidence can establish | "Whether other devices or the internet can actually reach this app can't be told from this PC's settings alone." |

## Boundaries every UX0 design respects
- **All technical evidence stays available** (layer 3). Nothing collected today is removed.
- **Read-only, non-elevated.** No design offers to change firewall settings. "What you can review next" never means "FirewallAI will fix it" (v0.1).
- **No invented assessments.**
  - No security score.
  - No "Protected" or "Safe" badge.
  - No green whole-PC verdict.
  - Green applies to one completely read setting that matches a documented recommendation (ux-principles §5A).
- **SB-18:** incomplete evidence is shown as *Unknown / Partly checked*, never as a warning or problem.
- **SB-19:** one heavy rule collection at a time. The UI shows "already running" instead of starting a second one.
- **SB-20:** rule relationships are "possibly relevant" only, with the Allow-rule caveat. No reachability claims.
- **N-07:** keyboard and colour-independent status. **N-08:** no score, no exposure claims, confidence shown.
- **N-04 stays visible:** a full rule check currently takes about half a minute on the development PC (27–35 s measured). The UI gives an honest estimate, never an exact promise, with progress, and never hides it.
- **The findings catalog** ([planning 05 §6](../../planning/05-firewall-analysis.md)) is **presented, not changed** (ux-principles §5C).

## Exit criteria
| # | Criterion | Status |
|---|---|---|
| 1 | The human reviews and approves the information architecture, wireframes, tokens, copy guide, and test plan as the design to validate | Structure approved as a **draft** (2026-10-15); final approval after the usability round |
| 2 | The beginner usability round (usability-test-plan.md) is **run** with real participants, results are recorded, and the human reviews them; misreadings are fixed or explicitly accepted | **Not met: the study has not been run** |
| 3 | Recommendations R1–R4 are decided | **Met** (human, 2026-10-15; R2 with refinements) |

Until then, UX0 stays **DRAFT**, and nothing in it is described as validated.

## Settled by the human (decision F, 2026-10-15)
- **Windows network profile names stay technically correct:** "Domain network profile", "Private network profile", "Public network profile", each with a plain-language description. Examples are labelled as examples ("for example, often…") and never presented as the meaning. The navigation label is **"Network profiles"**.
- **A beginner-friendly Overview is the default**, with optional technical details (progressive disclosure).

## Decisions R1–R4 (human, 2026-10-15): design requirements, not implemented
**R1. Advanced view: session-only. Approved.**
- The Advanced view switch applies to the current session only. Every start opens in the beginner view.
- The preference is **not persisted** until the storage/privacy design (Sprint 2 question Q5) is separately approved.
- If it is persisted later: per Windows user, in the user's profile folder, never in the install folder.

**R2. A quick check and a full check. Approved with refinements.** Future behaviour:
1. **First launch:** clearly explain what local information FirewallAI will read (network profile settings and apps waiting for or using connections; read-only; nothing leaves the PC).
2. **Explicit authorization** is obtained before the **first** automatic quick check. Nothing is read before the user agrees.
3. After authorization, the quick check may run **automatically on later launches**, controlled by a clear user setting ("Check automatically when FirewallAI opens") and always with a **Cancel** control.
4. The quick check collects **network profiles and endpoints only**, with the existing read-only, non-elevated collectors.
5. The **full firewall-rule collection stays a separate, user-initiated action**. It is never started automatically.
6. Its expected duration is explained **honestly, as an estimate**, without promising an exact completion time (for example "usually about half a minute on this PC; it can take longer").
7. Quick-check completion is **never** presented as proof that the computer is safe.
8. **No complete firewall security verdict from partial collection.** Without the rule collection, rule-dependent results stay "Not checked yet" or Unknown.
9. **SB-18, SB-19, and SB-20 are respected**, including single-flight: one heavy collection at a time, with "already running" instead of a second start.

**Dependency (R1 and R2):** remembering the authorization and the "check automatically" setting across launches **requires persisted settings**, which R1 does not yet allow. Until the storage/privacy design is approved, the authorization applies **to the current session only**: the app asks again at each launch, and nothing is stored. Persisting it is part of that separate design decision.

**R3. Prototype format. Approved.**
- **Now:** moderated walkthroughs of these text wireframes with synthetic data.
- **Later:** a clickable Qt prototype fed by synthetic fixtures, as a **separately authorized** implementation activity when Sprint 3 begins.
- The usability study is not complete, and the design is not validated, until real users have been tested.

**R4. Windows profile terminology. Approved.**
- Keep **Domain, Private, and Public** (the names Windows shows), each with a concise plain-language description and an **explicitly labelled example**.
- Never imply that a location always corresponds to a particular profile: the user and Windows decide which profile a network uses.
- Before Sprint 2 maps networks to profiles, the UI says "not checked yet" and never guesses.

## Still open
- The final wording of all copy, which is validated by the usability round.
- `[VERIFY]` the recommendation reference for "firewall on + default incoming Block" (status-and-tokens §1).
- Re-measuring colour contrast in Qt and Windows high-contrast mode (Sprint 3).
