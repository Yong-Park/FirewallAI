# ADR 0023: Beginner-first, evidence-honest user experience

- **Status:** Accepted (human, 2026-10-15), with the refinements recorded in §2.6
- **Decision ID:** D23 (see the [living index](README.md))
- **Date:** 2026-10-15
- **Proposed by:** human requirement (2026-10-15), drafted by claude-code
- **Decided by:** human, 2026-10-15: "Approve the beginner-first UX direction, subject to the refinements" and "Approve UX-01 through UX-10, subject to consistency with existing security boundaries and the changes below"; UX0 milestone approved; Sprint 2 plain-language finding requirements approved; no redesign of the current UI now.

## 1. Problem
The M1.1–M1.5 interface presents raw technical data: profile settings, rule filter tables, protocol/port/address tables, evidence states, and long technical limitation lists. That suits firewall experts and developers. It does not suit the PRD's first persona, the **non-expert Windows user** (P1: "plain-language status, no jargon, no fear-mongering"; [PRD §3](../planning/01-prd.md)).

The roadmap has a "full GUI" in Sprint 3, but no binding design principle, no information architecture, and no user validation for non-experts.

The human set this as a product-level requirement on 2026-10-15: FirewallAI must be understandable to someone with **no** knowledge of firewalls, networking, ports, protocols, or security, **without** sacrificing technical accuracy, transparency, or security.

## 2. Decision
### 2.1 Guardrails
Every user-facing surface (GUI first, reports later) follows **UX-01 … UX-10** in [docs/architecture/ux-principles.md](../architecture/ux-principles.md):
- plain language first, with correct terms kept;
- three-layer progressive disclosure with **no data loss**;
- **attention level kept separate from evidence confidence**;
- no reassurance or alarm beyond the evidence;
- colour never the only signal;
- clear screen states;
- short, honest limitations;
- guided review steps;
- accessibility at 100–200 % DPI;
- a calm, consistent visual language.

### 2.2 Security accuracy is mandatory and overrides wording
SB-18 (no verdict from incomplete evidence), SB-20 (descriptive correlation only; an Allow rule is not proof that traffic is permitted; no reachability claims), and N-08 (no single score, no external-exposure claims) bind the UX. A clearer screen may never claim more than the evidence. Analysis stays **deterministic and evidence-based**.

### 2.3 Sprint 2 (findings)
Every catalog finding carries plain-language fields alongside its technical evidence, and tests check them:
1. **What was observed**;
2. **Why it may matter**;
3. **When the observation can be normal**;
4. **What evidence supports the conclusion**;
5. **What is still unknown**;
6. **What the user can review next**.

"Indeterminate" verdicts and incomplete evidence map to the evidence-confidence dimension (**Unknown / Partly checked**), never to a raised attention level.

### 2.4 New milestone UX0, "Beginner-first UX foundation" (design only, before Sprint 3)
**Deliverables:**
1. information architecture and screen inventory;
2. low-fidelity wireframes (Overview, area pages, technical-details layer);
3. accessible visual design tokens (colour, icon, type, spacing; light and dark; contrast-checked);
4. clear status semantics: attention level vs. evidence confidence, with severity rules;
5. glossary and copywriting guidelines;
6. loading, empty, partial, cancelled, and error states;
7. a beginner usability-testing plan with measurable acceptance criteria (ux-principles §6).

**Exit:** the human approves the deliverables. The usability plan is in place; it is run on the prototype, with results recorded, before Sprint 3 implementation is accepted.

### 2.5 Sprint 3 and Sprint 4; current UI
- **Sprint 3** implements the approved UX0 designs. It adds wording, jargon, and status-mapping tests and an accessibility pass. Today's tables become the technical-details layer.
- **Sprint 4:** user documentation uses the same glossary, and the usability test is repeated on the release candidate.
- **Current UI:** **no redesign now.** The existing functional M1.x UI stays intact until an approved implementation milestone.

### 2.6 Refinements required by the human (2026-10-15), incorporated
1. **Network profiles:** keep the Windows **Domain / Private / Public** profile names, with plain explanations and examples labelled as examples. Do not replace them with "Work / Home / Café Wi-Fi".
2. **Rule relationships:** use labels that express **possible** relationships and unverified conditions ("Possibly relevant rule …"). Never imply a rule definitely applies. Always state that a matching Allow rule does not guarantee a connection is permitted (SB-20).
3. **Status and colour:** evidence confidence is separate from severity/attention. Unknown or incomplete evidence never automatically yields a warning or critical status. Green never implies the whole device is safe. Icons and text always accompany colour. Until Sprint 2 verified findings exist, no unsupported security verdicts are shown.
4. **Usability testing:** in addition to the five beginner questions, test the understanding that:
   - a listening port is not necessarily internet exposure;
   - an Allow rule is not necessarily permitted traffic;
   - a checked configuration differs from an unknown one.

   Misleading conclusions ("my computer is completely safe", "my computer has been hacked") must not occur.

## 3. Alternatives considered
| Alternative | Why not chosen |
|---|---|
| Keep the expert UI; explain it in a manual | Beginners don't read manuals first. It fails the five-question test. |
| A separate "Simple mode" toggle, with the expert UI as default | Beginners land in the expert view first. Two parallel UIs drift apart and double the testing. |
| Remove technical data for simplicity | Loses transparency for P2/P3 and contradicts evidence provenance. |
| Redesign immediately in M1.5/M1.6 | No findings engine yet, and design without user validation risks rework. UX0 first is cheaper. |
| An overall security score or traffic light for the whole PC | Prohibited by N-08. It implies certainty the evidence cannot give. |

## 4. Advantages and disadvantages
**Advantages:**
- serves the target persona;
- keeps expert transparency;
- the separate attention and confidence dimensions make honesty testable;
- design is validated with real beginners before implementation.

**Disadvantages:**
- adds a design milestone and copy work to every feature;
- simplifying security language needs careful review to stay accurate;
- some findings are hard to explain briefly.

## 5. Security implications
- **Main risk: misleading simplification.** False reassurance or false alarm both harm users. Mitigation:
  - the separate status dimensions;
  - evidence rules for every attention level;
  - forbidden-claims and jargon tests;
  - comprehension checks C1–C3 in usability testing;
  - SB-18/SB-20 tests stay authoritative.
- **Dark patterns** (urgency, fear) are prohibited (UX-10).
- **Privacy:** layer 1–2 summaries show app names, not paths or addresses. Host-sensitive data stays in the details layer and exports, with the existing sensitivity notes.

## 6. Performance implications
Summary cards reuse the precomputed, worker-thread pattern (M1.3/M1.4). GUI responsiveness (< 100 ms) still applies. N-04 stays visible as an honest progress/limitation message; summaries must not hide that a scan is slow.

## 7. Validation
- **UX0:** deliverables approved by the human, and the usability-test plan with measurable criteria in place (ux-principles §6).
- **Sprint 3:**
  - automated wording, jargon, and status-mapping tests;
  - accessibility pass (keyboard, contrast, DPI 100/150/200 %, light/dark);
  - the usability test run on the implemented UI: at least 4 of 5 participants correct on each of the five questions and C1–C3, and zero "completely safe"/"hacked" conclusions.

## 8. What the developer needs to learn
- Information architecture and progressive disclosure.
- Plain-language writing guidelines.
- WCAG 2.2 AA (contrast, non-colour cues, keyboard).
- Qt accessibility and high-DPI behaviour.
- Lightweight usability testing (think-aloud, task success, comprehension checks).

## Open items
- Name of the "Advanced view" switch, and whether it is remembered per user (UX0).
- `[VERIFY]` exact WCAG 2.2 contrast thresholds and Windows 11 high-contrast behaviour with Qt (UX0).
- Optional copy quick-wins for the existing M1.x screens: **not now** (human decision 5). Revisit only with an approved implementation milestone.
