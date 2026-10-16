# UX0 beginner usability-test plan (draft)

**Status: PLAN ONLY. Not run.** No participant results exist. Results are recorded only after a real, human-run session (§5).

This plan implements [ux-principles §6](../ux-principles.md) and [ADR 0023 §7](../../adr/0023-beginner-first-ux.md). It is run on the UX0 wireframes (static walkthrough, recommendation R3), again in Sprint 3 on the clickable Qt prototype and the implemented UI, and in Sprint 4 on the release candidate.

## 1. Participants and ethics
- **5 participants** with no security or networking background (they don't work in IT or security and have never configured a firewall).
- **Synthetic data only:** the prototype and app use fixture data (`--fixture` modes), never the participant's PC. Nothing about participants' computers is collected.
- **Consent:** verbal or written consent. Notes are anonymised (P1–P5) with no recordings unless consented. Results are summarised in HANDOFF/AI_DEVELOPMENT without personal data.

## 2. Protocol
- 30–40 minutes, think-aloud, moderator does not explain the UI.
- Fixed scenario: a fixture PC with:
  - firewall on for all profiles;
  - several listening apps (one loopback-only, one all-interfaces);
  - rules including one "possibly relevant" Allow rule with unevaluated conditions;
  - 19 rules Unknown;
  - in Sprint 2 runs, one "Review suggested" finding.

## 3. Tasks and questions
| ID | Question or task | Correct understanding (scored) |
|---|---|---|
| Q1 | "What is FirewallAI checking on this PC?" | The firewall settings, apps waiting for connections, and rules, read-only, on this PC |
| Q2 | "What did it find?" | Firewall on for the profiles; apps waiting; rule counts; (Sprint 2) the finding |
| Q3 | "Does anything need your attention?" | Nothing verified needs attention before Sprint 2; (Sprint 2) the one review item, without exaggeration |
| Q4 | "What is still unknown?" | Some rules couldn't be checked completely; reachability beyond this PC |
| Q5 | "What could you review next?" | Names a review step from the screen; does not expect FirewallAI to change anything |
| C1 | "This app is waiting for connections. Can people on the internet reach it?" | **Not necessarily**; it also depends on the firewall, the router, and the network |
| C2 | "This rule lets connections in for the app. Is the connection definitely permitted?" | **Not necessarily**; other rules, the profile, and outside devices can decide otherwise |
| C3 | "What's the difference between 'Matches recommendation (Checked)' and 'Unknown'?" | Checked means read and verified; Unknown means not verified, and is not a warning |
| T1 | Find the network profile that FirewallAI describes as often used for untrusted networks (its example mentions café Wi-Fi). Does a café network always use that profile? | Finds the Public network profile; answers **not necessarily**: the example is only an example, and the profile depends on how the network was set up in Windows |
| T2 | Open technical details for an app, then return | Succeeds with mouse **and** with keyboard only |

## 4. Measures and pass criteria
- **Correctness:** at least **4 of 5** participants correct on **each** of Q1–Q5 and C1–C3.
- **No misleading conclusions:** **zero** participants state or agree that "my computer is completely safe" or "my computer has been hacked" based on a screen. Any occurrence fails the round, and the screen is redesigned.
- **Findability:** at least 4 of 5 complete T1 and T2 within 2 minutes each, without help.
- **Confidence vs. accuracy:** record the participant's confidence (1–5) per C-question. High confidence in a wrong answer is flagged as a design defect.
- **Defect log:** every misreading becomes an issue with the screen, wording, and fix. All are resolved or explicitly accepted by the human before Sprint 3 implementation is accepted.

## 5. Reporting
Results go in HANDOFF.md and AI_DEVELOPMENT.md (anonymised): per-question scores, misreadings, fixes. Results are marked as human-run. Agents never claim usability results that weren't run.
