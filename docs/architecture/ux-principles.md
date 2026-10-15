# UX principles: beginner-first, evidence-honest

**Status: Accepted** with [ADR 0023](../adr/0023-beginner-first-ux.md) (human, 2026-10-15, with refinements). These are living guardrails. The current M1.x UI is **not** redesigned until an approved implementation milestone (UX0 design, then Sprint 3).

Like [security-boundaries.md](security-boundaries.md), these guardrails apply to every user-facing surface: the GUI first, reports (SecurityDocs) later. They never override a security boundary. **When clarity and accuracy conflict, accuracy wins and the wording changes.**

## 1. Audience and the questions every screen must answer
- **Default audience:** persona **P1, the non-expert Windows user** ([PRD §3](../planning/01-prd.md)). Assume no knowledge of firewalls, networking, ports, protocols, or security.
- **Advanced audience** (P2/P3: administrators, security professionals): full technical evidence, always reachable, never removed.
- A beginner must be able to answer, unaided:
  1. **What is being checked?**
  2. **What was found?**
  3. **Does anything need my attention?**
  4. **What is still unknown?**
  5. **What can I review or do next?**

## 2. Guardrails (UX-01 … UX-10)
| ID | Guardrail |
|---|---|
| UX-01 | **Plain language first, correct terms kept.** Primary text explains things in everyday words. Official Windows terms (for example the **Domain / Private / Public** network profiles) are **kept and explained**, not replaced by guesses about their meaning. Other technical terms appear in the technical details layer, or next to a plain explanation ("What does this mean?"). |
| UX-02 | **Progressive disclosure, never data loss.** Three layers (§3): Overview → plain-language area pages → technical details. Everything collected today stays available in the details layer. |
| UX-03 | **Two separate dimensions** (§5): *attention level* (how much something deserves the user's attention) and *evidence confidence* (how completely it was checked). They are never merged. **Unknown or incomplete evidence never produces a Review or Problem status by itself.** |
| UX-04 | **No reassurance or alarm beyond the evidence.** Never say "safe", "protected", "secure", "exposed", "vulnerable", "hacked", or "at risk" unless a verified finding supports exactly that statement. A listening app is **not** internet exposure. An Allow rule is **not** proof that traffic is permitted (SB-20). Policy results are local to this PC (N-08). Green never means "this computer is safe". |
| UX-05 | **Colour is never the only signal.** Every status has text and an icon or shape as well as colour (N-07). Colours meet WCAG 2.2 AA contrast (4.5:1 for normal text) in light and dark themes and stay distinguishable for common colour-vision deficiencies `[VERIFY thresholds in UX0]`. |
| UX-06 | **Every screen has clear states:** not checked yet, checking (what is happening, in plain words), done, partly done (what is missing and why), cancelled, and failed (what happened and what to try). No unexplained blank tables. |
| UX-07 | **Honest, short limitations.** One plain statement up front (for example "FirewallAI can only see this PC's own settings, not your router or other devices"), and the full technical list under "Learn more". Never hidden, never dumped in full on the main screen. |
| UX-08 | **Guided next steps.** Say what the user can **review** next, in plain words. v0.1 is read-only: never imply FirewallAI will change anything. |
| UX-09 | **Accessible and scalable.** Full keyboard navigation, accessible names, readable type, and layouts tested at 100/150/200 % DPI and in small windows (N-07). |
| UX-10 | **Calm, consistent, trustworthy.** One visual language; no flashing, no fake urgency, no overall "security score" (N-08); consistent placement of status, explanation, and details. |

## 3. Information layers
| Layer | For | Content |
|---|---|---|
| **1. Overview** (default home) | Everyone | Summary cards per area: **Firewall settings**, **Apps that accept connections**, **Firewall rules**, and later **Findings**. Each card shows its attention level and evidence confidence (§5), one plain sentence, and "See details". It also has a "What does FirewallAI check?" explainer and the last check time. |
| **2. Area pages** | Curious users | Grouped, readable lists, for example apps that accept connections, grouped by app, each in a plain sentence. Filters use everyday words. Each item has "What does this mean?" help. |
| **3. Technical details** | Experts | Today's tables (protocols, ports, addresses, rule filters, PIDs, evidence states, correlation checks), JSON export, and full limitations. Reached by "Show technical details" per item and an "Advanced view" switch. |

## 4. Glossary and wording rules (starting point; validated in UX0)
**Network profiles: keep the Windows names.** Windows assigns each network connection a profile. FirewallAI shows the official name with an explanation. Examples are labelled as examples, never as the meaning.

| Windows term (always shown) | Plain explanation shown with it |
|---|---|
| **Domain** network profile | "Used when this PC is connected to a network managed by an organisation's domain (for example, some workplaces)." |
| **Private** network profile | "Used for networks you have marked as trusted (for example, often a home network). Windows lets you choose this." |
| **Public** network profile | "Used for networks you have not marked as trusted (for example, often café or airport Wi-Fi). Usually the most restrictive." |
| Profile enabled | "The firewall is **on** for the {Domain/Private/Public} network profile." |
| Default incoming action: Block | "Incoming connections are **blocked unless a rule allows them**." |

**Other terms:**

| Technical term (layer 3) | Plain wording (layers 1–2) |
|---|---|
| Inbound / outbound | **Incoming** (from other devices to this PC) / **outgoing** (from this PC to the internet or other devices) |
| Firewall rule; Allow / Block | "A **rule** that tells the Windows Firewall to let a specific kind of connection in or out, or to stop it." |
| Listening TCP / bound UDP endpoint | "An **app waiting for connections** from other devices." (Protocol and port are in the details.) |
| TCP connection (established) | "An **active connection** between an app on this PC and another device." |
| Bind scope: loopback | "**Only this PC** can connect to it." |
| Bind scope: all interfaces | "It accepts connections on **every network this PC is connected to**. Whether the firewall lets them in is a separate question." |
| ActiveStore / effective policy | "The **firewall settings currently in effect** on this PC." |
| GPO / Group Policy | "Settings **managed by an organisation**." |
| Indeterminate / incomplete evidence / cannot evaluate | "**Unknown**: FirewallAI could not check this completely", plus the plain reason. |
| PID / process path / service | "**App name**", with the path and IDs in the details. |

**Firewall rule relationships (SB-20): describe possibilities, never applicability.** Labels must not imply that a rule definitely applies to an app or a connection. Every rule panel carries this sentence: *"An Allow rule does not guarantee that a connection is permitted. Other rules, the network profile, and devices outside this PC can still decide otherwise."*

| Correlation category (SB-20) | Plain label |
|---|---|
| `related` | "**Possibly relevant rule.** Its settings match this app's program and port. FirewallAI did not check whether it applies to real connections." |
| `related_with_unevaluated_conditions` | "**Possibly relevant, depending on conditions FirewallAI did not check**", followed by the conditions in plain words (for example "only on Public network profiles", "only for some remote addresses"). |
| `cannot_evaluate` | "**Unknown whether this rule is relevant**", followed by the plain reason (for example "the app's location could not be read"). |
| `not_related` | Not listed by default ("doesn't match this app"); shown in the technical details. |

**Future verdicts (Sprint 2) use the same caution.** For example, `PermittedByPolicy` becomes: "This PC's own firewall settings would let incoming connections reach this app on {profile} networks. Routers and other devices may still block them, and this does not mean anyone has connected." It is never "exposed" or "open to the internet".

## 5. Status semantics: attention level vs. evidence confidence
These are two independent dimensions, always shown with text and an icon, never colour alone.

**A. Attention level** (only from deterministic, evidence-based results):

| Level | Colour + icon | Allowed only when | Example |
|---|---|---|---|
| **Matches recommendation** | Green + check mark | One specific setting was **read completely** and matches a documented recommendation. It describes that setting only, **never the whole PC**. | "The firewall is on for the Public network profile." |
| **Information** | Blue/neutral + "i" | A neutral fact or explanation. | "12 apps are waiting for connections." |
| **Review suggested** | Amber + triangle | A **verified finding** (Sprint 2 catalog rule, complete evidence) suggests something worth looking at, with its benign explanations. | "An app accepts connections while on Public network profiles. Review whether you need this." |
| **Problem** | Red + octagon | A **verified finding** with complete evidence that the catalog marks as a confirmed misconfiguration. **Never from a listening port alone.** | "The firewall is turned off for the Public network profile." |

**B. Evidence confidence** (how completely FirewallAI could check):

| Confidence | Shown as (grey/neutral + icon, with text) | Meaning |
|---|---|---|
| **Checked** | Solid outline | All needed information was read. |
| **Partly checked** | Half outline | Some information was read; what is missing is listed. |
| **Unknown** | Question mark | Not enough information (SB-18): unreadable, not collected, cancelled, or not evaluable. |
| **Not checked yet** | Dotted outline | Nothing collected yet. |

**Rules:**
- **Unknown, Partly checked, and Not checked yet never raise the attention level** (no amber or red because of missing data). They are shown next to the attention level, never instead of it.
- Green ("Matches recommendation") requires **Checked**.
- **Until Sprint 2 delivers verified findings, only "Matches recommendation" and "Information" may appear as attention levels**, alongside the evidence-confidence indicator. "Review suggested" and "Problem" require the findings engine. No unsupported security verdicts.

**C. Mapping to the findings catalog** ([planning 05 §6](../planning/05-firewall-analysis.md): severity Info/Low/Medium/High, confidence Low/Medium/High). The UX does not redefine the catalog; it presents it. Final wording and thresholds are set in UX0.

| Catalog finding (complete evidence only, SB-18) | Attention level shown |
|---|---|
| Severity **Info** | Information |
| Severity **Low** or **Medium** | Review suggested |
| Severity **High** with confidence **High** | Problem |
| Severity **High** with confidence Low or Medium | Review suggested (with "How sure we are: …") |
| Verdict `Indeterminate` or incomplete evidence | No finding; evidence confidence **Unknown / Partly checked** with the plain reason |

- Catalog **confidence** (how reliable the finding's logic is) is shown as plain text ("How sure we are"). It is **not** the same as evidence confidence (§5B, how completely the data was read). Both are shown, neither is hidden.

## 6. Verification
- **Wording tests:**
  - extend the forbidden-claims tests (SB-20) to all layer 1–2 texts;
  - add a jargon lint that blocks unexplained layer-3 terms in layer 1–2 strings;
  - add tests that profile names appear with their explanation.
- **Status tests:**
  - every attention level maps to its evidence rule (§5A);
  - incomplete evidence never yields Review or Problem;
  - green requires Checked.
- **Accessibility checks:** keyboard-only walkthrough, accessible names, contrast measurement, screenshots at 100/150/200 % DPI, light and dark themes.
- **Beginner usability test** (planned in UX0, repeated in Sprint 3): 5 participants with no security background, think-aloud, on the prototype.
  - **Tasks:** the five questions (§1), plus three comprehension checks:
    - **C1:** "Does an app waiting for connections mean people on the internet can reach it?" Expected: not necessarily.
    - **C2:** "Does an Allow rule mean the connection is definitely permitted?" Expected: not necessarily.
    - **C3:** "What is the difference between 'Checked: matches recommendation' and 'Unknown'?" Expected: checked versus could not be verified.
  - **Pass criteria:**
    - at least 4 of 5 participants answer each of the five questions and each of C1–C3 correctly;
    - **zero** participants conclude "my computer is completely safe" or "my computer has been hacked" from any screen;
    - every misreading is recorded and fixed in the design before Sprint 3 starts.
