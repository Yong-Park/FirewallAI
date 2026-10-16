# UX0 information architecture (draft)

Applies [ux-principles.md](../ux-principles.md) (layers §3, glossary §4, status §5).

## 1. Navigation (left side bar, keyboard-reachable; labels with icons)
| # | Section | Answers | Collected today by | Status today |
|---|---|---|---|---|
| 1 | **Overview** (home) | All five beginner questions, at a glance | Summaries of 2–5 | New screen (Sprint 3) |
| 2 | **Network profiles** | "Is the Windows Firewall on, and how does it treat incoming connections on each network profile?" | M1.1 profiles | Exists as an expert table |
| 3 | **Apps and connections** | "Which apps are waiting for connections from other devices, and which are connected right now?" | M1.4 endpoints | Exists as an expert table |
| 4 | **Firewall rules** | "Which rules are configured, and which might be relevant to an app?" | M1.3 rules + M1.4 correlation | Exists as an expert table |
| 5 | **Findings** (from Sprint 2) | "Is there anything worth reviewing, and why?" | Sprint 2 engine | Not yet; shows an honest "not available yet" state |
| 6 | **Settings and help** | Help, glossary, privacy, "About this check", Advanced view | — | New |

Scan history, reports, and onboarding (F1-12, F1-13, US-10) are added in their own milestones. Their entry points appear in the navigation only when they exist; there are no dead links.

## 2. Screen inventory and layers
| Screen | Layer 1 (beginner default) | Layer 2 (explanations) | Layer 3 (technical details, "Show technical details" / Advanced view) |
|---|---|---|---|
| Overview | Four cards: Network profiles, Apps and connections, Firewall rules, Findings. Each has an attention level, evidence confidence, one sentence, "See details". Last-checked time; "What does FirewallAI check?"; and a short "What FirewallAI can't tell" line (actual reachability from other devices or the internet) | Card help texts | — |
| Network profiles | One row per Domain/Private/Public profile: "The firewall is on", and "Incoming connections are blocked unless a rule allows them" | "What is a network profile?" (Windows names kept, examples labelled), "What does 'default incoming action' mean?" | Raw profile settings, logging, merge flags, disabled interfaces, source, timing |
| Apps and connections | **Grouped by app**: "Waiting for connections" (listening/bound) and "Connected now" (active connections). Each app shows who can connect in plain words ("only this PC" / "every network this PC is on") | "Does this mean people on the internet can reach it? Not necessarily…" (C1), per-app explanation | Protocol, family, local/remote addresses and ports, TCP state, PID, path, services, bind scope, attribution state, limitations, JSON |
| App detail | "{App} is waiting for connections on {n} ports", plus "Rules that may be relevant" (possible only) | Allow-rule caveat (C2), why the result is Unknown where applicable | Correlation checks per rule, unevaluated conditions, evidence states |
| Firewall rules | Summary counts in plain words ("1,590 rules; 19 couldn't be checked completely") and searchable rule names, grouped by "lets connections in / out", "stops connections in / out" | "What is a firewall rule?", "Why couldn't some rules be checked?" | All filters, tokens, IDs, policy source, evidence reasons |
| Findings (Sprint 2) | List of findings with attention level, evidence confidence, title, one sentence | The six ADR 0023 fields | Evidence references (rules, endpoints, profiles), verdicts, catalog ID, version, confidence |
| Finding detail | Title, "What we observed", "Why it may matter" | "When this can be normal", "What is still unknown", "What you can review next" | "What evidence supports this" (exact rule IDs and filters, endpoint facts, verdict and reasons), catalog ID, severity, confidence |
| Settings and help | Glossary, privacy ("everything stays on this PC"), read-only statement | — | Advanced view toggle, build info |

## 3. Flows
1. **Open (decision R2; future behaviour, not implemented):**
   - **First launch:** a welcome screen explains what FirewallAI will read, and asks for explicit authorization before the first quick check. Nothing is read before the user agrees.
   - **After authorization:** the quick check (network profiles and endpoints only) runs, with Cancel. On later launches it may run automatically, controlled by a user setting. Until settings may be persisted (R1/Q5), the authorization lasts for the session only, and the app asks again at each launch.
   - The Overview shows the quick-check results and "Firewall rules: not checked yet". There is no overall verdict.
   - **The rule check is always user-started:** "Checking all firewall rules usually takes about half a minute on this PC; it can take longer" (an estimate, not a promise; N-04 honest).
2. **Card → section → item → technical details.** The way back (Esc, Alt+Left) is always available.
3. **Partial results:** a card shows what was checked and what is Unknown, with "Why?" leading to the plain reason and then the technical limitations list.
4. **Findings (Sprint 2):** Overview card → list → detail with the six fields → evidence.

## 4. Data and status sources per card (no invented status)
| Card | Attention level allowed in v0.1 (before Sprint 2) | Evidence confidence from |
|---|---|---|
| Network profiles | "Matches recommendation" per profile only if read completely and enabled + default incoming Block (documented recommendation). Otherwise "Information" | Profile read result (errors → Unknown) |
| Apps and connections | Information only (counts, plain facts). **Never Review/Problem** (F1-11, SB-20) | Snapshot result: attribution states, partial lookups |
| Firewall rules | Information only | Rule evidence completeness (SB-18): complete vs. incomplete counts |
| Findings | "Not available yet" until Sprint 2. Then catalog-mapped levels (ux-principles §5C) | Finding evidence completeness and verdict reasons |
