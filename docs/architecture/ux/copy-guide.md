# UX0 copy guide (draft)

The glossary and the forbidden claims are in [ux-principles §4 and UX-04](../ux-principles.md). This guide covers how to write.

## 1. Voice
- **Calm, factual, respectful.** Write to the user ("you", "this PC"). No fear, no urgency, no blame, no humour about security.
- **Short sentences:** one idea each. Lead with the fact, then the meaning. About grade 7–8 reading level `[VERIFY with UX0 usability results]`.
- **Say what FirewallAI did and did not check.** Prefer "FirewallAI couldn't read…" to "Error".
- **Never promise action.** v0.1 is read-only. Say "you can review…", never "fix", "protect", or "secure your PC".

## 2. Wording patterns
| Situation | Pattern | Avoid |
|---|---|---|
| Completely read, matches recommendation | "The firewall is on for the Public network profile." | "You are protected", "Secure" |
| Neutral fact | "14 apps are waiting for connections from other devices." | "14 open ports" (layer 1) |
| Listening app (C1) | "…waiting for connections. This does not mean it can be reached from the internet." | "Exposed", "open to the internet" |
| Rule relationship (C2) | "Possibly relevant rule…" + the Allow-rule caveat | "This rule allows the app", "allowed traffic" |
| Unknown (C3) | "Couldn't check completely: {plain reason}. [Why?]" | warnings, red/amber, "risk" |
| Slow check (N-04) | "Checking all firewall rules usually takes about half a minute on this PC; it can take longer." | hiding progress, "almost done", exact countdowns |
| Quick check done | "Quick check done: network profiles and apps. Firewall rules: not checked yet." | "All good", "Your PC is safe", any overall verdict |
| Reachability (always unknown locally) | "Whether other devices or the internet can actually reach this app can't be told from this PC's settings alone." | "reachable", "exposed", "open to the internet", "not reachable" |
| Network profile | "Public network profile: used for networks you have not marked as trusted (for example, often café or airport Wi-Fi)." | "Café Wi-Fi" as the profile's name; guessing which network uses which profile |
| Verified finding (Sprint 2) | the six fields (§3) | a verdict without evidence |

## 3. Finding template: the six ADR 0023 fields (Sprint 2)
Every catalog entry provides all six in plain language. Tests check that none is empty and that layer 1–2 text contains no forbidden claims or unexplained jargon.
1. **What we observed:** a fact from complete evidence. "This PC's own firewall settings would let incoming connections reach {app} on the {profile} network profile."
2. **Why it may matter:** cautious. "On networks you don't trust, other devices could try to connect to it."
3. **When this can be normal:** the catalog's benign conditions, in plain words.
4. **What supports this:** a summary sentence and "Show technical details" with rule IDs/filters, endpoint facts, verdict and qualifiers, catalog ID/version, severity, and confidence.
5. **What is still unknown:** always includes "whether devices outside this PC (router, network) block it" where relevant, plus any Indeterminate reasons.
6. **What you can review next:** concrete and read-only. "Check whether you need this app on public networks."

## 4. State messages (all screens)
| State | Message |
|---|---|
| First launch (R2) | "FirewallAI will read this PC's firewall network profile settings and which apps are waiting for or using connections. It only reads; it changes nothing and sends nothing over the internet. [Allow the quick check] [Not now]" |
| Not checked yet | "Not checked yet. [Check now]" |
| Checking: quick | "Checking network profiles and apps…" |
| Checking: rules | "Reading the firewall settings currently in effect… {done} of {total} rules. This usually takes about half a minute on this PC; it can take longer." (an estimate, never an exact promise) |
| Partly done | "Some information couldn't be read ({n} {items}). Results are based on what could be checked. [Why?]" |
| Cancelled | "Check cancelled. The results shown are incomplete. [Check again]" |
| Failed | "FirewallAI couldn't read {what}. Nothing was changed on this PC. [Try again] [Help]" (technical code in details) |
| Already running | "A firewall rule check is already running. Please wait for it to finish." |
| Empty: apps | "No apps are waiting for connections from other devices right now." |
| Empty: findings | "No findings. FirewallAI found nothing to review in the settings it could check completely." Always paired with the Unknown summary if any; never "Your PC is safe" |
| Findings not available (before Sprint 2) | "Security findings arrive in a later version. For now, FirewallAI shows the facts it reads." |

## 5. "What does this mean?" help (first set)
- **Network profile:** "Windows gives each network connection a profile: Domain, Private, or Public. The firewall can treat each one differently. Examples: Domain is often used on some workplace networks; Public is often used for café or airport Wi-Fi."
- **Waiting for connections:** "The app is ready to accept connections from other devices. Whether those devices can actually reach it also depends on the firewall rules, your router, and the network."
- **Firewall rule:** "An instruction for the Windows Firewall to let a specific kind of connection in or out, or to stop it."
- **Unknown:** "FirewallAI couldn't read everything it needs, often because Windows restricts access. Unknown is not a warning; it means 'not verified'."
