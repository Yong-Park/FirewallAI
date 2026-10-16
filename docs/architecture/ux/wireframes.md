# UX0 low-fidelity wireframes (draft)

These are text wireframes: structure, wording, and hierarchy only, not visual style. Every status uses **icon + text** (here `[✓]`, `[i]`, `[?]`, `[…]`, `[!]`, `[×]`) and a colour token from [status-and-tokens.md](status-and-tokens.md). The example numbers are illustrative, not measurements, and use no real host data.

Legend:
- **Attention:** `[✓]` matches recommendation, `[i]` information, `[!]` review suggested (Sprint 2), `[×]` problem (Sprint 2).
- **Evidence confidence:** `(Checked)`, `(Partly checked)`, `(Unknown)`, `(Not checked yet)`.

## 1. Overview (main dashboard)
```
┌ FirewallAI ─────────────────────────────────────────────────────────────── [?] Help ┐
│ Overview          │  This PC's firewall at a glance                Last check: 14:02 │
│ Network profiles  │  FirewallAI only reads settings. It changes nothing and sends    │
│ Apps & connections│  nothing over the internet.                    [ What we check ] │
│ Firewall rules    │                                                                  │
│ Findings          │  ┌ Network profiles ─────────────┐ ┌ Apps & connections ───────┐ │
│ ─────────────     │  │ [✓] Firewall is on for all 3   │ │ [i] 14 apps are waiting   │ │
│ Settings & help   │  │     network profiles (Checked) │ │     for connections from  │ │
│                   │  │ Domain · Private · Public      │ │     other devices         │ │
│                   │  │                 [See details]  │ │     (Checked)             │ │
│                   │  └────────────────────────────────┘ │ This does not mean they   │ │
│                   │                                     │ can be reached from the   │ │
│                   │  ┌ Firewall rules ────────────────┐ │ internet.  [See details]  │ │
│                   │  │ [i] 1,590 rules configured     │ └───────────────────────────┘ │
│                   │  │ [?] 19 couldn't be checked     │ ┌ Findings ─────────────────┐ │
│                   │  │     completely (Partly checked)│ │ [i] Not available yet.    │ │
│                   │  │ Checking all rules usually     │ │ Security findings arrive  │ │
│                   │  │ takes about half a minute.     │ │ in a later version.       │ │
│                   │  │       [Check rules] [Details]  │ └───────────────────────────┘ │
│                   │  └────────────────────────────────┘                              │
│                   │  What is still unknown?  19 rules couldn't be checked completely.│
│                   │  [Why?]                                                          │
│                   │  What FirewallAI can't tell: whether other devices or the        │
│                   │  internet can actually reach this PC's apps.  [Learn more]       │
└───────────────────┴──────────────────────────────────────────────────────────────────┘
```
- There is no overall score and no "Your PC is protected".
- Green applies only to the profile card's specific, completely read setting.
- The "Findings" card stays neutral until Sprint 2.

## 1a. First launch: explanation and authorization (decision R2)
```
┌ Welcome to FirewallAI ───────────────────────────────────────────────────────────────┐
│ FirewallAI helps you understand how this PC's Windows Firewall is set up.            │
│                                                                                      │
│ What it will read on this PC (read-only):                                            │
│   • The settings of the Windows Firewall network profiles (Domain, Private, Public)  │
│   • Which apps are waiting for connections or are connected right now                │
│ Later, only when you ask: all firewall rules (usually about half a minute).          │
│                                                                                      │
│ What it never does: change settings, need administrator rights, or send anything    │
│ over the internet.                                                                   │
│                                                                                      │
│ [ ] Check automatically each time FirewallAI opens (you can change this anytime)     │
│                                                                                      │
│            [ Not now ]                         [ Allow the quick check ]             │
└──────────────────────────────────────────────────────────────────────────────────────┘
```
- Nothing is read before "Allow the quick check".
- "Not now" opens the Overview in the "Not checked yet" state.
- The automatic-check option applies to the current session only until settings may be persisted (R1/Q5).

## 2. Network profiles
```
Network profiles
Windows uses a network profile for each network connection. FirewallAI shows how the firewall
treats incoming connections for each one.  [What is a network profile?]

┌ Domain network profile ──────────────────────────────────────────── [✓] Firewall on (Checked) ┐
│ Used when this PC is on a network managed by an organisation's domain (for example, some       │
│ workplaces).                                                                                   │
│ Incoming connections: blocked unless a rule allows them.                                      │
│ Outgoing connections: allowed unless a rule blocks them.            [Show technical details ▾] │
└────────────────────────────────────────────────────────────────────────────────────────────────┘
┌ Private network profile ────────────────────────────────────────── [✓] Firewall on (Checked) ┐ …
┌ Public network profile ──────────────────────────────────────────── [✓] Firewall on (Checked) ┐
│ Used for networks you have not marked as trusted (for example, often café or airport Wi-Fi).   │
│ Usually the most restrictive.  …                                                               │
└────────────────────────────────────────────────────────────────────────────────────────────────┘
Which network is using which profile right now? (Shown after Sprint 2 adds the network-to-profile
mapping; until then: "Which network uses which profile: not checked yet". FirewallAI never guesses
it from examples.)
```
Technical details (expanded): Enabled, DefaultInboundAction, DefaultOutboundAction, AllowInboundRules, AllowLocalFirewallRules, AllowLocalIPsecRules, NotifyOnListen, logging, DisabledInterfaceAliases, source (ActiveStore).

## 3. Apps and connections
```
Apps and connections                                            [Check again]  Last: 14:02
Apps on this PC that wait for connections, and apps that are connected right now.

  [ Waiting for connections (14) ]  [ Connected now (37) ]          Search apps: [_________]

┌ Synthetic Sync Service ────────────────────────────────────────────── [i] (Checked) ┐
│ Waiting for connections from other devices on 2 ports.                                │
│ Who can try to connect: every network this PC is connected to. Whether the firewall   │
│ lets them in is a separate question.                                                  │
│ [Rules that may be relevant (3)]   [What does this mean?]   [Show technical details ▾] │
└───────────────────────────────────────────────────────────────────────────────────────┘
┌ Example Database ──────────────────────────────────────────────────── [i] (Checked) ┐
│ Waiting for connections, but only from this PC itself. Other devices can't connect.   │
└───────────────────────────────────────────────────────────────────────────────────────┘
┌ (App name unavailable) ─────────────────────────────────────────── [?] (Unknown) ─────┐
│ Windows did not let FirewallAI read which app this is.  [Why?]                         │
└───────────────────────────────────────────────────────────────────────────────────────┘
[i] "Waiting for connections" does not mean someone on the internet can reach the app.
    Your router and other devices also decide that.                     [Learn more]
```
"Connected now" lists apps with active connections. Remote addresses appear only in the technical details (host-sensitive).

## 4. App detail with rules that may be relevant
```
Synthetic Sync Service
What it is doing: waiting for connections on 2 ports (technical details below).

Rules that may be relevant  [?]
An Allow rule does not guarantee that a connection is permitted. Other rules, the network
profile, and devices outside this PC can still decide otherwise.

 • "Synthetic Sync (TCP-In)": lets connections in · Possibly relevant rule: its settings
   match this app's program and port. Not checked against real connections.
 • "Synthetic Sync (UDP-In)": lets connections in · Possibly relevant, depending on
   conditions FirewallAI did not check: only on the Public network profile.
 • 2 rules: Unknown whether relevant. The app's location could not be read.   [Why?]
                                                                [Show technical details ▾]
```

## 5. Firewall rules
```
Firewall rules                                           [Check rules: ~half a minute]  Last: 14:05
1,590 rules are configured.  19 couldn't be checked completely  [?] (Partly checked)  [Why?]

Show: (•) All  ( ) Let connections in  ( ) Stop connections in  ( ) Outgoing rules
      [ ] Only rules that are turned on            Search: [______________]

 Name                                   What it does                    On?  Checked
 Synthetic Sync (TCP-In)                Lets incoming connections in    Yes  [✓] Checked
 Example Remote Tool                    Lets incoming connections in    Yes  [?] Partly ▸ Why?
 …                                                                         [Technical details]
While checking: "Checking firewall rules… 900 of 1,590. This usually takes about half a minute on this PC; it can take longer."
After: "Done in 27.9 s. This is slower than FirewallAI's 10 s goal. Known limitation."
```

## 6. Findings (Sprint 2) and finding detail
```
Findings                                                              Last check: 14:05
Things worth reviewing, based only on settings FirewallAI could check completely.

 [!] Review suggested · An app may accept incoming connections on public networks    (Checked)
 [i] Information      · Dropped-connection logging is turned off                      (Checked)
 [?] Couldn't check   · 2 apps: not enough information to evaluate          [Why?]

──── Finding detail ───────────────────────────────────────────────────────────────────────
[!] Review suggested · How sure we are: Medium · Evidence: Checked
What we observed:      This PC's own firewall settings would let incoming connections reach
                       "Synthetic Sync Service" on the Public network profile.
Why it may matter:     On networks you don't trust, other devices could try to connect to it.
When this can be normal: If you use this app to sync with other devices.
What is still unknown: Whether your router or the network blocks these connections.
                       Whether anyone has connected (FirewallAI does not check that).
What you can review next: Whether you need this app on public networks; its settings.
What supports this:    [Show technical details ▾] rule IDs and filters, verdict
                       PermittedByPolicy, qualifiers, catalog FW-EXP-001 v1, severity Medium
```

## 7. States (every screen)
| State | Pattern |
|---|---|
| Not checked yet | Neutral card: "Not checked yet. [Check now]". No status colour |
| Checking | Progress with plain words: "Reading the firewall settings currently in effect… (usually about half a minute)"; Cancel button; the window stays responsive |
| Done | Results, last-check time, duration (N-04 note where relevant) |
| Partly done | "Some information couldn't be read (19 rules). Results below are based on what could be checked. [Why?]" |
| Cancelled | "Check cancelled. Results shown are incomplete. [Check again]". Nothing shown as Checked unless it was completed |
| Failed | "FirewallAI couldn't read the firewall settings. Nothing was changed. Try again; if it keeps happening, see Help." Technical error code in the details |
| Already running (SB-19) | "A rule check is already running. Wait for it to finish." |
| Empty | Example: "No apps are waiting for connections from other devices right now." |
