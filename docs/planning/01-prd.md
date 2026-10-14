# 01 — Product Requirements Document (PRD)

Status: Approved plan rev. 3 (2026-10-14), frozen snapshot. Covers deliverables (1) PRD and (16) user stories.

## 1. Problem

Windows Firewall policy is hard to understand. Hundreds of rules come from Windows, applications, installers, and Group Policy. Profiles change with the network. Listening services appear without the user knowing. Existing tools either show raw rule lists (Windows Defender Firewall with Advanced Security, `Get-NetFirewallRule`) or make alarming claims ("Port 445 open — vulnerable!") that don't hold up.

## 2. Vision

**FirewallAI helps people understand, audit, and safely manage their Windows host firewall.** It does this with:
- evidence-based deterministic analysis;
- honest uncertainty: an explicit *Indeterminate* verdict when the evidence can't settle a question;
- local-first, explainable AI that advises but never acts;
- professional documentation;
- human-approved changes with safe rollback, in later versions.

### Product principles
1. **Evidence before opinion.** Every finding links to observed data.
2. **No false certainty.** No single "security score". An open port alone is never called a vulnerability, and external exposure is never claimed from host data.
3. **Local-first and private.** Works offline. Nothing leaves the machine without explicit consent. No paid accounts required.
4. **Human in control.** AI recommends, deterministic code validates, and the human approves.
5. **Read-only first.** Write capability comes later, behind VM-validated safety controls.

## 3. Personas

| Persona | Needs | Typical question |
|---|---|---|
| **P1: Non-expert Windows user** | Plain-language status, no jargon, no fear-mongering | "Is my PC exposing anything on café Wi-Fi?" |
| **P2: Developer** | See which dev servers, databases, and tools listen, and on which profiles they are reachable | "Is my Postgres reachable from the LAN?" |
| **P3: Sysadmin / analyst / student** | Rule-level detail, GPO awareness, exportable evidence-based reports, standards references | "Which inbound allow rules are overly broad on the Public profile?" |

## 4. Goals and non-goals

**Goals for v0.1:** accurate read-only auditing, correlation of ports, processes, services, and rules, deterministic findings, scan history, reports (JSON, HTML, basic PDF), and an installable EXE.

**Goals for later versions:** local AI advisor (v0.2); advanced docs, RAG, and standards (v0.3); human-approved rule management (v0.4); background monitoring (v0.5).

**Non-goals for now:**
- deep packet inspection;
- kernel drivers;
- replacing an EDR/AV product;
- remote or fleet management;
- compliance certification;
- macOS or Linux support.

## 5. Success metrics (v0.1)

| Metric | How it is measured |
|---|---|
| Verdict correctness | 100% agreement with the hand-built truth table, about 40 scenarios ([05](05-firewall-analysis.md)) |
| False-positive rate | Fraction of findings dismissed by the owner on 3 or more real machines and VMs, tracked and reported, with no target until a baseline exists |
| Scan time | Measured. Target < 10 s with 1,500 rules [NEEDS PROTOTYPE] |
| Install success | Installs on clean Windows 11 and Windows 10 22H2 VMs without Python |

## 6. User stories and acceptance criteria (v0.1 unless marked)

**US-01: See firewall profile status** (P1, P3)
- *Given* a standard user launches FirewallAI, *when* a scan completes, *then* each profile (Domain, Private, Public) shows enabled state, default inbound and outbound actions, and "block all incoming" status.
- *And* each connected network shows which profile applies to it.
- *And* nothing requires admin rights.

**US-02: Understand which listening services are permitted by local policy** (P2)
- *Given* a process listens on TCP 5432 on `0.0.0.0`, *when* I open Listening Ports, *then* I see the process, its path (or "unavailable: requires elevation"), and services, plus a per-profile verdict: `PermittedByPolicy`, `BlockedByPolicy`, `NotExposed_LoopbackOnly`, or `Indeterminate` with reasons.
- *And* the UI states that external reachability also depends on routers, NAT, and other firewalls.

**US-03: Loopback-only services are not flagged** (P2)
- *Given* a service bound only to `127.0.0.1` or `::1`, *then* its verdict is `NotExposed_LoopbackOnly` and no exposure finding is raised.

**US-04: Indeterminate is explained** (P3)
- *Given* a third-party firewall is registered as active, *then* affected verdicts are `Indeterminate`, with the reason "third-party firewall active: Windows Firewall rules may not be the effective control".

**US-05: Review findings with evidence** (P1, P3)
- *Given* findings exist, *when* I open one, *then* I see a title, severity, confidence, a plain-language explanation, the exact rules and endpoints as evidence, "when this is benign", recommended next steps, and references.
- *And* no finding is raised from an open port alone.

**US-06: Browse effective rules** (P3)
- *When* I open Rules, *then* I can filter by direction, action, profile, enabled state, program, port, and policy source (local or GPO). Each rule shows all its filters.

**US-07: Scan history and diff** (P3)
- *Given* two saved scans, *when* I compare them, *then* I see rules added, removed, or changed, new or disappeared listeners, and new or resolved findings.

**US-08: Export a report** (P3)
- *When* I export, *then* I can choose JSON, HTML, or PDF.
- *And* the report has a provenance header (scan time, app and catalog versions, privilege level) and separate sections for Observed Facts, Evidence, Assessment, Recommendations, and Limitations.
- *And* I can redact hostnames, usernames, and IP addresses.

**US-09: Install without Python** (P1)
- *Given* a clean Windows 11 PC, *when* I run the installer, *then* FirewallAI installs per-user without admin rights, starts, and can be uninstalled cleanly.
- *And* the uninstaller asks whether to keep my scan data.

**US-10: Understand privacy at first run** (P1)
- *When* I first launch, *then* onboarding explains what is collected, that it stays local, that the app is read-only, and that AI is off.

**US-11: Degraded data is visible** (P3)
- *Given* some process details are inaccessible, *then* the scan completes, affected items say "unavailable", and the Limitations panel counts them.

**US-12 (v0.2): Ask the local AI to explain a finding** (P1)
- *Given* Ollama is running locally with a selected model, *when* I click "Explain", *then* I get an explanation labeled "AI-generated" that shows the model name, assumptions, missing evidence, and only citations that exist in the reference registry.
- *And* if validation fails, I see "AI response failed validation" instead.

**US-13 (v0.2): Set up local AI** (P1)
- *Given* Ollama is not installed, *then* FirewallAI shows a guided screen with the official download link. It never downloads or installs anything silently.
- *Given* Ollama is installed, *then* I can pick an installed model, or pull one after seeing its size and license.

**US-14 (v0.4, VM-only first): Apply an approved rule change** (P3)
- *Given* a proposed change, *then* I see a before/after diff and must explicitly approve it.
- *And* after it is applied, FirewallAI verifies the change and logs it.
- *And* I can roll back only FirewallAI's delta.

**US-15 (v0.5): Get notified about new suspicious activity** (P1, P3)
- *Given* monitoring is enabled, *when* a deterministic rule matches, such as a new inbound listener on Public, *then* I get a tray notification with the evidence and allow, block, or snooze options.
- *And* the AI is never consulted in the decision path.

## 7. Assumptions
- [ASSUMPTION] Most profile and rule data is readable by a standard user. To be confirmed in the Sprint 1 spike.
- [ASSUMPTION] Users accept a per-user unsigned installer in early releases if verification steps are documented.
