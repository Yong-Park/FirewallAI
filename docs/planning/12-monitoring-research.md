# 12: Monitoring and Connection Authorization: Feasibility Research

Status: Approved plan rev. 3, frozen snapshot. Covers Module D and rev. 2 requirement §5. **Not part of the v0.1 MVP.** Passive monitoring and reactive blocking target v0.5. Pre-connection authorization is a **research milestone** that needs a feasibility prototype and a go/no-go ADR.

## 1. Four capability tiers

| Tier | What it means | Prevents traffic? |
|---|---|---|
| 1. Passive detection and alerting | Observe connections and processes; alert on deterministic rules | No |
| 2. Reactive blocking | After detecting something, add a rule or filter to block future traffic | Future traffic only |
| 3. Pre-connection authorization | Hold or deny a new connection until a policy or the user decides | Yes, before it is permitted |
| 4. Deep packet inspection | Inspect payloads | n/a (not planned) |

**Hard rule: the LLM is never in the decision path.** Real-time decisions use a deterministic local policy only. The AI may explain an alert *afterwards*, asynchronously.

## 2. Mechanisms

| Mechanism | Tier | Privilege | Driver? | Python-feasible? | Notes |
|---|---|---|---|---|---|
| psutil polling | 1 | User (partial) | No | Yes | Cheap; **misses short-lived connections**; no blocked-attempt data |
| ETW `Microsoft-Windows-TCPIP` / `Microsoft-Windows-Kernel-Network` | 1 | Admin | No | Possible, but a native helper is easier | Real-time, process-attributed events; volume needs filtering [NEEDS PROTOTYPE] |
| Security log events 5156 (permitted) / 5157 (blocked) / 5152 (dropped) | 1 | Admin + audit policy ("Filtering Platform Connection") | No | Yes (event log API) | **Very noisy**; changing audit policy is a system change, so it needs approval |
| `FwpmNetEventSubscribe` (WFP net events) | 1 | Admin | No | ctypes is possible; native preferred | Drop and allow events with app IDs |
| Sysmon event 3 (network connection) | 1 | Admin to install | No | Yes (read event log) | Optional integration if the user already runs Sysmon |
| Windows Firewall rules (`New-NetFirewallRule`) | 2 | Admin | No | Yes, via the helper | Persistent. Must be FirewallAI-owned and reversible ([ADR 0011](../adr/0011-change-rollback-model.md)) |
| User-mode WFP filters (`FwpmFilterAdd0`) | 2 | Admin | **No** | ctypes is possible; native preferred | **Dynamic sessions remove their filters automatically when the session ends**, which fits *temporary permissions* and fails safe if the service crashes [VERIFY semantics] |
| Driverless default-deny model (3a) | 3 (approximation) | Admin / service | **No** | Native service recommended | Unknown apps are blocked outbound by a WFP or firewall filter. A drop event triggers a notification. On approval an allow filter is added, and the app's **retry** succeeds. Prior art: simplewall and TinyWall (GPL; study the design only, copy no code) |
| WFP callout driver with ALE pend/complete (3b) | 3 (true hold) | Kernel | **Yes** | **No** (C/C++ kernel code) | EV certificate and Microsoft attestation signing required; BSOD risk; HVCI compatibility. Highest cost. |
| WinDivert | 3/4 | Admin + third-party signed driver | Yes (bundled) | Bindings exist | LGPL-3/GPL-2 licensing; packet-level; a large trust dependency |
| DPI | 4 | — | — | — | **Not planned**: privacy cost, encrypted (TLS) traffic, complexity |

**Conclusion:** a kernel driver is **not** required for tiers 1–2, or for a useful approximation of tier 3 (3a). A driver is only needed for true pend-and-decide (3b), which may never be justified.

## 3. Design constraints for v0.5 and research
- **Fail-safe policy per profile:** if the service crashes or hangs, the default is fail-open on Private and Domain, plus a user choice on Public. This is documented and tested.
- **Protected connectivity:** DNS, DHCP, loopback, Windows Update, time sync, and FirewallAI's own IPC are never blocked by the authorization flow.
- **Interruption budget:** notifications are rate-limited and grouped by app. Options are "allow once", "allow for N minutes" (dynamic filter), and "allow always" (persistent, narrowly scoped rule).
- **Performance:** the event pipeline must keep up with peak connection rates without dropping events silently. Overload is reported as a limitation.
- **Privacy:** store connection metadata only (no payloads), with configurable retention.
- **Compatibility:** coexist with third-party firewalls and EDR; detect them and step back when one is present.

## 4. Research milestones (each gated)
1. **R1, passive ETW prototype (VM):** event volume, CPU cost, process attribution accuracy vs. psutil.
2. **R2, dynamic WFP session prototype (VM):** temporary allow and block filters; verify that they are removed on session end and on a crash.
3. **R3, driverless default-deny (3a) prototype (VM):** measure app breakage (browsers, updaters, games, VPNs), retry behavior, and notification latency the user can accept.
4. **Go/no-go ADR** for productizing 3a. A separate ADR, much later, covers whether 3b is justified at all.

Every prototype runs in **disposable VMs only**. Nothing is deployed to the primary machine (see [security-boundaries.md](../architecture/security-boundaries.md) SB-11).
