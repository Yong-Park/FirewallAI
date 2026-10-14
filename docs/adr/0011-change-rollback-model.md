# ADR 0011: Rule change rollback model (v0.4)

- **Status:** Proposed · **Decision ID:** D11 · **Date:** 2026-10-14 · **Proposed by:** claude-code · **Decided by:** pending

## 1. Problem
Rollback must undo FirewallAI's changes **without overwriting legitimate changes** that other applications or administrators made in the meantime. A naive "restore full policy export" approach destroys those changes.

## 2. Decision (recommended)
- Each approved change set records **inverse operations** for the delta it applied. Rollback replays only those inverses.
- **Drift detection:**
  - Before applying a change, the helper compares current rule hashes against the hashes captured at proposal time, and aborts if any target rule changed.
  - Before rolling back, it checks that FirewallAI's rules are still in the state it left them. If not, it asks the user.
- FirewallAI-created rules carry a dedicated `Group` and a marker in the description. Modifying rules FirewallAI doesn't own requires a second confirmation.
- `netsh advfirewall export` snapshots are kept as a **last-resort disaster recovery** option only, and are clearly labeled as overwriting everything.
- An auto-revert timer ("keep these changes?") protects against lockout.

## 3. Alternatives considered
- **Full export/import:** simple, but clobbers concurrent changes. Rejected as the routine path.
- **No rollback:** unacceptable.

## 4. Advantages and disadvantages
- **Advantages:** precise, respects other administrators, and is auditable.
- **Disadvantages:** more complex. Inverse operations have to be correct for every operation type.

## 5. Security implications
- Audit entries are append-only and hash-chained.
- The helper re-validates every operation itself and does not trust what the UI sends.

## 6. Performance implications
Negligible.

## 7. Validation
VM-only test matrix:
- apply → external change → rollback (the external change must survive);
- apply → rule deleted externally → rollback (must detect the drift and ask);
- an auto-revert timeout.

## 8. What to learn
- Compensating transactions.
- Optimistic concurrency (ETags/hashes).
- Hash-chained audit logs.
