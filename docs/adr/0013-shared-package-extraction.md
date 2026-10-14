# ADR 0013: Defer extracting shared packages for SentinelAI and SecureCode AI

- **Status:** Proposed · **Decision ID:** D13 · **Date:** 2026-10-14 · **Proposed by:** claude-code · **Decided by:** pending

## 1. Problem
The AI provider layer and the SecurityDocs engine should eventually serve SentinelAI and SecureCode AI. Sharing them too early creates coupling and versioning overhead across three projects.

## 2. Decision (recommended)
- Keep `firewallai.ai` and `firewallai.securitydocs` as **internal packages** with **no imports from FirewallAI-specific modules**. CI enforces this with an import-linter contract.
- Extract them into standalone packages only when a second project actually consumes them.

## 3. Alternatives considered
- **A shared repo or monorepo now:** premature, and it slows down FirewallAI.
- **Copy-paste later:** causes drift. The import contract makes a later extraction mechanical instead.

## 4. Advantages and disadvantages
- **Advantages:** low overhead now and a clean extraction later.
- **Disadvantages:** discipline is required to keep the boundary clean.

## 5. Security implications
A clean boundary also stops the AI package from reaching privileged code.

## 6. Performance implications
None.

## 7. Validation
The import-linter contract runs in CI from Sprint 1.

## 8. What to learn
Package boundaries, dependency inversion, and semantic versioning for libraries.
