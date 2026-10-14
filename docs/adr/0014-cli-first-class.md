# ADR 0014: CLI as a first-class interface alongside the GUI

- **Status:** Accepted. Explicit human requirement (rev. 2 feedback, 2026-10-14): "Prioritize a professional PySide6 GUI. Keep the CLI for development, automation, and testing, but introduce a functional GUI early."
- **Decision ID:** D14 · **Date:** 2026-10-14 · **Proposed by:** claude-code · **Decided by:** human, 2026-10-14

## 1. Problem
Development, CI, testing, and automation need a headless interface. The product, however, is a desktop GUI.

## 2. Decision (recommended)
- Ship a CLI, `firewallai scan --json` and `firewallai report …`.
- The CLI and the GUI both call the same `app/` service layer.
- **The GUI is the primary product** and appears early, from Sprint 1. The CLI is for development, automation, and testing.

## 3. Alternatives considered
- **GUI only:** hard to test and to automate.
- **CLI first, GUI later:** conflicts with the requirement to have a working GUI early.

## 4. Advantages and disadvantages
- **Advantages:** testable end to end, scriptable, and useful in CI and VMs.
- **Disadvantages:** a second interface to maintain. Keeping it thin keeps that cost low.

## 5. Security implications
The CLI has the same read-only privilege as the GUI. Output files are written with user-only permissions.

## 6. Performance implications
None.

## 7. Validation
Integration tests drive the CLI against fixtures, and against real collectors on the CI runner.

## 8. What to learn
Separating application services from presentation (hexagonal / ports-and-adapters architecture).
