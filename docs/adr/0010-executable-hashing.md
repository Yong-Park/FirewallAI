# ADR 0010: Executable hashing off by default

- **Status:** Proposed · **Decision ID:** D10 · **Date:** 2026-10-14 · **Proposed by:** claude-code · **Decided by:** pending

## 1. Problem
SHA-256 hashes of process executables help with change detection and reputation lookups. However, hashing large binaries on every scan is slow, and hashes are a fingerprint of the host's software.

## 2. Decision (recommended)
- Executable hashing is **off by default** and can be turned on in Settings.
- When on, hashes are cached by (path, size, mtime) and never sent anywhere without consent.
- The Authenticode signer is collected on a best-effort basis by default, since it is cheaper and more useful.

## 3. Alternatives considered
- **On by default:** slower scans, and more sensitive data stored.
- **Never:** loses a useful forensic signal for v0.5 monitoring.

## 4. Advantages and disadvantages
- **Advantages:** faster scans and privacy-preserving defaults.
- **Disadvantages:** less evidence available by default.

## 5. Security implications
Hashes and signer data are untrusted inputs to reports and to the AI, so they are validated as hex or strings.

## 6. Performance implications
Hashing hundreds of binaries could take seconds to minutes [NEEDS PROTOTYPE].

## 7. Validation
Sprint 2 measures scan time with hashing on and off.

## 8. What to learn
Hash caching, Authenticode verification (`WinVerifyTrust`), and privacy-by-default.
