# ADR 0007: Code signing

- **Status:** Proposed · **Decision ID:** D7 · **Date:** 2026-10-14 · **Proposed by:** claude-code · **Decided by:** pending
- **Revised after verification:** the approved plan recommended Azure Artifact Signing first. Microsoft's documentation says **individual developers must be located in the United States or Canada** to get Public Trust certificates. Organizations are accepted only from a listed set of countries: US, Canada, EU, UK, Australia, New Zealand, Japan, South Korea, Singapore, Switzerland, Norway, Israel ([Artifact Signing quickstart](https://learn.microsoft.com/azure/artifact-signing/quickstart), checked 2026-10-14).
- **Developer location (provided by the human, 2026-10-14): Guatemala.** Azure Artifact Signing Public Trust is therefore **not available**, either as an individual or as a Guatemalan organization. Option 2 below is kept only in case eligibility changes.

## 1. Problem
Unsigned EXEs trigger SmartScreen warnings and are more likely to be flagged by antivirus. For a security tool that undermines trust.

## 2. Decision (recommended)
1. **SignPath Foundation, free signing for open-source projects** ([terms](https://signpath.org/terms)).
   - Requires an OSI-approved license (MIT qualifies) with no proprietary code.
   - The project must be actively maintained and already released.
   - Signed binaries must come from an automated build of the public repository, and SignPath verifies the build's origin.
   - A code signing policy must be published.
   - The certificate is issued to "SignPath Foundation", not the developer.
   - **Earliest possible: after the first unsigned v0.1 release.**
2. A conventional **OV code signing certificate** from a CA that validates individuals or organizations in Guatemala. It is paid and needs hardware or HSM key storage [VERIFY: which CAs, cost, and individual validation from Guatemala].
3. **Azure Artifact Signing**: **not currently eligible** (Guatemala). Re-check only if Microsoft's country list changes.

Until one of these is in place, releases are unsigned. The release notes document SmartScreen behavior and how to verify the SHA-256 checksums and GitHub attestations.

## 3. Alternatives considered
- **Self-signed certificate:** gives no SmartScreen trust; useful only for internal test VMs.
- **EV certificate:** no longer grants instant SmartScreen reputation and costs more [VERIFY].

## 4. Advantages and disadvantages
- **SignPath:** free, CI-integrated, and its origin verification strengthens the supply chain. Downsides: it requires an approved application and a public release first, and the publisher name shows as SignPath Foundation.
- **Azure Artifact Signing:** cheap and integrates with CI, but eligibility is restricted.
- **OV certificate:** under the developer's own name, but costs more and requires careful key custody.

## 5. Security implications
- Signing keys must never be stored in the repo or on developer machines.
  - SignPath and Azure keep keys in HSMs.
  - An OV certificate requires an HSM or token.
- Signing only proves who published a binary, not that it is safe. Reproducible builds plus SBOM plus attestations complement it.

## 6. Performance implications
None at runtime. Signing adds a short CI step.

## 7. Validation
Download a signed release on a clean VM and check:
- `Get-AuthenticodeSignature` returns Valid;
- SmartScreen behavior is recorded.

## 8. What to learn
- Authenticode and certificate chains.
- How SmartScreen reputation works.
- HSM-backed signing in CI.
- Supply-chain levels (SLSA) and artifact attestations.
