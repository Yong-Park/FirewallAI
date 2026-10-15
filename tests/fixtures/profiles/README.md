# Profile fixtures

Raw payloads in the exact shape that the `firewall_profiles` PowerShell script emits (`{"profiles": [...]}`).

| File | Origin |
|---|---|
| `win11_default.json` | **Synthetic.** Hand-written to match the values observed read-only on test environment TE-1 on 2026-10-14: all profiles enabled, default inbound Block (4), default outbound Allow (2), inbound rules allowed, local rules merged. Fields that weren't observed use Windows defaults. It contains no host-specific data (the log path is the generic `%systemroot%` default). |
| `invalid_values.json` | **Synthetic.** Unknown enum values and a malformed item, used for error-path tests. |

Rules:
- Never commit raw captures from a real machine. Run captures through a sanitizer first (the recorder and sanitizer are planned for a later milestone).
- Keep the files small and readable.
