# ADR 0012: Language for the privileged helper and service (deferred to v0.4)

- **Status:** Proposed (deferred) · **Decision ID:** D12 · **Date:** 2026-10-14 · **Proposed by:** claude-code · **Decided by:** pending

## 1. Problem
The v0.4 elevated helper and the v0.5 Windows Service run with high privilege. Some of their work (ETW, WFP user-mode APIs, service plumbing) is awkward in Python.

## 2. Decision (recommended)
**Defer** this decision until the v0.4 kickoff, when the operation set is known. The candidates are:
- **C#/.NET:** first-class Windows Service support, WFP P/Invoke samples, and ETW through TraceEvent.
- **Rust:** memory safety and the `windows` crate; a steeper learning curve.
- **Python + ctypes/pywin32:** a single language, but a larger runtime runs as a privileged process.

## 3–6. Tradeoffs
To be completed at v0.4. Key criteria:
- size of the privileged attack surface;
- memory safety;
- API ergonomics for WFP and ETW;
- signing and packaging;
- the developer's learning goals.

## 7. Validation
A v0.4 spike that implements one typed operation, `CreateRule`, in the top two candidates inside a VM.

## 8. What to learn
Windows service security (service SIDs, virtual accounts), named-pipe DACLs, and the WFP management API.
