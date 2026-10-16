# UX0 status semantics and accessible design tokens (draft)

The rules come from [ux-principles §5](../ux-principles.md): attention level (A), evidence confidence (B), and catalog mapping (C). This document fixes the **visual tokens** for them.

## 0. Observed facts, verified findings, unknowns, and reachability
The four-way distinction in [README](README.md) decides which visual treatment is allowed. **Actual network reachability has no status token at all**: it is never displayed as known. It appears only as an explanation of what local firewall evidence cannot establish.

## 1. Two dimensions, always both shown
| | Checked | Partly checked | Unknown | Not checked yet |
|---|---|---|---|---|
| **Matches recommendation** `[✓]` | allowed | **not allowed** | **not allowed** | **not allowed** |
| **Information** `[i]` | allowed | allowed (with "what is missing") | allowed ("couldn't check") | allowed ("not checked yet") |
| **Review suggested** `[!]` (Sprint 2) | allowed (verified finding) | **not allowed**: becomes "couldn't check completely" | **not allowed** | **not allowed** |
| **Problem** `[×]` (Sprint 2) | allowed (verified, catalog High + High confidence) | **not allowed** | **not allowed** | **not allowed** |

Missing evidence can only *lower* what is claimed, never raise attention (SB-18). Before Sprint 2, only the first two rows exist.

**Recommendation sources.** "Matches recommendation" for a network profile means: the firewall is on and the default incoming action is Block for that profile. This is a common baseline in firewall hardening guidance `[VERIFY: cite the exact reference IDs from the standards registry before use]`. It describes that profile only.

## 2. Colour tokens (candidate; WCAG relative-luminance contrast computed 2026-10-15)
| Token | Use | Light theme | Contrast on bg #FFFFFF / surface #F6F8FA | Dark theme | Contrast on bg #0D1117 / surface #161B22 |
|---|---|---|---|---|---|
| `text` | body text | #1F2328 | 15.80 / 14.84 | #E6EDF3 | 16.02 / 14.64 |
| `muted` | secondary text, Unknown, Not checked | #59636E | 6.11 / 5.74 | #9198A1 | 6.50 / 5.94 |
| `status.ok` | Matches recommendation | #1A7F37 | 5.08 / 4.77 | #3FB950 | 7.45 / 6.81 |
| `status.info` | Information | #0969DA | 5.19 / 4.88 | #4493F8 | 6.11 / 5.58 |
| `status.review` | Review suggested | #9A6700 | 4.87 / 4.57 | #D29922 | 7.50 / 6.85 |
| `status.problem` | Problem | #CF222E | 5.36 / 5.03 | #F85149 | 5.65 / 5.16 |

All values meet **4.5:1** for normal text on both background and surface (WCAG 2.x AA). They must be re-measured in Qt on the real surfaces, and in Windows high-contrast mode, during Sprint 3 `[VERIFY]`. Status colour is used only for the icon and a thin accent, never as the only cue, and never as a full-card background behind body text.

## 3. Icons and shapes (distinguishable without colour)
| Status | Shape | Text always shown |
|---|---|---|
| Matches recommendation | circle with check mark | "Matches recommendation" or the specific fact |
| Information | circle with "i" | the fact |
| Review suggested | triangle with "!" | "Review suggested" |
| Problem | octagon with "×" | "Problem" |
| Unknown | circle with "?" | "Unknown" / "Couldn't check" |
| Partly checked | half-filled circle | "Partly checked" |
| Not checked yet | dotted circle | "Not checked yet" |

Icons are original simple shapes, not Windows Security or Microsoft Defender artwork (consistent with the M1.5 icon decision).

## 4. Typography and spacing (Qt; scaled with Windows DPI)
- **Type sizes:** body 10.5 pt (Segoe UI or the system UI font); headings 14/12 pt semibold; at least 9 pt anywhere.
- **Line length:** about 60–90 characters for explanation text.
- **Spacing scale:** 4 / 8 / 12 / 16 / 24 px (logical pixels; Qt scales them with DPI).
- **Targets:** at least 24×24 logical pixels; visible keyboard focus ring.
- Layouts must work from **1024×640 logical pixels** at 100 % up to 200 % DPI without clipped text (re-verify the M1.5 DPI pass in Sprint 3).
