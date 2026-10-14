# 10: SecurityDocs Report Engine

Status: Approved plan rev. 3, frozen snapshot. Implements rev. 2 requirement §6. Basic output ships in v0.1 ([ADR 0005](../adr/0005-v0-1-report-formats.md)); the full suite ships in v0.3.

## 1. Goal
A reusable, product-agnostic engine that produces professional security documents. Every document keeps observed facts, evidence, AI interpretation, risk assessment, recommendations, standards references, and limitations clearly separate.

## 2. Document model
```
ReportDocument
  meta: title, report_type, product, version, generated_at, provenance (scan id, app/catalog versions, privilege level), redaction_profile
  sections: list[Section]
Section
  heading, blocks: list[Block]
Block (tagged union)
  ObservedFact      – data exactly as collected (with source)
  Evidence          – references to specific rules/endpoints/events
  Finding           – deterministic finding (catalog id, severity, confidence)
  RiskAssessment    – likelihood/impact reasoning (deterministic or human-entered)
  Recommendation    – action, rationale, expected impact
  AIInterpretation  – AI text + model + digest + timestamp + validation status
  StandardReference – registry id, "relates to" wording only
  Limitation        – what could not be determined and why
  Table / Text / Chart
```
Renderers use the block type to decide styling. For example, an `AIInterpretation` block always gets a distinct, labeled box.

## 3. Report types (templates over the same model)

| Report | Version | Audience |
|---|---|---|
| Firewall Security Audit Report | v0.1 (basic), v0.3 (full) | Technical |
| Security Configuration Assessment | v0.3 | Technical |
| Network Security Findings | v0.1 (findings export) | Technical |
| Executive Summary | v0.3 | Non-technical |
| Detailed Technical Report | v0.3 | Analyst |
| Risk Assessment | v0.3 | Mixed |
| Remediation Plan | v0.3 | Technical |
| Firewall Rule Change Report | v0.4 | Audit trail |
| Technical Incident Summary | v0.5 | Analyst |

## 4. Mandatory content in every report
- A provenance header.
- A **Limitations and uncertainty** section. It cannot be removed and includes the counts of `Indeterminate` verdicts and of unavailable data.
- A statement that results reflect local policy only.
- A disclaimer against compliance claims, for example: "References indicate related guidance; this report does not assert compliance."

## 5. Renderers
| Format | v0.1 | Later |
|---|---|---|
| JSON | Schema-versioned export of the model | — |
| HTML | Jinja2 with autoescaping, inline CSS, no external resources, CSP meta tag | Richer themes |
| PDF | Qt `QTextDocument` + `QPdfWriter` rendering the same HTML (simple layout) [NEEDS PROTOTYPE] | v0.3 evaluation: WeasyPrint vs ReportLab vs Qt WebEngine |
| DOCX | — | python-docx (v0.3) |

## 6. Security
- Autoescaping is always on, and no template uses `|safe` on untrusted data (CWE-79).
- No remote fonts, images, or scripts.
- Redaction profiles are applied *before* rendering: hostnames, usernames in paths, IP/MAC addresses, domain names.
- Exported files get user-only permissions where possible.

## 7. Reuse
The `securitydocs` package has no imports from FirewallAI-specific modules. Product-specific templates sit in a templates directory that the product passes in. SentinelAI and SecureCode AI could supply their own templates and block types later ([ADR 0013](../adr/0013-shared-package-extraction.md)).
