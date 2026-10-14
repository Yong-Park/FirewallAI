# ADR 0005: v0.1 report formats: JSON, HTML, and basic PDF via Qt

- **Status:** Proposed · **Decision ID:** D5 · **Date:** 2026-10-14 · **Proposed by:** claude-code · **Decided by:** pending

## 1. Problem
Professional documentation is a core product goal. Users expect a PDF, but heavy PDF or DOCX stacks would delay v0.1.

## 2. Decision (recommended)
- v0.1 exports three formats:
  - **JSON**: machine-readable and schema-versioned.
  - **HTML**: Jinja2 with autoescaping and no remote resources.
  - **Basic PDF**: the same HTML rendered through Qt `QTextDocument` + `QPdfWriter`.
- PySide6 is already a dependency, so the PDF output adds none.
- DOCX and richer PDF layout come in v0.3 ([10-securitydocs.md](../planning/10-securitydocs.md)).

## 3. Alternatives considered
- **WeasyPrint.** Excellent CSS support, but needs native Pango/GTK libraries on Windows, which complicates packaging [VERIFY current Windows packaging story].
- **ReportLab.** Powerful, but you build the layout in code, so templates are no longer shared with HTML.
- **Qt WebEngine `printToPdf`.** Full CSS support, but it adds a Chromium-sized dependency to the installer.

## 4. Advantages and disadvantages
- **Advantages:** no new dependencies, and one template serves both HTML and PDF.
- **Disadvantages:** `QTextDocument` supports only a subset of HTML and CSS, so layouts must stay simple [NEEDS PROTOTYPE].

## 5. Security implications
- Report content includes untrusted strings such as rule names and process paths. Autoescaping is mandatory (CWE-79).
- No external resource loading, and the HTML carries a CSP.
- Reports may contain sensitive host data. Export offers redaction options.

## 6. Performance implications
Expected to be negligible for reports with fewer than about 5,000 rows [NEEDS PROTOTYPE].

## 7. Validation
- Sprint 3 renders a sample report with about 1,500 rules to PDF and records the time it takes.
- Escaping tests use an injection corpus, for example a rule named `<script>`.

## 8. What to learn
- Template autoescaping.
- Qt rich text and HTML subset limits.
- Separating the document model from rendering.
