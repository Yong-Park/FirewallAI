# 11: Standards and Reference Registry

Status: Approved plan rev. 3, frozen snapshot. Implements rev. 2 requirement §7. Minimal registry in v0.1 (IDs referenced from the findings catalog), full registry and RAG in v0.3.

## 1. Principles
- **Evidence-based mapping only.** Findings point to guidance with the wording "relates to". FirewallAI **never** says "violates", "non-compliant", or "compliant".
- **Not every finding maps to a standard.** An empty mapping is acceptable.
- Mappings are **maintained by a human** in the findings catalog. The AI may cite only IDs that exist in the registry, and the validator enforces this.
- **Licensing is respected.** Copyrighted or restricted frameworks are referenced by identifier and title only. Their text is never ingested or quoted.

## 2. Registry schema
`references(id, framework, version, control_id, title, url, license_class, excerpt_allowed, reviewed)`
- `license_class` is one of:
  - `public_domain`: US government works, e.g. NIST.
  - `open`: openly licensed, e.g. OWASP (CC BY-SA) or MITRE CWE (terms of use) [VERIFY each].
  - `restricted_reference_only`.
- `reviewed` is set to true only after the human checks the entry against the official source.

## 3. Initial entries

### Public-domain or open sources (excerpts may be ingested for RAG in v0.3)
| Framework | IDs | Status |
|---|---|---|
| NIST SP 800-41 Rev. 1, *Guidelines on Firewalls and Firewall Policy* (2009) | Whole document; sections on host-based firewalls and policy | Rev. 1 is the latest revision found ([NIST](https://www.nist.gov/publications/guidelines-firewalls-and-firewall-policy)) |
| NIST SP 800-53 Rev. 5 | SC-7 (Boundary Protection), SC-7(5) (Deny by Default, Allow by Exception), CM-7 (Least Functionality), CM-6 (Configuration Settings), CM-3 (Configuration Change Control), AC-4 (Information Flow Enforcement), AU-2 (Event Logging), AU-12 (Audit Record Generation), SI-4 (System Monitoring) | Control titles [VERIFY each against the SP 800-53 Rev. 5 catalog] |
| NIST CSF 2.0 (CSWP 29) | DE.CM-01 "Networks and network services are monitored to find potentially adverse events"; ID.AM-02 "Inventories of software, services, and systems managed by the organization are maintained"; PR.PS-02 "Software is maintained, replaced, and removed commensurate with risk"; PR.PS-04 "Log records are generated and made available for continuous monitoring"; PR.PS-06 (secure software development, for FirewallAI itself); PR.PS-01 and PR.IR-01 [VERIFY exact text] | Quoted text was extracted from [NIST CSWP 29](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf) on 2026-10-14; PR.PS-01 and PR.IR-01 could not be extracted |
| MITRE CWE (for FirewallAI's own security) | CWE-78, CWE-79, CWE-269, CWE-312, CWE-427, CWE-532 | [VERIFY titles] |
| OWASP Top 10 for LLM Applications 2025 (for FirewallAI's own AI) | LLM01 Prompt Injection, LLM02 Sensitive Information Disclosure, LLM05 Improper Output Handling, LLM06 Excessive Agency, LLM09 Misinformation, LLM10 Unbounded Consumption | Names cross-checked against secondary sources; [VERIFY on genai.owasp.org] |

### Restricted sources (identifier and title only; no text ingested)
| Framework | IDs | Licensing note |
|---|---|---|
| CIS Microsoft Windows 11 Benchmark | Section "Windows Defender Firewall with Advanced Security" (section numbers vary by benchmark version) [VERIFY numbers per version] | CIS Benchmarks are licensed CC BY-NC-SA 4.0. Commercial use requires CIS approval (as reproduced in NIST NCP records). Reference only. |
| CIS Controls v8.1 | 4.4 Implement and Manage a Firewall on Servers; 4.5 Implement and Manage a Firewall on End-User Devices; 4.8 Uninstall or Disable Unnecessary Services; 13.x Network Monitoring and Defense | [VERIFY titles and v8.1 numbering] |
| ISO/IEC 27001:2022 / 27002:2022 | 8.9 Configuration management; 8.15 Logging; 8.16 Monitoring activities; 8.20 Networks security; 8.21 Security of network services; 8.22 Segregation of networks | Copyrighted by ISO/IEC. Titles only. [VERIFY titles] |
| Microsoft Learn (Windows Firewall documentation) | Links | Linked and summarized in our own words |

## 4. Example finding mapping
`FW-RULE-001` (overly broad inbound allow rule on Public) **relates to**: NIST SP 800-53 SC-7(5); CM-7; CIS Controls 4.5; ISO/IEC 27002:2022 8.20; NIST SP 800-41r1.

## 5. RAG (v0.3)
- Corpus: `public_domain` and `open` entries only, chunked with their source URL and version.
- Retrieval: SQLite FTS5 (BM25) first. Vectors from `nomic-embed-text` via Ollama are added if they measurably improve retrieval.
- Retrieved chunks are **untrusted input**. They go into data fields and are subject to the same prompt-injection controls.
- Every citation shown to the user resolves to a registry entry with a URL.
