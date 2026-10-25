# Authoritative Security Standard Mapping Audit

Last reviewed: 2026-07-24

This document records whether KODA's standard names, categories, and rule
mappings match the current public taxonomies from their issuing organizations.
KODA produces **evidence** from static heuristics and opt-in external checks. It
does not certify compliance, and zero findings do not prove compliance.

## Korean public-sector profiles

| KODA profile | Relationship to the authoritative source | KODA coverage | Result |
| --- | --- | --- | --- |
| Software Development Security 49 | Registers the seven types and 49 implementation-stage weaknesses from the 2021 MOIS/KISA guide as individual controls | Distinguishes automated, partial, manual-review, and unsupported controls | Taxonomy aligned |
| Seven Software Security Types | Aggregates the same 49 controls into the seven official parent types | Shows evidence from the mapped 49 controls by parent type | Taxonomy aligned |
| KISA Software Security Weakness Diagnostic Guide 2021 | The official KISA guide published on 2021-11-30, with seven types and 49 implementation-stage weaknesses | Distinguishes automated, partial, manual-review, and unsupported controls | Taxonomy aligned |

MOIS publishes the 2021 Software Development Security Guide, and KISA publishes
the corresponding 2021 Software Security Weakness Diagnostic Guide. See the
[Software Development Security 49 mapping](sw-development-security-49.en.md)
for the control-level support table.

Official sources:

- [MOIS Software Development Security Guide (2021)](https://www.mois.go.kr/frt/bbs/type001/commonSelectBoardArticle.do?bbsId=BBSMSTR_000000000015&nttId=88956)
- [KISA Software Security Weakness Diagnostic Guide (2021)](https://www.kisa.or.kr/2060204/form?page=1&postSeq=9)
- [KISA Python Secure Coding Guide (2022)](https://www.kisa.or.kr/2060204/form?postSeq=13)

The KISA Python guide is a language-specific reference. The current
`kisa-secure-coding-guide` profile does not claim to implement that entire
document as a separate standard.

## OWASP profiles

| KODA profile | Authoritative taxonomy check | KODA coverage and limitation |
| --- | --- | --- |
| OWASP Top 10:2025 | Matches the ten current official risk categories | Connects only directly related rules. A04 includes key length, randomness, certificate verification, and password hashing; A05 includes LDAP, XML, CRLF, and format-string injection |
| OWASP Proactive Controls 2024 | Corrected to the official C1-C10 names | Checks only repository evidence related to each preventive control |
| OWASP ASVS 5.0.0 | Corrected to the 17 official chapters | Fifteen chapters have related static evidence; V10 OAuth/OIDC and V17 WebRTC are unsupported. KODA does not claim requirement-level compliance |
| OWASP WSTG v4.2 | Corrected to the 12 official test areas | Nine areas have static hints. Information Gathering, Identity Management, and Business Logic are unsupported; live-target testing is required |
| OWASP API Security Top 10:2023 | Matches official API1-API10 | Source and configuration hints only; runtime authorization and business-flow testing remain external |
| OWASP Mobile Top 10:2024 | Matches official M1-M10 | Mobile source, manifest, and plist hints only; runtime and deployment validation remain external |
| OWASP MASVS | Corrected to the eight official control groups | Maps only related local evidence for storage, crypto, auth, network, platform, code, resilience, and privacy |
| OWASP SAMM 2 | Corrected to the five official business functions | Shows evidence for Governance, Design, Implementation, Verification, and Operations, but does not score the 15 practices or maturity levels |
| OWASP SCVS | Matches the six official control families | Covers repository evidence and optional SBOM/VEX integrations only |
| OWASP Top 10 for LLM Applications 2025 | Matches official LLM01-LLM10 | Checks related code and configuration hints; model and prompt attack validation remain external |
| Dependency-Check baseline | KODA readiness profiles for using OWASP projects | Not represented as separate OWASP compliance standards |

### Source finding semantics

- Source rules do not judge each line independently. The scanner first examines the whole file for untrusted assignments and aliases, sanitizers, global authentication and rate-limit controls, and nearby timeout or debug guards.
- A finding is `confirmed` only when untrusted input reaches an unguarded SQL, HTML, command, file, eval, HTTP, redirect, LDAP, response-header, deserialization, upload, mass-assignment, or format-string sink in the same file.
- API or configuration pattern matches without a proven flow remain `needs_review` and do not contribute to risk scores or failure gates.
- Cross-function and cross-file calls, framework-wide policy, object authorization, business flows, and deployment behavior still require design or runtime evidence. KODA does not infer ASVS compliance or completed WSTG/SAMM assessment from static findings.

Official sources:

- [OWASP Top 10:2025](https://owasp.org/Top10/2025/0x00_2025-Introduction/)
- [OWASP Proactive Controls 2024](https://top10proactive.owasp.org/the-top-10/)
- [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/)
- [OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP API Security](https://owasp.org/API-Security/)
- [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/2023-risks/)
- [OWASP MASVS](https://mas.owasp.org/MASVS/)
- [OWASP SAMM](https://owaspsamm.org/model/)
- [OWASP SCVS](https://scvs.owasp.org/scvs/using-scvs/)
- [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/)

## CWE profiles

| KODA profile | Relationship to the authoritative source | KODA coverage |
| --- | --- | --- |
| CWE Top 25:2025 | Corrected to the official order, CWE IDs, and names of the 25 MITRE entries | Connects direct local evidence to 18 entries and leaves seven memory-safety or semantic-analysis entries unsupported. CWE-476 has limited same-file Java/Kotlin evidence |

Official sources:

- [MITRE CWE Top 25:2025](https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html)

Profiles without a verifiable authoritative source or current edition, previous
editions, and KODA-defined convenience taxonomies are excluded from the
standard selector. CLI help and macOS settings show each registered standard's
issuer, edition, and publication year or date.

## Interpreting coverage

- `automated`: a mapped heuristic automatically checks the locally observable
  part of the criterion.
- `partial`: only some patterns are observable, so zero findings still requires
  further review.
- `manual-review`: a person must inspect design, business-flow, or runtime
  evidence.
- `unsupported`: KODA does not assess the criterion.
- Source-selectable standards and reference profiles shown in the dashboard are
  separate. Verification systems such as WSTG, MASVS, and SAMM cannot be judged
  compliant from static results alone.
