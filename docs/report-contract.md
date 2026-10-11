# KODA Report Contract

Linux, Windows, CI, and server flows use the shared Python engine. The macOS app
uses the native Swift scanner and a bundled shared-engine helper for Java scans.
Consumers must select the contract for the
artifact they read; the fields below describe findings from shared-engine
`scan --format json` output.

## Finding Fields

Every `scan --format json` finding uses these keys:

| Field | Required | Notes |
| --- | --- | --- |
| `rule_id` | yes | Stable rule identifier such as `secret.openai-key` or `host.linux.ssh-root-login`. |
| `category` | yes | One of the category values below. |
| `severity` | yes | One of `info`, `low`, `medium`, `high`, `critical`. Lowercase only. |
| `title` | yes | Short user-facing finding title. |
| `target` | yes | Logical scan target name. Empty string is allowed when not applicable. |
| `path` | yes | File path when file-backed; host findings may use a relevant system path or an empty path. |
| `line` | yes | 1-based line number or `null`. |
| `evidence` | yes | Redacted evidence. Do not expose raw secrets. |
| `description` | yes | Why this matters. Empty string is allowed. |
| `recommendation` | yes | Remediation guidance. Empty string is allowed. |
| `resource` | yes | Stable host/resource identifier. Empty string for file-backed findings. |
| `reachable` | yes | Empty string, `reachable`, `unreachable`, or `unknown`. |
| `verification_status` | yes | `confirmed`, `needs_review`, or `unverified`. `unverified` means the check could not be evaluated (probe unavailable or blocked); it is an evidence gap, not a risk judgement, and never counts toward scores or gates. Unknown imported values fail closed to `needs_review`. |
| `verification_note` | yes | Reason for the deterministic verification state. Empty string when not needed. |
| `triage_verdict` | yes | Empty string, `likely_true`, `likely_false`, or `uncertain`. |
| `triage_confidence` | yes | Number from 0 to 1, or `null`. |
| `triage_note` | yes | Short triage note. Empty string when not triaged. |
| `analyzer` | yes | Analyzer identity, such as `koda-local` or an approved external analyzer. |
| `analyzer_version` | yes | Analyzer version when known. |
| `analyzer_rule_id` | yes | Original external analyzer rule ID when applicable. |
| `cwe_ids` | yes | CWE identifiers associated with the evidence. Empty array when unavailable. |
| `evidence_kind` | yes | Evidence type, such as `direct` or `dataflow`. |
| `trace` | yes | Ordered evidence trace steps. Empty array when unavailable. |
| `evidence_id` | yes | Stable evidence identifier when assigned. |
| `issue_key` | yes | Stable issue correlation key when assigned. |
| `standard_mappings` | yes | Selected standard/category mappings for the rule. Empty array when unmapped. |

File findings with a line number also include an additive `source_context`
object. Consumers must tolerate additive fields.

## Other JSON artifacts

- `release-package` writes a compact `scan-findings.json` with core finding,
  verification, and analyzer-provenance fields. It does not include
  `target`, `resource`, reachability/AI-triage fields, `standard_mappings`, or
  `source_context`.
- `web-audit` results use the separate 21-control status/coverage/evidence
  contract documented in [WEB_AUDIT.md](security/WEB_AUDIT.md).
- Java archive and SBOM-verification JSON files have workflow-specific schemas;
  use the [Java runbook](security/java-sbom-vulnerability-scan.en.md).

## Categories

Current production categories:

- `secrets`
- `dependencies`
- `configuration`
- `code`
- `prevention`
- `screen_quality`
- `host`

`web` is used by authorized web posture scans and should keep the same finding field shape.

## Platform Rules

- macOS Swift and shared Python implementations may differ internally.
- Shared fields such as `rule_id`, `category`, and `severity` keep the same
  meaning across platform lanes, but artifact-specific schemas are not identical.
- Severity values are lowercase and ordered as: `info`, `low`, `medium`, `high`, `critical`.
- CI gates must use `severity`, not localized labels or UI text.
- Report additions should be additive. Do not rename or remove existing keys without a migration.

## CSV export behavior — 2026-10-11

In the security-boundary implementation included in this GitHub publication, NIS-SBOM CSV cells are quoted and
values beginning with formula characters (`=`, `+`, `-`, `@`, including fullwidth
forms after leading whitespace/BOM/NUL) are prefixed with a tab. CSV text can
therefore differ from the original value. Use JSON or CycloneDX for exact machine
values; do not strip this guard when opening the CSV in a spreadsheet. This
changes presentation, not original finding severity or identity. See the
[status snapshot](current-status.en.md) for implementation publication status.

## Verification

The [2026-10-11 validation record](verification-2026-10-11.md) describes the
Java-enabled macOS build and ARM execution, and Linux x86_64 portal/PDF/Java
execution. Windows runtime validation was excluded at the user's request.
Java HTML/Markdown reports use Korean, including in the macOS helper regardless
of UI language. A requested Java vulnerability gate without Grype comparison
exits `2`; a missing source scan target also exits `2`. Review warnings and
coverage alongside exit status.

The shared Python serializer is `security_scanner.reporting._finding_payload`.
Run `tests.test_source_analysis`, `tests.test_sw49_standards`, and
`tests.test_settings_and_exports` after changing finding serialization or report
exports.

When changing the macOS Swift scanner output, verify the consumer's actual export
format rather than assuming byte-for-byte parity with shared-engine scan JSON.
