# KODA CLI and local usage

This guide covers the shared Python engine used by Linux, Windows, CI, and server deployments. For platform installation and closed-network bundles, use the [English documentation index](README.en.md). For Korean navigation, use the [Korean CLI guide](usage.ko.md).

## Choose a workflow

| Goal | Start with | What it gives you |
| --- | --- | --- |
| Scan a repository before review or release | `scan --target . --standard owasp-asvs-5 --format html --output reports/source.html` | A summary HTML page plus a linked detail page for source, configuration, dependencies, secrets, and prevention gaps. |
| Run a repeatable CI gate | `scan --changed-only --base origin/main --format sarif --fail-on high` | Changed-file scan, SARIF output, and a nonzero exit code at the chosen severity. |
| Create an offline Java inventory | `jar-scan --target /deploy/apps [--target /deploy/worker-apps]` | CycloneDX, vulnerability, HTML, Markdown, and scan-metadata artifacts from all supplied roots. |
| Export the joint-guideline SBOM columns | `scan --target . --format nis-sbom --output reports/koda-nis-sbom-1.0.csv` | UTF-8 CSV with the 20 NIS-SBOM 1.0 basic fields; unavailable values remain empty. |
| Compare a deployment to an approved baseline | `sbom-verify --target /deploy/apps --sbom approved.cdx.json` | Archive, version, PURL, and optional SHA-256 mismatch evidence. |
| Check the current workstation | `host-scan --format json --min-severity info` | Opt-in host posture findings; network enrichment remains separately opt-in. |
| Check a website you are authorized to test | `web-scan --url https://example.com` | Headers, TLS, cookie, CORS, and coverage findings. |

Run `python3 -m security_scanner <command> --help` before adding optional flags to a production workflow.

## Run from a source checkout

```bash
export PYTHONPATH="$PWD/platforms/shared/python"
python3 -m security_scanner app
```

`app` opens the local dashboard in the default browser. `serve` starts the same dashboard without opening a browser:

```bash
python3 -m security_scanner serve
```

The default binding is `127.0.0.1:8765`. Open `http://127.0.0.1:8765/security-dashboard.html`.

### Development dashboard access changes — 2026-10-02

In the unpublished security-boundary development checkout, scan, directory
selection, export, prevention, web, and ZAP POST requests require
`Origin: http://<Host>` and the `X-KODA-Session` value from `/api/health`.
The built-in dashboard supplies both. A stale exported dashboard or a direct API
client that omits them receives HTTP 403; use the dashboard served by the same
running instance. `web-audit` additionally requires a loopback binding and client.
See the [status snapshot](current-status.en.md) for publication and test scope.

## Configure a scan

Copy the example configuration and change its target path:

```json
{
  "targets": [
    {
      "name": "security-workspace",
      "path": ".",
      "discover_projects": false,
      "categories": ["secrets", "dependencies", "configuration", "code", "prevention"],
      "exclude_globs": ["**/.git/**", "**/node_modules/**"],
      "max_file_size_bytes": 524288
    }
  ],
  "enable_osv": false,
  "enable_vuln_intel": false,
  "report": {
    "format": "html",
    "output": "reports/security-dashboard.html",
    "min_severity": "low",
    "language": "ko"
  }
}
```

To suppress a known false positive without changing a scanner rule, add `koda-ignore.yml` or `.koda-ignore.yml` to the scanned-folder root:

```yaml
ignore:
  - rule: secret.openai-key
    path: .env
    reason: local development placeholder
    until: 2099-12-31
```

## Common commands

```bash
# Discover project roots and run local scans
python3 -m security_scanner discover --target /path/to/projects
python3 -m security_scanner scan --target /path/to/project --category secrets --format json
python3 -m security_scanner scan --target . --standard owasp-proactive-controls --format html --output reports/source.html
python3 -m security_scanner scan --target . --standard sw-dev-security-49 --standard-category input-validation-expression --format html --output reports/sw49-input.html
python3 -m security_scanner scan --target . --standard sw-dev-security-49 --format json --output reports/sw49-source.json
python3 -m security_scanner scan --config scanner_config.example.json --fail-on high
python3 -m security_scanner scan --target . --format sarif --output reports/results.sarif
python3 -m security_scanner scan --target . --format cyclonedx --output reports/sbom.cdx.json
python3 -m security_scanner scan --target . --format nis-sbom --output reports/koda-nis-sbom-1.0.csv

# Optional external dependency intelligence
python3 -m security_scanner scan --target . --enable-osv --format html
python3 -m security_scanner scan --target . --enable-vuln-intel --format html
python3 -m security_scanner scan --target . --enable-osv --reachability --format json

# CI-oriented changed-file scan
python3 -m security_scanner scan --target . --changed-only --base origin/main --format sarif --fail-on high

# Offline Java archive scan and deployed-SBOM verification
python3 -m security_scanner jar-scan --target /deploy/apps --target /deploy/worker-apps --output-dir reports/java-scan --fail-on high --fail-on-kev
python3 -m security_scanner jar-scan --target /deploy/apps --sbom-format nis-1.0 --output-dir reports/java-scan
python3 -m security_scanner sbom-verify --target /deploy/apps --sbom reports/approved-sbom.cdx.json --output-dir reports/sbom-verification --strict-hash --fail-on-mismatch
```

Source HTML writes the requested summary path and a `-detail.html` sibling. The
summary is the landing page; the detail page contains the complete static finding
table and filters. `--standard` accepts only profiles registered by KODA and
`--standard-category` selects one supported category. The profiles are mappings to
the local static rules, not a claim of full SAST or formal compliance.

### Offline source-only SW49 analysis

The SW49 path inventories and scans only `.java`, `.xml`, `.js`, `.jsp`, `.html`,
`.py`, `.ts`, and `.tsx` files (case-insensitive). All other extensions and
extensionless files are excluded.
It does not run web, host, OSV/CVE, SBOM, JAR, binary, build, test, package-manager,
or project scripts. Changed-only reports retain unchanged supported files as analysis
context.

The first external mapping accepts administrator-generated CodeQL `2.26.1` Java
SARIF. KODA never downloads or executes CodeQL and does not fall back to an
unsandboxed invocation. Runtime analyzer requests are explicitly `SKIPPED`/
`NOT_SCANNED`; use `source_analyzer_sarif` for positive-only import.

SARIF imports are positive-only and fail closed: only SARIF 2.1.0 results inside the
target with an allowlisted analyzer/rule pair are accepted. Unknown rules warn and
are ignored; malformed, oversized, wrong-version, or path-escaping documents fail.
A clean or digest-matched SARIF file cannot certify negative coverage or `PASS`.

Every SW49 scan emits all 49 controls. `VULNERABLE` requires confirmed source
evidence, `NEEDS_REVIEW` marks heuristic/business-context candidates, and `PASS`
requires a benchmark-certified profile with every required strategy complete. The
fixture index at [`tests/fixtures/sw49/manifest.json`](../tests/fixtures/sw49/manifest.json)
tracks all controls; manual/unsupported pairs are bounded review placeholders, not
measured accuracy evidence.

Java reports are generated in Korean (`--language ko`). `server-library-report.html` is the landing page and
`server-library-report-detail.html` contains the complete table. Java findings are grouped by library and installed version;
`Fixed` lists advisory candidates and `Final` is the lowest candidate verified against
the same Grype database with no matching vulnerability. Repeat `--target` to scan
multiple roots into this one report pair; archive, component, SBOM, and vulnerability
entries are combined and duplicate archive locations are removed.

`--fail-on` exits nonzero when a finding meets the specified severity. `--enable-osv` queries OSV.dev using exact package names and versions. `--enable-vuln-intel` includes OSV and enriches available CVEs with CISA KEV and FIRST EPSS data; both options are off by default so ordinary scans remain offline.

`--reachability` labels dependency findings as `reachable`, `unreachable`, or `unknown` from local Python and JavaScript/TypeScript import analysis. It does not remove a finding. Add `--reachable-only` with `--fail-on` when an unreachable result should not fail a gate.

## AI assists (opt-in)

All AI assists are optional, default-off, and never change a finding's severity or
gate result. They share one backend selected by `--llm` / `KODA_LLM` and degrade
gracefully (with a one-line warning) when no backend is configured. Raw secrets and
source are never sent for `secrets` findings. Flags, by scan type:

| Flag | Effect | Where |
| --- | --- | --- |
| `--ai-triage` | Label findings `likely_true` / `likely_false` / `uncertain` | scan, web-scan, net-scan |
| `--ai-remediate` | Append a concrete fix suggestion to each finding | scan, web-scan, net-scan |
| `--ai-explain` | Append a one/two-sentence impact narrative to high-impact findings | web-scan, net-scan |
| `--ai-map` | Suggest a CWE/OWASP mapping for findings that lack one | web-scan, net-scan |
| `--ai-summary` | Print an executive risk summary of the findings | scan, web-scan, net-scan |
| `--ai-query "<question>"` | Print the findings an LLM judges relevant to a question (read-only) | scan, web-scan, net-scan |

```bash
python3 -m security_scanner scan --target . --ai-triage --ai-remediate \
  --llm ollama/qwen2.5-coder:7b --format json
```

Use a local Ollama backend to keep finding context on the machine. A cloud backend
such as `anthropic/<model>` or `openai/<model>` is an explicit data transfer and
requires an API key through `KODA_LLM_API_KEY` (or the provider-specific variable).
See [Privacy Policy](../PRIVACY.md) before using a cloud backend.

### Local OpenAI-compatible server (LM Studio, llama.cpp, vLLM)

Point the `openai` backend at a local server that speaks the OpenAI API. The key
is required by the SDK but ignored by the server, so any placeholder works, and a
loopback endpoint is treated as local (no external-network warning):

```bash
export KODA_LLM=openai/qwen3.8-27b-uncensored-mlx   # the id from GET /v1/models
export KODA_LLM_API_BASE=http://localhost:1234/v1    # LM Studio default
export KODA_LLM_API_KEY=local                        # placeholder; the server ignores it
python3 -m security_scanner scan --target . --ai-triage --ai-remediate --llm-timeout 180
```

Large local models (e.g. a 27B served via LM Studio) are slow — raise
`--llm-timeout` (default 120s) so calls don't time out. Only `localhost`,
`127.0.0.1`, and `::1` count as on-machine; a LAN address still triggers the
data-left-this-machine warning.

## New-only gate (baseline)

`--baseline REPORT` makes `--fail-on` trip only on findings absent from a prior JSON
report (matched on rule id / target / path / line), so CI can gate on newly
introduced issues without failing on a known backlog:

```bash
python3 -m security_scanner scan --target . --format json --output baseline.json
# later, in CI:
python3 -m security_scanner scan --target . --fail-on high --baseline baseline.json
```

Available on `scan`, `web-scan`, and `net-scan`. A missing baseline file suppresses
nothing. Web-scan and net-scan findings are also correlated into higher-level
`attack-path.*` findings (e.g. SSRF→metadata credential theft, exposed Docker API→
host takeover) so end-to-end impact is prioritized.

For a complete command list and current flags, run:

```bash
python3 -m security_scanner --help
python3 -m security_scanner scan --help
```

## Reports

| Format | Use |
| --- | --- |
| `html` | Static dashboard with filtering, severity metrics, coverage, and finding details. |
| `markdown` | Readable text report. |
| `json` | Scanner-native structured report. |
| `sarif` | SARIF 2.1.0 for static-analysis consumers. |
| `cyclonedx` | CycloneDX JSON SBOM from supported dependency manifests. |
| `nis-sbom` | UTF-8 CSV using the NIS-SBOM 1.0 20-field column set. |
| `cyclonedx-vex` | CycloneDX VEX draft; vulnerabilities remain `in_triage` until human review. |

See the [report contract](report-contract.md) for output fields.

### NIS-SBOM 1.0 CSV

KODA follows the 20 basic SBOM fields described in the 2024 joint
[SW Supply Chain Security Guideline 1.0](https://www.krcert.or.kr/kr/bbs/view.do?bbsId=B0000127&menuNo=205021&nttId=71432&pageIndex=1):
`SBOM Standard`, `SBOM Type`, `CycloneDXNo.`, `SPDX Doc. ID`, `SBOM ID`,
`Product Name`, `Product Version`, `Component Name`, `Component Alias`,
`Component Version`, `Component Supplier Name`, `Component Hash`,
`Component Path`, `SBOM Author Name`, `Unique Identifier`,
`Dependency Relationship`, `Timestamp`, `License Name·Version`, `Vul. DB`, and
`Vul. Info`.

The Windows desktop shared dashboard exposes this as **NIS-SBOM 1.0 (CSV)**
next to the SBOM download button. The authenticated Linux portal exposes the
same choice on each completed analysis-round page. `scan --format nis-sbom`
writes the requested CSV directly; `jar-scan --sbom-format nis-1.0` additionally
writes `server-sbom.nis.csv` beside the normal Java reports and CycloneDX SBOM.
KODA preserves all 20 columns and leaves fields empty when the scan evidence
does not establish a value. This exporter is format support, not NIS
certification or a formal compliance determination.

## CI

The repository includes a composite action at `.github/actions/koda/`. A consuming repository can scan pull-request changes and upload SARIF:

```yaml
jobs:
  koda-security:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: <owner>/<koda-repo>/.github/actions/koda@main
        with:
          fail-on: high
          changed-only: "true"
```

The action scopes pull-request scans to changed files when history is available. Use `fail-on: none` to report without failing the job.

## Authorized web scanning

The default `web-scan` performs a bounded posture check. `--crawl`, `--render`,
`--discover-assets`, `--capture-network`, `--interact`, `--scan-js-secrets`,
`--ingest-sitemap`, and `--probe-paths` increase the requests or discovery scope.

`web-scan` escalates in explicit opt-in tiers — passive (default), `--active`
(bounded verified payloads: reflected/JS-context XSS, multi-engine SSTI, SQLi,
LFI, open redirect, CRLF, header injection on query params, forms, and the
`--api-spec` surface), and `--intrusive` (adds time-based blind SQLi / OS command
injection, JSON write-endpoint fuzzing, and stored XSS; `--oob-listen HOST:PORT`
adds a built-in collector that confirms blind SSRF / RCE). `--intrusive` requires
`--active`, sends state-changing requests, and is for authorized staging only.
`--exploit` (requires `--intrusive`) adds proof-of-impact: for a confirmed
injection it extracts a single read-only evidence value (DB version, `id` output,
an evaluated expression) and stops — no data dump, shell, or destruction. No tier
sends data-destroying payloads. Tune coverage with `--max-params` and
`--max-form-fields`; set `--delay 0` for maximum throughput. See the
[web-scan scanning tiers](security/WEB_AUDIT.md#web-scan-scanning-tiers) table for
the full breakdown and when to escalate to `web-audit` or `zap-run --mode full`.

`--crawl` defaults to 50 pages and depth 3; use `--max-pages` and `--max-depth`
to adjust those budgets. KODA deduplicates URLs and applies a separate request
safety limit. Page, depth, or request limits, body-read limits, and rendering
failures are reported as warnings with unscanned coverage rather than hidden as
PASS. `--timeout` is a per-request connection/idle-read limit, not a strict
wall-clock limit for the complete scan.

The local dashboard's Select all control is scoped to web-scan options and does
not change ZAP options. It includes active verification, so use it only on an
authorized target. The dashboard automatically forwards its loopback session
token before an active scan. Direct API clients must send the `X-KODA-Session`
value returned by `/api/health` together with the exact loopback `Origin`.

```bash
# Bounded posture scan
python3 -m security_scanner web-scan --url https://example.com --format markdown

# Active checks (XSS/SSTI/SQLi/LFI/redirect/CRLF): explicit authorization required
python3 -m security_scanner web-scan --url https://example.com --active

# Intrusive tier (blind SQLi/RCE timing, JSON fuzzing, stored XSS): authorized staging only
python3 -m security_scanner web-scan --url https://staging.example.com --active --intrusive \
  --api-spec openapi.json

# Add an out-of-band collector to confirm blind SSRF / command injection.
# HOST:PORT is the address the target can reach this scanner on.
python3 -m security_scanner web-scan --url https://staging.example.com --active --intrusive \
  --oob-listen 10.0.0.5:8899

# Proof-of-impact: pull ONE read-only evidence value from a confirmed injection
# (DB version, `id` output, evaluated expression). No dump/shell/destruction.
python3 -m security_scanner web-scan --url https://staging.example.com --active --intrusive --exploit

# ZAP's default is a baseline scan. Full/API/active automation also require
# --authorize-active and an authorized target.
python3 -m security_scanner zap-run --url https://example.com --mode full --authorize-active
```

Use `--header`, `--login-url`, and `--password-env` rather than putting a session
or password directly in shell history. `--compare-unauth` and `--secondary-header`
can compare access behavior, so use them only with suitable test accounts and
authorization.

For the 21-control profile-driven audit, use the approval-gated `web-audit` command:

```bash
export KODA_APPROVAL_KEY='operator-managed-secret'
python3 -m security_scanner web-audit plan --profile profile.json --out approval-request.json
python3 -m security_scanner web-audit approve --request approval-request.json --approver name --out approval.json
python3 -m security_scanner web-audit run --profile profile.json --approval approval.json \
  --confirm-origin https://staging.example.com --format markdown --output reports/web-audit.md
```

`plan` performs DNS/IP preflight without target traffic. `run` verifies the profile
hash, exact origin, current IP set, expiry, signature, and one-time nonce. A profile
must declare its expected success/rejection oracles; undeclared surfaces cannot be
reported as PASS. See the [web audit runbook](security/WEB_AUDIT.md).

Use `--dry-run` to validate the approval, profile, and installed capability without
sending target requests or consuming the nonce:

```bash
python3 -m security_scanner web-audit run \
  --profile profile.json \
  --approval approval.json \
  --confirm-origin https://staging.example.com \
  --dry-run
```

Build a profile in this order:

1. Pin exact `target.origins`, path includes/exclusions, approved IP/CIDR ranges,
   and the smallest required scopes.
2. Declare every `resources` entry with an ID, allowed methods, read-only flag,
   and actor-specific access expectation. Scenarios may reference resource IDs only.
3. Attach each scenario to one `web.*` control and declare its strategies, steps,
   mutations, cleanup, and success/rejection oracle. Every required strategy must
   complete before the control can be `PASS`.
4. Reference credentials with `${ENV:NAME}` or an environment-variable name. Do
   not put passwords, cookies, tokens, shell/eval, Python callbacks, or arbitrary
   URLs in a profile.
5. Mark a genuinely unavailable control with `applicability` status
   `NOT_APPLICABLE` and a reason. An omitted scenario is `NOT_SCANNED`, not N/A.

The dashboard exposes the same gate through loopback-only endpoints:

| Endpoint | Purpose | Required JSON fields |
| --- | --- | --- |
| `POST /api/web-audit/plan` | Validate a profile without target traffic | `profile` |
| `POST /api/web-audit/approve` | Create an HMAC approval | `request`, `approver` |
| `POST /api/web-audit/run` | Execute one approved run | `profile`, `approval`, `confirm_origin`, optional `dry_run` |

The request must come from a loopback client with the exact local `Origin` and the
per-process `X-KODA-Session` value returned by the dashboard HTML. Binding the
server to a non-loopback address disables these three endpoints with 403. Results
always contain all 21 `web.*` controls, but publish only redacted evidence IDs,
coverage, tested surfaces, and status—not raw requests/responses, cookies, tokens,
passwords, or ZAP plugin IDs.

The CLI exits with 1 for `VULNERABLE`, 2 for profile/approval/capability errors,
and 0 for `PASS`, `NEEDS_REVIEW`, `UNSUPPORTED`, or `NOT_SCANNED`. Treat exit 0 as
“the run completed” rather than “all 21 controls passed”; inspect every control and
require `coverage.completed == coverage.required` in a stricter CI policy.

## Actions that can change state or contact a target

| Command | Behavior |
| --- | --- |
| `fix --target .` | Prints a dry-run diff. Add `--apply` to write deterministic fixes; backups are created unless `--no-backup` is supplied. |
| `init-security` | Creates prevention templates without overwriting existing files by default. |
| `install-hook` | Installs a local KODA pre-commit gate. |
| `web-scan` | Contacts an authorized URL. Crawling, rendering, and path probes widen the request scope. |
| `net-scan` | Actively probes a host's exposed network services (ports/banners, TLS, default credentials). Requires `--authorize-active`. |
| `zap-run` | Runs an authorized OWASP ZAP baseline through Docker. |
| `upload-sbom` | Uploads an SBOM to Dependency-Track; store its API key in an environment variable. |

`net-scan` covers the non-web network surface: a curated TCP port/banner sweep, active
TLS tests (deprecated TLS 1.0/1.1, weak ciphers, certificate validity), and a small
published-default-credential check over HTTP Basic auth (not a brute forcer). It
actively contacts the target, so it requires `--authorize-active`:

```bash
python3 -m security_scanner net-scan --host 10.0.0.10 --tls --authorize-active
python3 -m security_scanner net-scan --host 10.0.0.10 --default-creds-url https://10.0.0.10/admin --authorize-active
```

`web-scan`, `net-scan`, and `zap-run` must only target systems you own or are explicitly authorized to test. The [ZAP guide](security/ZAP_BASELINE.md), [Dependency-Track guide](security/DEPENDENCY_TRACK.md), and [offline Java runbook](security/java-sbom-vulnerability-scan.en.md) contain the operating details.

## Limits

KODA provides consistent local evidence and optional intelligence; it is not a replacement for full SAST, authenticated DAST, container scanning, a vulnerability database, CVSS scoring, or manual review. Security-standard selections map local rules to profiles. Requirements that need runtime testing, hosted-service settings, release artifacts, or organizational evidence remain marked as external integration or evidence review.
