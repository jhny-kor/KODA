# KODA profile-driven 21-control web audit

> Updated 2026-10-11 against the local source checkout, including changes under
> development. Publishing these docs does not publish the source changes or update
> existing release images. See the [2026-10-11 validation record](../verification-2026-10-11.md)
> and confirm the installed version and matching rebuilt bundle before use.

`web-audit` is the approval-gated path for testing an owned or explicitly
authorized staging/test service. It is not a generic crawler command and it does
not infer that an undeclared endpoint is safe. A control is `PASS` only when its
profile declares the tested surface, expected result, required strategies, and
cleanup, and all of those checks complete without evidence of a violation.

The existing `web-scan` command remains the lightweight web-posture/crawl path.
Use `web-audit` when the result must carry a reproducible target scope, approval,
one-time nonce, bounded traffic, and per-control coverage.

## web-scan scanning tiers

`web-scan` escalates in explicit, opt-in tiers. Each tier verifies findings by
observing the server's response (reflected marker, evaluated expression, error
signature, measured delay, out-of-band callback) rather than guessing, and no
tier sends data-destroying payloads — a benign proof of concept (`sleep`, a
unique marker, an OAST hit) proves the same bug without damaging the target.

| Tier | Flag | What it does | Traffic |
| --- | --- | --- | --- |
| Passive | *(default)* | TLS, security headers, cookie flags, CSP/HSTS quality, information disclosure, CORS reflection, JWT, advertised HTTP methods, Host-header reflection, secrets in JS assets. | Read-only GET/OPTIONS. |
| Active | `--active` | Bounded, verified payloads to query params, form fields, and (with `--api-spec`) the API surface: reflected XSS, JS-context XSS, multi-engine SSTI, error-based SQL injection, path traversal/LFI, open redirect, CRLF / response-header injection, and `Referer`/`X-Forwarded-For` header injection. | GET + non-login form submits; non-destructive. |
| Intrusive | `--intrusive` (requires `--active`) | Time-based blind SQL injection and OS command injection (timing differential, re-confirmed), JSON write-endpoint fuzzing (POST/PUT/PATCH bodies from `--api-spec`), and stored / second-order XSS (a marker injected on one page detected on another). | State-changing requests — authorized staging only. |
| Intrusive + OAST | `--oob-listen HOST:PORT` (requires `--intrusive`) | Starts a built-in HTTP out-of-band collector and confirms blind SSRF and blind OS command injection via a caller-controlled callback. `HOST:PORT` is the address the target can reach the scanner on; the port is bound locally. | Adds outbound fetches the target performs to the collector. |
| Proof-of-impact | `--exploit` (requires `--intrusive`) | Runs real exploitation against a confirmed injection but pulls exactly ONE read-only evidence value and stops: SQLi → DB `version()`/`current_user`, command injection → benign `id` output, SSTI → an arbitrary expression result. Evidence is redacted for the report. Deliberately not a data dump, shell, secret exfiltration, or destructive action. | A few extra requests per confirmed finding. |

Coverage and throughput knobs: `--max-params` (query params probed per URL),
`--max-form-fields` (fields probed per form), and `--delay` (seconds between
crawl requests; `0` for maximum throughput). Scope stays bounded by `--max-pages`,
the internal request-safety limit, and same-host origin scoping; crawling never
shares an account's cookies or credential headers across origins.

Escalate beyond `web-scan` when you need more:

- `web-audit` — approval-gated, profile-driven, reproducible 21-control coverage
  with a one-time nonce and bounded traffic envelope (the rest of this document).
- `zap-run --mode full|api --authorize-active` — comprehensive third-party active
  scanning (fuzzing, the full attack-rule set). `web-scan --intrusive` deliberately
  stays a bounded, verification-first probe set; it does not replace ZAP's full
  active scanner.

Every active/intrusive tier is for systems you are explicitly authorized to test.
`--intrusive` prints a warning and should target a staging copy.

## Checkout authentication and rendering boundaries

The 2026-10-11 checkout implements the following web boundaries. They apply
to the shared crawl/authentication helpers used by
`web-scan` and `web-audit`; confirm the installed engine before relying on them.

- Origins compare scheme, lowercase hostname and effective port (default
  HTTP 80 / HTTPS 443). Matching hostnames with a different scheme or port
  do not share credentials. Origin allowlisting does not authorize sharing an
  account's cookie jar or custom credential headers.
- Crawling follows each redirect only after checking its destination against
  the allowed origins, blocks HTTPS downgrade, and uses a separate anonymous
  opener for another approved origin. Cross-origin headers are reduced to
  `User-Agent` and `Accept`. Forms, JS assets, robots and sitemap requests use
  these same destination checks; password/file forms are excluded from generic
  active form probes.
- Form login requires HTTPS outside loopback HTTP, disables automatic redirects,
  and keeps discovered actions on the login origin. A cross-origin explicit
  `login_request_url` must be in the approved origins. Audit authentication also
  requires all credentialed profile origins to be HTTPS or loopback HTTP; a
  violation records incomplete authentication rather than silently sending
  credentials.
- Playwright blocks service workers and WebSockets and routes requests at
  BrowserContext scope. Rendering is skipped if the installed Playwright lacks
  `route_web_socket` support.
  An unapproved origin, HTTPS downgrade, or rejected audit path/method aborts
  rendering. Audit HTTP(S) rendering requests are fetched through the approved-IP
  network opener and fulfilled into the browser with the audit response/time
  budgets. Redirect responses are aborted. Lightweight rendering also disables
  redirect following for its fetched HTTP(S) responses.

Browser fallback or skipped rendering is a coverage gap. Neither a successful
static crawl nor these source checks proves a live Chromium run, ZAP integration,
or complete application-specific 21-control coverage. The 2026-10-11 Linux
x86_64 container validation exercised real Chromium PDF generation and the local
portal. It did not validate full audits of live external services, live ZAP/OAST
integration, or performance. Web-boundary regressions were included in the full
Linux suite.

## Quick start

Run from a source checkout with Python 3.10 or newer:

```bash
export PYTHONPATH="$PWD/platforms/shared/python"
export KODA_APPROVAL_KEY='operator-managed-secret'

python3 -m security_scanner web-audit plan \
  --profile profile.json \
  --out approval-request.json

python3 -m security_scanner web-audit approve \
  --request approval-request.json \
  --approver 'security-operator' \
  --out approval.json

python3 -m security_scanner web-audit run \
  --profile profile.json \
  --approval approval.json \
  --confirm-origin https://staging.example.com \
  --format json \
  --output reports/web-audit.json
```

The approval request is valid for at most 24 hours. `run` revalidates the
canonical profile hash, exact origin, current DNS/IP set, scope, limits,
signature, and expiry, then consumes the approval nonce from
`~/.koda/web-audit-nonces.sqlite3`. A nonce cannot be reused.

Use a no-traffic preflight before the real run:

```bash
python3 -m security_scanner web-audit run \
  --profile profile.json \
  --approval approval.json \
  --confirm-origin https://staging.example.com \
  --dry-run
```

`--dry-run` validates the approval and capabilities without sending target
requests or consuming the nonce. `plan` also performs no target requests; it
does resolve the declared target DNS/IP addresses so the approval envelope can
record them.

## Profile contract

Profiles use strict JSON `schema_version: 1`. Unknown keys, unknown controls,
undeclared resource references, unsafe interpolation, and out-of-range limits
are rejected before execution.

| Section | Required declaration |
| --- | --- |
| `target` | Environment, exact origins, included/excluded paths, approved IP/CIDR ranges, scopes, distribution, and optional ZAP manifest. |
| `limits` | Request/response/upload/time/rate/redirect/retry/OAST/ZAP envelope. Defaults are bounded and values cannot exceed the engine maximums. |
| `accounts` / `auth` | Role/account references and form, JSON, or header authentication. Credentials are environment references, not literal secrets. |
| `resources` | Stable resource ID, origin-relative path, allowed methods, optional probe methods, actors, access expectations, and read-only/state flags. |
| `scenarios` | One `web.*` control, required flag, strategies, steps, mutations, assertions/oracle, captures, and cleanup. Every step references a declared resource ID. |
| `oast` | BOAST control-plane origin, callback DNS name, approved control-plane IP/CIDR list, and polling interval when callback verification is used. |
| `applicability` | Explicit `NOT_APPLICABLE` plus a non-empty reason for a control that the service does not provide. |

Only these interpolations are supported:

- `${ENV:NAME}` for an environment value.
- `${CAPTURE:NAME}` for a value captured by an earlier declared step, including
  `${CAPTURE:OAST_PAYLOAD}`.
- `${RUN_ID}` for the current run identifier.

Shell, `eval`, Python callbacks, arbitrary URLs, raw request/response bodies,
literal passwords, cookies, tokens, and secret-bearing profile keys are rejected
or redacted. Use `body_type` `json`, `form`, `raw`, or bounded `multipart`; use
`delay_seconds` for bounded expiry/replay timing rather than an unbounded sleep.

## 21-control coverage contract

The profile must attach scenarios to the canonical IDs below. The table is the
minimum oracle contract; it is not a promise that a generic crawl can close the
control without application-specific resources and expected outcomes.

| # | ID | Required declaration before PASS |
| ---: | --- | --- |
| 1 | `web.code-injection` | Bounded canary/input sink, response/state oracle, and OAST only where an approved callback is required. |
| 2 | `web.ssrf` | Every URL sink, approved BOAST control plane, callback polling, and no-callback oracle. |
| 3 | `web.file-download` | Download/file resources, traversal/LFI and object-scope variants, and deny-oracle for unauthorized files. |
| 4 | `web.sql-injection` | Declared parameters, bounded KODA/ZAP strategies, and response/time/data/state baseline. |
| 5 | `web.session-management` | Pre/post-login session observation, cookie attributes, logout reuse, and expiry evidence or explicit review. |
| 6 | `web.directory-indexing` | Declared directory surfaces and non-listing status/body oracle. |
| 7 | `web.password-policy` | Disposable account, weak/valid password cases, and cleanup/restoration. |
| 8 | `web.plaintext-transmission` | Complete page/asset/form surface plus HTTPS, redirect, mixed-content, and cookie-security oracle. |
| 9 | `web.error-pages` | Safe malformed requests and forbidden-pattern/general-error oracle for stack, path, SQL, and secret disclosure. |
| 10 | `web.authentication` | Valid login success followed by unauthenticated/negative access checks. |
| 11 | `web.cookie-tampering` | Deleted/changed/swapped session or role cookies and protected-resource/state oracle. |
| 12 | `web.information-disclosure` | Declared seed/API/JS/header/sensitive-path surface and forbidden-pattern/passive results. |
| 13 | `web.authorization` | Anonymous/userA/userB/admin and object-ID access matrix with allow/deny expectations. |
| 14 | `web.admin-exposure` | Declared admin paths checked as anonymous and non-admin; discovered-but-undeclared paths remain review. |
| 15 | `web.xss` | Reflected/stored/DOM strategy declaration, canary/browser coverage where needed, and stored-data cleanup. |
| 16 | `web.password-recovery` | Disposable account/test inbox, enumeration, token binding/expiry/one-use, and cleanup. |
| 17 | `web.automated-attacks` | Bounded login/recovery attempts, declared throttle/lock/CAPTCHA threshold, and unlock cleanup. |
| 18 | `web.csrf` | Normal state snapshot, missing/invalid token and Origin/Referer variants, rejection plus unchanged state. |
| 19 | `web.process-validation` | Normal sequence and skip/reorder/replay mutations with rejection and unchanged state. |
| 20 | `web.http-methods` | Resource `methods`/`probe_methods` comparison, TRACE/override/forbidden-verb checks; OPTIONS alone is not a finding. |
| 21 | `web.file-upload` | Inert extension/MIME/HTML/SVG canaries, reject/quarantine/non-execution/private access, and cleanup. |

Supported strategy names include `koda-scenario`, `passive`, `browser`,
`playwright`, `dom`, `browser-canary`, `oast`, `ssrf-oast`, `callback`, `zap`,
`zap-active`, `zap-passive`, `access-control`, `authorization`, `matrix`,
`timing`, `state`, `http-methods`, and `upload`. All strategies declared on a required scenario
run; one incomplete strategy prevents a `PASS`.

`timing` requires a named baseline plus a response-time delta assertion. `state`
compares a later `state_unchanged` assertion to a named step snapshot (for example,
`{"snapshot":"baseline"}`) and requires cleanup before state-changing mutations.
Access expectations may set `state_resource` and `state_account` to perform the
same before/after comparison around an actor request. `http-methods` executes only
declared `probe_methods`; OPTIONS success alone is allowed, while an unexpected
`Allow` advertisement or an accepted forbidden verb is a finding. `upload` accepts
only `KODA-INERT-CANARY...` multipart content and requires both read-only
post-upload verification and cleanup.

## Status and output

Each result contains the canonical ID/title, `status`, `executed`, `reason_code`,
`coverage.required/completed`, `surfaces_tested`, `strategy_results`, and
`evidence_ids`. The top-level result also includes capability, traffic, auth
summary, warnings, and redacted findings.

| Status | Meaning |
| --- | --- |
| `VULNERABLE` | Verified exploit, state violation, forbidden access, or OAST callback evidence. |
| `PASS` | Every required scenario/strategy/oracle/cleanup completed without a violation. |
| `NEEDS_REVIEW` | Oracle, coverage, OAST polling, browser response validation, or cleanup is incomplete. |
| `NOT_APPLICABLE` | The profile explicitly excludes the control with a reason. |
| `UNSUPPORTED` | The selected distribution lacks a required capability. |
| `NOT_SCANNED` | Approval, credential, profile, origin/IP preflight, or another execution gate prevented the run. |

The CLI exits 1 when the top-level status is `VULNERABLE`, 2 for profile,
approval, or execution errors, and 0 for `PASS`, `NEEDS_REVIEW`, `UNSUPPORTED`,
`NOT_APPLICABLE`, or `NOT_SCANNED`. A zero exit code is therefore not equivalent
to “all 21 controls passed”; CI should inspect every control and its coverage.

Dynamic evidence is redacted. Reports do not expose raw requests/responses,
headers, cookies, credentials, passwords, tokens, or ZAP plugin IDs. The
canonical public IDs remain `web.*` even when a ZAP alert contributes evidence.

## Local dashboard API

The API is intentionally stricter than ordinary dashboard endpoints:

| Endpoint | Purpose | JSON fields |
| --- | --- | --- |
| `POST /api/web-audit/plan` | Validate a profile and create a no-traffic plan | `profile` |
| `POST /api/web-audit/approve` | Sign an approval request with the server key | `request`, `approver` |
| `POST /api/web-audit/run` | Execute one approved audit | `profile`, `approval`, `confirm_origin`, optional `dry_run` |

The server must bind to `127.0.0.1`, `localhost`, or `::1`, and the client must
also be loopback. POST requests require the exact local `Origin` and the
per-process `X-KODA-Session` returned in the dashboard HTML response. A
non-loopback binding disables these execution endpoints with 403. The token is
not a profile credential and must not be copied into a report.

## Capability and packaging boundaries

| Distribution | Native web audit | ZAP/Playwright/OAST behavior |
| --- | --- | --- |
| Shared Python CLI/server | Native stdlib strategy available | External capabilities are preflighted and fail closed. |
| Windows Full | Included | External Docker/ZAP, Chromium, and BOAST must already exist. |
| Windows SourceOnly | `UNSUPPORTED(package_capability_missing)` | No Java/library/web/Playwright vulnerability-data bundle. |
| macOS direct distribution | Supported by the direct/shared lane | Use the preinstalled capability set; no automatic downloads. |
| macOS App Store | GET/HEAD native read-only only | Active/state-changing steps, login POST, ZAP, and non-read-only profiles are rejected or review/unsupported. |

ZAP requires an image containing `@sha256:<digest>` and an add-on manifest whose
entries are `sha256:<64 lowercase hex>` digests. Docker uses pull-never behavior.
The approved ZAP envelope defaults to 2 RPS, 1 thread per host, 15 minutes total,
and 2 minutes per rule; the maximums are 5 RPS, 2 threads, 60 minutes, and 5
minutes. Native defaults are 1,000 requests, 2 MiB responses, 1 MiB uploads,
900 seconds, 3 redirects, 120 seconds OAST polling, and 30 seconds cleanup. The
engine rejects values above its hard maximums and never retries state-changing
requests.

## OAST/BOAST boundary

For SSRF or code-injection callbacks, add `oast` to `target.scopes` and declare
`control_plane_origin`, DNS `callback_domain`, and approved `allowed_ips`/CIDRs.
Set the base64 BOAST credential only in `KODA_OAST_SECRET`. KODA pins the control
plane to the approved IP set, registers a test, polls `GET /events`, and treats a
new event as `VULNERABLE`. A completed poll with no event can contribute to PASS
only after the scenario oracle and cleanup pass. Missing/invalid secret, callback
domain, or control-plane preflight remains unsupported/not scanned.

## Verification checklist

Before a real run:

1. Confirm written authorization, staging ownership, disposable accounts/inbox,
   cleanup ownership, and the exact origin/IP scope.
2. Run `plan`, inspect control declarations and the traffic envelope, then create
   the HMAC approval with an operator identity.
3. Run `--dry-run`; stop if capability is missing or the approval envelope is not
   the intended one.
4. Run once, archive the redacted JSON/Markdown report, and verify that every
   required control has complete coverage or an explicit non-PASS status.
5. Confirm cleanup and inspect the target for test records, uploads, sessions,
   locks, password changes, and callback events.

Repository-level checks for the implementation are:

```bash
PYTHONPATH=platforms/shared/python python3 -m unittest -q \
  tests.test_web_audit tests.test_cli_reports tests.test_settings_and_exports
python3 -m compileall -q platforms/shared/python/security_scanner
```

These checks cover profile canonicalization, HMAC/expiry/nonce, redaction,
network pinning, status aggregation, packaging capability boundaries, and report
exports. They do not authorize a live target or replace an application-specific
oracle.
