# KODA Privacy Policy

Effective date: May 17, 2026

Documentation reviewed: 2026-10-02

KODA's native macOS app analyzes files and folders selected by the user on the
user's Mac. The shared Python engine also supports Windows, Linux, CI, and an
authenticated server portal. These paths have different data flows.

## Data collection

The native macOS app and local shared dashboard do not require a KODA account.
The Linux portal uses KODA SBOM Tracker accounts and sessions and stores account
identity, project access, uploaded inputs, analysis history, and audit records on
the configured server. KODA does not collect information for advertising,
tracking, analytics, or resale.

Security scan results are generated on the user's device from files and folders selected by the user. Reports, snapshots, and exported artifacts are stored locally unless the user chooses to share them outside the app.

## Local file access

KODA reads only user-selected files, folders, or archives for security analysis. The app uses this access to identify possible secrets, dependency risks, configuration issues, code patterns, and release-preparation gaps.

## Optional online vulnerability enrichment

KODA can optionally enrich dependency and vulnerability findings through public security intelligence services such as OSV.dev, CISA Known Exploited Vulnerabilities, and FIRST EPSS. When this feature is used, dependency package names, package versions, or CVE identifiers may be sent to those public endpoints. KODA does not intentionally send source code, local file contents, account credentials, or scan reports to those services.

Network providers may receive standard request metadata such as IP address and user agent as part of normal HTTPS requests.

## Optional AI triage

KODA can optionally use a large language model to label findings as likely true or false positives (`--ai-triage`). This feature is disabled by default. When Ollama runs on the default `http://localhost:11434` address, finding
context is sent to that local service. The shared Python provider permits a
custom HTTP(S) `KODA_LLM_API_BASE`; a remote address sends that context to the
configured server. Selecting `ollama/...` alone does not guarantee that the
server is local. When the user explicitly selects a **cloud** backend (for example `anthropic/...` or `openai/...`), KODA sends finding metadata and a short surrounding source snippet to that provider in order to obtain the label; KODA surfaces a one-time warning when this external transfer happens. Raw secret values are never included in the data sent for triage: `secrets` findings are triaged from their redacted evidence only, without a source snippet. API keys for cloud backends are read from environment variables and are not stored by KODA.

## Native macOS local AI development

The separate local AI development implementation documented in the
[development guide](docs/macos-local-ai.md) accepts loopback OpenAI-compatible
endpoints and rejects redirects. Explanation requests contain finding metadata;
source review and fix proposals may send the selected source context/file and
its filename and line number. Test drafts send before/after candidate source;
impact drafts send bounded declaration names and counts.
These features are user-triggered. Candidate fixes are generated separately
from the original file; passing syntax and scanner checks does not establish
functional equivalence. Saved connection profiles contain the URL and model,
not the API key.

This describes unpublished local development work as of 2026-10-02 and does not
establish availability in the Mac App Store app.

## Server and external integrations

Uploaded projects and server reports reside in the configured portal storage.
GitLab, Tracker, Dependency-Track, and SBOM upload integrations can send project,
component, or finding data to the configured systems. Online web and ZAP checks
contact their authorized targets. Operators control those endpoints, storage
access, and retention; local-app privacy claims do not imply that server data
stays on the submitting user's device.

## Tracking and advertising

KODA does not use third-party advertising SDKs, does not track users across apps or websites, and does not sell user data.

## Contact

For privacy questions or support requests, use the project support page:

https://github.com/jhny-kor/KODA

For the Korean version, see [PRIVACY.ko.md](PRIVACY.ko.md).
