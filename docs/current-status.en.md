# KODA Current Implementation and Verification

Baseline: **2026-10-02 (Asia/Seoul)** · [한국어](current-status.ko.md)

This is the source and verification snapshot inspected during the documentation
refresh. Matching version labels do not establish matching build revisions or
vulnerability data packages.

## Source and publication scope

| Area | Observed state | Meaning |
| --- | --- | --- |
| GitHub `main` baseline | `95297eb76c781cbe579b41b5e3f2b91bcd13e9ee` at the start of the refresh | Published source before the development changes below |
| This refresh | Documentation only | Local implementation changes, tests, and development scripts are excluded from this documentation commit |
| macOS local AI | Implementation files, fixtures, and an app script exist in the local worktree | Availability in a fresh GitHub clone or the Mac App Store app is not established |
| Security boundary work | Local changes to portal, gateway, web, Java, reports, and regression checks | Availability in installed binaries is not established |
| Dated delivery guides and validation records | Evidence for their stated dates | They do not prove current deployment success or a passing full suite |

Development-only sections apply to checkouts containing the required implementation
files. Results here cover the local checkout including existing uncommitted
changes, rather than only the published GitHub `main` source.

## Current behavior

| Area | Source-backed behavior | Guide |
| --- | --- | --- |
| Runtime lanes | Native Swift on macOS; shared Python on Linux, Windows, CI, and servers | [Documentation index](README.en.md) |
| Shared AI triage | Default OFF; adds `triage_*` without changing severity. Default Ollama address is loopback; a custom API base can be remote | [Privacy policy](../PRIVACY.md), [roadmap](roadmap-ai-augmentation.en.md) |
| Separate macOS AI development | Loopback OpenAI-compatible connections, explanation, source review, candidate fixes and re-scan, test/impact drafts, AI reports; candidates remain separate from originals | [Local AI development](macos-local-ai.md) |
| Development portal and gateway | Gateway proof, project/feature permissions, request origin checks, upload/JSON/archive resource limits | [Combined suite guide (Korean)](../platforms/linux/suite/README.ko.md), [Docker guide](../platforms/linux/docker/README.en.md) |
| Development local dashboard | Work POST requests require same-origin headers and a session token; built-in UI supplies them | [CLI and local usage](usage.md) |
| Development web boundaries | Origin-scoped credentials and redirect restrictions; rendering stops when required boundary/WebSocket interception is unavailable | [Web audit](security/WEB_AUDIT.md) |
| Development Java scans | Bounded archives, metadata, and Syft output; resource-limited incomplete scans exit with code 2 | [Java runbook](security/java-sbom-vulnerability-scan.en.md) |
| Development NIS-SBOM CSV | Quoted cells and guard tabs for formula prefixes; use JSON/CycloneDX for original machine values | [Report contract](report-contract.md) |

Security boundaries intentionally affect behavior: invalid credentials, permissions,
origins, cross-origin credential forwarding, and over-budget uploads or archives
are rejected or marked incomplete. Scanner and syntax checks on an AI candidate
do not prove functional equivalence; review and regression tests are still needed.

## Fresh verification

Run from the repository root on 2026-10-02:

```bash
PYTHONPATH=platforms/shared/python python3 -m unittest discover -s tests -q
python3 -m unittest discover -s platforms/macos/tests -q
PYTHONPATH=platforms/shared/python python3 -m unittest discover -s tests -p test_project_deletion_and_schedule_labels.py -q
PYTHONPATH=platforms/shared/python python3 -m unittest discover -s tests -p test_schedule_gitlab_api.py -q
git diff --check
```

| Check | Observed result |
| --- | --- |
| Full shared Python suite | 609 tests: **600 passed, 2 failed, 7 skipped**; 65.021 seconds, exit code 1 |
| Project deletion/schedule label module rerun | 7 passed, 1 failed out of 8. `test_project_delete_is_only_on_admin_detail_page`: list-page HTML includes the `data-delete-project` string |
| GitLab scheduled API module rerun | 1 passed, 1 failed out of 2. `test_gitlab_http_collection_analysis_persist_and_cleanup`: expected `completed`, observed `queued` |
| macOS fixtures | Seven Swift fixture success messages for client, profiles, report, fix gates, impact, test plan, and triage; process exit code 0 |
| macOS archives | Five unittest checks passed |
| Documents | 29 documents: 235 local file/image targets and 5 internal anchors passed; `git diff --check` passed |

Both failures reproduced in isolated module reruns. Their fixes are outside this
documentation publication. The full suite is not passing and release readiness
has not been established.

## Unverified areas

- Live Docker/Nginx gateway installation, login, operation, and server deployment
- Real Playwright Chromium rendering and network behavior
- Current Mac App Store/Windows/offline packages and their vulnerability data
- A new Xcode app build, real local-model generation quality, or a Java-enabled macOS build during this refresh
- AI candidate functional equivalence and compatibility across all use cases

GitHub private vulnerability reporting was disabled at the baseline check.
See the [security policy](../SECURITY.md) for the currently documented reporting route.
