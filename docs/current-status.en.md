# KODA Current Implementation and Verification

Baseline: **2026-10-02 (Asia/Seoul)** · [한국어](current-status.ko.md)

This is the source and verification snapshot inspected during the documentation
refresh. Matching version labels do not establish matching build revisions or
vulnerability data packages.

## Source and publication scope

| Area | Observed state | Meaning |
| --- | --- | --- |
| GitHub `main` baseline | `e322fd6816ea4d37cfc46820b5717794db4cf938` at the start of the refresh | Published source before the development changes below |
| This refresh | Documentation only | Local implementation changes, tests, and development scripts are excluded from this documentation commit |
| Sequential Linux execution | Shared manual/scheduled ownership and multi-user queue implemented and tested locally | Only guidance is published here; image rebuild and live Linux deployment remain unverified |
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
| Development Linux queue | One analysis engine or scheduled collection/analysis/cleanup at a time. Manual FIFO across users/projects; manual priority at the next dispatch | [Sequential scan guide](linux-scan-queue.en.md) |
| Development local dashboard | Work POST requests require same-origin headers and a session token; built-in UI supplies them | [CLI and local usage](usage.md) |
| Development web boundaries | Origin-scoped credentials and redirect restrictions; rendering stops when required boundary/WebSocket interception is unavailable | [Web audit](security/WEB_AUDIT.md) |
| Development Java scans | Bounded archives, metadata, and Syft output; resource-limited incomplete scans exit with code 2 | [Java runbook](security/java-sbom-vulnerability-scan.en.md) |
| Development NIS-SBOM CSV | Quoted cells and guard tabs for formula prefixes; use JSON/CycloneDX for original machine values | [Report contract](report-contract.md) |

Security boundaries intentionally affect behavior: invalid credentials, permissions,
origins, cross-origin credential forwarding, and over-budget uploads or archives
are rejected or marked incomplete. Scanner and syntax checks on an AI candidate
do not prove functional equivalence; review and regression tests are still needed.

## Latest verification

Run from the repository root in the local development worktree on 2026-10-02.
The new tests and implementation changes used by these commands are excluded
from this documentation publication; a fresh GitHub clone is not expected to
reproduce the same results.

```bash
PYTHONPATH=platforms/shared/python python3 -m unittest discover -s tests -q
PYTHONPATH=platforms/shared/python:tests python3 -m unittest test_scan_serialization -q
PYTHONPATH=platforms/shared/python:tests python3 -m unittest test_project_deletion_and_schedule_labels test_scan_serialization test_schedule_gitlab_api -q
git diff --check
```

| Check | Observed result |
| --- | --- |
| Full shared Python suite | 623 tests: **616 passed, 0 failed, 7 skipped**; 70.018 seconds, exit code 0 |
| Serialization regressions | Eleven passed: execution races across DB connections, manual FIFO, resuming after scheduled cleanup, cancellation, duplicate-worker prevention, leadership handoff |
| Final deletion UI/serialization/GitLab scheduled API rerun | 29 passed in 4.949 seconds |
| Skips | Six Linux-only checks on macOS; one PDF renderer check without Playwright |
| This documentation refresh | Nine documents: 180 local file/image targets and five internal anchors checked; `git diff --check` passed |
| macOS fixtures and archives | Earlier refresh on the same date: seven Swift fixture success messages (process exit code 0), five archive unittest checks passed. Not rerun after the serialization change |

### Original failures and follow-up fixes

Documentation commit `e322fd6` recorded 600 passed, 2 failed, and 7 skipped out
of 609. Both causes were corrected in subsequent local work, and the full suite
and focused rerun above passed.

- The deletion UI test matched a CSS selector string rather than an actual delete
  control. It now inspects HTML elements and attributes. This test correction
  does not change product deletion permissions or behavior.
- GitLab scheduled collection held the small control-request slot while streaming
  an archive, causing heartbeat requests to receive HTTP 429. Archive and control
  slots are now separate; a slow transfer permits heartbeat and rejects a second
  archive stream.

Passing local checks do not establish image, installer, or production deployment
readiness. See [sequential scans](linux-scan-queue.en.md) for dispatch policy and
resource limits.

## Unverified areas

- Live Docker/Nginx gateway installation, login, operation, and server deployment
- Real Playwright Chromium rendering and network behavior
- Current Mac App Store/Windows/offline packages and their vulnerability data
- A new Xcode app build, real local-model generation quality, or a Java-enabled macOS build during this refresh
- AI candidate functional equivalence and compatibility across all use cases

GitHub private vulnerability reporting was disabled at the baseline check.
See the [security policy](../SECURITY.md) for the currently documented reporting route.
