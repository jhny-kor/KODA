# Sequential Linux Scans

Source review and verification: **2026-10-11** · [한국어](linux-scan-queue.ko.md)

This describes current local source behavior. This GitHub documentation
publication excludes implementation/test files and operational image deployment.
Running an amd64 test image is separate from deploying an operational server.

## User-visible behavior

- Source and library scan requests from multiple users share one server execution
  slot. Other requests remain durable in the DB with status `queued`.
- Manual scans run in submission order across users and projects. Cancelled queued
  requests are skipped.
- A started scheduled job owns the slot through collection, analysis, and source
  cleanup. Manual requests arriving during that job wait until cleanup finishes.
- At the next dispatch, the existing manual-priority policy remains. Schedules run
  in their existing due-time/configured order after the manual queue drains.
  Continuous manual requests can delay schedules; this is not a combined FIFO.
- Disabling schedules prevents new scheduled jobs. A job that already owns the slot
  finishes; use cancellation to stop a current job.
- Page reads, authentication, and ordinary uploads are not globally serialized.
  Manual GitLab input retrieval remains preparation before submission. The scope
  of this change is the analysis engine and scheduled collection/analysis/cleanup.

Scheduled concurrency remains `1`. Existing defaults are one CPU, 4 GiB memory,
5 MiB/s collection, and a 30-second gap. Operators can adjust existing settings.
Container/analyzer resource ceilings still matter for each job; one-at-a-time
execution does not mean zero server load.

## Recovery and request control

SQLite write transactions recheck manual execution, schedule execution, and the
schedule lease before granting ownership. The manual worker polls the durable DB
queue, retaining blocked jobs. A DB-specific file lock protects recovery and
manual worker leadership; a standby worker takes over after the owner closes.

At most one scheduled GitLab archive stream is allowed. Its separate slot lets
small control calls such as heartbeat and cancellation proceed during a download,
while archive/result transfer remains bounded. Authentication, lease checks, and
existing body size limits remain in place.

## Verification on 2026-10-11

The full suite ran in a Debian 12 / Python 3.12.15 `linux/amd64` Docker container:
**767 passes, no failures, one local LLM integration skip out of 768 tests**
(198.051 seconds). Docker's LinuxKit VM on Apple Silicon emulated amd64 user
space; no physical x86_64 server or native x86_64 kernel was tested.

The current Docker launcher created real web, scan and delivery containers.
ZIP upload, scanning, result retrieval and PDF download completed. Both workers
were healthy and no scan workspaces remained. All test containers were stopped
and removed. Real GitLab/Tracker delivery, Nginx gateway login, forced OOM
recovery and operational Suite upgrade/rollback remain unverified. Installer and
rollback unit tests use Docker test doubles.

If analyzer termination cannot be confirmed, the worker preserves the workspace
and execution state, records `scan.termination_failed`, and stops accepting the
next scan. An exited leader alone does not prove its child group is gone;
PermissionError is accepted only after group disappearance is confirmed. The
cause of the initial intermittent error has not been established. See the
[current verification summary](verification-2026-10-11.md).

## Historical verification: 2026-10-02

The results below and the unavailable Docker daemon describe the 2026-10-02 run.
Use the current results above for the latest full regression count.

These commands ran in the local development worktree containing the new tests
and modified source. Implementation and test files are excluded from this documentation publication.

```bash
PYTHONPATH=platforms/shared/python python3 -m unittest discover -s tests -q
PYTHONPATH=platforms/shared/python:tests python3 -m unittest test_scan_serialization -q
```

- Full Python suite: **616 passed, 7 skipped out of 623**, no failures/errors
  (70.018 seconds).
- Eleven serialization regressions passed: separate DB connection races, user FIFO,
  manual waiting during schedules and resuming after cleanup, cancellation,
  duplicate-worker prevention, and leadership handoff.
- A slow GitLab stream permits heartbeat and rejects a second archive. Both API
  and legacy schedule paths complete when a manual request arrives during collection.
- The old deletion UI test now inspects real HTML attributes instead of matching a
  CSS selector string. That test correction does not change product deletion behavior.
- Skips: six Linux-only checks on macOS and one PDF test without Playwright.
- The local Docker daemon was unavailable, so live Linux containers and Linux-only
  checks were not run. GitLab coverage used fixtures rather than a live server.

[Documentation index](README.en.md) · [Combined suite guide (Korean)](../platforms/linux/suite/README.ko.md)
