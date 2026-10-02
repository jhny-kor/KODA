# Sequential Linux Scans

Source review and verification: **2026-10-02** · [한국어](linux-scan-queue.ko.md)

This describes changes in the local development source. Publishing implementation
code, rebuilding images, and deploying to an operational Linux server are outside
this verification.

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

## Verification

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
