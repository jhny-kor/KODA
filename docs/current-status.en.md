# KODA Current Implementation and Verification

Baseline: **2026-10-11 (Asia/Seoul)** · [한국어](current-status.ko.md)

This snapshot covers the local worktree at validation, fixes, builds, and runtime checks.
**This GitHub publication includes the validated product source, tests, build
scripts, and documentation. Java assets, app binaries, Docker images, and raw logs
remain local.** Publishing source does not update an existing installation,
App Store app, or production server, or provide the same vulnerability data.

## Source and publication scope

| Area | Observed state | Meaning |
| --- | --- | --- |
| GitHub source baseline at validation | `4efb0bce1e0f5a00a078c77d9f91608d5127a757` | Validation includes that revision plus local modified and new source files |
| Earlier documentation publication | `f1f040193ae74609e089b4af486dd46dca0bc2d4` | Documentation-only record; source publication follows below |
| This publication | GitHub product source, tests, build scripts, and documentation | Java assets, binaries, images, and raw logs excluded; no production or App Store deployment |
| macOS | Java-enabled universal Release build/analyze and ARM execution | Separate validation app; existing App Store app was not replaced |
| Linux | Installed amd64 source image and web/scan/delivery workers | amd64 user space emulated in Docker LinuxKit on Apple Silicon |
| Windows | Source, package dependencies, PowerShell, and process contracts reviewed | Native Windows execution excluded at the user's request |
| Installed releases and dated delivery material | Records for their stated revisions/dates | Not equivalent to the current worktree or this validation |

## Current behavior

The [126-feature OS matrix (Korean)](platform-feature-matrix.ko.md) uses macOS,
Windows, and Linux x86_64 columns with O/X implementation cells. O does not mean
native execution was verified, every input is detected, or an entire standard is met.

| Area | Behavior in the current local source | Guide |
| --- | --- | --- |
| Runtime paths | Native macOS Swift app, Windows Full dashboard/CLI, Linux host/Docker/authenticated portal | [Index](README.en.md), [OS matrix (Korean)](platform-feature-matrix.ko.md) |
| Source scans | Code, configuration, secrets, dependencies, quality, prevention, changed files, and standard profiles | [CLI](usage.md) |
| Shared AI | Default OFF; explanations, triage, remediation guidance, summaries; original severity preserved. Custom API bases may be remote | [Privacy](../PRIVACY.md), [CLI](usage.md) |
| macOS local AI development | Localhost profiles/model lists/Keychain, separate fix candidates, rescans, test/impact drafts, and AI reports | [Local AI](macos-local-ai.md) |
| Java | Bundled/configured Syft, Grype, DB, NVD, CISA; Korean SBOM/vulnerability reports | [Java](security/java-sbom-vulnerability-scan.en.md) |
| Failure states | Missing source targets are errors. A Java vulnerability gate without Grype exits 2; explicit SBOM-only without a gate remains allowed | [CLI](usage.md), [Java](security/java-sbom-vulnerability-scan.en.md) |
| Processes and archives | Valid empty DEFLATE accepted; malformed/over-budget archives rejected. Both Syft streams and the full deadline are handled; macOS drains Java output during execution | [Validation](verification-2026-10-11.md) |
| Linux portal/workers | Gateway proof, feature permissions, upload quota, shared manual/scheduled ownership, separate scan/delivery workers, cancellation and recovery | [Queue](linux-scan-queue.en.md), [Docker](../platforms/linux/docker/README.en.md) |
| Web | Origin-scoped authentication/render boundaries, opt-in active/intrusive/proof checks, shared CLI approval-driven 21-control audit | [Web audit](security/WEB_AUDIT.md) |
| Reports | Platform-specific exports and NIS-SBOM formula protection. CodeQL direct execution is unavailable; preflight and SARIF import are separate capabilities | [Report contract](report-contract.md), [OS matrix (Korean)](platform-feature-matrix.ko.md) |

Rejected, unsupported, and incomplete checks are not successful scans. Syntax and
security rescans of an AI candidate do not establish functional equivalence.

## Latest verification

The [2026-10-11 validation record](verification-2026-10-11.md) and
[machine-readable summary](verification-2026-10-11.json) record conditions and
identifiers. The validated product source, tests, and build scripts are included
in this GitHub publication. Reproducing the results also requires the recorded
tools, Java assets, and runtime environments.

| Check | Observed result | Conditions |
| --- | --- | --- |
| Linux full Python suite | 768: **767 passed, 0 failed, 1 skipped**, 198.051 seconds | Debian 12, Python 3.12.15, real linux/amd64 container |
| macOS-host full Python suite | 768: **760 passed, 0 failed, 8 skipped**, 142.730 seconds | Python 3.14.6, earlier fix phase |
| Python 3.12 focused suite | **214 passed** | CLI, Java, web, network, Syft, packaging, worker |
| macOS harness | **All 10 scripts passed** | Seven local-AI fixtures, archives, Java processes, asset packaging |
| Java-enabled macOS Release | **arm64+x86_64 build/analyze passed** | Validation build without developer signing/notarization |
| macOS Java execution | **English UI setting and network-denied Korean setting both exit 0** | Actual ARM app with bundled helper/Syft/Grype |
| Linux install and portal | **Installer, CLI, ZIP upload, worker scan, JSON/PDF passed** | Three web/scan/delivery containers, stopped and removed afterward |
| Linux Java execution | **DB import 0; vulnerability gate 1** | No network, 4GiB limit |
| Synthetic Java input | Both: **1 component, 7 vulnerabilities, 1 KEV, no warnings** | Log4j 2.14.1 metadata only, no Java execution |
| Windows contracts | Eight new regressions and two PowerShell parsers passed | On macOS; not native Windows execution |
| Static/document checks | Ruff F/E9, shell syntax, diff checks passed; publication links and O/X cells checked | Separate from runtime/deployment validation |

Linux skips only the local-LLM integration. The earlier macOS suite skipped one
LLM, one Linux resource-limit check, five Linux installation/rollback checks,
and one Chromium PDF check. Final Linux execution includes resource limits,
installation/rollback contracts, and actual Chromium PDF. Installation/rollback
unit tests use a Docker double and do not prove a live Suite upgrade or restore.

## Unverified areas

- Actual Intel execution: binaries and links verified, but this host reports `Bad CPU type in executable`.
- Physical x86_64/native x86_64 kernel, production load, real OOM/failure recovery.
- Native Windows EXE/installer/WebView2/Syft execution.
- Production Nginx gateway login, real Tracker/GitLab delivery, live Suite upgrade/rollback.
- Developer signing, notarization, App Store submission, existing release updates.
- External target efficacy, real local-model quality, AI candidate functional equivalence.

## Previous records

The 2026-10-02 refresh ended with 616 passed and seven skipped out of 623.
Earlier documentation commit `e322fd6` recorded 600 passed, two failed, and seven
skipped out of 609. These remain historical worktree records; the current
snapshot is the 2026-10-11 result above. Dated releases, plans, and design notes
retain their original dates and scopes.

[English index](README.en.md) · [OS matrix (Korean)](platform-feature-matrix.ko.md)
