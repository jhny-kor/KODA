# KODA Fix, Build, and Runtime Validation — 2026-10-11

[한국어](verification-2026-10-11.ko.md) · [Current status](current-status.en.md) · [Machine-readable summary](verification-2026-10-11.json)

Validation covers GitHub source baseline `4efb0bce1e0f5a00a078c77d9f91608d5127a757`
plus local modified/new development source. **Only documentation is published.
Fixed source, new tests, assets, binaries, and raw logs remain local.** These
results do not validate an existing installer, App Store app, or fresh GitHub clone.

## Fixes

- Preserve the Grype adapter imported during Windows SourceOnly startup and add a built GUI EXE startup smoke check.
- Drain Syft pipes with two reader threads and a bounded queue, keeping 32MiB stdout/1MiB stderr limits and the original deadline after EOF.
- Reject missing source targets. Java `--fail-on`/`--fail-on-kev` without an enabled Grype comparator exits 2; explicit SBOM-only without a gate remains exit 0.
- Accept valid empty macOS DEFLATE ZIP/GZIP while rejecting malformed/truncated/trailing data and retaining expansion limits.
- Drain macOS Java output during execution, with a 30-minute per-process deadline and TERM/KILL cleanup.
- Include helper rule/report resources, set and verify each architecture, repair checksum formatting, and separate English UI locale from Korean-only Java reports.
- Stop the Linux execution owner on unconfirmed group termination, retain workspace/nonterminal ownership/error, and block subsequent execution. The earlier intermittent permission error's original cause remains unconfirmed.
- Correct synthetic-secret and Linux release fixtures to match existing contracts; remove unused-code warnings without weakening detection or safety checks.

## Results

| Check | Result | Scope |
| --- | --- | --- |
| Linux full unittest | **768: 767 passed, 0 failed, 1 skipped**, 198.051 seconds | Debian 12, Python 3.12.15, amd64 |
| macOS-host full unittest | **768: 760 passed, 0 failed, 8 skipped**, 142.730 seconds | Python 3.14.6, earlier fix phase |
| Python 3.12 focused unittest | **214 passed** | CLI, Java, web, network, Syft, packaging, worker |
| macOS harness | **All 10 scripts passed** | Eight archive tests, four Java-process tests, two staging tests, seven AI fixture scripts; overlapping results are not added |
| Full macOS app | **Java-enabled universal Release build/analyze passed** | arm64+x86_64, no developer signing/notarization |
| macOS Java runtime | **Both ARM app runs exit 0** | English UI setting and network-denied Korean setting |
| Linux installation | **Actual installer/CLI/PDF/portal passed** | Non-root, no network, cached wheels/Chromium |
| Linux live portal | **ZIP upload→external worker→JSON/PDF passed** | Three web/scan/delivery containers, healthy workers, no remaining workspace |
| Linux Java runtime | **DB import 0; high-severity gate 1** | Actual Syft/Grype, no network, 4GiB limit |
| Source identity | **106 installed product source/resource hashes matched** | Finder metadata/Python cache excluded |
| Static checks | **Ruff F/E9, modified shell syntax, diff passed** | Separate from deployment validation |

Linux used **emulated amd64 user space in Docker LinuxKit on Apple Silicon**.
Actual x86-64 ELF Python/tools and Linux process/filesystem paths ran; this is
not physical x86_64/native x86_64 kernel validation or a performance certification.

## Java inputs and assets

- Syft 1.46.0, Grype 0.115.0.
- Grype DB schema v6.1.10, built `2026-10-10T06:30:01Z`.
- NVD 2002–2026 plus recent/modified: 27 feeds; CISA KEV.
- Official release checksums, DB SHA-256, and asset-pack manifest passed.
- App/helper/tool architectures and both helpers' rule/report resources verified; helper links contain no external temporary Python build path.

The fixture contains only Maven metadata for `log4j-core 2.14.1`, with no executable
Java code. Both platforms reported one component, seven unique vulnerabilities
(two Critical, one High, four Medium), one KEV, no warnings, and `CVE-2021-44228`.
Linux exit 1 is the expected high-severity gate. macOS Java reports remain Korean
regardless of UI locale.

The installer check ran `platforms/linux/install.sh --no-link`, the source-install
path. It did not import a complete Docker delivery through
`platforms/linux/docker/install.sh`. The image ID is recorded in the JSON summary. It is a validation image, not a
repackaged production Suite release. Test containers were stopped/removed; the
validation app, image, test data, and logs remain local. The App Store installation
was not replaced.

## Initial setup failures

Missing samples/Git metadata, work-directory conditions, and an outdated Linux
release fixture were corrected. The affected tests were not skipped; the final
full suite passed. A separate synthetic Git metadata fixture supplied contract
requirements, without copying host credentials. Release unit tests use a Docker
double and are separate from the real installer and portal checks.

## Remaining validation

Native Windows execution was excluded at the user's request. Intel helpers passed
build/link checks, but execution returned `Bad CPU type in executable` on this host.
Developer signing/notarization/App Store submission, external target or LLM quality,
physical x86_64, production Nginx login/Tracker/GitLab delivery, and live Suite
upgrade/recovery remain unverified.

[OS matrix (Korean)](platform-feature-matrix.ko.md) · [English index](README.en.md)
