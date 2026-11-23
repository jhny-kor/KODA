# KODA macOS packaging

This folder contains the direct-distribution and App Store packaging for KODA.

The October 11 validation covered a Java-inclusive universal Release build,
Apple Silicon app startup, and offline Java scanning. Follow-up Apple Silicon
checks covered the loopback dashboard and its bundled CLI helper. SpotBugs
4.10.5 and Semgrep CE 1.186.0 ran on local fixtures through both paths. Intel
execution, release signing and notarization, and Store submission remain
unverified for these analyzer changes. [October 11 verification summary](../../../docs/verification-2026-10-11.md)

## What is included

- `assets/KODA.icns`: app icon generated from the supplied KODA image.
- `assets/KODA-AppStore-1024.png`: 1024 px App Store marketing icon source.
- `KODA.entitlements`: App Sandbox entitlements required for Mac App Store distribution.
- `KODA.direct.entitlements`: App Sandbox entitlements for the direct build and its loopback dashboard.
- `../app/KODA/KODA.xcodeproj`: native SwiftUI macOS project for the App Store lane. The app supports folder selection, multiple file selection, and common archive inputs with a built-in Swift scanner.
- `../scripts/build-koda-xcode-app.command`: builds the native Xcode app to `dist/macos/KODA.app`, including the offline Java scanner assets.
- `../scripts/prepare-java-scan-assets.command`: builds the embedded Python scanner, downloads checksum-verified Syft/Grype release binaries, and stages the offline Grype/NVD/CISA data pack.
- `../scripts/archive-koda-app-store.command`: prepares the assets and creates an App Store archive.
- `../scripts/build-koda-app.command`: legacy PyInstaller-based macOS app and package build script for non-store experiments.

## Requirements

- macOS with full Xcode for the native app project.
- Python with the requested architecture for Java helper packaging.
- Apple Developer Program membership for Store distribution (not unsigned local builds).
- A Mac App Store bundle identifier, for example `com.yourcompany.koda`.
- Mac App Distribution and Mac Installer Distribution signing certificates.

## Local build

### Xcode project

Open the native project:

```zsh
open platforms/macos/app/KODA/KODA.xcodeproj
```

For local command-line verification without signing:

```zsh
platforms/macos/scripts/build-koda-xcode-app.command
```

The Xcode app uses the native Swift scanner for its standard scan. The Java
archive scan menu uses an embedded Python helper and bundled Syft, Grype,
Grype DB, NVD, and CISA KEV data. The local build output is:

```text
dist/macos/KODA.app
```

The App Store Java helper packages only the command-line scan path. Dashboard
server and Tk folder-picker modules are explicitly excluded from this helper so
Tcl/Tk is not shipped in the App Store bundle. This exclusion does not apply to
the shared Python, Windows, Linux, or legacy macOS application lanes.

### Direct-distribution dashboard

The `macOS-1.2` GitHub prerelease includes the local desktop dashboard, local
source and Java checks, and read-only website checks. SpotBugs and Semgrep CE
are installed separately.

Open **Prevention Kit → Open browser dashboard** in the direct build. The
loopback dashboard supports local source scanning and reports, HAR review, TCP
listener inventory, PEM/DER certificate review, and JWT HMAC key-size checks.
The TCP list may be partial when the App Sandbox restricts access to the OS
socket inventory. Run `koda-local local-listeners` from Terminal for the OS
inventory, or `koda-local approval-review --help` for signed-document checks
and locally recorded use.

To start the dashboard from Terminal:

```zsh
dist/macos/KODA.app/Contents/Resources/koda-local dashboard
```

For **SpotBugs · Semgrep CE**, start the dashboard from the terminal where you
configured the installed tools. Both analyzers are also available through
`koda-local scan`.

- Set `KODA_SPOTBUGS_JAR` to the SpotBugs distribution's `lib/spotbugs.jar`.
  KODA locates Java through `KODA_JAVA_BIN`, `JAVA_HOME`, then `PATH`.
  Select an existing Java JAR, `.class` file, or classes directory. Supply
  `--spotbugs-source-root` if the Java package root inside the selected source
  directory differs from the inferred root.
- Put Semgrep CE on `PATH` or set `KODA_SEMGREP_BIN` to its full path.
  Select one local YAML rule file and one source directory.

Previously generated CodeQL results are available through supported SARIF
2.1.0 mappings. SpotBugs can contribute a Java null-dereference review
candidate for SW49 C-01. An empty external report leaves control coverage
unproven. [Analyzer usage and evidence limits](../../../docs/usage.md)

The release scripts default to `arm64`. Asset preparation builds one architecture
per invocation: `KODA_MACOS_ARCH=arm64` or `KODA_MACOS_ARCH=x86_64`; Intel helper
packaging requires an x86_64-capable Python runtime, either on Intel macOS or a
cross-build environment. Architecture-specific build venvs and PyInstaller
`--target-architecture` prevent mixing helper runtimes. Both rule resources and
report assets are included explicitly. Prepare both asset sets before a universal
build with `KODA_MACOS_ARCHS="arm64 x86_64"`; use `KODA_MACOS_ARCHS=x86_64` for an
Intel-only app. The staging phase verifies actual Mach-O architectures for the
helper, Syft, and Grype, and fails if any required architecture is absent.
`manifest.sha256` applies to the prepared asset-pack root, not the relocated app
bundle paths.

`prepare-java-scan-assets.command` obtains NVD feeds from 2002 through the
current year by default and needs an existing offline data cache (created with
`platforms/linux/package-offline.sh`). Java archive traversal has default safety
limits: nesting depth 8, 10,000 outer archives and 10,000 ZIP entries across
selected roots, 256 MiB per outer archive, 256 MiB nested expanded data, 512 MiB
retained data, 4 MiB central-directory data per archive, and compression ratio
1,000. The CLI can override nesting depth with `--max-depth`; it does not expose
all of these limits as options. Limit warnings represent incomplete coverage.
The macOS wrapper also applies a 1,800-second deadline per helper/tool process;
the shared Java CLI defaults to 300 seconds per Syft/Grype invocation.

### PyInstaller package lane

```zsh
platforms/macos/scripts/build-koda-app.command
```

The local build creates an unsigned test package at:

```text
dist/macos/KODA.app
dist/macos/KODA-0.1.0-unsigned.pkg
```

## App Store archive

Use the native Xcode project as the App Store lane:

```zsh
platforms/macos/scripts/archive-koda-app-store.command
```

The archive script passes the `KODA_APP_STORE` Swift condition. In that build,
the native web scanner is restricted to GET/HEAD read-only requests; login POSTs,
active probes, ZAP, and state-changing scenarios are disabled. Run the complete
21-control profile-driven audit through the separate shared Python CLI. The
native direct-distribution app does not provide this profile CLI. Keep App Store
capability gaps as `UNSUPPORTED`/review rather
than treating them as PASS.

The distribution boundary is:

| Distribution | 21-control web audit | Execution boundary |
| --- | --- | --- |
| Shared Python CLI on macOS | Supported | Separate from the native app; profile, approval, and one-time nonce gates apply. |
| Native direct macOS app | Partial | Native website scanner; no shared CLI profile/oracle engine. |
| Mac App Store | Partial | Native GET/HEAD read-only checks only; POST, active probes, ZAP, and state-changing scenarios are disabled. |

For the shared Python CLI lane, set `PYTHONPATH` from the repository root and run
`web-audit run --dry-run` before any target traffic. ZAP, Playwright, and BOAST
are never downloaded by the app; missing preinstalled capability, image digest, or
add-on manifest must remain a capability status rather than PASS. App Store
profiles that request `state_change` or a non-GET/HEAD step fail profile validation.

Then upload the archive from Xcode Organizer or export it with an App Store
Connect export profile. Before submission, verify the signed app has the App
Sandbox entitlement:

```zsh
codesign -dvvv --entitlements :- build/KODA.xcarchive/Products/Applications/KODA.app
```

For command-line export, provide an App Store export options plist and run:

```zsh
/Applications/Xcode.app/Contents/Developer/usr/bin/xcodebuild \
  -exportArchive \
  -archivePath build/KODA.xcarchive \
  -exportPath dist/app-store \
  -exportOptionsPlist /path/to/ExportOptions-app-store.plist
```

The legacy `build-koda-app.command` PyInstaller lane is for non-store
experiments. Do not use it for the Mac App Store submission unless the store
lane is intentionally changed back to the Python bundle.

## Current limitation

The Xcode app is the App Store build. Its Java archive inventory reads selected
JAR/WAR/EAR files as data. Before App Review submission, verify the signed
archive with `codesign --verify --deep --strict --verbose=2`, inspect each
helper entitlement, and run an offline JAR smoke test from the exported app.

Apple references:

- [Upload builds to App Store Connect](https://developer.apple.com/help/app-store-connect/manage-builds/upload-builds/)
- [App Sandbox](https://developer.apple.com/documentation/security/app_sandbox)
- [Configuring the macOS App Sandbox](https://developer.apple.com/documentation/xcode/configuring-the-macos-app-sandbox)
