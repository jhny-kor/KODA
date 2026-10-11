# KODA macOS App Store Packaging

This folder contains the App Store packaging lane for the macOS app named `KODA`.

As of **2026-10-11**, this guide describes the local working tree, including
uncommitted development changes. Java-inclusive universal Release build and
analysis passed; ARM app startup and offline Java scanning passed. Intel
execution, distribution signing, notarization, and Store submission remain
unverified. See the [verification summary](../../../docs/verification-2026-10-11.md).

## What is included

- `assets/KODA.icns`: app icon generated from the supplied KODA image.
- `assets/KODA-AppStore-1024.png`: 1024 px App Store marketing icon source.
- `KODA.entitlements`: App Sandbox entitlements required for Mac App Store distribution.
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

The Xcode app uses the native Swift scanner for its standard scan. Its Java archive scan menu uses an embedded Python helper plus bundled Syft, Grype, Grype DB, NVD, and CISA KEV data; the shipped app executes only its bundled scanner helper and tools, with no runtime scanner download. The local build output is:

```text
dist/macos/KODA.app
```

The App Store Java helper packages only the command-line scan path. Dashboard
server and Tk folder-picker modules are explicitly excluded from this helper so
Tcl/Tk is not shipped in the App Store bundle. This exclusion does not apply to
the shared Python, Windows, Linux, or legacy macOS application lanes.

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

The Xcode app is the preferred App Store lane. The Java scan reads selected JAR/WAR/EAR files as data only; it never invokes Java or executes archive content. Before App Review submission, verify the signed archive with `codesign --verify --deep --strict --verbose=2`, inspect each helper entitlement, and run an offline JAR smoke test from the exported app.

Apple references:

- [Upload builds to App Store Connect](https://developer.apple.com/help/app-store-connect/manage-builds/upload-builds/)
- [App Sandbox](https://developer.apple.com/documentation/security/app_sandbox)
- [Configuring the macOS App Sandbox](https://developer.apple.com/documentation/xcode/configuring-the-macos-app-sandbox)
