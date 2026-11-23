#!/usr/bin/env bash
set -euo pipefail

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(CDPATH= cd -- "$script_dir/../../.." && pwd)"
archive_path="${KODA_ARCHIVE_PATH:-$repo_root/build/KODA.xcarchive}"
macos_archs="${KODA_MACOS_ARCHS:-arm64}"
xcodebuild_bin="${XCODEBUILD:-/Applications/Xcode.app/Contents/Developer/usr/bin/xcodebuild}"

export KODA_MACOS_JAVA_ASSETS="${KODA_MACOS_JAVA_ASSETS:-$repo_root/.build/koda-macos-java-assets-app-store}"
KODA_MACOS_HELPER_APP_STORE=1 "$script_dir/prepare-java-scan-assets.command"
"$xcodebuild_bin" \
  -project "$repo_root/platforms/macos/app/KODA/KODA.xcodeproj" \
  -scheme KODA \
  -configuration Release \
  -archivePath "$archive_path" \
  ARCHS="$macos_archs" \
  KODA_MACOS_JAVA_ASSETS="$KODA_MACOS_JAVA_ASSETS" \
  SWIFT_ACTIVE_COMPILATION_CONDITIONS="KODA_APP_STORE" \
  KODA_INCLUDE_JAVA_SCANNER=1 \
  archive
echo "Created App Store archive: $archive_path"
