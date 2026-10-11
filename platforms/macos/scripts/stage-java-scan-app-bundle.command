#!/usr/bin/env bash
set -euo pipefail

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(CDPATH= cd -- "$script_dir/../../.." && pwd)"
app_bundle=""
asset_dir="${KODA_MACOS_JAVA_ASSETS:-$repo_root/.build/koda-macos-java-assets}"
identity=""
code_signing_allowed="NO"

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --app) app_bundle="$2"; shift 2 ;;
    --assets) asset_dir="$2"; shift 2 ;;
    --identity) identity="$2"; shift 2 ;;
    --code-signing-allowed) code_signing_allowed="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [[ -z "$app_bundle" || ! -d "$app_bundle" ]]; then
  echo "A built KODA.app path is required." >&2
  exit 2
fi
for required in \
  "$asset_dir/helpers" \
  "$asset_dir/tools" \
  "$asset_dir/resources/grype-db/incoming" \
  "$asset_dir/resources/vuln-data/nvd" \
  "$asset_dir/resources/vuln-data/known_exploited_vulnerabilities.json" \
  "$asset_dir/manifest.sha256"; do
  if [[ ! -e "$required" ]]; then
    echo "Incomplete Java scanner asset pack: $required" >&2
    exit 2
  fi
done

main_executable="$app_bundle/Contents/MacOS/KODA"
if [[ -x "$main_executable" ]]; then
  for app_architecture in $(lipo -archs "$main_executable"); do
    case "$app_architecture" in
      arm64) asset_architecture=arm64 ;;
      x86_64) asset_architecture=amd64 ;;
      *) echo "Unsupported KODA.app architecture: $app_architecture" >&2; exit 2 ;;
    esac
    for required in \
      "$asset_dir/helpers/$asset_architecture/koda-java-scan.app/Contents/MacOS/koda-java-scan" \
      "$asset_dir/tools/$asset_architecture/syft" \
      "$asset_dir/tools/$asset_architecture/grype"; do
      if [[ ! -x "$required" ]]; then
        echo "Java scanner assets are missing for KODA.app architecture $app_architecture: $required" >&2
        exit 2
      fi
      if ! lipo -verify_arch "$app_architecture" "$required"; then
        echo "Java scanner asset has the wrong architecture for $app_architecture: $required" >&2
        exit 2
      fi
    done
  done
fi

helpers="$app_bundle/Contents/Helpers"
resources="$app_bundle/Contents/Resources/java-scan"
rm -rf "$helpers/koda-java-scan-arm64.app" "$helpers/koda-java-scan-amd64.app" "$helpers/java-scan-tools" "$resources"
mkdir -p "$helpers" "$app_bundle/Contents/Resources"
for asset_architecture in arm64 amd64; do
  source_helper="$asset_dir/helpers/$asset_architecture/koda-java-scan.app"
  if [[ -d "$source_helper" ]]; then
    ditto "$source_helper" "$helpers/koda-java-scan-$asset_architecture.app"
  fi
done
ditto "$asset_dir/tools" "$helpers/java-scan-tools"
ditto "$asset_dir/resources" "$resources"
cp "$asset_dir/manifest.sha256" "$resources/manifest.sha256"
cp "$asset_dir/asset-manifest.json" "$resources/asset-manifest.json"

if [[ "$code_signing_allowed" == "YES" && -n "$identity" ]]; then
  helper_entitlements="$repo_root/platforms/macos/packaging/KODA.helper.entitlements"
  while IFS= read -r -d '' binary; do
    codesign --force --options runtime --timestamp --sign "$identity" "$binary"
  done < <(find "$helpers" -type f -print0 | while IFS= read -r -d '' candidate; do file "$candidate" | grep -q 'Mach-O' && printf '%s\0' "$candidate"; done)
  for helper in \
    "$helpers/koda-java-scan-arm64.app" \
    "$helpers/koda-java-scan-amd64.app" \
    "$helpers/java-scan-tools/arm64/syft" \
    "$helpers/java-scan-tools/arm64/grype" \
    "$helpers/java-scan-tools/amd64/syft" \
    "$helpers/java-scan-tools/amd64/grype"; do
    if [[ -x "$helper" ]]; then
      codesign --force --options runtime --timestamp --entitlements "$helper_entitlements" --sign "$identity" "$helper"
    fi
  done
fi
