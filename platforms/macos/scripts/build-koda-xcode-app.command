#!/bin/zsh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
PROJECT="$REPO_ROOT/platforms/macos/app/KODA/KODA.xcodeproj"
SCHEME="KODA"
CONFIGURATION="${CONFIGURATION:-Release}"
MACOS_ARCHS="${KODA_MACOS_ARCHS:-arm64}"
export KODA_MACOS_JAVA_ASSETS="${KODA_MACOS_JAVA_ASSETS:-$REPO_ROOT/.build/koda-macos-java-assets}"
DERIVED_DATA_PATH="${DERIVED_DATA_PATH:-$REPO_ROOT/.build/koda-xcode-derived}"
DIST_DIR="$REPO_ROOT/dist/macos"
APP_SOURCE="$DERIVED_DATA_PATH/Build/Products/$CONFIGURATION/KODA.app"
APP_DESTINATION="$DIST_DIR/KODA.app"
XCODEBUILD="${XCODEBUILD:-/Applications/Xcode.app/Contents/Developer/usr/bin/xcodebuild}"
if [[ ! -x "$XCODEBUILD" ]]; then
  XCODEBUILD="xcodebuild"
fi

mkdir -p "$DIST_DIR"

if [[ "${KODA_INCLUDE_JAVA_SCANNER:-1}" != "0" ]]; then
  "$SCRIPT_DIR/prepare-java-scan-assets.command"
fi

"$XCODEBUILD" \
  -project "$PROJECT" \
  -scheme "$SCHEME" \
  -configuration "$CONFIGURATION" \
  -derivedDataPath "$DERIVED_DATA_PATH" \
  ARCHS="$MACOS_ARCHS" \
  KODA_MACOS_JAVA_ASSETS="$KODA_MACOS_JAVA_ASSETS" \
  CODE_SIGN_ENTITLEMENTS="$REPO_ROOT/platforms/macos/packaging/KODA.direct.entitlements" \
  CODE_SIGNING_ALLOWED="${CODE_SIGNING_ALLOWED:-NO}" \
  build

if [[ ! -d "$APP_SOURCE" ]]; then
  echo "KODA.app was not produced at $APP_SOURCE" >&2
  exit 1
fi

rm -rf "$APP_DESTINATION"
ditto "$APP_SOURCE" "$APP_DESTINATION"

echo "Built $APP_DESTINATION"
