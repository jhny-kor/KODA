#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="${1:-run}"
case "$MODE" in run|--verify|--debug|--logs|--telemetry) ;; *) echo "usage: $0 [--verify|--debug|--logs|--telemetry]" >&2; exit 2;; esac
APP_BUNDLE="$ROOT_DIR/.build/macos-local-ai/Build/Products/Debug/KODA.app"
# Dedicated development identity preserves installed release settings and Keychain.
pkill -f "$APP_BUNDLE/Contents/MacOS/KODA" >/dev/null 2>&1 || true
xcodebuild -quiet -project "$ROOT_DIR/platforms/macos/app/KODA/KODA.xcodeproj" -scheme KODA -destination "platform=macOS,arch=$(uname -m)" -configuration Debug -derivedDataPath "$ROOT_DIR/.build/macos-local-ai" PRODUCT_BUNDLE_IDENTIFIER=com.jhnykor.koda.localai CODE_SIGN_IDENTITY=- CODE_SIGN_STYLE=Manual DEVELOPMENT_TEAM= KODA_INCLUDE_JAVA_SCANNER=0 build
case "$MODE" in
 --debug) lldb -- "$APP_BUNDLE/Contents/MacOS/KODA";;
 --logs|--telemetry) open -n "$APP_BUNDLE"; /usr/bin/log stream --info --style compact --predicate 'process == "KODA"';;
 --verify) open -n "$APP_BUNDLE"; sleep 2; pgrep -f "$APP_BUNDLE/Contents/MacOS/KODA";;
 *) open -n "$APP_BUNDLE";;
esac
