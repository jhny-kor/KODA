#!/usr/bin/env bash
set -euo pipefail

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(CDPATH= cd -- "$script_dir/../../.." && pwd)"
asset_dir="${KODA_MACOS_JAVA_ASSETS:-$repo_root/.build/koda-macos-java-assets}"
source_assets="${KODA_JAVA_SCAN_SOURCE_ASSETS:-$repo_root/.build/koda-offline-cache/assets}"
extra_assets="${KODA_JAVA_SCAN_EXTRA_SOURCE_ASSETS:-$repo_root/.build/koda-offline-cache-2025/assets}"
cache_dir="${KODA_MACOS_JAVA_CACHE:-$repo_root/.build/koda-macos-java-cache}"
python_bin="${KODA_PYTHON:-python3}"
architecture="${KODA_MACOS_ARCH:-$(uname -m)}"
syft_version="${KODA_SYFT_VERSION:-1.46.0}"
grype_version="${KODA_GRYPE_VERSION:-0.115.0}"
nvd_start_year="${KODA_NVD_START_YEAR:-2002}"
nvd_end_year="${KODA_NVD_END_YEAR:-$(date +%Y)}"

case "$architecture" in
  arm64) archive_arch=arm64; target_arch=arm64 ;;
  x86_64|amd64) architecture=amd64; archive_arch=amd64; target_arch=x86_64 ;;
  *) echo "Unsupported macOS architecture: $architecture" >&2; exit 2 ;;
esac

for required in \
  "$source_assets/grype-db/incoming" \
  "$source_assets/vuln-data/nvd"; do
  if [[ ! -e "$required" ]]; then
    echo "Missing offline vulnerability data: $required" >&2
    echo "Build it first with platforms/linux/package-offline.sh on a connected build host." >&2
    exit 2
  fi
done

download() {
  local url="$1" destination="$2"
  if [[ -s "$destination" ]]; then
    return
  fi
  mkdir -p "$(dirname "$destination")"
  curl --fail --location --retry 3 --retry-delay 2 --output "$destination.part" "$url"
  mv "$destination.part" "$destination"
}

verify_release_checksum() {
  local archive="$1" checksums="$2"
  local expected
  expected="$(awk -v name="$(basename "$archive")" '$NF == name || $NF == "*" name { print $1; exit }' "$checksums")"
  if [[ -z "$expected" ]]; then
    echo "Release checksum entry missing for $(basename "$archive")" >&2
    exit 2
  fi
  local actual
  actual="$(shasum -a 256 "$archive" | awk '{print $1}')"
  if [[ "$actual" != "$expected" ]]; then
    echo "Checksum mismatch for $(basename "$archive")" >&2
    exit 2
  fi
}

stage_tool() {
  local name="$1" version="$2"
  local archive="$cache_dir/${name}_${version}_darwin_${archive_arch}.tar.gz"
  local checksums="$cache_dir/${name}_${version}_checksums.txt"
  download "https://github.com/anchore/$name/releases/download/v$version/${name}_${version}_darwin_${archive_arch}.tar.gz" "$archive"
  download "https://github.com/anchore/$name/releases/download/v$version/${name}_${version}_checksums.txt" "$checksums"
  verify_release_checksum "$archive" "$checksums"
  local extract_dir
  extract_dir="$(mktemp -d)"
  tar -xzf "$archive" -C "$extract_dir" "$name"
  install -m 0755 "$extract_dir/$name" "$asset_dir/tools/$architecture/$name"
  rm -rf "$extract_dir"
}

rm -rf "$asset_dir/resources" "$asset_dir/helpers/$architecture" "$asset_dir/tools/$architecture"
mkdir -p "$asset_dir/resources" "$asset_dir/helpers" "$asset_dir/tools/$architecture" "$cache_dir"
ditto "$source_assets/grype-db" "$asset_dir/resources/grype-db"
ditto "$source_assets/vuln-data" "$asset_dir/resources/vuln-data"
if [[ -d "$extra_assets/vuln-data/nvd" ]]; then
  find "$extra_assets/vuln-data/nvd" -type f -name '*.json.gz' -exec cp -n {} "$asset_dir/resources/vuln-data/nvd/" \;
fi
downloads=()
for year in $(seq "$nvd_start_year" "$nvd_end_year"); do
  feed="$asset_dir/resources/vuln-data/nvd/nvdcve-2.0-$year.json.gz"
  if [[ -s "$feed" ]]; then
    continue
  fi
  download "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-$year.json.gz" "$feed" &
  downloads+=("$!")
  if [[ "${#downloads[@]}" -eq 4 ]]; then
    for pid in "${downloads[@]}"; do wait "$pid"; done
    downloads=()
  fi
done
if [[ ${downloads[0]+_} ]]; then
  for pid in "${downloads[@]}"; do wait "$pid"; done
fi
for feed in recent modified; do
  download "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-$feed.json.gz" "$asset_dir/resources/vuln-data/nvd/nvdcve-2.0-$feed.json.gz"
done
if [[ ! -f "$asset_dir/resources/vuln-data/known_exploited_vulnerabilities.json" ]]; then
  if [[ -f "$extra_assets/vuln-data/known_exploited_vulnerabilities.json" ]]; then
    cp "$extra_assets/vuln-data/known_exploited_vulnerabilities.json" "$asset_dir/resources/vuln-data/known_exploited_vulnerabilities.json"
  else
    download "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" "$asset_dir/resources/vuln-data/known_exploited_vulnerabilities.json"
  fi
fi
stage_tool syft "$syft_version"
stage_tool grype "$grype_version"

builder_venv="$cache_dir/pyinstaller-venv-$architecture"
if [[ ! -x "$builder_venv/bin/python" ]]; then
  "$python_bin" -m venv "$builder_venv"
fi
"$builder_venv/bin/python" -m pip install --quiet --upgrade pyinstaller
"$builder_venv/bin/python" -m PyInstaller \
  --noconfirm \
  --clean \
  --onedir \
  --windowed \
  --target-architecture "$target_arch" \
  --name koda-java-scan \
  --distpath "$asset_dir/helpers/$architecture" \
  --workpath "$cache_dir/pyinstaller-work-$architecture" \
  --specpath "$cache_dir/pyinstaller-spec-$architecture" \
  --paths "$repo_root/platforms/shared/python" \
  --collect-submodules security_scanner \
  --add-data "$repo_root/platforms/shared/python/security_scanner/resources:security_scanner/resources" \
  --add-data "$repo_root/platforms/shared/python/security_scanner/assets:security_scanner/assets" \
  --exclude-module security_scanner.server \
  --exclude-module security_scanner.app \
  --exclude-module tkinter \
  --exclude-module _tkinter \
  "$repo_root/platforms/macos/packaging/java-scan-entry.py"

lipo -verify_arch "$target_arch" "$asset_dir/helpers/$architecture/koda-java-scan.app/Contents/MacOS/koda-java-scan"
(
  cd "$asset_dir"
  find resources tools helpers -type f -print0 | sort -z | xargs -0 shasum -a 256
) > "$asset_dir/manifest.sha256"
cat > "$asset_dir/asset-manifest.json" <<EOF
{
  "architecture": "$architecture",
  "syft_version": "$syft_version",
  "grype_version": "$grype_version",
  "offline_data_source": "${source_assets#$repo_root/}",
  "network_at_runtime": false
}
EOF
echo "Prepared signed-input Java scanner assets at $asset_dir"
