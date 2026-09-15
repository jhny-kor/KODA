#!/usr/bin/env bash
set -euo pipefail

script_dir="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(CDPATH= cd -- "$script_dir/../.." && pwd)"
dist_dir="${KODA_LINUX_DIST_DIR:-$repo_root/dist/linux}"
cache_dir="${KODA_OFFLINE_CACHE_DIR:-$repo_root/.build/koda-offline-cache}"
asset_dir="$cache_dir/assets"
syft_version="${KODA_SYFT_VERSION:-1.46.0}"
grype_version="${KODA_GRYPE_VERSION:-0.115.0}"
nvd_start_year="${KODA_NVD_START_YEAR:-2002}"
nvd_end_year="${KODA_NVD_END_YEAR:-$(date +%Y)}"
cisa_url="${KODA_CISA_URL:-https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json}"
grype_db_latest_url="${KODA_GRYPE_DB_LATEST_URL:-https://grype.anchore.io/databases/v6/latest.json}"

refresh=0
vuln_data_only=0
data_cache_only=0
vuln_data_dir="${KODA_VULN_DATA_DIR:-$repo_root/dist/Windows}"

usage() {
  cat <<'EOF'
Usage: package-offline.sh [--refresh] [--vuln-data-only]

Builds dist/linux/koda-linux-x86_64-<version>.tar.gz on a connected
macOS/Linux host.

Options:
  --refresh         re-validate cached yearly NVD feeds against their .meta
                    files and re-download the Grype DB latest metadata
  --data-cache-only download/verify NVD and KEV only, for Linux update packages
  --vuln-data-only  download only NVD and CISA KEV, then write
                    dist/Windows/koda-vuln-data-<date>.zip for the Windows
                    installer. Skips Syft, Grype, the Grype DB, and the Linux
                    tarball, which the Windows installer already carries.

Mutable feeds (NVD recent/modified, CISA KEV) are re-downloaded on every
build regardless of --refresh. Version-pinned Syft/Grype releases always
reuse the cache.

Environment:
  KODA_OFFLINE_CACHE_DIR download cache, default .build/koda-offline-cache
  KODA_LINUX_DIST_DIR    output directory, default dist/linux
  KODA_VULN_DATA_DIR     --vuln-data-only output directory, default dist/Windows
  KODA_SYFT_VERSION      default 1.46.0
  KODA_GRYPE_VERSION     default 0.115.0
  KODA_NVD_START_YEAR    default 2002
  KODA_NVD_END_YEAR      default current year
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --refresh)
      refresh=1
      shift
      ;;
    --data-cache-only)
      vuln_data_only=1
      data_cache_only=1
      shift
      ;;
    --vuln-data-only)
      vuln_data_only=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

command -v curl >/dev/null 2>&1 || { echo "error: curl is required." >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "error: python3 is required." >&2; exit 2; }
mkdir -p "$asset_dir/tools" "$asset_dir/grype-db/incoming" "$asset_dir/vuln-data/nvd" "$dist_dir"
find "$cache_dir" -type f -name '*.part.*' -delete

download() {
  local url="$1" destination="$2"
  local marker="$cache_dir/.complete/$(basename -- "$destination").done"
  if [ -s "$destination" ] && [ -f "$marker" ]; then
    return
  fi
  mkdir -p "$(dirname -- "$destination")" "$(dirname -- "$marker")"
  echo "Downloading $url" >&2
  local partial="$destination.part.$$"
  if ! curl -fL --retry 3 --retry-delay 2 -o "$partial" "$url"; then
    rm -f "$partial"
    return 1
  fi
  mv "$partial" "$destination"
  touch "$marker"
}

# Drop the completion marker so the next download() call re-fetches the file.
invalidate() {
  rm -f "$cache_dir/.complete/$(basename -- "$1").done"
}

# Verify a cached NVD .json.gz feed against the freshly downloaded .meta
# (sha256 in .meta is over the uncompressed JSON). Returns 1 on mismatch.
verify_nvd_meta() {
  local feed_file="$1" meta_file="$2"
  python3 - "$feed_file" "$meta_file" <<'PY'
import gzip
import hashlib
import pathlib
import sys

feed = pathlib.Path(sys.argv[1])
expected = None
for line in pathlib.Path(sys.argv[2]).read_text(encoding="utf-8").splitlines():
    key, _, value = line.strip().partition(":")
    if key.lower() == "sha256":
        expected = value.strip().lower()
        break
if not expected:
    raise SystemExit(f"no sha256 entry in {sys.argv[2]}")
digest = hashlib.sha256()
with gzip.open(feed, "rb") as stream:
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
        digest.update(chunk)
if digest.hexdigest() != expected:
    print(f"stale NVD feed {feed.name}: {digest.hexdigest()} != {expected}", file=sys.stderr)
    raise SystemExit(1)
print(f"verified {feed.name} against .meta")
PY
}

verify_release_checksum() {
  local archive="$1" checksums="$2"
  python3 - "$archive" "$checksums" <<'PY'
import hashlib
import pathlib
import sys

archive = pathlib.Path(sys.argv[1])
checksums = pathlib.Path(sys.argv[2])
expected = None
for line in checksums.read_text(encoding="utf-8").splitlines():
    fields = line.split()
    if len(fields) >= 2 and pathlib.Path(fields[-1].lstrip("* ")).name == archive.name:
        expected = fields[0].lower()
        break
if not expected:
    raise SystemExit(f"checksum entry not found for {archive.name}")
digest = hashlib.sha256()
with archive.open("rb") as stream:
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
        digest.update(chunk)
actual = digest.hexdigest()
if actual != expected:
    raise SystemExit(f"checksum mismatch for {archive.name}: {actual} != {expected}")
print(f"verified {archive.name}: {actual}")
PY
}

download_tool() {
  local name="$1" version="$2"
  local archive="$cache_dir/${name}_${version}_linux_amd64.tar.gz"
  local checksums="$cache_dir/${name}_${version}_checksums.txt"
  download "https://github.com/anchore/$name/releases/download/v$version/${name}_${version}_linux_amd64.tar.gz" "$archive"
  download "https://github.com/anchore/$name/releases/download/v$version/${name}_${version}_checksums.txt" "$checksums"
  verify_release_checksum "$archive" "$checksums"
  local tmp
  tmp="$(mktemp -d)"
  tar -xzf "$archive" -C "$tmp" "$name"
  install -m 0755 "$tmp/$name" "$asset_dir/tools/$name"
  rm -rf "$tmp"
}

if [ "$vuln_data_only" -eq 0 ]; then

download_tool syft "$syft_version"
download_tool grype "$grype_version"

latest_json="$cache_dir/grype-db-latest.json"
if [ "$refresh" -eq 1 ]; then
  invalidate "$latest_json"
fi
download "$grype_db_latest_url" "$latest_json"
read -r db_path db_checksum db_url <<EOF
$(python3 - "$latest_json" <<'PY'
import json
import sys
import urllib.parse

payload = json.loads(open(sys.argv[1], encoding="utf-8").read())
path = payload.get("path")
checksum = payload.get("checksum")
if not isinstance(path, str) or not isinstance(checksum, str):
    raise SystemExit("Grype DB latest metadata has no path/checksum")
url = "https://grype.anchore.io/databases/v6/" + urllib.parse.quote(path, safe="")
url += "?checksum=" + urllib.parse.quote(checksum, safe=":")
print(path, checksum, url)
PY
)
EOF
db_archive="$asset_dir/grype-db/incoming/$(basename -- "$db_path")"
download "$db_url" "$db_archive"
python3 - "$db_archive" "$db_checksum" <<'PY'
import hashlib
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
expected = sys.argv[2].removeprefix("sha256:").lower()
digest = hashlib.sha256()
with path.open("rb") as stream:
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
        digest.update(chunk)
actual = digest.hexdigest()
if actual != expected:
    raise SystemExit(f"Grype DB checksum mismatch: {actual} != {expected}")
print(f"verified {path.name}: {actual}")
PY

fi

download_nvd_feed() {
  local feed="$1" mutable="${2:-0}"
  local nvd_file="$asset_dir/vuln-data/nvd/nvdcve-2.0-$feed.json.gz"
  local nvd_url="https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-$feed.json.gz"
  local meta_file="$cache_dir/nvd-meta/nvdcve-2.0-$feed.meta"
  local cached_pair_valid=0
  if [ -s "$nvd_file" ] && [ -s "$meta_file" ] && verify_nvd_meta "$nvd_file" "$meta_file" >/dev/null 2>&1; then
    cached_pair_valid=1
  fi
  if [ "$mutable" -eq 1 ]; then
    invalidate "$nvd_file"
  fi
  if ! download "$nvd_url" "$nvd_file"; then
    if [ "$mutable" -eq 1 ] && [ "$cached_pair_valid" -eq 1 ]; then
      echo "warning: NVD $feed feed unavailable; reusing the checksum-verified cached feed." >&2
      touch "$cache_dir/.complete/$(basename -- "$nvd_file").done"
      return
    fi
    return 1
  fi
  if [ "$mutable" -eq 1 ] || [ "$refresh" -eq 1 ]; then
    invalidate "$meta_file"
    download "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-$feed.meta" "$meta_file"
    if ! verify_nvd_meta "$nvd_file" "$meta_file"; then
      invalidate "$nvd_file"
      rm -f "$nvd_file"
      download "$nvd_url" "$nvd_file"
      verify_nvd_meta "$nvd_file" "$meta_file" \
        || { echo "error: NVD feed $feed does not match its .meta after re-download." >&2; exit 2; }
    fi
  fi
}

feed_batch=()
for year in $(seq "$nvd_start_year" "$nvd_end_year"); do
  download_nvd_feed "$year" &
  feed_batch+=("$!")
  if [ "${#feed_batch[@]}" -eq 4 ]; then
    for pid in "${feed_batch[@]}"; do wait "$pid"; done
    feed_batch=()
  fi
done
for pid in "${feed_batch[@]}"; do wait "$pid"; done

for feed in recent modified; do
  download_nvd_feed "$feed" 1
done

cisa_file="$asset_dir/vuln-data/known_exploited_vulnerabilities.json"
invalidate "$cisa_file"
download "$cisa_url" "$cisa_file"

if [ "$data_cache_only" -eq 1 ]; then
  echo "$asset_dir/vuln-data"
  exit 0
fi

# The Windows installer already bundles Syft, Grype, and the Grype DB, so its
# data package carries only the feeds that change daily.
if [ "$vuln_data_only" -eq 1 ]; then
  mkdir -p "$vuln_data_dir"
  vuln_data_dir="$(CDPATH= cd -- "$vuln_data_dir" && pwd)"
  python3 - "$asset_dir/vuln-data/versions.txt" "$nvd_start_year" "$nvd_end_year" "$cisa_file" <<'PY'
import datetime
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
kev = json.loads(pathlib.Path(sys.argv[4]).read_text(encoding="utf-8"))
path.write_text(
    "KODA offline vulnerability data (NVD + CISA KEV)\n"
    f"built_at={datetime.datetime.now(datetime.timezone.utc).isoformat()}\n"
    f"nvd_start_year={sys.argv[2]}\n"
    f"nvd_end_year={sys.argv[3]}\n"
    f"cisa_kev_date_released={kev.get('dateReleased', 'unknown')}\n"
    f"cisa_kev_catalog_version={kev.get('catalogVersion', 'unknown')}\n",
    encoding="utf-8",
)
PY
  zip_path="$vuln_data_dir/koda-vuln-data-$(date -u +%Y-%m-%d).zip"
  rm -f "$zip_path"
  # Entries are vuln-data/..., so the zip extracts straight into the install
  # directory that the Windows runtime hook probes.
  (cd "$asset_dir" && python3 -m zipfile -c "$zip_path" vuln-data)
  # Keep it out of the shared cache; a full build writes its own versions.txt
  # and must not inherit this one's build date.
  rm -f "$asset_dir/vuln-data/versions.txt"
  python3 - "$zip_path" <<'PY'
import hashlib
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
digest = hashlib.sha256()
with path.open("rb") as stream:
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
        digest.update(chunk)
print(f"sha256={digest.hexdigest()}", file=sys.stderr)
PY
  echo "$zip_path"
  exit 0
fi

python3 - "$asset_dir/versions.txt" "$syft_version" "$grype_version" "$db_path" "$db_checksum" "$nvd_start_year" "$nvd_end_year" "$cisa_file" <<'PY'
import datetime
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
kev = json.loads(pathlib.Path(sys.argv[8]).read_text(encoding="utf-8"))
path.write_text(
    "KODA offline Linux x86_64 bundle\n"
    f"built_at={datetime.datetime.now(datetime.timezone.utc).isoformat()}\n"
    f"syft={sys.argv[2]}\n"
    f"grype={sys.argv[3]}\n"
    f"grype_db={sys.argv[4]}\n"
    f"grype_db_checksum={sys.argv[5]}\n"
    f"nvd_start_year={sys.argv[6]}\n"
    f"nvd_end_year={sys.argv[7]}\n"
    f"cisa_kev_date_released={kev.get('dateReleased', 'unknown')}\n"
    f"cisa_kev_catalog_version={kev.get('catalogVersion', 'unknown')}\n",
    encoding="utf-8",
)
PY

python3 - "$asset_dir/manifest.sha256" "$asset_dir" <<'PY'
import hashlib
import pathlib
import sys

root = pathlib.Path(sys.argv[2])
manifest = pathlib.Path(sys.argv[1])
lines = []
for path in sorted(root.rglob("*")):
    if not path.is_file() or path == manifest:
        continue
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    lines.append(f"{digest.hexdigest()}  {path.relative_to(root)}")
manifest.write_text("\n".join(lines) + "\n", encoding="utf-8")
PY

offline_asset_rel="${asset_dir#$repo_root/}"
dist_rel="${dist_dir#$repo_root/}"
if [ "$(uname -s)" = "Darwin" ]; then
  command -v docker >/dev/null 2>&1 || { echo "error: Docker is required on macOS to build Linux x86_64 renderer assets." >&2; exit 2; }
  docker run --rm \
    --platform linux/amd64 \
    --user "$(id -u):$(id -g)" \
    -e HOME=/tmp/koda-home \
    -v "$repo_root:/src" \
    -w /src \
    python:3.10-bookworm \
    bash -lc "KODA_LINUX_ARCH=x86_64 KODA_OFFLINE_ASSET_DIR='$offline_asset_rel' KODA_LINUX_DIST_DIR='$dist_rel' bash platforms/linux/package.sh"
else
  KODA_LINUX_ARCH=x86_64 \
  KODA_OFFLINE_ASSET_DIR="$asset_dir" \
  KODA_LINUX_DIST_DIR="$dist_dir" \
  bash "$script_dir/package.sh"
fi
