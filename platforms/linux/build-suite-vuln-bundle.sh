#!/usr/bin/env bash
# Reuses verified KODA datasets and signs the Tracker first-install seed.
set -euo pipefail

script_dir="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(CDPATH= cd -- "$script_dir/../.." && pwd)"
version="$(awk -F'"' '/^version =/ { print $2; exit }' "$repo_root/platforms/shared/python/pyproject.toml")"
koda_bundle="${KODA_LINUX_BUNDLE:-$repo_root/dist/linux/koda-linux-x86_64-${version:-0.1.0}.tar.gz}"
tracker_repo="${KODA_TRACKER_REPO:-$repo_root/../security-sbom-dependecy}"
output="${1:-}"
signing_key="${KODA_DATA_UPDATE_SIGNING_KEY:-}"

usage() {
  cat <<'EOF'
Usage: build-suite-vuln-bundle.sh OUTPUT_DIR

Environment:
  KODA_LINUX_BUNDLE  KODA Linux offline bundle containing Grype/NVD/KEV data
  KODA_TRACKER_REPO  adjacent KODA SBOM Tracker repository
  KODA_DATA_UPDATE_SIGNING_KEY external private data-signing key, never included
  KODA_GRYPE_IMPORT_IMAGE optional Grype importer image, default Tracker's pinned KODA_GRYPE_IMAGE
  KODA_EPSS_SNAPSHOT approved FIRST CSV(.gz), required unless already bundled
  KODA_INTELLIGENCE_SNAPSHOT optional approved supplemental index, overrides bundled file
EOF
}

fail() { echo "error: $*" >&2; exit 2; }
[[ -n "$output" ]] || { usage >&2; exit 2; }
[[ -f "$koda_bundle" ]] || fail "KODA Linux bundle not found: $koda_bundle"
[[ -x "$tracker_repo/scripts/build-vuln-bundle.sh" ]] \
  || fail "Tracker vulnerability builder not found: $tracker_repo"
[[ -f "$tracker_repo/scripts/collect-unified-data.py" ]] \
  || fail "Tracker signed unified collector not found: $tracker_repo"
[[ -n "$signing_key" && -f "$signing_key" && -r "$signing_key" ]] \
  || fail "set KODA_DATA_UPDATE_SIGNING_KEY to an external private data-signing key"
for command_name in python3 docker; do
  command -v "$command_name" >/dev/null 2>&1 || fail "$command_name is required."
done

output_parent="$(mkdir -p "$(dirname -- "$output")" && CDPATH= cd -- "$(dirname -- "$output")" && pwd)"
output="$output_parent/$(basename -- "$output")"
[[ ! -e "$output" ]] || fail "output already exists: $output"
python3 - "$signing_key" "$output" "${KODA_EPSS_SNAPSHOT:-}" "${KODA_INTELLIGENCE_SNAPSHOT:-}" <<'PY_KEY'
from pathlib import Path
import sys
key, output = Path(sys.argv[1]).resolve(strict=True), Path(sys.argv[2]).resolve()
sources = [Path(value).resolve(strict=True).parent for value in sys.argv[3:] if value]
if key == output or output in key.parents or any(key == source or source in key.parents for source in sources):
    raise SystemExit('private data-signing key must be outside output and collected source directories')
PY_KEY
temp="$(mktemp -d "$output_parent/.koda-vuln.XXXXXX")"
cleanup() { rm -rf "$temp"; }
trap cleanup EXIT

python3 - "$koda_bundle" "$temp/selection.txt" <<'PY'
import pathlib
import posixpath
import shutil
import sys
import tarfile

archive_path, selection_path = map(pathlib.Path, sys.argv[1:])
with tarfile.open(archive_path, "r:gz") as archive:
    names = []
    regular = set()
    members = {}
    version_documents = {}
    for member in archive:
        normalized = posixpath.normpath(member.name)
        if member.name.startswith("/") or ".." in pathlib.PurePosixPath(member.name).parts or "\n" in member.name or "\r" in member.name:
            raise SystemExit(f"unsafe KODA archive path: {member.name}")
        if normalized in members:
            raise SystemExit(f"duplicate KODA archive path: {normalized}")
        names.append(normalized)
        members[normalized] = member
        if member.isfile():
            regular.add(normalized)
            if normalized.count('/') == 1 and normalized.endswith('/versions.txt'):
                if member.size > 65536:
                    raise SystemExit('KODA versions metadata exceeds limit')
                version_documents[normalized] = archive.extractfile(member).read()
roots = {name.split("/", 1)[0] for name in names if name not in {"", "."}}
if len(roots) != 1:
    raise SystemExit(f"KODA archive must have one root: {sorted(roots)}")
root = roots.pop()
feeds = sorted(name for name in names if name.startswith(f"{root}/vuln-data/nvd/") and name.endswith(".json.gz"))
kev = f"{root}/vuln-data/known_exploited_vulnerabilities.json"
versions = f"{root}/versions.txt"
if not feeds or kev not in names or versions not in version_documents:
    raise SystemExit("KODA bundle is missing Grype, NVD, KEV, or versions metadata")
values = dict(line.split('=', 1) for line in version_documents[versions].decode().splitlines() if '=' in line)
grype_filename = values.get('grype_db', '')
if not grype_filename or pathlib.PurePosixPath(grype_filename).name != grype_filename:
    raise SystemExit('KODA versions metadata must identify the exact Grype DB archive')
grype = f'{root}/grype-db/incoming/{grype_filename}'
selection_path.write_text("\n".join([root, versions, grype, kev, *feeds]) + "\n", encoding="utf-8")
extras = [name for name in names if name in {f"{root}/vuln-data/epss.csv.gz", f"{root}/vuln-data/intelligence.json"}
          or name.startswith(f"{root}/vuln-data/intelligence-sources/") and name in regular]
if any(name not in regular for name in [versions, grype, kev, *feeds, *extras]):
    raise SystemExit("selected KODA data must be regular files")
selection_path.with_name("supplemental.txt").write_text("\n".join(extras), encoding="utf-8")

# Extract only the validated regular files in archive order. One forward pass
# replaces a separate full gzip decompression for every yearly NVD feed.
selected = [versions, grype, kev, *feeds, *extras]
with tarfile.open(archive_path, "r:gz") as archive:
    for name in sorted(selected, key=lambda item: members[item].offset_data):
        target = selection_path.parent / name
        target.parent.mkdir(parents=True, exist_ok=True)
        source = archive.extractfile(members[name])
        if source is None:
            raise SystemExit(f"selected KODA data is unavailable: {name}")
        with target.open("xb") as destination:
            shutil.copyfileobj(source, destination)
PY

versions_member="$(sed -n '2p' "$temp/selection.txt")"
grype_member="$(sed -n '3p' "$temp/selection.txt")"
kev_member="$(sed -n '4p' "$temp/selection.txt")"
versions="$temp/$versions_member"
grype_archive="$temp/$grype_member"
expected="$(awk -F= '$1 == "grype_db_checksum" { sub(/^sha256:/, "", $2); print $2; exit }' "$versions")"
[[ -n "$expected" ]] || fail "KODA versions metadata has no Grype checksum."
if command -v sha256sum >/dev/null 2>&1; then
  actual="$(sha256sum "$grype_archive" | awk '{print $1}')"
else
  actual="$(shasum -a 256 "$grype_archive" | awk '{print $1}')"
fi
[[ "$actual" == "$expected" ]] || fail "KODA Grype DB checksum mismatch."

grype_schema="$(basename -- "$grype_member" | sed -E 's/^vulnerability-db_v([0-9]+)\..*/\1/')"
[[ "$grype_schema" =~ ^[0-9]+$ ]] || fail "cannot determine Grype DB schema."
mkdir -p "$temp/grype"
import_image="${KODA_GRYPE_IMPORT_IMAGE:-$(awk -F= '/^ARG KODA_GRYPE_IMAGE=/ {print substr($0, index($0, "=") + 1); exit}' "$tracker_repo/apps/api/Dockerfile")}"
[[ -n "$import_image" ]] || fail "set KODA_GRYPE_IMPORT_IMAGE to the approved Grype importer image"
docker run --rm --platform linux/amd64 --user "$(id -u):$(id -g)" \
  --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,size=128m --entrypoint /grype \
  --mount "type=bind,source=$grype_archive,target=/database.tar.zst,readonly" \
  --mount "type=bind,source=$temp/grype,target=/grype-cache" \
  -e HOME=/tmp -e GRYPE_DB_CACHE_DIR=/grype-cache -e GRYPE_DB_AUTO_UPDATE=false \
  -e GRYPE_DB_VALIDATE_AGE=false -e GRYPE_CHECK_FOR_APP_UPDATE=false \
  -e GRYPE_EXTERNAL_SOURCES_ENABLE=false \
  "$import_image" db import /database.tar.zst
[[ -f "$temp/grype/$grype_schema/vulnerability.db" && -f "$temp/grype/$grype_schema/import.json" ]] \
  || fail "Grype import did not produce the schema database and its original import metadata"
data_date="$(basename -- "$grype_member" | sed -E 's/.*_([0-9]{4}-[0-9]{2}-[0-9]{2})T.*/\1/')"
kev_date="$(awk -F= '$1 == "cisa_kev_date_released" { print substr($2, 1, 10); exit }' "$versions")"
[[ "$data_date" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || fail "cannot determine Grype dataset date."
[[ "$kev_date" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || fail "cannot determine KEV dataset date."

raw_seed="$temp/raw-seed"
args=("$raw_seed" --grype-db "$temp/grype" --data-date "$data_date" \
  --nvd-date "$data_date" --kev "$temp/$kev_member" --kev-date "$kev_date")
bundle_root="$(sed -n '1p' "$temp/selection.txt")"
epss_snapshot="${KODA_EPSS_SNAPSHOT:-$temp/$bundle_root/vuln-data/epss.csv.gz}"
intelligence_snapshot="${KODA_INTELLIGENCE_SNAPSHOT:-$temp/$bundle_root/vuln-data/intelligence.json}"
[[ -f "$epss_snapshot" ]] || fail "an approved KODA_EPSS_SNAPSHOT or bundled EPSS snapshot is required"
args+=(--epss "$epss_snapshot")
if [[ -n "${KODA_INTELLIGENCE_SNAPSHOT:-}" || -f "$intelligence_snapshot" ]]; then
  [[ -f "$intelligence_snapshot" ]] || fail "supplemental snapshot not found: $intelligence_snapshot"
  args+=(--intelligence-index "$intelligence_snapshot")
fi
while IFS= read -r feed; do
  [[ -n "$feed" ]] && args+=(--nvd-feed "$temp/$feed")
done < <(sed -n '5,$p' "$temp/selection.txt")
"$tracker_repo/scripts/build-vuln-bundle.sh" "${args[@]}"
# These are private copies already represented by the verified raw seed. Drop
# them before the collector stages its own large imported database copies.
rm -rf "$temp/grype" "$temp/$bundle_root"

python3 - "$raw_seed" "$temp/unified-source" "$signing_key" <<'PY_SOURCE'
from pathlib import Path
import os
import sys
raw, source, key = map(lambda value: Path(value).resolve(), sys.argv[1:])
if raw in key.parents or source in key.parents:
    raise SystemExit('private data-signing key must be outside collected sources')
for path in raw.rglob('*'):
    if path.is_symlink():
        raise SystemExit('seed source symlinks are not allowed')
    if not path.is_file() or (path.parent == raw and path.name in {'metadata.env', 'manifest.sha256'}):
        continue
    relative = path.relative_to(raw)
    target = source / relative if relative.parts[0] == 'grype-db' else source / 'vuln-data' / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    os.link(path, target)
PY_SOURCE

seed_version="$(awk -F= '$1 == "BUNDLE_VERSION" {print $2; exit}' "$raw_seed/metadata.env")"
python3 "$tracker_repo/scripts/collect-unified-data.py" \
  --source "$temp/unified-source" --output "$raw_seed/unified-update.tar.gz" \
  --signing-key "$signing_key" --version "$seed_version" \
  --data-date "$data_date" --grype-date "$data_date"

publisher="$temp/publisher-seed"
mkdir "$publisher"
python3 - "$raw_seed" "$publisher" <<'PY_MANIFEST'
from pathlib import Path
import hashlib
import sys
import tarfile
raw, root = map(Path, sys.argv[1:])
metadata = dict(line.split('=', 1) for line in (raw / 'metadata.env').read_text().splitlines() if '=' in line)
with tarfile.open(raw / 'unified-update.tar.gz', 'r|gz') as archive:
    for member in archive:
        if member.name == 'metadata.env' and member.isfile():
            incoming = archive.extractfile(member)
            metadata.update(line.split('=', 1) for line in incoming.read().decode().splitlines() if '=' in line)
            break
    else:
        raise SystemExit('signed bootstrap source metadata is missing')
metadata['UNIFIED_BOOTSTRAP_FILE'] = 'unified-update.tar.gz'
(root / 'metadata.env').write_text(''.join(f'{key}={value}\n' for key, value in sorted(metadata.items())))
(raw / 'unified-update.tar.gz').rename(root / 'unified-update.tar.gz')
lines = []
for path in sorted(root.rglob('*')):
    if path.is_file() and path != root / 'manifest.sha256':
        checksum = hashlib.sha256()
        with path.open('rb') as incoming:
            for chunk in iter(lambda: incoming.read(1024 * 1024), b''):
                checksum.update(chunk)
        lines.append(f'{checksum.hexdigest()}  {path.relative_to(root).as_posix()}\n')
(root / 'manifest.sha256').write_text(''.join(lines))
PY_MANIFEST
"$tracker_repo/scripts/verify-vuln-bundle.sh" "$publisher"
mv "$publisher" "$output"
echo "Created signed first-install vulnerability seed: $output"
