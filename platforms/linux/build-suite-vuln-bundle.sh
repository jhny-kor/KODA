#!/usr/bin/env bash
# Reuses the verified KODA offline datasets as the Tracker reset seed.
set -euo pipefail

script_dir="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(CDPATH= cd -- "$script_dir/../.." && pwd)"
version="$(awk -F'"' '/^version =/ { print $2; exit }' "$repo_root/platforms/shared/python/pyproject.toml")"
koda_bundle="${KODA_LINUX_BUNDLE:-$repo_root/dist/linux/koda-linux-x86_64-${version:-0.1.0}.tar.gz}"
tracker_repo="${KODA_TRACKER_REPO:-$repo_root/../security-sbom-dependecy}"
output="${1:-}"

usage() {
  cat <<'EOF'
Usage: build-suite-vuln-bundle.sh OUTPUT_DIR

Environment:
  KODA_LINUX_BUNDLE  KODA Linux offline bundle containing Grype/NVD/KEV data
  KODA_TRACKER_REPO  adjacent KODA SBOM Tracker repository
  KODA_EPSS_SNAPSHOT optional approved local FIRST CSV(.gz), overrides bundled file
  KODA_INTELLIGENCE_SNAPSHOT optional approved supplemental index, overrides bundled file
EOF
}

fail() { echo "error: $*" >&2; exit 2; }
[[ -n "$output" ]] || { usage >&2; exit 2; }
[[ -f "$koda_bundle" ]] || fail "KODA Linux bundle not found: $koda_bundle"
[[ -x "$tracker_repo/scripts/build-vuln-bundle.sh" ]] \
  || fail "Tracker vulnerability builder not found: $tracker_repo"
for command_name in python3 tar; do
  command -v "$command_name" >/dev/null 2>&1 || fail "$command_name is required."
done

output_parent="$(mkdir -p "$(dirname -- "$output")" && CDPATH= cd -- "$(dirname -- "$output")" && pwd)"
output="$output_parent/$(basename -- "$output")"
[[ ! -e "$output" ]] || fail "output already exists: $output"
temp="$(mktemp -d "$output_parent/.koda-vuln.XXXXXX")"
cleanup() { rm -rf "$temp"; }
trap cleanup EXIT

python3 - "$koda_bundle" "$temp/selection.txt" <<'PY'
import pathlib
import posixpath
import sys
import tarfile

archive_path, selection_path = map(pathlib.Path, sys.argv[1:])
with tarfile.open(archive_path, "r:gz") as archive:
    names = []
    regular = set()
    for member in archive.getmembers():
        normalized = posixpath.normpath(member.name)
        if member.name.startswith("/") or normalized == ".." or normalized.startswith("../"):
            raise SystemExit(f"unsafe KODA archive path: {member.name}")
        names.append(normalized)
        if member.isfile():
            regular.add(normalized)
roots = {name.split("/", 1)[0] for name in names if name not in {"", "."}}
if len(roots) != 1:
    raise SystemExit(f"KODA archive must have one root: {sorted(roots)}")
root = roots.pop()
grype = sorted(name for name in names if name.startswith(f"{root}/grype-db/incoming/") and name.endswith(".tar.zst"))
feeds = sorted(name for name in names if name.startswith(f"{root}/vuln-data/nvd/") and name.endswith(".json.gz"))
kev = f"{root}/vuln-data/known_exploited_vulnerabilities.json"
versions = f"{root}/versions.txt"
if not grype or not feeds or kev not in names or versions not in names:
    raise SystemExit("KODA bundle is missing Grype, NVD, KEV, or versions metadata")
selection_path.write_text("\n".join([root, versions, grype[-1], kev, *feeds]) + "\n", encoding="utf-8")
extras = [name for name in names if name in {f"{root}/vuln-data/epss.csv.gz", f"{root}/vuln-data/intelligence.json"}
          or name.startswith(f"{root}/vuln-data/intelligence-sources/") and name in regular]
if any(name not in regular for name in [versions, grype[-1], kev, *feeds, *extras]):
    raise SystemExit("selected KODA data must be regular files")
selection_path.with_name("supplemental.txt").write_text("\n".join(extras), encoding="utf-8")
PY

versions_member="$(sed -n '2p' "$temp/selection.txt")"
grype_member="$(sed -n '3p' "$temp/selection.txt")"
kev_member="$(sed -n '4p' "$temp/selection.txt")"
tar -xzf "$koda_bundle" -C "$temp" "$versions_member" "$grype_member" "$kev_member"
while IFS= read -r feed; do
  [[ -n "$feed" ]] || continue
  tar -xzf "$koda_bundle" -C "$temp" "$feed"
done < <(sed -n '5,$p' "$temp/selection.txt")
while IFS= read -r extra || [[ -n "$extra" ]]; do
  [[ -n "$extra" ]] || continue
  tar -xzf "$koda_bundle" -C "$temp" "$extra"
done < "$temp/supplemental.txt"

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
mkdir -p "$temp/grype/$grype_schema"
tar -xf "$grype_archive" -C "$temp/grype/$grype_schema"
data_date="$(basename -- "$grype_member" | sed -E 's/.*_([0-9]{4}-[0-9]{2}-[0-9]{2})T.*/\1/')"
kev_date="$(awk -F= '$1 == "cisa_kev_date_released" { print substr($2, 1, 10); exit }' "$versions")"
[[ "$data_date" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || fail "cannot determine Grype dataset date."
[[ "$kev_date" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || fail "cannot determine KEV dataset date."

args=("$output" --grype-db "$temp/grype" --data-date "$data_date" \
  --nvd-date "$data_date" --kev "$temp/$kev_member" --kev-date "$kev_date")
bundle_root="$(sed -n '1p' "$temp/selection.txt")"
epss_snapshot="${KODA_EPSS_SNAPSHOT:-$temp/$bundle_root/vuln-data/epss.csv.gz}"
intelligence_snapshot="${KODA_INTELLIGENCE_SNAPSHOT:-$temp/$bundle_root/vuln-data/intelligence.json}"
if [[ -n "${KODA_EPSS_SNAPSHOT:-}" || -f "$epss_snapshot" ]]; then
  [[ -f "$epss_snapshot" ]] || fail "EPSS snapshot not found: $epss_snapshot"
  args+=(--epss "$epss_snapshot")
fi
if [[ -n "${KODA_INTELLIGENCE_SNAPSHOT:-}" || -f "$intelligence_snapshot" ]]; then
  [[ -f "$intelligence_snapshot" ]] || fail "supplemental snapshot not found: $intelligence_snapshot"
  args+=(--intelligence-index "$intelligence_snapshot")
fi
while IFS= read -r feed; do
  [[ -n "$feed" ]] && args+=(--nvd-feed "$temp/$feed")
done < <(sed -n '5,$p' "$temp/selection.txt")
"$tracker_repo/scripts/build-vuln-bundle.sh" "${args[@]}"
