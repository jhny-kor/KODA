#!/usr/bin/env bash
# Wraps the existing KODA and KODA SBOM Tracker air-gap releases in one
# portable linux/amd64 archive. It does not rebuild either payload.
set -euo pipefail

script_dir="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(CDPATH= cd -- "$script_dir/../.." && pwd)"
dist_dir="${KODA_LINUX_DIST_DIR:-$repo_root/dist/linux}"
version="$(awk -F'"' '/^version =/ { print $2; exit }' "$repo_root/platforms/shared/python/pyproject.toml")"
version="${KODA_SUITE_VERSION:-${version:-0.1.0}}"
koda_bundle="${KODA_DOCKER_BUNDLE:-$dist_dir/koda-docker-offline-x86_64-$version.tar.gz}"
tracker_bundle="${KODA_TRACKER_BUNDLE:-}"
output="${1:-$dist_dir/koda-suite-offline-x86_64-$version.tar.gz}"

usage() {
  cat <<'EOF'
Usage: package-suite-offline.sh [output.tar.gz]

Required environment:
  KODA_TRACKER_BUNDLE  verified KODA SBOM Tracker air-gap tar.gz

Optional environment:
  KODA_DOCKER_BUNDLE   verified KODA Docker air-gap tar.gz
  KODA_LINUX_DIST_DIR  output directory, default dist/linux
  KODA_SUITE_VERSION   suite archive version, default KODA version
  KODA_SUITE_ALLOW_DIRTY=1 explicitly permits a development snapshot build;
                         metadata records both worktrees as dirty
EOF
}

fail() { echo "error: $*" >&2; exit 2; }

case "${1:-}" in
  -h|--help) usage; exit 0 ;;
esac

command -v python3 >/dev/null 2>&1 || fail "python3 is required."
command -v tar >/dev/null 2>&1 || fail "tar is required."
command -v gzip >/dev/null 2>&1 || fail "gzip is required."
case "$version" in
  ''|*[!A-Za-z0-9._-]*) fail "invalid suite version: $version" ;;
esac
[[ -f "$koda_bundle" ]] || fail "KODA bundle not found: $koda_bundle"
[[ -n "$tracker_bundle" && -f "$tracker_bundle" ]] \
  || fail "set KODA_TRACKER_BUNDLE to the verified Tracker tar.gz"

python3 - "$koda_bundle" "$tracker_bundle" <<'PY'
import pathlib
import posixpath
import sys
import tarfile

path = pathlib.Path(sys.argv[1])
required = {"manifest.sha256", "install.sh", "koda-docker.sh", "image-ref.txt"}
with tarfile.open(path, "r:gz") as archive:
    names = []
    for member in archive.getmembers():
        name = member.name
        normalized = posixpath.normpath(name)
        if name.startswith("/") or normalized == ".." or normalized.startswith("../"):
            raise SystemExit(f"unsafe KODA archive path: {name}")
        names.append(normalized)
roots = {name.split("/", 1)[0] for name in names if name not in {"", "."}}
if len(roots) != 1:
    raise SystemExit(f"KODA archive must have one root directory, found: {sorted(roots)}")
root = next(iter(roots))
missing = sorted(item for item in required if f"{root}/{item}" not in names)
if missing:
    raise SystemExit(f"KODA archive is missing: {', '.join(missing)}")

with tarfile.open(sys.argv[2], "r:gz") as archive:
    for member in archive.getmembers():
        name = member.name
        normalized = posixpath.normpath(name)
        if name.startswith("/") or normalized == ".." or normalized.startswith("../"):
            raise SystemExit(f"unsafe Tracker archive path: {name}")
        if pathlib.PurePosixPath(name).name.startswith("._"):
            raise SystemExit(f"Tracker archive contains AppleDouble metadata: {name}")
PY

tracker_repo="${KODA_TRACKER_REPO:-$repo_root/../security-sbom-dependecy}"
tracker_verifier="${KODA_TRACKER_VERIFIER:-$tracker_repo/scripts/verify-airgap-release.sh}"
[[ -x "$tracker_verifier" ]] || fail "Tracker verifier not found; set KODA_TRACKER_VERIFIER"
"$tracker_verifier" "$tracker_bundle"

koda_revision="$(git -C "$repo_root" rev-parse HEAD 2>/dev/null || echo unknown)"
tracker_root="$(CDPATH= cd -- "$(dirname -- "$tracker_verifier")/.." && pwd)"
tracker_revision="$(git -C "$tracker_root" rev-parse HEAD 2>/dev/null || echo unknown)"
koda_dirty=false
tracker_dirty=false
[[ -n "$(git -C "$repo_root" status --porcelain --untracked-files=all 2>/dev/null)" ]] && koda_dirty=true
[[ -n "$(git -C "$tracker_root" status --porcelain --untracked-files=all 2>/dev/null)" ]] && tracker_dirty=true
if [[ "$koda_dirty" == true || "$tracker_dirty" == true ]]; then
  [[ "${KODA_SUITE_ALLOW_DIRTY:-0}" == 1 ]] \
    || fail "production suite archives require clean KODA and Tracker worktrees; set KODA_SUITE_ALLOW_DIRTY=1 for an explicit snapshot."
fi

python3 - "$koda_bundle" "$tracker_bundle" "$koda_revision" "$tracker_revision" "$koda_dirty" "$tracker_dirty" <<'PY'
import pathlib
import posixpath
import sys
import tarfile

koda, tracker, expected_koda, expected_tracker, dirty_koda, dirty_tracker = sys.argv[1:]

def metadata(archive, root=None):
    with tarfile.open(archive, "r:gz") as stream:
        names = [posixpath.normpath(item.name) for item in stream.getmembers()]
        if root is None:
            roots = {name.split("/", 1)[0] for name in names if name not in {"", "."}}
            if len(roots) != 1:
                raise SystemExit(f"archive must have one root: {archive}")
            root = next(iter(roots))
        target = f"{root}/versions.txt" if archive == koda else "metadata.env"
        member = next((item for item in stream.getmembers() if posixpath.normpath(item.name) == target), None)
        if member is None:
            raise SystemExit(f"provenance metadata is missing: {archive}: {target}")
        handle = stream.extractfile(member)
        assert handle is not None
        values = {}
        for line in handle.read().decode("utf-8").splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                values[key] = value
        return values

koda_values = metadata(koda)
tracker_values = metadata(tracker, root="")
if koda_values.get("git_revision") != expected_koda or koda_values.get("git_worktree_dirty") != dirty_koda:
    raise SystemExit("KODA bundle provenance does not match the current worktree")
if tracker_values.get("TRACKER_GIT_REVISION") != expected_tracker or tracker_values.get("TRACKER_WORKTREE_DIRTY") != ("true" if dirty_tracker == "true" else "false"):
    raise SystemExit("Tracker bundle provenance does not match the current worktree")
PY

mkdir -p "$(dirname -- "$output")"
output="$(CDPATH= cd -- "$(dirname -- "$output")" && pwd)/$(basename -- "$output")"
stage_parent="$(mktemp -d "$(dirname -- "$output")/.koda-suite.XXXXXX")"
package_name="koda-suite-offline-x86_64-$version"
stage="$stage_parent/$package_name"
archive_tmp="$output.tmp.$$"
cleanup() { rm -rf "$stage_parent" "$archive_tmp"; }
trap cleanup EXIT

export COPYFILE_DISABLE=1
mkdir -p "$stage/bundles" "$stage/gateway"
cp "$koda_bundle" "$stage/bundles/$(basename -- "$koda_bundle")"
cp "$tracker_bundle" "$stage/bundles/$(basename -- "$tracker_bundle")"
install -m 0755 "$script_dir/suite/koda-suite" "$stage/koda-suite"
install -m 0755 "$script_dir/suite/reset-install.sh" "$stage/reset-install.sh"
sed "s/@SUITE_VERSION@/$version/g" "$script_dir/suite/README.md" > "$stage/README.md"
cp "$script_dir/suite/TROUBLESHOOTING.md" "$stage/TROUBLESHOOTING.md"
cp "$script_dir/suite/compose.integration.yaml" "$stage/compose.integration.yaml"
cp "$script_dir/suite/gateway.conf.template" "$stage/gateway/gateway.conf.template"
cp "$(CDPATH= cd -- "$(dirname -- "$tracker_verifier")/.." && pwd)/.env.example" \
  "$stage/.env.example"
cp "$script_dir/suite/koda-suite.env.example" "$stage/koda-suite.env.example"
python3 - "$stage/.env.example" "$stage/koda-suite.env.example" <<'PY'
import pathlib
import re
import sys

target, overlay = map(pathlib.Path, sys.argv[1:])
assignment = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$")

def read(path):
    values, lines = {}, []
    for line in path.read_text(encoding="utf-8").splitlines():
        match = assignment.match(line)
        if match:
            values[match.group(1)] = match.group(2)
        lines.append(line)
    return values, lines

values, lines = read(target)
suite, _ = read(overlay)
seen = set()
merged = []
for line in lines:
    match = assignment.match(line)
    if match and match.group(1) in suite:
        key = match.group(1)
        if key not in seen:
            merged.append(f"{key}={suite[key]}")
            seen.add(key)
    else:
        merged.append(line)
for key, value in suite.items():
    if key not in values:
        merged.append(f"{key}={value}")
target.write_text("\n".join(merged) + "\n", encoding="utf-8")
PY
cp "$repo_root/LICENSE" "$repo_root/NOTICE" "$stage/"

tracker_vuln_bundle="$(tar -xzOf "$tracker_bundle" ./metadata.env 2>/dev/null | awk -F= '$1 == "VULNERABILITY_BUNDLE" { print $2; exit }')"
[[ "$tracker_vuln_bundle" == included ]] \
  || fail "Tracker release must include fresh vulnerability data for an offline install."

cat > "$stage/metadata.env" <<EOF
SUITE_VERSION=$version
TARGET_PLATFORM=linux/amd64
DISTRIBUTION_SCOPE=internal-only
BUILT_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
KODA_BUNDLE=bundles/$(basename -- "$koda_bundle")
TRACKER_BUNDLE=bundles/$(basename -- "$tracker_bundle")
KODA_GIT_REVISION=$koda_revision
KODA_TRACKED_WORKTREE_DIRTY=$koda_dirty
KODA_WORKTREE_DIRTY=$koda_dirty
TRACKER_GIT_REVISION=$tracker_revision
TRACKER_WORKTREE_DIRTY=$tracker_dirty
TRACKER_GIT_WORKTREE_DIRTY=$tracker_dirty
TRACKER_VULNERABILITY_BUNDLE=$tracker_vuln_bundle
AUTHORITY=tracker
AUTH_CONTRACT_VERSION=1
AUTH_COOKIE_NAME=__Host-koda_session
AUTH_COOKIE_SCHEMA_VERSION=2
TRACKER_SESSION_ENDPOINT=/api/v1/auth/session
KODA_BASE_PATH=/koda/
GATEWAY_AUTH_MODE=auth_request
KODA_PORTAL_SCHEMA_VERSION=1
KODA_RBAC_CATALOG_VERSION=koda-rbac-v1
EOF

python3 - "$stage" <<'PY'
import hashlib
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
manifest = root / "manifest.sha256"
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

tar --no-xattrs -C "$stage_parent" -cf - "$package_name" | gzip -1 > "$archive_tmp"
mv "$archive_tmp" "$output"
python3 - "$output" <<'PY'
import hashlib
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
digest = hashlib.sha256()
with path.open("rb") as stream:
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
        digest.update(chunk)
path.with_name(path.name + ".sha256").write_text(
    f"{digest.hexdigest()}  {path.name}\n", encoding="utf-8"
)
print(path)
print(path.with_name(path.name + ".sha256"))
PY
