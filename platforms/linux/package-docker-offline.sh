#!/usr/bin/env bash
# Builds the single closed-network Docker deliverable:
#   dist/linux/koda-docker-offline-x86_64-<version>.tar.gz
# containing install.sh, koda-docker.sh, README.md, image-ref.txt,
# versions.txt, manifest.sha256, and image/koda-offline-amd64.tar.
set -euo pipefail

# Prevent macOS extended attributes from becoming `._*` AppleDouble entries
# that Linux/Python tar readers treat as extra release roots.
export COPYFILE_DISABLE=1

script_dir="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(CDPATH= cd -- "$script_dir/../.." && pwd)"
dist_dir="${KODA_LINUX_DIST_DIR:-$repo_root/dist/linux}"
python_image="${KODA_PYTHON_IMAGE:-python:3.12-slim-bookworm}"
refresh=0
without_vulnerability_data=0

usage() {
  cat <<'EOF'
Usage: package-docker-offline.sh [--refresh]

--without-vulnerability-data builds tools/applications only; no vulnerability feeds or DB.

Builds the closed-network Docker deliverable on a connected host with
Docker + buildx. Reuses dist/linux/koda-linux-x86_64-<version>.tar.gz,
building it first (package-offline.sh) when missing or with --refresh.

Environment:
  KODA_PYTHON_IMAGE   base image, default python:3.12-slim-bookworm
                      (pinned to its digest at build time)
  KODA_LINUX_DIST_DIR output directory, default dist/linux
  KODA_DOCKER_IMAGE   explicit tagged output image (KODA_IMAGE also accepted)
  KODA_DOCKER_IMAGE_TAG explicit tag override; default version-UTC-git12[-dirty]
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --refresh) refresh=1; shift ;;
    --without-vulnerability-data) without_vulnerability_data=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

fail() { echo "error: $*" >&2; exit 2; }

worktree_dirty=false
if [[ -n "$(git -C "$repo_root" status --porcelain --untracked-files=all 2>/dev/null)" ]]; then
  worktree_dirty=true
fi
if [[ "$worktree_dirty" == true && "${KODA_SUITE_ALLOW_DIRTY:-0}" != 1 ]]; then
  fail "production Docker archives require a clean KODA worktree; set KODA_SUITE_ALLOW_DIRTY=1 for an explicit development snapshot."
fi

# 1. toolchain
command -v docker >/dev/null 2>&1 || fail "docker is required."
docker buildx version >/dev/null 2>&1 || fail "docker buildx is required."
command -v python3 >/dev/null 2>&1 || fail "python3 is required."

# 2-3. version + git revision
version="$(awk -F'"' '/^version =/ { print $2; exit }' "$repo_root/platforms/shared/python/pyproject.toml")"
version="${version:-0.1.0}"
git_sha="$(git -C "$repo_root" rev-parse HEAD 2>/dev/null || echo unknown)"
bundle_name="koda-linux-x86_64-$version"
bundle_tar="$dist_dir/$bundle_name.tar.gz"
package_name="koda-docker-offline-x86_64-$version"

# 4-5. source offline tarball
profile_mismatch=0
if [[ -f "$bundle_tar" ]]; then
  cached_profile="$(tar -xzOf "$bundle_tar" "$bundle_name/versions.txt" 2>/dev/null | sed -n 's/^vulnerability_data=//p' || true)"
  if [[ "$without_vulnerability_data" == 1 && "$cached_profile" != absent ]] || [[ "$without_vulnerability_data" == 0 && "$cached_profile" == absent ]]; then profile_mismatch=1; fi
fi
if [ ! -f "$bundle_tar" ] || [ "$refresh" -eq 1 ] || [ "$profile_mismatch" -eq 1 ]; then
  refresh_flag=()
  [ "$refresh" -eq 1 ] && refresh_flag=(--refresh)
  [ "$without_vulnerability_data" -eq 1 ] && refresh_flag+=(--without-vulnerability-data)
  bash "$script_dir/package-offline.sh" ${refresh_flag[@]+"${refresh_flag[@]}"}
fi
[ -f "$bundle_tar" ] || fail "offline bundle not found: $bundle_tar"

# The cached application must match the source revision used in image labels.
python3 "$script_dir/docker/build_identity.py" verify-source --bundle "$bundle_tar" \
  --root-name "$bundle_name" --source "$repo_root/platforms/shared/python/security_scanner"

# read tool versions/data ranges from the bundle for OCI labels
bundle_versions="$(tar -xzOf "$bundle_tar" "$bundle_name/versions.txt" 2>/dev/null || true)"
bundle_field() {
  printf '%s\n' "$bundle_versions" | awk -F= -v key="$1" '$1 == key { print $2; exit }'
}
syft_version="$(bundle_field syft)"
grype_version="$(bundle_field grype)"
nvd_start="$(bundle_field nvd_start_year)"
nvd_end="$(bundle_field nvd_end_year)"

# pin the base image to a digest
docker pull --platform linux/amd64 "$python_image" >/dev/null
python_image_digest="$(docker image inspect --format '{{index .RepoDigests 0}}' "$python_image")"
[ -n "$python_image_digest" ] || fail "could not resolve a digest for $python_image"
echo "base image: $python_image_digest"

# 6-7. temporary build context: Dockerfile + tarball only
build_context="$(mktemp -d)"
staging_parent="$(mktemp -d)"
cleanup() { rm -rf "$build_context" "$staging_parent"; }
trap cleanup EXIT
cp "$script_dir/docker/Dockerfile" "$build_context/Dockerfile"
cp "$bundle_tar" "$build_context/$bundle_name.tar.gz"

# 8. Assign one UTC identity immediately before the actual build.
IFS=$'\t' read -r image_ref build_tag built_at git_sha worktree_dirty < <(
  python3 "$script_dir/docker/build_identity.py" stamp --repo "$repo_root" --version "$version" \
    --image "${KODA_DOCKER_IMAGE:-${KODA_IMAGE:-}}" --tag "${KODA_DOCKER_IMAGE_TAG:-}"
)
# Build linux/amd64 image (--load so docker save can find it).
docker buildx build \
  --platform linux/amd64 \
  --load \
  --build-arg KODA_BUNDLE="$bundle_name.tar.gz" \
  --build-arg PYTHON_IMAGE="$python_image_digest" \
  --label "org.opencontainers.image.title=KODA offline scanner" \
  --label "org.opencontainers.image.version=$build_tag" \
  --label "org.opencontainers.image.created=$built_at" \
  --label "io.koda.product.version=$version" \
  --label "org.opencontainers.image.revision=$git_sha" \
  --label "io.koda.syft.version=${syft_version:-unknown}" \
  --label "io.koda.grype.version=${grype_version:-unknown}" \
  --label "io.koda.nvd.range=${nvd_start:-unknown}-${nvd_end:-unknown}" \
  --label "io.koda.offline=true" \
  -t "$image_ref" \
  "$build_context"

# 9. offline smoke tests
smoke() {
  docker run --rm \
    --platform linux/amd64 \
    --pull never \
    --network none \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --pids-limit 64 \
    --memory 512m \
    --tmpfs /tmp:rw,noexec,nosuid,size=128m \
    "$@"
}
echo "running offline smoke tests ..."
smoke "$image_ref" list-categories >/dev/null || fail "smoke test failed: list-categories"
smoke --entrypoint /opt/koda/tools/syft "$image_ref" version >/dev/null || fail "smoke test failed: syft version"
# The runtime image deliberately contains no vulnerability database. Approved
# managed data is checked when it is mounted for analysis; packaging checks the
# executable itself without requiring or downloading a database.
smoke --entrypoint /opt/koda/tools/grype "$image_ref" version >/dev/null || fail "smoke test failed: grype version"
echo "smoke tests OK"

# 10-11. save + stage
stage="$staging_parent/$package_name"
mkdir -p "$stage/image" "$dist_dir"
echo "saving image ..."
docker image save --output "$stage/image/koda-offline-amd64.tar" "$image_ref"
install -m 0755 "$script_dir/docker/install.sh" "$stage/install.sh"
install -m 0755 "$script_dir/docker/koda-docker.sh" "$stage/koda-docker.sh"
cp "$script_dir/docker/README.md" "$stage/README.md"
printf '%s\n' "$image_ref" > "$stage/image-ref.txt"
{
  printf '%s\n' "$bundle_versions"
  echo "docker_image=$image_ref"
  echo "docker_image_tag=$build_tag"
  echo "docker_image_built_at=$built_at"
  echo "docker_base_image=$python_image_digest"
  echo "git_revision=$git_sha"
  echo "git_worktree_dirty=$worktree_dirty"
} > "$stage/versions.txt"

# 12. manifest (sha256sum -c compatible)
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

# 13. single deliverable (image tar is compressed only once, here)
deliverable="$dist_dir/$package_name.tar.gz"
tar --no-xattrs -C "$staging_parent" -czf "$deliverable" "$package_name"
echo "$deliverable"
