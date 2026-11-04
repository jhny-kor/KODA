#!/usr/bin/env bash
# KODA closed-network Docker bundle installer. Verifies the bundle, loads
# the image, smoke-tests it offline, and copies the wrapper to the install
# prefix. Touches nothing outside the prefix: no /usr/local/bin, /etc,
# systemd, firewall, docker daemon config, or global PATH changes.
set -euo pipefail

script_dir="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
prefix="${KODA_DOCKER_PREFIX:-/home/user0/projects/koda}"

usage() {
  cat <<'EOF'
Usage: install.sh [--prefix DIR]

Environment:
  KODA_DOCKER_PREFIX  install root, default /home/user0/projects/koda
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --prefix) prefix="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

fail() { echo "error: $*" >&2; exit 2; }

# 1. bundle integrity
[ -f "$script_dir/manifest.sha256" ] || fail "manifest.sha256 is missing."
(cd "$script_dir" && sha256sum --check --quiet manifest.sha256) \
  || fail "bundle checksum verification failed."
echo "bundle integrity OK"

# 2. host architecture
arch="$(uname -m)"
case "$arch" in
  x86_64|amd64) ;;
  *) fail "this bundle is linux/amd64 only; host is $arch." ;;
esac

# 3-4. docker CLI and daemon
command -v docker >/dev/null 2>&1 || fail "docker CLI not found."
docker info >/dev/null 2>&1 || fail "cannot reach the Docker daemon (check permissions/group)."

image_tar="$script_dir/image/koda-offline-amd64.tar"
[ -f "$image_tar" ] || fail "image tar is missing: $image_tar"
IFS= read -r image_ref < "$script_dir/image-ref.txt" || fail "image-ref.txt is missing."

# 5. disk headroom in the docker data root (image tar size x2)
docker_root="$(docker info --format '{{.DockerRootDir}}' 2>/dev/null || echo /var/lib/docker)"
tar_kb="$(du -k "$image_tar" | awk '{print $1}')"
free_kb="$(df -Pk "$docker_root" 2>/dev/null | awk 'NR==2 {print $4}')"
if [ -n "$free_kb" ] && [ "$free_kb" -lt "$((tar_kb * 2))" ]; then
  fail "not enough free space in $docker_root: need ~$((tar_kb * 2 / 1024)) MiB, have $((free_kb / 1024)) MiB."
fi

# 6. load (idempotent: re-loading the same image is a no-op)
echo "loading $image_ref ..."
docker load --input "$image_tar"
docker image inspect "$image_ref" >/dev/null 2>&1 || fail "image $image_ref not present after docker load."

# 7. architecture check
img_arch="$(docker image inspect --format '{{.Architecture}}' "$image_ref")"
[ "$img_arch" = "amd64" ] || fail "image architecture is $img_arch, expected amd64."

# 8. OCI labels
img_version="$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.version"}}' "$image_ref")"
offline_label="$(docker image inspect --format '{{index .Config.Labels "io.koda.offline"}}' "$image_ref")"
[ "$offline_label" = "true" ] || fail "image is missing the io.koda.offline=true label."
echo "image version: ${img_version:-unknown}"

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
    --cpus 0.5 \
    --tmpfs /tmp:rw,noexec,nosuid,size=128m \
    "$@"
}
echo "running offline smoke tests ..."
smoke "$image_ref" list-categories >/dev/null \
  || fail "smoke test failed: list-categories"
smoke --entrypoint /opt/koda/tools/syft "$image_ref" version >/dev/null \
  || fail "smoke test failed: syft version"
# Approved managed data is mounted separately at runtime. This image has no
# embedded database, so installation checks the executable without DB access.
smoke --entrypoint /opt/koda/tools/grype "$image_ref" version >/dev/null \
  || fail "smoke test failed: grype version"
echo "smoke tests OK"

# 10. install wrapper + references (idempotent; keeps existing reports and
# any running dashboard untouched)
mkdir -p "$prefix"
install -m 0755 "$script_dir/koda-docker.sh" "$prefix/koda-docker"
for meta in image-ref.txt versions.txt README.md; do
  [ -f "$script_dir/$meta" ] && cp "$script_dir/$meta" "$prefix/$meta"
done

echo "installed: $prefix/koda-docker (image $image_ref)"
echo "run: $prefix/koda-docker list-categories"
