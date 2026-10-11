#!/usr/bin/env bash
# Destructive, KODA-scoped reset followed by a verified offline install.
set -euo pipefail

script_dir="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
default_prefix="${KODA_SUITE_PREFIX:-${HOME:-$PWD}/koda-suite}"
prefix="$default_prefix"
merged_env=""

usage() {
  cat <<'EOF'
Usage: reset-install.sh --delete-all-koda-data [--prefix DIR]

Place .env and koda-suite.env beside this script first. The command permanently
deletes only the validated KODA Suite install, containers, networks, and named
volumes, then installs this verified release. No backup or rollback is made.
EOF
}

fail() { echo "error: $*" >&2; exit 2; }

cleanup() {
  [[ -z "$merged_env" || ! -f "$merged_env" ]] || rm -f "$merged_env"
}
trap cleanup EXIT

[[ "${1:-}" == --delete-all-koda-data ]] || { usage >&2; exit 2; }
shift
while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix) prefix="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) fail "unknown option: $1" ;;
  esac
done

for command_name in python3 docker flock realpath; do
  command -v "$command_name" >/dev/null 2>&1 || fail "$command_name is required."
done
docker info >/dev/null 2>&1 || fail "cannot reach the Docker daemon."
docker compose version >/dev/null 2>&1 || fail "the Docker Compose plugin is required."
[[ -f "$script_dir/.env" ]] || fail "copy the existing .env to $script_dir/.env first."
[[ -f "$script_dir/koda-suite.env" ]] \
  || fail "copy the existing koda-suite.env to $script_dir/koda-suite.env first."
chmod 600 "$script_dir/.env" "$script_dir/koda-suite.env"

prefix="$(python3 - "$prefix" <<'PY'
import os
import sys
print(os.path.realpath(sys.argv[1]))
PY
)"
case "$prefix" in
  /|/home|/root|"${HOME:-}"|"$script_dir") fail "unsafe install prefix: $prefix" ;;
esac
[[ "$prefix" != "$script_dir"/* && "$script_dir" != "$prefix"/* ]] \
  || fail "install prefix and extracted release directory must be separate."
if [[ -e "$prefix" ]]; then
  [[ -f "$prefix/metadata.env" && -f "$prefix/tracker/compose.yaml" \
      && -x "$prefix/koda/koda-docker" ]] \
    || fail "refusing to delete a directory that is not a validated KODA Suite install: $prefix"
fi

merged_env="$(mktemp "${TMPDIR:-/tmp}/koda-suite-env.XXXXXX")"
chmod 600 "$merged_env"
python3 - "$script_dir/.env" "$script_dir/koda-suite.env" "$merged_env" <<'PY'
import pathlib
import re
import sys

base_path, suite_path, output_path = map(pathlib.Path, sys.argv[1:])
assignment = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)=(.*)$")
allowed_suite_keys = {
    "PUBLIC_HTTP_PORT", "GATEWAY_SERVER_NAME", "TRACKER_SECURE_COOKIES",
    "KODA_BASE_PATH", "KODA_DASHBOARD_BIND", "KODA_PORT",
    "KODA_PUBLISH_DASHBOARD", "KODA_DASHBOARD_NETWORK",
    "KODA_PORTAL_UPSTREAM", "TRACKER_SESSION_UPSTREAM",
    "TRACKER_ENVIRONMENT", "TRACKER_PUBLIC_ORIGIN", "GATEWAY_PUBLIC_SCHEME",
    "DTRACK_API_BASE_URL", "DTRACK_ADMIN_API_BASE_URL", "DTRACK_BASE_PATH",
    "TRACKER_DEPENDENCY_TRACK_UI_URL", "APP_NETWORK_SUBNET", "GATEWAY_APP_IP",
    "TRACKER_TRUSTED_PROXY_CIDRS", "KODA_SSBOM_TRACKER_URL", "KODA_GITLAB_URL",
    "KODA_GITLAB_TOKEN_FILE", "KODA_GITLAB_WRITE_TOKEN_FILE", "KODA_GITLAB_CA_FILE", "KODA_GITLAB_NETWORK",
    "KODA_TRACKER_URL", "KODA_TRACKER_TOKEN_DIR", "KODA_TRACKER_CA_FILE", "KODA_CPUS",
    "KODA_MEMORY", "KODA_PIDS_LIMIT", "KODA_TMPFS_SIZE",
    "KODA_SCAN_CPUS", "KODA_SCAN_MEMORY", "KODA_DELIVERY_CPUS", "KODA_DELIVERY_MEMORY",
    "KODA_SCAN_TIMEOUT_SECONDS", "KODA_SCAN_TERMINATE_GRACE_SECONDS",
    "KODA_WORKER_STOP_TIMEOUT_SECONDS", "KODA_JSON_MAX_BYTES", "KODA_PORTAL_UPLOAD_QUOTA_BYTES",
    "KODA_PORTAL_REPORT_TIMEOUT_SECONDS", "KODA_PORTAL_REPORT_MEMORY_BYTES",
    "KODA_SCHEDULE_ENABLED", "KODA_SCHEDULE_SSH_DIR", "KODA_SCHEDULE_STATE_DIR",
    "KODA_SCHEDULE_CPUS", "KODA_SCHEDULE_MEMORY", "KODA_SCHEDULE_RATE_BYTES",
    "KODA_SCHEDULE_GAP_SECONDS", "KODA_SCHEDULE_DISK_RESERVE_BYTES", "KODA_SCHEDULE_MIN_FREE_BYTES",
}

def read_env(path):
    values = {}
    order = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = assignment.match(line)
        if not match:
            raise SystemExit(f"{path.name}:{number}: expected KEY=VALUE")
        key, value = match.groups()
        if key in values:
            raise SystemExit(f"{path.name}:{number}: duplicate key: {key}")
        if "$(" in value or "`" in value:
            raise SystemExit(f"{path.name}:{number}: command substitution is not allowed")
        values[key] = value
        order.append(key)
    return values, order

base, order = read_env(base_path)
suite, suite_order = read_env(suite_path)
for key in suite_order:
    if key not in allowed_suite_keys:
        if key in base and suite[key] == base[key]:
            continue  # Accept unchanged keys from the previous combined env format.
        if key.endswith("_IMAGE") and key in base and suite[key].split("@", 1)[0] == base[key].split("@", 1)[0]:
            continue  # The old installer removes registry digests after verified docker load.
        raise SystemExit(f"koda-suite.env may not override {key}; keep it in .env")
    if key not in base:
        order.append(key)
    base[key] = suite[key]

if not re.fullmatch(r"koda-sbom(?:[-_][a-z0-9][a-z0-9_-]*)?", base.get("COMPOSE_PROJECT_NAME", "")):
    raise SystemExit("COMPOSE_PROJECT_NAME must be koda-sbom or a koda-sbom-* name")

output_path.write_text("".join(f"{key}={base[key]}\n" for key in order), encoding="utf-8")
PY

env_value() {
  local file="$1" key="$2" fallback="$3" value
  value="$(awk -F= -v key="$key" '$1 == key { sub(/^[^=]*=/, ""); value=$0 } END { print value }' "$file")"
  value="${value#${value%%[![:space:]]*}}"
  value="${value%${value##*[![:space:]]}}"
  if [[ "$value" == \"*\" && "$value" == *\" ]]; then value="${value:1:${#value}-2}"; fi
  if [[ "$value" == \'*\' && "$value" == *\' ]]; then value="${value:1:${#value}-2}"; fi
  printf '%s\n' "${value:-$fallback}"
}

project="$(env_value "$merged_env" COMPOSE_PROJECT_NAME koda-sbom)"
exec 9>"${TMPDIR:-/tmp}/koda-suite-reset-${project}.lock"
flock -n 9 || fail "another reset is already running for $project."

# Verify both payloads, Compose wiring, secrets, and vulnerability data before
# the first destructive operation.
"$script_dir/koda-suite" preflight --env-file "$merged_env" \
  --prefix "$prefix" --require-vulnerability-data

old_env="$merged_env"
[[ -f "$prefix/tracker/.env" ]] && old_env="$prefix/tracker/.env"
old_project="$(env_value "$old_env" COMPOSE_PROJECT_NAME koda-sbom)"
[[ "$old_project" == "$project" ]] \
  || fail "existing and new COMPOSE_PROJECT_NAME differ: $old_project != $project"

volume_specs=(
  "POSTGRES_DATA_VOLUME_NAME:koda-sbom-postgres-data"
  "DTRACK_DATA_VOLUME_NAME:koda-sbom-dtrack-data"
  "TRACKER_ARTIFACTS_VOLUME_NAME:koda-sbom-tracker-artifacts"
  "VULN_DATA_VOLUME_NAME:koda-sbom-vuln-data"
  "BACKUP_VOLUME_NAME:koda-sbom-backups"
)
volumes=()
for spec in "${volume_specs[@]}"; do
  key="${spec%%:*}"
  fallback="${spec#*:}"
  volume="$(env_value "$old_env" "$key" "$fallback")"
  [[ "$volume" =~ ^koda-sbom[-_][a-z0-9][a-z0-9_.-]*$ ]] \
    || fail "unsafe KODA volume name in $key: $volume"
  volumes+=("$volume")
done

compose_services=(gateway portal-web portal-api portal-worker postgres dtrack-apiserver dtrack-frontend)
for service in "${compose_services[@]}"; do
  container="${project}-${service}"
  docker container inspect "$container" >/dev/null 2>&1 || continue
  owner="$(docker inspect -f '{{index .Config.Labels "com.docker.compose.project"}}' "$container")"
  [[ "$owner" == "$project" ]] || fail "refusing to delete foreign container: $container"
done
koda_containers=(koda-scan-worker koda-delivery-worker koda-schedule-worker koda-dashboard)
for container in "${koda_containers[@]}"; do
  docker container inspect "$container" >/dev/null 2>&1 || continue
  koda_label="$(docker inspect -f '{{index .Config.Labels "io.koda.offline"}}' "$container")"
  [[ "$koda_label" == true ]] || fail "refusing to delete foreign container named $container"
done
for network in "${project}-edge" "${project}-app"; do
  docker network inspect "$network" >/dev/null 2>&1 || continue
  owner="$(docker network inspect -f '{{index .Labels "com.docker.compose.project"}}' "$network")"
  [[ "$owner" == "$project" ]] || fail "refusing to delete foreign network: $network"
done
for network in koda-dashboard koda-dashboard-schedule; do
  docker network inspect "$network" >/dev/null 2>&1 || continue
  attached="$(docker network inspect -f '{{range .Containers}}{{.Name}} {{end}}' "$network")"
  for container in $attached; do
    if [[ "$network" == koda-dashboard-schedule ]]; then
      [[ "$container" == koda-schedule-worker ]] \
        || fail "refusing to delete $network network; foreign container attached: $container"
    else
      [[ "$container" == koda-dashboard || "$container" == koda-delivery-worker \
          || "$container" == koda-schedule-worker || "$container" == "${project}-gateway" ]] \
        || fail "refusing to delete koda-dashboard network; foreign container attached: $container"
    fi
  done
done
for volume in "${volumes[@]}"; do
  docker volume inspect "$volume" >/dev/null 2>&1 || continue
  owner="$(docker volume inspect -f '{{index .Labels "com.docker.compose.project"}}' "$volume")"
  [[ "$owner" == "$project" ]] || fail "refusing to delete foreign volume: $volume"
done

echo "WARNING: no backup will be created. Deleting KODA Suite project '$project' and prefix '$prefix'."

if [[ -f "$prefix/tracker/compose.yaml" && -f "$prefix/tracker/compose.airgap.yaml" \
    && -f "$prefix/tracker/compose.integration.yaml" ]]; then
  docker compose --project-directory "$prefix/tracker" --env-file "$old_env" \
    -f "$prefix/tracker/compose.yaml" -f "$prefix/tracker/compose.airgap.yaml" \
    -f "$prefix/tracker/compose.integration.yaml" down --volumes --remove-orphans
fi

for service in "${compose_services[@]}"; do
  container="${project}-${service}"
  docker container inspect "$container" >/dev/null 2>&1 || continue
  owner="$(docker inspect -f '{{index .Config.Labels "com.docker.compose.project"}}' "$container")"
  [[ "$owner" == "$project" ]] || fail "refusing to delete foreign container: $container"
  docker rm -f "$container" >/dev/null
done

for container in "${koda_containers[@]}"; do
  docker container inspect "$container" >/dev/null 2>&1 || continue
  koda_label="$(docker inspect -f '{{index .Config.Labels "io.koda.offline"}}' "$container")"
  [[ "$koda_label" == true ]] || fail "refusing to delete foreign container named $container"
  docker stop --time "$(env_value "$old_env" KODA_WORKER_STOP_TIMEOUT_SECONDS 20)" "$container" >/dev/null
  docker rm "$container" >/dev/null
done

for network in "${project}-edge" "${project}-app"; do
  docker network inspect "$network" >/dev/null 2>&1 || continue
  owner="$(docker network inspect -f '{{index .Labels "com.docker.compose.project"}}' "$network")"
  [[ "$owner" == "$project" ]] || fail "refusing to delete foreign network: $network"
  docker network rm "$network" >/dev/null
done
for network in koda-dashboard koda-dashboard-schedule; do
  docker network inspect "$network" >/dev/null 2>&1 || continue
  attached="$(docker network inspect -f '{{range .Containers}}{{.Name}} {{end}}' "$network")"
  [[ -z "${attached//[[:space:]]/}" ]] \
    || fail "refusing to delete $network network; attached containers: $attached"
  docker network rm "$network" >/dev/null
done

for volume in "${volumes[@]}"; do
  docker volume inspect "$volume" >/dev/null 2>&1 || continue
  owner="$(docker volume inspect -f '{{index .Labels "com.docker.compose.project"}}' "$volume")"
  [[ "$owner" == "$project" ]] || fail "refusing to delete foreign volume: $volume"
  docker volume rm "$volume" >/dev/null
done

[[ ! -e "$prefix" ]] || rm -rf -- "$prefix"
"$script_dir/koda-suite" install --env-file "$merged_env" --prefix "$prefix"
install -m 0600 "$script_dir/.env" "$prefix/.env"
install -m 0600 "$script_dir/koda-suite.env" "$prefix/koda-suite.env"

subnet="$(env_value "$merged_env" APP_NETWORK_SUBNET 172.30.80.0/24)"
gateway_ip="$(env_value "$merged_env" GATEWAY_APP_IP 172.30.80.10)"
network="${project}-app"
actual_subnet="$(docker network inspect -f '{{range .IPAM.Config}}{{.Subnet}}{{end}}' "$network")"
actual_gateway_ip="$(docker inspect -f "{{with index .NetworkSettings.Networks \"$network\"}}{{.IPAddress}}{{end}}" "${project}-gateway")"
[[ "$actual_subnet" == "$subnet" ]] \
  || fail "app network subnet mismatch: expected $subnet, got $actual_subnet"
[[ "$actual_gateway_ip" == "$gateway_ip" ]] \
  || fail "gateway IP mismatch: expected $gateway_ip, got $actual_gateway_ip"
"$prefix/koda-suite" status --prefix "$prefix"
echo "KODA Suite reset and fresh vulnerability-data installation completed."
