#!/usr/bin/env bash
# KODA closed-network Docker wrapper. Runs the koda-offline image with
# network none, read-only rootfs, no capabilities, resource limits, and
# ro/rw mounts derived from the CLI arguments. Exit codes: container exit
# code passes through; wrapper errors exit 2.
set -euo pipefail

script_dir="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

image="${KODA_IMAGE:-}"
if [ -z "$image" ] && [ -f "$script_dir/image-ref.txt" ]; then
  IFS= read -r image < "$script_dir/image-ref.txt" || true
fi
if [ -z "$image" ]; then
  echo "error: image reference not found; set KODA_IMAGE or provide image-ref.txt" >&2
  exit 2
fi

dashboard_name="koda-dashboard"
dashboard_network="koda-dashboard"
schedule_worker_name="koda-schedule-worker"

dashboard_is_owned() {
  local offline_label
  docker container inspect "$dashboard_name" >/dev/null 2>&1 || return 1
  offline_label="$(docker inspect -f '{{index .Config.Labels "io.koda.offline"}}' "$dashboard_name")"
  if [ "$offline_label" != true ]; then
    echo "error: refusing to replace foreign container named $dashboard_name" >&2
    exit 2
  fi
}

schedule_worker_is_owned() {
  local offline_label
  docker container inspect "$schedule_worker_name" >/dev/null 2>&1 || return 1
  offline_label="$(docker inspect -f '{{index .Config.Labels "io.koda.offline"}}' "$schedule_worker_name")"
  if [ "$offline_label" != true ]; then
    echo "error: refusing to replace foreign container named $schedule_worker_name" >&2
    exit 2
  fi
}

usage() {
  cat <<'EOF'
Usage:
  koda-docker <koda subcommand> [args...]     e.g. jar-scan, sbom-verify, list-categories
  koda-docker audit --target DIR --baseline SBOM --reports DIR [extra jar-scan args]
  koda-docker dashboard start [--reports DIR] [--port PORT] [--bind ADDRESS]
  koda-docker dashboard status | logs [-f] | stop
  koda-docker dashboard bootstrap --tracker-user-id UUID

Path arguments (--target/--sbom/--baseline-sbom read-only, --output-dir/--output
read-write) are bind-mounted automatically at the same absolute path.

Environment:
  KODA_IMAGE            image reference, default from image-ref.txt
  KODA_CPUS             default 2
  KODA_SCHEDULE_CPUS    schedule worker CPU limit, default 1
  KODA_SCHEDULE_MEMORY  schedule worker memory limit, default 4g
  KODA_SCHEDULE_RATE_BYTES maximum collection rate, default 5242880
  KODA_SCHEDULE_GAP_SECONDS seconds between targets, default 30
  KODA_SCHEDULE_DISK_RESERVE_BYTES minimum free worker disk, default 1073741824
  KODA_SCHEDULE_MIN_FREE_BYTES alias for minimum free worker disk
  KODA_MEMORY           default 4g
  KODA_PIDS_LIMIT       default 256
  KODA_TMPFS_SIZE       default 512m
  KODA_ALLOW_CONCURRENT set 1 to allow parallel scans
  KODA_PORT             dashboard host port, default 8765
  KODA_DASHBOARD_BIND   dashboard bind address, default 127.0.0.1
  KODA_PORTAL_DATA_DIR  durable portal database/input directory
  KODA_PUBLISH_DASHBOARD set 0 when a gateway reaches the private Docker network
  KODA_GITLAB_URL        GitLab HTTPS base URL
  KODA_GITLAB_TOKEN_FILE host path to the GitLab service-account token
  KODA_GITLAB_WRITE_TOKEN_FILE host path to the GitLab result-write API token
  KODA_GITLAB_CA_FILE    optional private CA bundle for GitLab
  KODA_GITLAB_NETWORK    optional pre-created Docker network with GitLab reachability
  KODA_TRACKER_URL       optional KODA-SBOM-Tracker base URL
  KODA_TRACKER_TOKEN_DIR host directory for per-repository Tracker token files
  KODA_TRACKER_PROVISIONING_TOKEN_FILE shared Tracker provisioning token file
  KODA_TRACKER_RESULT_TIMEOUT_SECONDS analysis-result wait limit, default 900
  KODA_TRACKER_CA_FILE   optional private CA bundle for Tracker
  KODA_SCHEDULE_ENABLED  set 1 to start the nightly remote-directory worker (default 0)
  KODA_SCHEDULE_SSH_DIR  host directory containing read-only SSH keys and known_hosts
  KODA_DOCKER_EXTRA_ARGS extra docker run options, whitespace-separated
EOF
}

# Extra docker options come from a whitespace-split env var; never eval.
extra_args=()
if [ -n "${KODA_DOCKER_EXTRA_ARGS:-}" ]; then
  read -r -a extra_args <<<"$KODA_DOCKER_EXTRA_ARGS"
fi

base_run_opts() {
  printf '%s\n' \
    --rm \
    --platform linux/amd64 \
    --pull never \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --label io.koda.offline=true \
    --pids-limit "${KODA_PIDS_LIMIT:-256}" \
    --memory "${KODA_MEMORY:-4g}" \
    --cpus "${KODA_CPUS:-2}" \
    --tmpfs "/tmp:rw,noexec,nosuid,size=${KODA_TMPFS_SIZE:-512m}" \
    --user "$(id -u):$(id -g)" \
    -e HOME=/tmp/koda-home \
    -e XDG_CACHE_HOME=/tmp/koda-cache
}

mount_paths=()
mount_modes=()

add_mount() {
  local path="$1" mode="$2" index
  for index in "${!mount_paths[@]}"; do
    if [ "${mount_paths[$index]}" = "$path" ]; then
      # rw wins when the same path is requested both ways.
      [ "${mount_modes[$index]}" = "rw" ] || mount_modes[$index]="$mode"
      return
    fi
  done
  mount_paths+=("$path")
  mount_modes+=("$mode")
}

require_path() {
  local flag="$1" path="$2"
  if [ ! -e "$path" ]; then
    echo "error: $flag path does not exist: $path" >&2
    exit 2
  fi
}

run_cli() {
  local args=() flag value
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --target|--sbom|--baseline-sbom|--target=*|--sbom=*|--baseline-sbom=*)
        case "$1" in
          *=*) flag="${1%%=*}"; value="${1#*=}"; shift ;;
          *) flag="$1"; value="${2:-}"; shift 2 ;;
        esac
        require_path "$flag" "$value"
        value="$(realpath "$value")"
        add_mount "$value" ro
        args+=("$flag" "$value")
        ;;
      --output-dir|--output-dir=*)
        case "$1" in
          *=*) value="${1#*=}"; shift ;;
          *) value="${2:-}"; shift 2 ;;
        esac
        mkdir -p "$value"
        value="$(realpath "$value")"
        add_mount "$value" rw
        args+=(--output-dir "$value")
        ;;
      --output|--output=*)
        case "$1" in
          *=*) value="${1#*=}"; shift ;;
          *) value="${2:-}"; shift 2 ;;
        esac
        mkdir -p "$(dirname -- "$value")"
        value="$(realpath "$(dirname -- "$value")")/$(basename -- "$value")"
        add_mount "$(dirname -- "$value")" rw
        args+=(--output "$value")
        ;;
      *)
        args+=("$1")
        shift
        ;;
    esac
  done

  # ponytail: one scan at a time by default; the JEUS host shares its I/O.
  if [ "${KODA_ALLOW_CONCURRENT:-0}" != "1" ]; then
    exec 9>"$script_dir/.koda-docker-scan.lock"
    if ! flock -n 9; then
      echo "error: another koda-docker run holds the scan lock; set KODA_ALLOW_CONCURRENT=1 to override." >&2
      exit 2
    fi
  fi

  local run_opts=() path index
  while IFS= read -r line; do run_opts+=("$line"); done < <(base_run_opts)
  run_opts+=(--network none)
  for index in "${!mount_paths[@]}"; do
    path="${mount_paths[$index]}"
    run_opts+=(-v "$path:$path:${mount_modes[$index]}")
  done
  local docker_opts=("${run_opts[@]}")
  if [ "${#extra_args[@]}" -gt 0 ]; then
    docker_opts+=("${extra_args[@]}")
  fi
  exec docker run "${docker_opts[@]}" "$image" "${args[@]}"
}

run_audit() {
  local target="" baseline="" reports="" rest=()
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --target) target="${2:-}"; shift 2 ;;
      --baseline) baseline="${2:-}"; shift 2 ;;
      --reports) reports="${2:-}"; shift 2 ;;
      *) rest+=("$1"); shift ;;
    esac
  done
  if [ -z "$target" ] || [ -z "$baseline" ] || [ -z "$reports" ]; then
    echo "error: audit requires --target, --baseline, and --reports." >&2
    exit 2
  fi
  run_cli jar-scan \
    --target "$target" \
    --output-dir "$reports" \
    --verify-sbom \
    --baseline-sbom "$baseline" \
    --strict-hash \
    --fail-on-mismatch \
    --fail-on-version-conflict \
    --fail-on-untracked \
    --fail-on high \
    --fail-on-kev \
    ${rest[@]+"${rest[@]}"}
}

dashboard_start() {
  local reports=""
  local bind="${KODA_DASHBOARD_BIND:-127.0.0.1}"
  local port="${KODA_PORT:-8765}"
  local portal_data="${KODA_PORTAL_DATA_DIR:-$script_dir/data/portal}"
  local schedule_ssh_dir="${KODA_SCHEDULE_SSH_DIR:-}"
  local run_network="$dashboard_network" run_network_arg server_major
  local dashboard_running=0 worker_running=0
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --reports) reports="${2:-}"; shift 2 ;;
      --port) port="${2:-}"; shift 2 ;;
      --bind) bind="${2:-}"; shift 2 ;;
      *) echo "error: unknown dashboard start option: $1" >&2; exit 2 ;;
    esac
  done
  case "$port" in
    ''|*[!0-9]*) echo "error: dashboard port must be an integer from 1 to 65535: $port" >&2; exit 2 ;;
  esac
  if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
    echo "error: dashboard port must be an integer from 1 to 65535: $port" >&2
    exit 2
  fi
  if [ "${KODA_SCHEDULE_ENABLED:-0}" = "1" ] && [ -z "$schedule_ssh_dir" ]; then
    echo "error: KODA_SCHEDULE_SSH_DIR is required when scheduled scans are enabled" >&2
    exit 2
  fi
  if [ -n "$schedule_ssh_dir" ]; then
    schedule_ssh_dir="$(realpath "$schedule_ssh_dir")"
    [ -d "$schedule_ssh_dir" ] && [ -r "$schedule_ssh_dir" ] && [ -x "$schedule_ssh_dir" ] || {
      echo "error: schedule SSH directory is not readable" >&2
      exit 2
    }
  fi
  if dashboard_is_owned; then
    if docker ps --format '{{.Names}}' | grep -qx "$dashboard_name"; then
      dashboard_running=1
    else
      docker rm -f "$dashboard_name" >/dev/null
    fi
  fi
  if schedule_worker_is_owned; then
    if [ "${KODA_SCHEDULE_ENABLED:-0}" = "1" ] && docker ps --format '{{.Names}}' | grep -qx "$schedule_worker_name"; then
      worker_running=1
    else
      docker rm -f "$schedule_worker_name" >/dev/null
    fi
  fi
  # A dedicated bridge with IP masquerade disabled keeps standalone published
  # ports working while blocking container egress. Gateway mode publishes no
  # dashboard port, so an internal network also leaves GitLab as the only
  # eligible external gateway on Docker versions without gw-priority.
  if ! docker network inspect "$dashboard_network" >/dev/null 2>&1; then
    local network_opts=(
      -o com.docker.network.bridge.enable_ip_masquerade=false
    )
    [ "${KODA_PUBLISH_DASHBOARD:-1}" = 1 ] || network_opts+=(--internal)
    docker network create "${network_opts[@]}" "$dashboard_network" >/dev/null
  fi
  if [ -n "${KODA_GITLAB_NETWORK:-}" ]; then
    [ "$KODA_GITLAB_NETWORK" != "$dashboard_network" ] || {
      echo "error: KODA_GITLAB_NETWORK must differ from $dashboard_network" >&2
      exit 2
    }
    docker network inspect "$KODA_GITLAB_NETWORK" >/dev/null 2>&1 || {
      echo "error: KODA_GITLAB_NETWORK does not exist: $KODA_GITLAB_NETWORK" >&2
      exit 2
    }
    run_network="$KODA_GITLAB_NETWORK"
  fi
  run_network_arg="$run_network"
  if [ "$run_network" != "$dashboard_network" ]; then
    server_major="$(docker version --format '{{.Server.Version}}' 2>/dev/null)"
    server_major="${server_major%%.*}"
    if [[ "$server_major" =~ ^[0-9]+$ ]] && [ "$server_major" -ge 28 ]; then
      run_network_arg="name=$run_network,gw-priority=1"
    fi
  fi
  local run_opts=(-d --name "$dashboard_name" --network "$run_network_arg")
  while IFS= read -r line; do run_opts+=("$line"); done < <(base_run_opts)
  # -d and --rm conflict with container inspection after exit; drop --rm.
  local filtered=() opt
  for opt in "${run_opts[@]}"; do
    [ "$opt" = "--rm" ] || filtered+=("$opt")
  done
  if [ "${KODA_PUBLISH_DASHBOARD:-1}" = 1 ]; then
    filtered+=(-p "$bind:$port:8765")
  fi
  mkdir -p "$portal_data"
  portal_data="$(realpath "$portal_data")"
  filtered+=(
    -v "$portal_data:/var/lib/koda:rw"
    -e KODA_PORTAL_DATA_DIR=/var/lib/koda
    -e KODA_PORTAL_DB=/var/lib/koda/portal.sqlite3
    -e KODA_PORTAL_INPUT_DIR=/var/lib/koda/inputs
  )
  if [ -n "$schedule_ssh_dir" ]; then
    filtered+=(-v "$schedule_ssh_dir:/run/koda/ssh:ro")
  fi
  local data_volume="${KODA_VULN_DATA_VOLUME:-}"
  if [ -n "$data_volume" ]; then
    [[ "$data_volume" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] || { echo "error: invalid KODA_VULN_DATA_VOLUME" >&2; exit 2; }
    docker volume inspect "$data_volume" >/dev/null || { echo "error: vulnerability data volume is missing" >&2; exit 2; }
    filtered+=(-v "$data_volume:/var/lib/koda-vuln-data:ro" -e KODA_VULN_DATA_ROOT=/var/lib/koda-vuln-data)
  fi
  local schedule_auth="$portal_data/schedule-auth"
  local schedule_state="${KODA_SCHEDULE_STATE_DIR:-${portal_data}-schedule}"
  if [ "${KODA_SCHEDULE_ENABLED:-0}" = "1" ]; then
    mkdir -p "$schedule_auth" "$schedule_state"
    chmod 700 "$schedule_auth" "$schedule_state"
    if [ ! -f "$schedule_auth/token" ]; then
      (umask 077; set -o noclobber; LC_ALL=C od -An -N32 -tx1 /dev/urandom | tr -d ' \n' > "$schedule_auth/token")
    fi
    chmod 600 "$schedule_auth/token"
    filtered+=(-v "$schedule_auth:/run/koda/schedule:ro"
      -e KODA_SCHEDULE_API_TOKEN_FILE=/run/koda/schedule/token)
  fi
  if [ -n "${KODA_SSBOM_TRACKER_URL:-}" ]; then
    filtered+=(-e "KODA_SSBOM_TRACKER_URL=${KODA_SSBOM_TRACKER_URL}")
  fi
  [ -z "${KODA_GITLAB_URL:-}" ] || filtered+=(-e "KODA_GITLAB_URL=${KODA_GITLAB_URL}")
  [ -z "${KODA_TRACKER_URL:-}" ] || filtered+=(-e "KODA_TRACKER_URL=${KODA_TRACKER_URL}")
  [ -z "${KODA_TRACKER_RESULT_TIMEOUT_SECONDS:-}" ] || filtered+=(-e "KODA_TRACKER_RESULT_TIMEOUT_SECONDS=${KODA_TRACKER_RESULT_TIMEOUT_SECONDS}")
  local source_path
  if [ -n "${KODA_GITLAB_TOKEN_FILE:-}" ]; then
    source_path="$(realpath "$KODA_GITLAB_TOKEN_FILE")"
    [ -f "$source_path" ] && [ -r "$source_path" ] || { echo "error: GitLab token file is not readable by uid $(id -u)" >&2; exit 2; }
    filtered+=(-v "$source_path:/run/secrets/koda-gitlab-token:ro" -e KODA_GITLAB_TOKEN_FILE=/run/secrets/koda-gitlab-token)
  fi
  if [ -n "${KODA_GITLAB_WRITE_TOKEN_FILE:-}" ]; then
    source_path="$(realpath "$KODA_GITLAB_WRITE_TOKEN_FILE")"
    [ -f "$source_path" ] && [ -r "$source_path" ] || { echo "error: GitLab write token file is not readable by uid $(id -u)" >&2; exit 2; }
    filtered+=(-v "$source_path:/run/secrets/koda-gitlab-write-token:ro" -e KODA_GITLAB_WRITE_TOKEN_FILE=/run/secrets/koda-gitlab-write-token)
  fi
  if [ -n "${KODA_TRACKER_TOKEN_DIR:-}" ]; then
    source_path="$(realpath "$KODA_TRACKER_TOKEN_DIR")"
    [ -d "$source_path" ] && [ -r "$source_path" ] && [ -w "$source_path" ] && [ -x "$source_path" ] || { echo "error: Tracker token directory is not private and writable by uid $(id -u)" >&2; exit 2; }
    filtered+=(-v "$source_path:/run/koda/tracker-tokens:rw" -e KODA_TRACKER_TOKEN_DIR=/run/koda/tracker-tokens)
  fi
  if [ -n "${KODA_TRACKER_PROVISIONING_TOKEN_FILE:-}" ]; then
    source_path="$(realpath "$KODA_TRACKER_PROVISIONING_TOKEN_FILE")"
    [ -f "$source_path" ] && [ -r "$source_path" ] || { echo "error: Tracker provisioning token file is not readable by uid $(id -u)" >&2; exit 2; }
    filtered+=(-v "$source_path:/run/secrets/koda-tracker-provisioning:ro" -e KODA_TRACKER_PROVISIONING_TOKEN_FILE=/run/secrets/koda-tracker-provisioning)
  fi
  if [ -n "${KODA_GITLAB_CA_FILE:-}" ]; then
    source_path="$(realpath "$KODA_GITLAB_CA_FILE")"
    [ -f "$source_path" ] || { echo "error: GitLab CA file not found" >&2; exit 2; }
    filtered+=(-v "$source_path:/run/secrets/koda-gitlab-ca.pem:ro" -e KODA_GITLAB_CA_FILE=/run/secrets/koda-gitlab-ca.pem)
  fi
  if [ -n "${KODA_TRACKER_CA_FILE:-}" ]; then
    source_path="$(realpath "$KODA_TRACKER_CA_FILE")"
    [ -f "$source_path" ] || { echo "error: Tracker CA file not found" >&2; exit 2; }
    filtered+=(-v "$source_path:/run/secrets/koda-tracker-ca.pem:ro" -e KODA_TRACKER_CA_FILE=/run/secrets/koda-tracker-ca.pem)
  fi
  if [ -n "$reports" ]; then
    mkdir -p "$reports"
    reports="$(realpath "$reports")"
    filtered+=(-v "$reports:$reports:rw")
  fi
  local docker_opts=("${filtered[@]}")
  if [ "${#extra_args[@]}" -gt 0 ]; then
    docker_opts+=("${extra_args[@]}")
  fi
  if [ "$dashboard_running" = "0" ]; then
    docker run "${docker_opts[@]}" "$image" \
      serve --host 0.0.0.0 --port 8765 >/dev/null
  fi
  if [ "${KODA_SCHEDULE_ENABLED:-0}" = "1" ] && [ "$worker_running" = "0" ]; then
    # Only the worker needs outbound SSH; the dashboard bridge keeps its no-egress policy.
    local schedule_network="${dashboard_network}-schedule"
    if ! docker network inspect "$schedule_network" >/dev/null 2>&1; then
      docker network create "$schedule_network" >/dev/null
    fi
    # Worker never inherits portal DB, uploads, reports, or publication credentials.
    local worker_opts=(-d --name "$schedule_worker_name" --network "$schedule_network"
      --restart unless-stopped --label io.koda.offline=true --platform linux/amd64 --pull never --read-only
      --cap-drop ALL --security-opt no-new-privileges --pids-limit "${KODA_PIDS_LIMIT:-256}"
      --user "$(id -u):$(id -g)" --tmpfs "/tmp:rw,noexec,nosuid,size=${KODA_TMPFS_SIZE:-512m}"
      --cpus "${KODA_SCHEDULE_CPUS:-1}" --memory "${KODA_SCHEDULE_MEMORY:-4g}"
      -v "$schedule_state:/var/lib/koda-schedule:rw"
      -v "$schedule_auth:/run/koda/schedule:ro"
      -v "$schedule_ssh_dir:/run/koda/ssh:ro"
      -e HOME=/tmp/koda-home -e XDG_CACHE_HOME=/tmp/koda-cache
      -e "KODA_SCHEDULE_API_URL=http://$dashboard_name:8765"
      -e KODA_SCHEDULE_API_TOKEN_FILE=/run/koda/schedule/token
      -e KODA_SCHEDULE_STATE_DIR=/var/lib/koda-schedule
      -e KODA_SCHEDULE_WORK_DIR=/var/lib/koda-schedule/work
    )
    if [ -n "$data_volume" ]; then
      worker_opts+=(-v "$data_volume:/var/lib/koda-vuln-data:ro" -e KODA_VULN_DATA_ROOT=/var/lib/koda-vuln-data)
    fi
    if ! docker run "${worker_opts[@]}" "$image" schedule-worker >/dev/null; then
      docker rm -f "$schedule_worker_name" >/dev/null 2>&1 || true
      echo "error: could not start $schedule_worker_name" >&2
      exit 2
    fi
    if ! docker network connect "$dashboard_network" "$schedule_worker_name"; then
      docker rm -f "$schedule_worker_name" >/dev/null 2>&1 || true
      echo "error: could not connect $schedule_worker_name to $dashboard_network" >&2
      exit 2
    fi
  fi
  if [ "$dashboard_running" = "0" ] && [ "$run_network" != "$dashboard_network" ] && ! docker network connect "$dashboard_network" "$dashboard_name"; then
    docker rm -f "$schedule_worker_name" "$dashboard_name" >/dev/null 2>&1 || true
    echo "error: could not connect dashboard to $dashboard_network" >&2
    exit 2
  fi
  if [ "${KODA_PUBLISH_DASHBOARD:-1}" = 1 ]; then
    echo "dashboard started: http://$bind:$port/koda/"
  else
    echo "dashboard started on private Docker network: $dashboard_network"
  fi
}

case "${1:-}" in
  -h|--help|"")
    usage
    exit 0
    ;;
  audit)
    shift
    run_audit "$@"
    ;;
  dashboard)
    shift
    case "${1:-}" in
      start) shift; dashboard_start "$@" ;;
      status)
        printf 'NAME\tSTATUS\tPORTS\n'
        docker ps --all --filter "name=^${dashboard_name}\$" --format '{{.Names}}\t{{.Status}}\t{{.Ports}}'
        docker ps --all --filter "name=^${schedule_worker_name}\$" --format '{{.Names}}\t{{.Status}}\t{{.Ports}}'
        ;;
      logs) shift; docker logs ${1:+"$1"} "$dashboard_name" ;;
      bootstrap)
        shift
        [[ "${1:-}" == --tracker-user-id && -n "${2:-}" && $# == 2 ]] \
          || { echo "Usage: koda-docker dashboard bootstrap --tracker-user-id UUID" >&2; exit 2; }
        docker exec "$dashboard_name" /opt/koda/bin/koda portal-bootstrap \
          --tracker-user-id "$2" --db /var/lib/koda/portal.sqlite3
        ;;
      stop)
        if schedule_worker_is_owned; then
          docker rm -f "$schedule_worker_name" >/dev/null
        fi
        if dashboard_is_owned; then
          docker rm -f "$dashboard_name" >/dev/null
          echo "dashboard stopped"
        else
          echo "dashboard not running"
        fi
        ;;
      *) echo "Usage: koda-docker dashboard start|status|logs|bootstrap|stop" >&2; exit 2 ;;
    esac
    ;;
  serve)
    echo "error: use 'koda-docker dashboard start' instead of 'serve'." >&2
    exit 2
    ;;
  *)
    run_cli "$@"
    ;;
esac
