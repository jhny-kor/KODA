#!/usr/bin/env bash
# Restore image tags from the last scheduled-release apply operation.
set -euo pipefail
umask 077
root="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
prefix="${KODA_SUITE_PREFIX:-${HOME:-$PWD}/koda-suite}"
[[ "${1:-}" != "" ]] && { [[ "$1" == --prefix && -n "${2:-}" ]] || { echo "Usage: $0 [--prefix DIR]" >&2; exit 2; }; prefix="$2"; }
[[ -f "$prefix/.koda-scheduled-last-backup" ]] || { echo "error: no scheduled-release backup found" >&2; exit 2; }
backup="$(head -n1 "$prefix/.koda-scheduled-last-backup")"
[[ -d "$backup" && -f "$backup/rollback-image-refs.txt" ]] || { echo "error: backup is incomplete: $backup" >&2; exit 2; }
[[ -x "$backup/koda-suite.previous" && -x "$backup/koda-docker.previous" ]] || { echo "error: launcher backup is incomplete: $backup" >&2; exit 2; }
for relative in tracker/compose.yaml tracker/compose.airgap.yaml tracker/compose.integration.yaml \
  tracker/gateway/gateway.conf.template tracker/.env; do
  [[ -f "$backup/$relative" ]] || { echo "error: configuration backup is incomplete: $relative" >&2; exit 2; }
done
command -v docker >/dev/null || { echo "error: docker is required" >&2; exit 2; }
exec 9>"$prefix/.koda-suite-operation.lock"
flock -n 9 || { echo "error: another Suite operation is running" >&2; exit 2; }
compose() {
  docker compose --project-directory "$prefix/tracker" --env-file "$prefix/tracker/.env" \
    -f "$prefix/tracker/compose.yaml" -f "$prefix/tracker/compose.airgap.yaml" \
    -f "$prefix/tracker/compose.integration.yaml" "$@"
}
if compose config --services 2>/dev/null | grep -qx 'portal-data-updater'; then
  compose stop portal-data-updater >/dev/null || { echo "error: could not stop Tracker data updater" >&2; exit 2; }
fi
"$prefix/koda/koda-docker" dashboard stop >/dev/null
compose stop portal-web portal-api portal-worker gateway >/dev/null
refs=() rollback=()
while IFS= read -r ref; do [[ -n "$ref" ]] && refs+=("$ref"); done <"$backup/old-image-refs.txt"
while IFS= read -r ref; do [[ -n "$ref" ]] && rollback+=("$ref"); done <"$backup/rollback-image-refs.txt"
[[ "${#refs[@]}" == "${#rollback[@]}" && "${#refs[@]}" -gt 0 ]] || { echo "error: invalid rollback metadata" >&2; exit 2; }
for i in "${!refs[@]}"; do docker tag "${rollback[$i]}" "${refs[$i]}"; done
for relative in tracker/compose.yaml tracker/compose.airgap.yaml tracker/compose.integration.yaml \
  tracker/gateway/gateway.conf.template tracker/.env; do
  install -m 0644 "$backup/$relative" "$prefix/$relative"
done
chmod 600 "$prefix/tracker/.env"
if [[ -d "$backup/tracker/gateway" ]]; then
  cp -a "$backup/tracker/gateway/." "$prefix/tracker/gateway/"
fi
if [[ -f "$backup/legacy-current-target" && -s "$backup/legacy-current-target" && -f "$backup/metadata.env" ]]; then
  migration_image="$(awk -F= '$1=="migration_image" {print substr($0,index($0,"=")+1)}' "$backup/metadata.env")"
  vuln_volume="$(awk -F= '$1=="vuln_volume" {print substr($0,index($0,"=")+1)}' "$backup/metadata.env")"
  [[ -n "$migration_image" && -n "$vuln_volume" ]] || { echo "error: migration rollback metadata is missing" >&2; exit 2; }
  docker run --rm --user 0 --read-only --tmpfs /tmp:rw,noexec,nosuid,size=32m --network none \
    -v "$backup:/backup:ro" -v "$vuln_volume:/data" "$migration_image" python -c \
    'from pathlib import Path; import os, uuid; target=Path("/backup/legacy-current-target").read_text().strip(); tmp=Path("/data")/(".current.rollback."+uuid.uuid4().hex); os.symlink(target,tmp); os.replace(tmp,"/data/current")' \
    || { echo "error: could not restore the original Tracker current pointer" >&2; exit 2; }
fi
install -m 0755 "$backup/koda-suite.previous" "$prefix/koda-suite"
install -m 0755 "$backup/koda-docker.previous" "$prefix/koda/koda-docker"
resource_env=()
if [[ -f "$backup/koda-dashboard-hostconfig.json" ]]; then
  read -r old_cpus old_memory old_pids < <(python3 - "$backup/koda-dashboard-hostconfig.json" <<'PYRES'
import json, pathlib, sys
r=json.loads(pathlib.Path(sys.argv[1]).read_text()); print(r.get("NanoCpus",0),r.get("Memory",0),r.get("PidsLimit",0))
PYRES
  )
  [[ "$old_cpus" == 0 ]] || resource_env+=(KODA_CPUS="$(python3 -c 'import sys; print(float(int(sys.argv[1]))/1e9)' "$old_cpus")")
  [[ "$old_memory" == 0 ]] || resource_env+=(KODA_MEMORY="${old_memory}b")
  [[ "$old_pids" == 0 ]] || resource_env+=(KODA_PIDS_LIMIT="$old_pids")
fi
schedule_env=()
if [[ -f "$backup/metadata.env" ]]; then
  old_schedule="$(awk -F= '$1=="schedule_enabled"{print $2}' "$backup/metadata.env")"
  old_ssh="$(awk -F= '$1=="schedule_ssh_dir"{print substr($0,index($0,"=")+1)}' "$backup/metadata.env")"
  [[ -z "$old_schedule" ]] || schedule_env+=(KODA_SCHEDULE_ENABLED="$old_schedule")
  [[ -z "$old_ssh" ]] || schedule_env+=(KODA_SCHEDULE_SSH_DIR="$old_ssh")
fi
env "${resource_env[@]}" "${schedule_env[@]}" "$prefix/koda-suite" start --prefix "$prefix" >/dev/null
compose up -d --no-build --pull never --no-deps --force-recreate portal-web portal-api portal-worker >/dev/null
if compose config --services 2>/dev/null | grep -qx 'portal-data-updater'; then
  compose up -d --no-build --pull never --no-deps --force-recreate portal-data-updater >/dev/null
fi
compose up -d --no-build --pull never --no-deps gateway >/dev/null
env "${resource_env[@]}" KODA_SCHEDULE_ENABLED=0 "$prefix/koda-suite" status --prefix "$prefix"
echo "rolled back application images; data volumes and databases were preserved; backup=$backup"
