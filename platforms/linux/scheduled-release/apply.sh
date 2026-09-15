#!/usr/bin/env bash
# Apply a scheduled-scan image bundle to an existing KODA Suite.
set -euo pipefail
umask 077

root="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
prefix="${KODA_SUITE_PREFIX:-${HOME:-$PWD}/koda-suite}"
enable=0
ssh_dir=""
previous_schedule_enabled=0
previous_schedule_ssh_dir="${KODA_SCHEDULE_SSH_DIR:-}"
fail() { echo "error: $*" >&2; exit 2; }
usage() { echo "Usage: $0 [--prefix DIR] [--enable-schedule --ssh-dir DIR]"; }
while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix) prefix="${2:-}"; shift 2 ;;
    --enable-schedule) enable=1; shift ;;
    --ssh-dir) ssh_dir="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) fail "unknown option: $1" ;;
  esac
done
[[ "$enable" == 0 || -d "$ssh_dir" ]] || fail "--ssh-dir is required when scheduled scans are enabled"
[[ "$(uname -s)" == Linux && "$(uname -m)" =~ ^(x86_64|amd64)$ ]] || fail "this bundle requires Linux x86_64"
for c in docker python3 tar sha256sum flock; do command -v "$c" >/dev/null || fail "$c is required"; done
[[ -f "$root/images.tar" && -f "$root/image-inventory.json" && -f "$root/manifest.sha256" ]] || fail "bundle files are missing"
[[ -x "$root/launchers/koda-suite" && -x "$root/launchers/koda-docker" ]] || fail "release launchers are missing"
[[ -d "$prefix" && -f "$prefix/tracker/.env" && -x "$prefix/koda/koda-docker" ]] || fail "existing KODA Suite is missing: $prefix"
previous_schedule_enabled="$(awk -F= '$1=="KODA_SCHEDULE_ENABLED" {v=$2} END{print v}' "$prefix/tracker/.env")"
previous_schedule_enabled="${previous_schedule_enabled:-0}"
previous_schedule_ssh_dir="$(awk -F= '$1=="KODA_SCHEDULE_SSH_DIR" {v=substr($0,index($0,"=")+1)} END{print v}' "$prefix/tracker/.env")"
previous_schedule_ssh_dir="${previous_schedule_ssh_dir:-${KODA_SCHEDULE_SSH_DIR:-}}"

(cd "$root" && sha256sum --check --quiet manifest.sha256) || fail "bundle checksum verification failed"
[[ -f "$root/preflight.py" && -d "$root/contract" ]] || fail "release compatibility contract is missing"
python3 - "$root/image-inventory.json" <<'PYINV'
import json, pathlib, sys
inventory = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
items = inventory if isinstance(inventory, list) else list(inventory.values()) if isinstance(inventory, dict) else []
expected = {
    "koda": next((i.get("reference") for i in items if i.get("reference", "").startswith("local/koda-scheduled:")), ""),
    "portal-web": next((i.get("reference") for i in items if i.get("reference", "").startswith("local/koda-tracker-web-scheduled:")), ""),
    "portal-api": next((i.get("reference") for i in items if i.get("reference", "").startswith("local/koda-tracker-api-scheduled:")), ""),
}
by_ref = {item.get("reference"): item for item in items if isinstance(item, dict)}
for name, ref in expected.items():
    item = by_ref.get(ref)
    if not item or item.get("platform") != "linux/amd64" or not isinstance(item.get("id"), str) or not item["id"].startswith("sha256:"):
        raise SystemExit(f"image inventory mismatch: {name}")
PYINV
refs_json="$(python3 - "$root/image-inventory.json" <<'PYREFS'
import json, pathlib, sys
items = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
by = {str(item.get("reference", "")).split(":", 1)[0]: item.get("reference", "") for item in items if isinstance(item, dict)}
print(json.dumps(by))
PYREFS
)"
koda_release_ref="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["local/koda-scheduled"])' <<<"$refs_json")"
portal_web_release_ref="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["local/koda-tracker-web-scheduled"])' <<<"$refs_json")"
portal_api_release_ref="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["local/koda-tracker-api-scheduled"])' <<<"$refs_json")"
exec 9>"$prefix/.koda-suite-operation.lock"
flock -n 9 || fail "another Suite operation is running"
python3 "$root/preflight.py" --prefix "$prefix" || fail "existing Suite preflight failed"
python3 - "$prefix/data/koda-portal" <<'PYOWNER'
import os, pathlib, sys
if pathlib.Path(sys.argv[1]).stat().st_uid != os.getuid():
    raise SystemExit("run as the existing KODA portal data owner; do not switch to sudo/root")
PYOWNER

# Never overwrite a running release tag before its rollback image is saved.
python3 - "$root/image-inventory.json" "$prefix/koda/image-ref.txt" <<'PYCOLLISION'
import json, pathlib, subprocess, sys
refs={item['reference'] for item in json.loads(pathlib.Path(sys.argv[1]).read_text())}
selected=pathlib.Path(sys.argv[2]).read_text().splitlines()[0].strip()
ids=subprocess.check_output(['docker','ps','-q'], text=True).split()
if ids:
    running=json.loads(subprocess.check_output(['docker','inspect',*ids], text=True))
    if isinstance(running, list):
        if any(item.get('Config',{}).get('Image') in refs for item in running):
            raise SystemExit('release tag already running; use a new release revision')
if selected in refs:
    raise SystemExit('release tag is already selected; use a new release revision')
PYCOLLISION

# Load and verify the bundle while the existing Suite is still serving traffic.
# A bad archive or digest must never be discovered after services are stopped.
docker load --input "$root/images.tar" >/dev/null || fail "could not load image bundle"
while IFS=$'\t' read -r inventory_ref inventory_id source_image_id; do
  actual_id="$(docker image inspect "$inventory_ref" --format '{{.Id}}' 2>/dev/null || true)"
  [[ -n "$actual_id" && ( "$actual_id" == "$inventory_id" || "$actual_id" == "$source_image_id" ) ]] || fail "loaded image digest mismatch: $inventory_ref"
done < <(python3 - "$root/image-inventory.json" <<'PYINV2'
import json, pathlib, sys
value=json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
items=value if isinstance(value,list) else list(value.values()) if isinstance(value,dict) else []
for item in items:
    if isinstance(item,dict) and item.get("reference") and item.get("id"):
        print(f'{item["reference"]}\t{item["id"]}\t{item.get("source_image_id", item["id"])}')
PYINV2
)

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
backup="$prefix/backups/scheduled-release/$stamp"
mkdir -p "$backup/sqlite" "$backup"
chmod 700 "$backup" "$backup/sqlite"
compose() {
  docker compose --project-directory "$prefix/tracker" --env-file "$prefix/tracker/.env" \
    -f "$prefix/tracker/compose.yaml" -f "$prefix/tracker/compose.airgap.yaml" \
    -f "$prefix/tracker/compose.integration.yaml" "$@"
}
for relative in tracker/compose.yaml tracker/compose.airgap.yaml tracker/compose.integration.yaml \
  tracker/gateway/gateway.conf.template tracker/.env; do
  [[ -f "$prefix/$relative" ]] || fail "existing Tracker configuration is missing: $relative"
  mkdir -p "$backup/$(dirname -- "$relative")"
  cp -p "$prefix/$relative" "$backup/$relative"
done
cp -a "$prefix/tracker/gateway/." "$backup/tracker/gateway/"

# Identify and archive the existing Tracker vulnerability volume while it is
# still mounted read-only by the running API. The archive is independent of
# the database backup and is retained for recovery even if migration fails.
if compose config --services 2>/dev/null | grep -qx 'portal-data-updater'; then
  compose stop portal-data-updater >/dev/null || fail "could not quiesce Tracker data updater"
fi
portal_api_container="$(compose ps -q portal-api 2>/dev/null || true)"
vuln_volume="$(docker inspect "$portal_api_container" --format '{{range .Mounts}}{{if eq .Destination "/var/lib/sbom-tracker/vuln-data"}}{{.Name}}{{end}}{{end}}' 2>/dev/null || true)"
[[ -n "$vuln_volume" ]] || fail "existing Tracker vulnerability-data volume could not be identified"
docker run --rm --user 0 --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --network none \
  -v "$vuln_volume:/data:ro" -v "$backup:/backup" "$portal_api_release_ref" \
  tar -czf /backup/tracker-vuln-data-volume.tar.gz -C /data . \
  || fail "Tracker vulnerability-data volume backup failed"
chmod 600 "$backup/tracker-vuln-data-volume.tar.gz"
printf 'vuln_volume=%s\n' "$vuln_volume" >>"$backup/metadata.env.pending"
docker run --rm --user 0 --read-only --tmpfs /tmp:rw,noexec,nosuid,size=32m --network none \
  -v "$vuln_volume:/data:ro" -v "$backup:/backup:rw" "$portal_api_release_ref" python -c \
  'from pathlib import Path; import os; p=Path("/data/current"); Path("/backup/legacy-current-target").write_text(os.readlink(p) if p.is_symlink() else "")' \
  || fail "could not record the legacy Tracker current pointer"
printf 'migration_image=%s\n' "$portal_api_release_ref" >>"$backup/metadata.env.pending"

# The Suite is stopped before copying SQLite files and before pg_dump. Volumes
# and the database containers remain intact throughout this operation.
declare -a old_refs=() rollback_refs=()
resource_json="$(docker inspect koda-dashboard --format '{{json .HostConfig}}' 2>/dev/null || true)"
[[ -n "$resource_json" ]] || fail "koda-dashboard is not inspectable"
read -r saved_cpus saved_memory saved_pids < <(python3 - "$resource_json" <<'PYRES'
import json, sys
r=json.loads(sys.argv[1]); print(r.get("NanoCpus", 0), r.get("Memory", 0), r.get("PidsLimit", 0))
PYRES
)
printf '%s\n' "$resource_json" >"$backup/koda-dashboard-hostconfig.json"
"$prefix/koda/koda-docker" dashboard stop >/dev/null || fail "could not stop KODA dashboard"
compose stop portal-web portal-api portal-worker gateway >/dev/null || fail "could not quiesce Tracker application"
# A prior rollout may already have a standalone worker. Stop it before the
# database snapshot so it cannot acknowledge work while the app is quiesced.
while IFS= read -r worker; do
  [[ -n "$worker" ]] && docker stop "$worker" >/dev/null || true
done < <(docker ps --format '{{.Names}}' | awk '/(^|[-_])koda-schedule-worker($|[-_])/')

sqlite_found=0
while IFS= read -r db; do
  [[ -f "$db" ]] || continue
  sqlite_found=1
  destination="$backup/sqlite/$(basename -- "$db").$stamp"
  python3 - "$db" "$destination" <<'PYSQLITE'
import sqlite3, sys
source, destination = sys.argv[1:]
with sqlite3.connect(source) as src, sqlite3.connect(destination) as dst:
    src.backup(dst)
PYSQLITE
done < <(find "$prefix/data/koda-portal" -type f \( -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' \) -print 2>/dev/null)
# pg_dumpall runs inside the existing container, so host credentials are never
# parsed or written by this script.
compose exec -T postgres sh -c 'exec pg_dumpall -U "$POSTGRES_USER" --clean --if-exists' >"$backup/tracker.pg_dump.sql" \
  || fail "PostgreSQL backup failed; Suite remains stopped and no image was changed"
chmod 600 "$backup/tracker.pg_dump.sql"
printf 'created_at=%s\nsqlite_found=%s\nschedule_enabled=%s\nschedule_ssh_dir=%s\n' \
  "$stamp" "$sqlite_found" "$previous_schedule_enabled" "$previous_schedule_ssh_dir" >"$backup/metadata.env"
cat "$backup/metadata.env.pending" >>"$backup/metadata.env"
rm -f "$backup/metadata.env.pending"

env_value() { awk -F= -v k="$2" '$1==k {v=$0; sub(/^[^=]*=/,"",v)} END{print v}' "$1"; }
tag_image() {
  local target="$1" current="$2" arch
  [[ "$current" != *@sha256:* && -n "$current" ]] || fail "digest-pinned or empty application image reference: $current"
  arch="$(docker image inspect "$target" --format '{{.Architecture}}' 2>/dev/null || true)"
  [[ "$arch" == amd64 ]] || fail "loaded image is not linux/amd64: $target"
  docker tag "$target" "$current"
}

koda_ref="$(head -n1 "$prefix/koda/image-ref.txt" 2>/dev/null || true)"
[[ -n "$koda_ref" ]] || fail "KODA image-ref.txt is empty"
compose config --format json >"$backup/compose-config.json" || fail "could not render Tracker Compose config"
read -r web_ref api_ref worker_ref < <(python3 - "$backup/compose-config.json" <<'PYCOMPOSE'
import json, pathlib, sys
services=json.loads(pathlib.Path(sys.argv[1]).read_text()).get("services", {})
values=[services.get(name,{}).get("image","") for name in ("portal-web","portal-api","portal-worker")]
if any(not value or "@sha256:" in value for value in values): raise SystemExit("invalid resolved application image reference")
print(*values)
PYCOMPOSE
)
[[ -n "$web_ref" && -n "$api_ref" && -n "$worker_ref" ]] || fail "Tracker application image references are missing"
[[ "$koda_ref" != "$web_ref" && "$koda_ref" != "$api_ref" && "$koda_ref" != "$worker_ref" && "$web_ref" != "$api_ref" && "$web_ref" != "$worker_ref" ]] || fail "conflicting application image references"
service_refs=("$koda_ref" "$web_ref" "$api_ref" "$worker_ref")
for current in "${service_refs[@]}"; do
  [[ "$current" != *@sha256:* && -n "$current" ]] || fail "digest-pinned or empty application image reference: $current"
  duplicate=0
  for old in "${old_refs[@]-}"; do [[ -n "$old" && "$old" == "$current" ]] && duplicate=1; done
  if [[ "$duplicate" == 0 ]]; then
    old_refs+=("$current")
    rollback_refs+=("local/koda-rollback:$stamp-${#old_refs[@]}")
    docker image inspect "$current" >/dev/null 2>&1 || fail "current image is missing: $current"
    rollback_ref="${rollback_refs[${#rollback_refs[@]}-1]}"
    docker tag "$current" "$rollback_ref" || fail "could not preserve current image: $current"
  fi
done
printf '%s\n' "${old_refs[@]}" >"$backup/old-image-refs.txt"
printf '%s\n' "${rollback_refs[@]}" >"$backup/rollback-image-refs.txt"
cp -p "$prefix/koda-suite" "$backup/koda-suite.previous"
cp -p "$prefix/koda/koda-docker" "$backup/koda-docker.previous"
printf '%s\n' "$backup" >"$prefix/.koda-scheduled-last-backup"
echo "rollback backup ready: $backup"
# Install the reviewed data-updater Compose wiring only after the old files and
# .env have been backed up. The env file remains authoritative for all secrets.
if [[ -d "$root/migration/tracker" ]]; then
  for relative in compose.yaml compose.airgap.yaml compose.integration.yaml; do
    [[ -f "$root/migration/tracker/$relative" ]] || fail "migration file is missing: $relative"
    install -m 0644 "$root/migration/tracker/$relative" "$prefix/tracker/$relative"
  done
  if [[ -f "$root/migration/tracker/gateway/gateway.conf.template" ]]; then
    install -m 0644 "$root/migration/tracker/gateway/gateway.conf.template" \
      "$prefix/tracker/gateway/gateway.conf.template"
  fi
  if ! grep -q '^VULN_DATA_VOLUME_NAME=' "$prefix/tracker/.env"; then
    printf '\n# Added by scheduled release data-update migration; existing volume preserved.\nVULN_DATA_VOLUME_NAME=%s\n' "$vuln_volume" >>"$prefix/tracker/.env"
  fi
  if ! grep -q '^KODA_VULN_DATA_VOLUME=' "$prefix/tracker/.env"; then
    printf 'KODA_VULN_DATA_VOLUME=%s\n' "$vuln_volume" >>"$prefix/tracker/.env"
  fi
  # Normalize the legacy current tree into an immutable composite release
  # before any new scan can observe the switched layout. The engine validates
  # both datasets and leaves current untouched when validation fails.
  docker run --rm --user 0 --read-only --tmpfs /tmp:rw,noexec,nosuid,size=256m \
    --network none \
    -v "$vuln_volume:/var/lib/sbom-tracker/vuln-data" \
    -e TRACKER_GRYPE_DB_DIR=/var/lib/sbom-tracker/vuln-data/current/grype-db \
    -e TRACKER_DATA_UPDATE_KODA_GRYPE_BINARY=/usr/local/bin/koda-grype \
    "$portal_api_release_ref" python -c \
    'from koda_tracker.config import Settings; from koda_tracker.data_updates import DataUpdateEngine; print(DataUpdateEngine(Settings()).migrate_legacy(version="legacy-20260914").version)' \
    || fail "legacy Tracker vulnerability data migration failed; original volume is preserved"
  docker run --rm --user 0 --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m \
    --network none \
    -v "$vuln_volume:/data" "$portal_api_release_ref" python -c \
    'from pathlib import Path; import os, pwd; root=Path("/data"); uid=pwd.getpwnam("tracker").pw_uid; gid=pwd.getpwnam("tracker").pw_gid; [os.chown(p,uid,gid) for p in (root, root/"releases", root/"staging", root/".update.lock") if p.exists() and not p.is_symlink()]' \
    || fail "Tracker updater runtime ownership preparation failed"
  data_updates_volume="$(awk -F= '$1=="DATA_UPDATES_VOLUME_NAME" {print substr($0,index($0,"=")+1)}' "$prefix/tracker/.env")"
  data_updates_volume="${data_updates_volume:-koda-sbom-data-updates}"
  docker volume create "$data_updates_volume" >/dev/null
  docker run --rm --user 0 --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m \
    --network none \
    -v "$data_updates_volume:/spool" "$portal_api_release_ref" python -c \
    'from pathlib import Path; import os, pwd; p=Path("/spool"); u=pwd.getpwnam("tracker"); os.chown(p,u.pw_uid,u.pw_gid)' \
    || fail "Tracker updater spool ownership preparation failed"
fi
tag_image "$koda_release_ref" "$koda_ref"
tag_image "$portal_web_release_ref" "$web_ref"
tag_image "$portal_api_release_ref" "$api_ref"
tag_image "$portal_api_release_ref" "$worker_ref"
install -m 0755 "$root/launchers/koda-suite" "$prefix/koda-suite"
install -m 0755 "$root/launchers/koda-docker" "$prefix/koda/koda-docker"
printf '%s\n' "$backup" >"$prefix/.koda-scheduled-last-backup"

schedule_env=(KODA_SCHEDULE_ENABLED="$previous_schedule_enabled")
[[ -z "$previous_schedule_ssh_dir" ]] || schedule_env+=(KODA_SCHEDULE_SSH_DIR="$previous_schedule_ssh_dir")
if [[ "$enable" == 1 ]]; then
  schedule_env=(KODA_SCHEDULE_ENABLED=1 KODA_SCHEDULE_SSH_DIR="$ssh_dir")
fi
if [[ "$saved_cpus" != 0 ]]; then schedule_env+=(KODA_CPUS="$(python3 -c 'import sys; print(float(int(sys.argv[1]))/1e9)' "$saved_cpus")"); fi
if [[ "$saved_memory" != 0 ]]; then schedule_env+=(KODA_MEMORY="${saved_memory}b"); fi
if [[ "$saved_pids" != 0 ]]; then schedule_env+=(KODA_PIDS_LIMIT="$saved_pids"); fi
env "${schedule_env[@]}" "$prefix/koda-suite" start --prefix "$prefix" >/dev/null || fail "could not start KODA Suite"
compose up -d --no-build --pull never --no-deps --force-recreate portal-web portal-api portal-worker >/dev/null \
  || fail "could not start Tracker application"
if [[ -f "$root/migration/tracker/compose.yaml" ]]; then
  compose up -d --no-build --pull never --no-deps --force-recreate portal-data-updater >/dev/null \
    || fail "could not start Tracker data updater"
fi
compose up -d --no-build --pull never --no-deps gateway >/dev/null || fail "could not start Tracker gateway"
env "${schedule_env[@]}" "$prefix/koda-suite" status --prefix "$prefix"
if [[ "$enable" == 1 ]]; then
  echo "scheduled worker enabled; SSH directory: $ssh_dir"
elif [[ "$previous_schedule_enabled" == 1 ]]; then
  echo "existing scheduled worker activation preserved"
else
  echo "scheduled worker remains disabled (use --enable-schedule with a reviewed SSH directory)"
fi
echo "applied; backup=$backup"
