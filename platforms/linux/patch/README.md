# KODA·KODA SBOM Tracker 기존 포털 패치 안내

작성일: 2026-09-06. 대상: Linux x86_64, Docker Engine 및 Compose가 이미 설치된 서버.

- 기존 설치: `/home/user0/koda-suite`
- 압축파일 반입·해제: `/home/user0/koda-release`
- 백업: `/home/user0/koda-backups/<UTC 시각>`

**기존 설치를 삭제하거나 신규 설치하지 않습니다.** 수정된 애플리케이션 이미지를 `docker load`하고, 기존 이미지 참조에 연결한 다음 같은 데이터 저장소를 연결해 포털 컨테이너를 교체합니다. 실행 중인 컨테이너 내부에 `docker cp`로 파일을 덮어쓰는 방식은 사용하지 않습니다. 따라서 이후 재시작에도 패치가 유지됩니다.

## 1. 포함 범위와 호환 조건

| 대상 | 이번 처리 |
|---|---|
| KODA `koda-dashboard` | 최신 Python 코드·이미지·보고서 자산으로 교체 |
| Tracker `portal-web` | 최신 화면을 production build한 이미지로 교체 |
| Tracker API·Worker | 9월 2일 기준 이후 코드 변경 없음. 서버의 실제 코드 해시를 검사하고 유지 |
| PostgreSQL·Dependency-Track·gateway | 이미지·설정 유지. 백업을 위해 잠시 중지 후 재시작 |
| 계정·프로젝트·점검 회차·업로드·연동 토큰 | 기존 bind mount와 named volume 유지 |
| 취약점 데이터 | 갱신하지 않음. KODA는 9월 2일 런타임 기반이며 Grype DB 기준은 9월 1일 |

최근 커밋되지 않은 수정도 포함한 **작업 폴더 스냅샷**입니다. `provenance.json`에 기준 커밋과 스냅샷 여부를 기록했으며, 커밋된 정식 릴리스로 표시하지 않았습니다. 실제 이미지 파일은 `image-inventory.json` 및 `manifest.sha256`으로 식별합니다.

기존 9월 2일 통합본과 같은 Compose·인증·실행 스크립트 구성이 대상입니다. 서버에서 수동 수정한 구성 또는 더 오래된 Tracker 백엔드가 있으면 사전검사가 중단합니다. **검사를 우회하거나 contract 파일을 운영 폴더에 복사하지 마십시오.** 이 경우 오류에 나온 파일 또는 백엔드 차이에 맞는 추가 패치가 필요합니다. `.env`의 비밀번호·주소 등 운영값은 비교 기준 파일로 덮어쓰지 않습니다.

KODA 시작 시 SQLite에 `scan_runs.deleted_at` 열이 없으면 추가합니다. 테이블·기존 회차를 삭제하는 마이그레이션은 없습니다. 이전 코드로 돌아가면 신규 코드에서 숨겼던 삭제 회차가 다시 표시될 수 있으므로, 패치 확인 전에는 회차·사용자 삭제 기능을 사용하지 않는 것이 좋습니다.

## 2. 반입 및 압축 해제

아래 명령은 **서버의 user0 계정에서 Bash로** 실행합니다. Docker 권한이 있는 기존 운영 계정이어야 합니다. `sudo su -`로 HOME·실행 UID를 바꾸지 않습니다. 각 단계는 같은 Bash 세션에서 순서대로 실행하고, 오류가 있으면 다음 단계로 넘어가지 않습니다.

```bash
bash
set -euo pipefail
umask 077
cd /home/user0
mkdir -p /home/user0/koda-release
```

USB/SCP 등 기존 반입 수단으로 다음 파일 **한 개**를 `/home/user0/koda-release`에 복사합니다.

```text
koda-suite-patch-x86_64-20260906.tar.gz
```

외부 체크섬 파일을 추가 반입할 필요는 없습니다. 전달 메시지에 적힌 SHA-256을 아래 값에 넣습니다. 압축파일 자신의 체크섬을 내부 안내서에 넣으면 값이 다시 바뀌므로, 외부 체크섬은 전달 메시지에서 확인합니다.

```bash
cd /home/user0/koda-release
ARCHIVE=koda-suite-patch-x86_64-20260906.tar.gz
EXPECTED_SHA256='전달받은_64자리_SHA256'
printf '%s  %s\n' "$EXPECTED_SHA256" "$ARCHIVE" | sha256sum -c -

# 동일 이름의 해제 폴더가 있으면 삭제/덮어쓰지 않고 중단합니다.
test ! -e koda-suite-patch-x86_64-20260906
tar -xzf "$ARCHIVE"
cd /home/user0/koda-release/koda-suite-patch-x86_64-20260906
sha256sum -c manifest.sha256
```

정상 기준은 외부·내부 체크섬이 모두 `OK`입니다. 기존 해제 폴더가 있으면 별도 이름으로 이동해 보관한 다음 다시 풉니다. **`/home/user0/koda-suite`에 압축을 풀지 않습니다.**

## 3. 경로·상태·호환성 확인

```bash
PREFIX=/home/user0/koda-suite
PATCH=/home/user0/koda-release/koda-suite-patch-x86_64-20260906
ENV_FILE="$PREFIX/tracker/.env"
dc() {
  docker compose --project-directory "$PREFIX/tracker" --env-file "$ENV_FILE" \
    -f "$PREFIX/tracker/compose.yaml" \
    -f "$PREFIX/tracker/compose.airgap.yaml" \
    -f "$PREFIX/tracker/compose.integration.yaml" "$@"
}

uname -m
docker info --format '{{.OSType}}/{{.Architecture}}'
docker compose version
test -x "$PREFIX/koda-suite"
test -s "$ENV_FILE"
df -h /home/user0
docker system df
python3 "$PATCH/preflight.py" --prefix "$PREFIX"
"$PREFIX/koda-suite" status --prefix "$PREFIX"
```

호스트는 `x86_64`, 실행 이미지는 `linux/amd64`, 사전검사는 `compatibility=passed`여야 합니다. 기존 서비스부터 정상이어야 합니다. Docker 데이터 경로가 별도 파일시스템이면 해당 경로의 여유 공간도 확인합니다. 이미지 적재·해제용으로 약 10GB 이상에 더해 **기존 데이터와 이전 이미지 백업 크기만큼** 여유 공간이 필요합니다. 대량 업로드나 취약점 데이터가 있으면 백업 공간이 더 큽니다.

`.env`를 `cat`하거나 `source`하지 않습니다. 사전검사는 설정 내용과 비밀번호를 출력하지 않고 Compose에 환경파일 경로를 전달합니다.

## 4. 새 이미지 적재와 이전 이미지 보존 — 아직 서비스 중지 없음

다른 운영자와 유지보수 시간을 공유하고 동시 조작을 중단합니다. 아래 잠금은 잠금을 사용하는 패치 작업 간 충돌을 막습니다. 기존 `start/stop` 및 수동 Docker 명령 전체를 강제로 차단하는 잠금은 아닙니다.

```bash
exec 9>"$PREFIX/.koda-suite-operation.lock"
flock -n 9 || { echo '다른 패치 작업이 실행 중입니다.' >&2; exit 2; }
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
BACKUP_DIR="/home/user0/koda-backups/$STAMP"
mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"
printf '백업 위치: %s\n' "$BACKUP_DIR"

KODA_REF=$(head -n 1 "$PREFIX/koda/image-ref.txt")
WEB_CONTAINER=$(dc ps -q portal-web)
POSTGRES_ID=$(dc ps -q postgres)
API_ID=$(dc ps -q portal-api)
WORKER_ID=$(dc ps -q portal-worker)
DTRACK_ID=$(dc ps -q dtrack-apiserver)
WEB_REF=$(docker inspect -f '{{.Config.Image}}' "$WEB_CONTAINER")
KODA_OLD_ID=$(docker inspect -f '{{.Image}}' koda-dashboard)
WEB_OLD_ID=$(docker inspect -f '{{.Image}}' "$WEB_CONTAINER")

# 별도 환경변수로 조정해 운영했던 KODA 리소스 제한도 유지합니다.
KODA_MEMORY=$(docker inspect -f '{{.HostConfig.Memory}}' koda-dashboard)
KODA_PIDS_LIMIT=$(docker inspect -f '{{.HostConfig.PidsLimit}}' koda-dashboard)
KODA_CPUS=$(docker inspect -f '{{.HostConfig.NanoCpus}}' koda-dashboard | python3 -c 'import sys; print(int(sys.stdin.read())/1000000000)')
export KODA_MEMORY KODA_PIDS_LIMIT KODA_CPUS

{
  for key in PREFIX PATCH ENV_FILE STAMP BACKUP_DIR KODA_REF WEB_REF KODA_OLD_ID WEB_OLD_ID \
    POSTGRES_ID API_ID WORKER_ID DTRACK_ID KODA_MEMORY KODA_PIDS_LIMIT KODA_CPUS; do
    printf '%s=%q\n' "$key" "${!key}"
  done
} > "$BACKUP_DIR/recovery.env"

docker tag "$KODA_OLD_ID" "local/koda-rollback:$STAMP"
docker tag "$WEB_OLD_ID" "local/koda-tracker-web-rollback:$STAMP"
docker save -o "$BACKUP_DIR/previous-images.tar" \
  "local/koda-rollback:$STAMP" "local/koda-tracker-web-rollback:$STAMP"

# 기존 서비스가 사용하는 실제 named volume만 기록합니다.
docker inspect "$API_ID" "$WORKER_ID" "$DTRACK_ID" | python3 -c '
import json,sys
names=sorted({m["Name"] for c in json.load(sys.stdin) for m in c["Mounts"] if m["Type"]=="volume"})
if not names: raise SystemExit("백업할 기존 volume을 찾지 못했습니다")
print("\n".join(names))
' > "$BACKUP_DIR/volumes.txt"

docker load -i "$PATCH/images.tar"
python3 - "$PATCH/image-inventory.json" <<'PY'
import json,subprocess,sys
with open(sys.argv[1]) as f: inventory=json.load(f)
for expected in inventory.values():
    actual=json.loads(subprocess.check_output(["docker","image","inspect",expected["ref"]]))[0]
    assert actual["Id"] == expected["id"], expected["ref"]
    assert actual["Os"]+"/"+actual["Architecture"] == "linux/amd64", expected["ref"]
print("patch image inventory OK")
PY
```

새 이미지는 별도 태그로 적재되므로 여기까지는 기존 컨테이너를 바꾸지 않습니다. `previous-images.tar`와 `recovery.env`가 이후 롤백의 기준입니다.

## 5. 유지보수 중지와 데이터 백업

포털에서 진행 중인 점검·업로드·Tracker 분석·GitLab 전달이 완료되었는지 확인합니다. 중지하면 브라우저에서 포털을 사용할 수 없습니다. 백업 크기에 따라 점검 시간이 달라집니다.

```bash
"$PREFIX/koda-suite" stop --prefix "$PREFIX"

# prefix 전체에서 설정·토큰·KODA SQLite·입력을 보존합니다.
# 설치 때 남은 이미지 tar/source/취약점 반입 원본은 제외합니다.
# tar는 root로 읽지만 출력 파일은 현재 user0 셸이 안전하게 만듭니다.
docker run --rm --pull never --network none --user 0:0 --entrypoint tar \
  --mount "type=bind,source=$PREFIX,target=/from,readonly" \
  local/koda-patch:20260906 -C /from \
  --exclude=./tracker/images --exclude=./tracker/source \
  --exclude=./tracker/vulnerability-data -czf - . \
  > "$BACKUP_DIR/suite-files.tar.gz"

# 기존 PostgreSQL 컨테이너만 다시 켜서 논리 백업합니다.
docker start "$POSTGRES_ID" >/dev/null
for attempt in $(seq 1 60); do
  if docker exec "$POSTGRES_ID" sh -c 'pg_isready -U "$POSTGRES_USER" -d postgres' >/dev/null 2>&1; then break; fi
  sleep 2
done
docker exec "$POSTGRES_ID" sh -c 'pg_isready -U "$POSTGRES_USER" -d postgres'
docker exec "$POSTGRES_ID" sh -c 'exec pg_dumpall -U "$POSTGRES_USER"' \
  > "$BACKUP_DIR/postgres-all.sql"
test -s "$BACKUP_DIR/postgres-all.sql"

# API/Worker/DTrack가 사용하는 artifacts·취약점 자료·DTrack 파일·backups.
# PostgreSQL 원시 파일은 복사하지 않고 위 SQL 덤프로 보존합니다.
while IFS= read -r volume; do
  docker volume inspect "$volume" >/dev/null
  docker run --rm --pull never --network none --user 0:0 --entrypoint tar \
    --mount "type=volume,source=$volume,target=/from,readonly" \
    local/koda-patch:20260906 -C /from -czf - . \
    > "$BACKUP_DIR/volume-$volume.tar.gz"
done < "$BACKUP_DIR/volumes.txt"

gzip -t "$BACKUP_DIR"/*.tar.gz
(cd "$BACKUP_DIR" && sha256sum *.tar.gz previous-images.tar postgres-all.sql recovery.env volumes.txt > backup.sha256)
(cd "$BACKUP_DIR" && sha256sum -c backup.sha256)
```

정상 기준은 모든 명령이 종료코드 0이고 백업 체크섬이 `OK`인 것입니다. SQL 덤프에는 계정 정보가, 설정 백업에는 연동 비밀값이 포함되므로 백업 폴더의 0700/파일 0600 권한을 유지합니다. `$PREFIX` 밖에 별도로 보관한 TLS 인증서·GitLab PAT 파일이 있으면 해당 파일도 기존 비밀정보 백업 정책에 따라 보존합니다. 이 패치는 그 외부 파일을 변경하지 않습니다.

**백업 실패 시 새 태그 적용을 하지 않습니다.** 실패 원인을 해소하거나 기존 `"$PREFIX/koda-suite" start --prefix "$PREFIX"`로 기존 이미지를 다시 기동합니다. 잠금은 세션 종료 또는 `exec 9>&-`로 해제합니다.

## 6. 기존 포털에 패치 적용

```bash
(cd "$BACKUP_DIR" && sha256sum -c backup.sha256)

docker tag local/koda-patch:20260906 "$KODA_REF"
docker tag local/koda-tracker-web-patch:20260906 "$WEB_REF"

# Tracker는 web만 재생성합니다. 기존 API·Worker·DB 이미지 태그는 유지합니다.
dc up -d --no-build --pull never --no-deps --force-recreate portal-web

# 기존 launcher가 같은 데이터·설정으로 KODA를 재생성하고 다른 서비스를 재시작합니다.
"$PREFIX/koda-suite" start --prefix "$PREFIX"
```

`install`, `reset-install.sh`, `down -v`는 실행하지 않습니다. Gateway도 유지보수 때 중지했다가 재시작되므로 교체한 KODA·Web의 이전 IP를 Nginx가 계속 참조하는 문제를 피합니다. `.env`와 이미지 참조 파일은 유지하며, 기존 launcher는 원래 동작대로 Tracker 토큰 경로를 정규화할 수 있습니다.

`start`가 health timeout으로 끝나면 바로 재설치하지 말고 다음의 `dc ps`와 로그를 확인합니다. Dependency-Track의 기존 데이터 기동이 늦은 경우 준비 완료 후 `status`를 다시 실행합니다.

## 7. 적용 검증

```bash
dc ps
"$PREFIX/koda-suite" status --prefix "$PREFIX"
python3 "$PATCH/preflight.py" --prefix "$PREFIX"

test "$(docker inspect -f '{{.Image}}' koda-dashboard)" = \
  "$(docker image inspect -f '{{.Id}}' local/koda-patch:20260906)"
test "$(docker inspect -f '{{.Image}}' "$(dc ps -q portal-web)")" = \
  "$(docker image inspect -f '{{.Id}}' local/koda-tracker-web-patch:20260906)"

# 기존 백엔드/DB 컨테이너가 그대로인지 확인합니다.
test "$(dc ps -q postgres)" = "$POSTGRES_ID"
test "$(dc ps -q portal-api)" = "$API_ID"
test "$(dc ps -q portal-worker)" = "$WORKER_ID"
test "$(dc ps -q dtrack-apiserver)" = "$DTRACK_ID"
printf 'patch=20260906 applied_at=%s backup=%s\n' "$(date -u +%FT%TZ)" "$BACKUP_DIR" >> "$PREFIX/patches.log"
exec 9>&-
```

`status`의 `/healthz`, `/koda/live`, `/api/v1/healthz`, Dependency-Track 관련 검사들이 정상이어야 합니다. `metadata.env`의 설치 버전은 그대로 남습니다. 이번 적용 여부는 `patches.log`·실행 이미지 ID·`image-inventory.json`으로 확인합니다.

브라우저에서도 다음을 확인합니다.

1. 기존 HTTPS 주소 `/`에서 Tracker 로그인, 기존 계정·서비스·회차가 남아 있는지 확인합니다.
2. `Ctrl+Shift+R`로 새로고침하고 변경된 아이콘·화면이 보이는지 확인합니다.
3. `/koda/`에서 기존 프로젝트·입력·완료 회차·보고서 다운로드를 확인합니다.
4. 작은 테스트 입력으로 새 점검과 Tracker SBOM 업로드·분석을 확인합니다.
5. GitLab 연동은 기존 설정을 유지한 상태에서 저장소·브랜치 조회 후 운영 정책에 맞게 테스트합니다. 실제 점검은 Issue/MR 게시를 일으킬 수 있습니다. 결과 경로와 동일 회차 재시도 시 중복 여부를 확인합니다.

작업 PC의 테스트 통과는 실제 Linux 서버의 로그인·외부 TLS·GitLab 연결 성공을 대신하지 않습니다.

## 8. 문제가 생겼을 때 이미지 롤백

일반 롤백은 **이미지만 이전 것으로 돌립니다. DB·업로드·설정은 유지**합니다. 새 분석·삭제 기능 사용을 중지하고 실행합니다. 새 Bash 세션이라면 아래 백업 경로의 시각을 실제 값으로 바꿉니다.

```bash
bash
set -euo pipefail
umask 077
BACKUP_DIR=/home/user0/koda-backups/실제_백업_시각
(cd "$BACKUP_DIR" && sha256sum -c backup.sha256)
# 이 파일은 위 절차가 printf %q로 만든 로컬 복구 변수 파일입니다. 운영 .env가 아닙니다.
source "$BACKUP_DIR/recovery.env"
export KODA_MEMORY KODA_PIDS_LIMIT KODA_CPUS
exec 9>"$PREFIX/.koda-suite-operation.lock"
flock -n 9 || { echo '다른 패치 작업이 실행 중입니다.' >&2; exit 2; }

"$PREFIX/koda-suite" stop --prefix "$PREFIX"
docker load -i "$BACKUP_DIR/previous-images.tar"
docker tag "local/koda-rollback:$STAMP" "$KODA_REF"
docker tag "local/koda-tracker-web-rollback:$STAMP" "$WEB_REF"
"$PREFIX/koda-suite" start --prefix "$PREFIX"
"$PREFIX/koda-suite" status --prefix "$PREFIX"

test "$(docker inspect -f '{{.Image}}' koda-dashboard)" = "$KODA_OLD_ID"
python3 - "$PREFIX" "$WEB_OLD_ID" <<'PY'
import subprocess,sys
p=sys.argv[1]
cmd=['docker','compose','--project-directory',p+'/tracker','--env-file',p+'/tracker/.env']
for name in ['compose.yaml','compose.airgap.yaml','compose.integration.yaml']:cmd+=['-f',p+'/tracker/'+name]
cid=subprocess.check_output(cmd+['ps','-q','portal-web'],text=True).strip()
assert subprocess.check_output(['docker','inspect','-f','{{.Image}}',cid],text=True).strip()==sys.argv[2]
PY
exec 9>&-
```

같은 세션에서 9번 잠금을 이미 보유 중이라면 기존 `exec 9>&-` 후 롤백용 잠금을 다시 잡습니다. 이미지 롤백 후에도 `deleted_at` 열은 남으며, 이전 버전은 이를 사용하지 않습니다. 삭제 회차 표시·사용자 등록 변경 등 패치 이후 사용자가 변경한 업무 데이터는 이미지 롤백만으로 되돌아가지 않습니다.

DB·파일 자체를 이전 시점으로 복구해야 한다면 일반 패치 롤백과 별도 작업입니다. 현재 데이터를 먼저 추가 백업하고, `postgres-all.sql`·`suite-files.tar.gz`·`volume-*.tar.gz`를 검증한 뒤 복구 시점과 이후 쓰기 보존 여부를 결정해야 합니다. 이 안내서는 기존 데이터를 덮어쓰거나 삭제하는 DB 복구 명령을 자동 절차에 넣지 않았습니다. 기존 `restore-system.sh`에는 DB 삭제가 있으므로 이번 패치 절차로 실행하지 않습니다.

## 9. 증상별 확인

```bash
# 위에서 정의한 dc 함수가 있는 세션에서 실행합니다.
dc ps
dc logs --tail 100 gateway portal-web portal-api portal-worker
docker logs --tail 100 koda-dashboard
docker inspect koda-dashboard --format 'state={{.State.Status}} oom={{.State.OOMKilled}} exit={{.State.ExitCode}}'
```

- **`installed contract differs`**: 서버의 구성 파일이 기준과 다릅니다. 경로만 확인하려면 `diff -q "$PATCH/contract/koda-suite" "$PREFIX/koda-suite"`처럼 비교합니다. 내용을 강제로 덮어쓰거나 검사 코드를 지우지 않습니다.
- **`backend source differs`**: 서버 Tracker가 이 패치의 기준과 다릅니다. 이 파일에는 API·Worker 교체 이미지가 없으므로 별도 호환 패치가 필요합니다.
- **`/healthz`만 성공, `/koda/live` 실패**: gateway 자체는 살아 있지만 `gateway → koda-dashboard:8765` 연결·프로세스를 확인해야 합니다. 이전 대화의 `authentication service unavailable` 문구도 이 경로의 장애일 수 있습니다. `/koda/live`는 인증 예외 경로입니다.
- **화면이 이전과 동일**: `/`는 Tracker, `/koda/`는 KODA인지 먼저 구분하고 강력 새로고침합니다. 위 이미지 ID 검증을 함께 확인합니다.
- **`permission denied`**: 기존 user0의 Docker 권한·데이터 권한을 확인합니다. `chmod -R 777` 또는 전체 폴더 `chown`으로 해결하지 않습니다.
- **포트·TLS 오류**: 기존 외부 TLS reverse proxy 주소와 포트는 이번 패치에서 바꾸지 않습니다. 8088은 기본값일 뿐 실제 값은 기존 `.env`를 따릅니다.

서버에서 `docker pull`, `docker build`, `pip install`, `npm install`은 필요 없습니다. 패치 승인·운영 확인 전에는 이전 이미지·백업을 정리하지 않습니다. `docker compose down -v`, `docker volume rm`, `docker system prune --volumes`, `reset-install.sh`는 사용하지 않습니다.
