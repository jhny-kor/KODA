# KODA · KODA-SBOM-Tracker Linux 설치·패치·장애복구 통합 운영서

작성 기준: 2026-09-09. 대상: Linux x86_64/amd64, Docker 기반 KODA Suite 통합 배포.
이 문서는 서버에서 실행할 절차서이며, 이번 작성 중 운영 서버에 접속하거나 설치·복구를 실행한 결과는 아니다.
과거 장애 기록의 조치안은 현재 소스·배포 문서와 함께 정리했다. 과거 서버 주소·인증서·포트는 현재값으로 재확인한다.

### 작업 유형과 실행 순서

| 유형 | 순서 | 완료 기준 |
|---|---|---|
| 신규 서버 | 1 사전점검 → 3 신규 설치 → 6 TLS/DNS → 7 LDAP → 8 장애 점검 → 9 인수검증 | 외부 HTTPS 로그인 및 두 프로그램 실제 분석 성공 |
| 기존 서버 전체 갱신 | 1 → 2 백업 → 4 전체 갱신 → 6·7 재검증 → 9 | 기존 데이터 유지, 새 이미지와 분석 성공 |
| 호환 그룹 패치 | 1 → 2 → 4 부분 패치 → 9 | 대상 그룹만 교체, 기존 데이터 유지 |
| 20260906 전용 이미지 패치 | 1 → 5의 반입·호환 검사·백업·패치·롤백 절차 | 전용 preflight와 실행 이미지 ID 일치 |
| 장애복구 | 8에서 증상 분류 → 현 상태 백업 → 10 복구 → 9 | 복구 시점 데이터 및 기능 확인 |

통합 구성: 사용자 HTTPS → 외부 Nginx/OpenResty TLS 종료 → Suite HTTP gateway → Tracker(`/`), KODA(`/koda/`), Dependency-Track(`/dependency-track/`).
LDAP 인증·중앙 세션은 Tracker가 담당하며 KODA 프로젝트 권한과 Dependency-Track 자체 UI 로그인은 별도다.

## 1. 서버 사전점검 및 공통 변수

각 유형은 독립된 작업이다. 문서 전체를 한 번에 실행하지 않는다. Bash에서 해당 유형의 블록을 순서대로 실행하고 오류 시 중단한다.
`/home/user0`, 도메인, 반입 경로, 버전은 실제 운영값으로 바꾼다. `VERSION_REPLACE`, `NEW_VERSION_REPLACE`, `UTC_REPLACE`는 실행 전 반드시 실제 값으로 치환한다. 기존 서버는 원래 운영 계정과 PREFIX를 유지한다.

```bash
bash
set -euo pipefail
umask 077
PREFIX="$HOME/koda-suite"
ENV_FILE="$PREFIX/tracker/.env"
FQDN=koda.example.internal
PUBLIC_ORIGIN="https://$FQDN"
uname -m
id
docker version
docker compose version
docker info --format '{{.OSType}}/{{.Architecture}} root={{.DockerRootDir}}'
df -h
df -i
free -h
timedatectl status
for cmd in python3 tar sha256sum flock realpath curl openssl; do command -v "$cmd"; done
ss -lnt
```

기대값: `x86_64`, Docker 서버 정상 응답, Compose v2, 시간 동기화, 예정 포트 충돌 없음.
이미지·압축 해제 공간 최소 15GB 권장에 더해 실제 데이터와 이전 이미지 백업 공간을 확보한다.
Docker 미설치 서버는 배포판에 맞는 승인된 오프라인 Engine/Compose 패키지를 먼저 설치한다. 배포판 미확정 상태에서 임의 저장소 설치 명령을 사용하지 않는다.

기존 설치에만 다음 함수를 정의한다. 통합 구성에서 Compose 파일 하나만으로 전체 서비스를 재기동하지 않는다.

```bash
dc() {
  docker compose --project-directory "$PREFIX/tracker" --env-file "$ENV_FILE" \
    -f "$PREFIX/tracker/compose.yaml" \
    -f "$PREFIX/tracker/compose.airgap.yaml" \
    -f "$PREFIX/tracker/compose.integration.yaml" "$@"
}
test -s "$ENV_FILE"
chmod 600 "$ENV_FILE"
dc ps
"$PREFIX/koda-suite" status --prefix "$PREFIX"
```

기대값: 기존 서비스 running/healthy. 기존 장애가 있으면 아래 장애 장에서 먼저 원인을 기록한다.
`.env`, 전체 `docker inspect` 환경변수, API 키·비밀번호·개인키를 로그나 보고서에 출력하지 않는다.

## 2. 변경 전 백업

먼저 진행 중인 분석·업로드·GitLab 전달을 완료하고 유지보수 시간에 쓰기를 중지한다.
백업 대상: KODA SQLite·입력, Tracker와 Dependency-Track DB, SBOM 원본, 취약점 자료, 운영 설정·토큰, 외부 TLS 설정·인증서, 이전 릴리스·이미지.

### 2.1 일반 전체 백업

아래 백업 스크립트는 PostgreSQL을 자체 기동하지만 준비 완료 대기는 하지 않으므로 먼저 기존 컨테이너를 기동하고 readiness를 확인한다.
설치된 `scripts/lib.sh`는 운영 `.env`를 shell source하므로 운영자가 관리한 신뢰 파일이며 shell 문법에도 맞는지 확인한다.
`ALPINE_BASE_IMAGE`에 지정된 백업 도구 이미지도 폐쇄망 서버에 미리 반입되어 있어야 한다.

```bash
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
BACKUP_DIR="$HOME/koda-backups/$STAMP"
mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"
POSTGRES_ID=$(dc ps -q postgres)
test -n "$POSTGRES_ID"
"$PREFIX/koda-suite" stop --prefix "$PREFIX"
tar -C "$PREFIX/data" -czf "$BACKUP_DIR/koda-portal.tar.gz" koda-portal
# 설정·launcher·secret 경로를 포함한 설치 파일 보존(공간을 먼저 확보).
sudo tar -C "$PREFIX" --exclude=./data --exclude=./tracker/images \
  --exclude=./tracker/source --exclude=./tracker/vulnerability-data \
  -czf - . > "$BACKUP_DIR/suite-config.tar.gz"
docker start "$POSTGRES_ID" >/dev/null
for attempt in $(seq 1 60); do
  if docker exec "$POSTGRES_ID" sh -c 'pg_isready -U "$POSTGRES_USER" -d postgres' >/dev/null 2>&1; then break; fi
  sleep 2
done
docker exec "$POSTGRES_ID" sh -c 'pg_isready -U "$POSTGRES_USER" -d postgres'
ENV_FILE="$ENV_FILE" BACKUP_ROOT="$BACKUP_DIR/tracker" INCLUDE_ENV_IN_BACKUP=1 \
  "$PREFIX/tracker/scripts/backup-system.sh"
```

기대값: `accepting connections`, `Created backup: ...` 및 종료코드 0. 출력된 실제 Tracker 백업 경로를 다음에 넣는다.

```bash
TRACKER_BACKUP="$BACKUP_DIR/tracker/실제_출력된_UTC_디렉터리"
ENV_FILE="$ENV_FILE" "$PREFIX/tracker/scripts/verify-backup.sh" "$TRACKER_BACKUP"
gzip -t "$BACKUP_DIR/koda-portal.tar.gz" "$BACKUP_DIR/suite-config.tar.gz"
(cd "$BACKUP_DIR" && sha256sum koda-portal.tar.gz suite-config.tar.gz > local-files.sha256)
(cd "$BACKUP_DIR" && sha256sum -c local-files.sha256)
```

기대값: `Backup verified`, 체크섬 `OK`. 이는 무결성 검사이며 실제 복원 성공 증명은 아니다. 격리 복구 서버에서 복원 시험한다.
외부 mount에 있는 TLS·CA·PAT·원본·보고서도 권한을 유지해 별도 보관한다. LDAP 암호화 키를 잃으면 저장된 bind 비밀번호를 복호화할 수 없다.
백업만 수행했다면 `"$PREFIX/koda-suite" start --prefix "$PREFIX"` 후 status를 확인한다. 패치 예정이면 중지 상태에서 해당 장으로 간다.

### 2.2 이전 이미지 보존

이미지 태그는 새 릴리스 load로 덮어쓸 수 있다. 변경 전에 실행 이미지 ID와 참조를 기록하고 이전 이미지 tar를 보존한다.
20260906 전용 패치는 5장에 실행 가능한 이미지 백업·롤백이 포함되어 있다.
전체 갱신은 이전 배포 압축파일·외부 checksum 및 설치 설정도 함께 보관한다. DB 스키마가 달라지면 이미지 롤백만으로 복구되지 않을 수 있다.



## 3. 유형 A — 신규 설치

### 서버 조건

- Linux x86_64/amd64
- Docker Engine과 `docker compose` 플러그인 선설치
- Docker 권한이 있는 비루트 운영 계정으로 실행
- `python3`, `tar`, `sha256sum`, `flock`, `realpath`
- 압축 해제 공간과 Docker 이미지·DB 공간을 합쳐 최소 15GB 여유 권장

### 최초 설치와 동시 기동

반입 파일의 SHA-256을 먼저 확인합니다.

```bash
sha256sum -c koda-suite-offline-x86_64-VERSION_REPLACE.tar.gz.sha256
tar -xzf koda-suite-offline-x86_64-VERSION_REPLACE.tar.gz
cd koda-suite-offline-x86_64-VERSION_REPLACE
./koda-suite verify
```

운영 환경파일 `.env` 하나를 준비합니다. 통합 압축파일의
`.env.example`은 Tracker 설정과 포트·게이트웨이·KODA 설정을 이미 합친
파일입니다. 예시의 모든
`change-me-*` 값을 실제 값으로 바꾸고,
`DTRACK_API_BASE_URL`은 브라우저가 접근할 수 있는 Dependency-Track base 주소인
`http://<서버주소>:8088/dependency-track` 형태로 지정합니다. 프론트엔드가 여기에
`/api`를 자동으로 붙이므로 `/dependency-track/api`까지 입력하면 안 됩니다.
관리자 자동화용 `DTRACK_ADMIN_API_BASE_URL`만 `/dependency-track/api`를 포함합니다.
`TRACKER_DEPENDENCY_TRACK_API_KEY`에는 Dependency-Track의 BOM 업로드·프로젝트
생성·조회에 필요한 최소 권한 전용 키를 넣습니다.

```bash
cp .env.example ./.env
chmod 600 ./.env
vi ./.env
./koda-suite install --env-file ./.env
```

위 명령은 기존 named volume과 `$PREFIX/data/koda-portal`을 보존한 채 두 내부
manifest·환경설정·취약점 bundle을 검증하고 모든 이미지를 `docker load`한 뒤
Tracker와 KODA 대시보드를 함께 기동하고 HTTP 상태까지 확인합니다. 압축파일의
`metadata.env`가 `TRACKER_VULNERABILITY_BUNDLE=included`이면 최초 설치에서 Tracker
전용 Grype/NVD/KEV 데이터도 manifest 검증 후 자동 반입합니다. 이 단계는 Docker
volume 반입까지이며, 최초 로그인 후 포털의 `취약점 데이터 → 반입 상태 동기화`를
한 번 실행해야 감사 이력과 기준일이 등록됩니다. 기본 설치
위치는 `$HOME/koda-suite`이며 다른 위치가 필요하면 최초 설치에
`--prefix /원하는/경로`를 추가합니다.

운영 게이트웨이는 반드시 HTTPS로 외부에 게시해야 합니다. 이 번들은 인증서
종료기를 제공하지 않으므로, 앞단 TLS reverse proxy가 원래 Host와 HTTPS scheme을
유지한 채 이 게이트웨이로 전달해야 합니다. `TRACKER_ENVIRONMENT=production`에서는
`GATEWAY_PUBLIC_SCHEME=https`와 `TRACKER_SECURE_COOKIES=true`가 아니면 launcher가
기동을 거부합니다. 개발용 예외는 loopback 전용에서만
`TRACKER_ENVIRONMENT=development`로 명시할 수 있습니다. 최초 Tracker 로그인 후
응답/사용자 관리 화면에서 계정 UUID를 확인하고 KODA 시스템 관리자를 한 번만
bootstrap합니다.

```bash
PREFIX="$HOME/koda-suite"
TRACKER_UUID='Tracker 화면에 표시된 UUID'
"$PREFIX/koda/koda-docker" dashboard bootstrap --tracker-user-id "$TRACKER_UUID"
```

기본 주소:

- Suite: `https://<서버주소>:8088/` (TLS reverse proxy 뒤)
- KODA: `https://<서버주소>:8088/koda/`
- SBOM Tracker: `https://<서버주소>:8088/`
- Dependency-Track: `https://<서버주소>:8088/dependency-track/`

화면 주소는 다음처럼 구분합니다.

- `/`는 KODA-SBOM-Tracker입니다. Tracker에서 수정한 UI는 이 주소에서 확인합니다.
- `/koda/`는 KODA 분석 포털입니다. Tracker에서 승인된 계정은 KODA에도 자동
  활성화되며, KODA 관리자는 필요한 프로젝트 역할만 별도로 배정합니다.
- `/dependency-track/`는 Dependency-Track 화면입니다. 정적 설정 파일 404가 나오면
  새 압축파일의 `install`을 반복하기보다 `./koda-suite status`와
  `docker compose ... logs gateway dtrack-frontend`를 먼저 확인합니다.

Tracker SBOM 업로드 기본 한도는 100MiB이고, KODA 입력 파일은 `/koda/api/`에서
1GiB까지 스트리밍 업로드합니다. 413이 계속되면 앞단 TLS reverse proxy의
`client_max_body_size` 또는 요청 본문 제한도 `/koda/api/` 기준 1GiB 이상으로 맞춥니다.
대용량 업로드가 503으로 끝나지 않도록 통합 gateway에는 `/koda/api/` 전용
1시간 body·proxy timeout과 요청 스트리밍 설정이 포함되어 있습니다. 외부 TLS
reverse proxy도 같은 경로에 `client_body_timeout 1h`, `proxy_send_timeout 1h`,
`proxy_read_timeout 1h`, `proxy_request_buffering off`를 적용해야 합니다.

Tracker UI가 이전 화면으로 보이면 브라우저에서 `Ctrl+Shift+R`로 캐시를 비운 뒤
`/`를 다시 엽니다.

KODA 대시보드의 `SBOM Tracker 열기` 버튼은 기본적으로 same-origin `/`를 엽니다.
별도 Tracker 주소를 사용할 때만 `.env`의
`KODA_SSBOM_TRACKER_URL`을 해당 HTTPS 주소로 바꿉니다.
KODA 컨테이너의 8765 포트는 호스트에 게시되지 않고 통합 게이트웨이 전용 Docker
네트워크에서만 접근됩니다. 인증과 권한은 Tracker 계정 및 게이트웨이의
`auth_request` 계약으로 처리됩니다.



## 4. 유형 B — 전체 갱신 또는 호환 그룹 패치

### 기존 설치를 최신 통합본으로 갱신할 때

지난 릴리스 이후 Compose, 인증 또는 환경변수 전달이 바뀐 통합본은 부분 `patch`가
아니라 같은 설치 경로에 `install`을 다시 실행합니다. 이 방식은 새 이미지를 검증·로드하고
Suite 소유 컨테이너를 `--force-recreate`하지만 다음 데이터는 삭제하지 않습니다.

- KODA 포털 DB와 입력: `$PREFIX/data/koda-portal`
- Tracker 계정·서비스·회차: PostgreSQL `sbom_tracker` DB
- Dependency-Track 프로젝트·정책: PostgreSQL `dtrack` DB와 `dtrack-data` volume
- 업로드 SBOM: `tracker-artifacts` volume
- 반입 취약점 자료: `vuln-data` volume

`reset-install.sh --delete-all-koda-data`, `docker compose down -v`, `docker volume rm`,
`docker system prune --volumes`는 이 갱신 절차에 사용하지 않습니다.

1. 기존 설치와 저장공간을 확인합니다.

```bash
PREFIX="$HOME/koda-suite"
ENV_FILE="$PREFIX/tracker/.env"

test -x "$PREFIX/koda-suite"
test -s "$ENV_FILE"
"$PREFIX/koda-suite" status
df -h "$PREFIX" "$(docker info --format '{{.DockerRootDir}}')"
docker inspect koda-dashboard \
  --format 'name={{.Name}} state={{.State.Status}} image={{.Config.Image}}'
```

정상 기대값은 `koda-dashboard`가 `state=running`, Tracker Compose 서비스가
`running` 또는 `healthy`, 마지막 출력이 `Suite: https://<server>:<port>/`입니다.
공간은 압축 해제 파일과 Docker image를 함께 적재할 수 있도록 최소 15GB를 권장합니다.

2. 운영값을 노출하지 않고 환경 계약을 확인합니다.

```bash
chmod 600 "$ENV_FILE"
grep -E \
  '^(COMPOSE_PROJECT_NAME|PUBLIC_HTTP_PORT|TRACKER_ENVIRONMENT|TRACKER_PUBLIC_ORIGIN|TRACKER_SECURE_COOKIES|DTRACK_API_BASE_URL)=' \
  "$ENV_FILE"
```

운영 환경이면 `TRACKER_ENVIRONMENT=production`, HTTPS origin,
`TRACKER_SECURE_COOKIES=true`여야 합니다. DB 비밀번호와 API 키는 출력하지 않습니다.
LDAP 로그인을 사용할 때만 `TRACKER_LDAP_ENCRYPTION_KEY`가 필요합니다. 기존 값이 없으면
다음 명령으로 실제 키를 화면에 출력하지 않고 추가합니다.

```bash
python3 - "$ENV_FILE" <<'PY'
import base64
import pathlib
import secrets
import sys

path = pathlib.Path(sys.argv[1])
lines = path.read_text(encoding="utf-8").splitlines()
key = "TRACKER_LDAP_ENCRYPTION_KEY"
current = next((line.split("=", 1)[1] for line in lines if line.startswith(f"{key}=")), "")
if not current or current.startswith("change-me"):
    value = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
    lines = [line for line in lines if not line.startswith(f"{key}=")]
    lines.append(f"{key}={value}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
PY
chmod 600 "$ENV_FILE"
```

3. 새 압축파일과 외부 SHA-256을 검증하고 별도 디렉터리에 풉니다.

```bash
RELEASE_DIR=/media/koda-release/latest
cd "$RELEASE_DIR"
sha256sum -c koda-suite-offline-x86_64-VERSION_REPLACE.tar.gz.sha256
tar -xzf koda-suite-offline-x86_64-VERSION_REPLACE.tar.gz
cd koda-suite-offline-x86_64-VERSION_REPLACE
./koda-suite verify
grep -E \
  '^(TARGET_PLATFORM|KODA_GIT_REVISION|TRACKER_GIT_REVISION|KODA_TRACKED_WORKTREE_DIRTY|TRACKER_WORKTREE_DIRTY|TRACKER_VULNERABILITY_BUNDLE)=' \
  metadata.env
```

기대값은 SHA 검사 `OK`, `KODA Suite release integrity OK`,
`TARGET_PLATFORM=linux/amd64`, 두 `*_DIRTY=false`,
`TRACKER_VULNERABILITY_BUNDLE=included`입니다. 하나라도 다르면 설치하지 않습니다.

4. 삭제나 이미지 로드 전에 새 릴리스와 기존 환경의 호환성을 검사합니다.

```bash
./koda-suite preflight \
  --env-file "$ENV_FILE" \
  --prefix "$PREFIX" \
  --require-vulnerability-data
```

기대 출력은 `Air-gap preflight OK`, `Vulnerability bundle verified`,
`KODA Suite preflight OK`이며, 이 명령 자체는 컨테이너나 volume을
삭제하지 않습니다.

5. 이 문서 2장의 전체 백업과 무결성 검증을 완료한다. PostgreSQL 준비 완료를 확인하고, 운영 설정·외부 secret도 보존한다.

6. 같은 `PREFIX`에 최신 통합본을 설치합니다.

```bash
./koda-suite install --env-file "$ENV_FILE" --prefix "$PREFIX"
```

정상 완료 시 각 image의 `Loaded image` 또는 `Loaded image ID`, KODA
`bundle integrity OK`, `smoke tests OK`, Tracker `Air-gap services are healthy`,
마지막에 `installed and started: $PREFIX`가 출력됩니다. 기존 volume과
`$PREFIX/data/koda-portal`은 그대로 유지됩니다.

7. 기존 설치에도 새 취약점 자료를 적용합니다. `install`은 기존 `vuln-data` volume을
보존하므로, 릴리스에 포함된 bundle을 명시적으로 검증·반입합니다.

```bash
"$PREFIX/tracker/scripts/verify-vuln-bundle.sh" \
  "$PREFIX/tracker/vulnerability-data"
ENV_FILE="$ENV_FILE" \
  "$PREFIX/tracker/scripts/import-vuln-bundle.sh" \
  "$PREFIX/tracker/vulnerability-data"
```

기대 출력은 `Vulnerability bundle verified`와
`Imported vulnerability data bundle <version>`입니다. 이후 Tracker 관리 화면의
`취약점 데이터 → 반입 상태 동기화`를 실행하고 새 분석 회차를 시작해야 새 기준일이
분석 결과에 반영됩니다. 기존 완료 회차는 자동 재분석되지 않습니다.

8. 컨테이너·image·HTTP·수정 포함 여부를 확인합니다.

```bash
"$PREFIX/koda-suite" status

PORT="$(awk -F= '$1 == "PUBLIC_HTTP_PORT" {print $2; exit}' "$ENV_FILE")"
curl -fsS "http://127.0.0.1:${PORT}/healthz"
curl -fsS "http://127.0.0.1:${PORT}/api/v1/healthz"
curl -fsS "http://127.0.0.1:${PORT}/koda/live"
curl -fsS "http://127.0.0.1:${PORT}/dependency-track/api/version"
curl -fsS "http://127.0.0.1:${PORT}/dependency-track/static/config.json" \
  | python3 -m json.tool

docker image inspect koda-offline:VERSION_REPLACE \
  --format 'arch={{.Architecture}} revision={{index .Config.Labels "org.opencontainers.image.revision"}} offline={{index .Config.Labels "io.koda.offline"}}'
docker exec koda-sbom-portal-api sh -c \
  "grep -n 'input-format' /app/koda_tracker/main.py /app/koda_tracker/sbom.py"
docker exec koda-sbom-portal-api python -c \
  'import cryptography, ldap3; print("LDAP runtime OK")'
```

기대값은 HTTP 응답이 각각 `ok`, `{"status":"ok"}`, `{"status":"live"}`와
Dependency-Track version JSON이고, image는 `arch=amd64`, `offline=true`입니다.
CycloneDX 확인에는 `--input-format` 코드가 표시되고 마지막 명령은
`LDAP runtime OK`를 출력해야 합니다. 외부 TLS 주소도 별도로 `/`, `/koda/`,
`/dependency-track/`를 열어 로그인·SBOM 업로드·새 분석 회차를 확인합니다.

### 응용프로그램·이미지 부분 교체

새 통합 압축파일을 별도 디렉터리에 풀고 무결성을 확인한 뒤 필요한 그룹만 패치합니다.
Compose·인증·포털 스키마 계약이 달라진 릴리스는 부분 패치를 거부하므로 같은
`PREFIX`에 전체 `install`을 사용합니다. PostgreSQL도 부분 패치 대상이 아닙니다.

```bash
PREFIX="$HOME/koda-suite"
cd /media/koda-release
sha256sum -c koda-suite-offline-x86_64-NEW_VERSION_REPLACE.tar.gz.sha256
cd koda-suite-offline-x86_64-NEW_VERSION_REPLACE
./koda-suite verify
GROUP=portal-api-worker # koda, gateway, portal-web, portal-api-worker, dependency-track 중 하나
./koda-suite patch --group "$GROUP" --prefix "$PREFIX"
./koda-suite status
```

`portal-api`와 `portal-worker`, Dependency-Track API와 frontend는 호환 그룹으로 함께
교체됩니다. 부분 패치는 취약점 volume을 변경하지 않습니다. 취약점 DB까지 새로
설치하려면 별도의 취약점 bundle 검증·반입 명령을 사용합니다. 데이터가 호환되지 않아
의도적으로 전체 초기화해야 하는 테스트 환경에서만 `reset-install.sh
--delete-all-koda-data`를 사용합니다.



## 5. 유형 C — 20260906 전용 패치 절차

이 장의 날짜·태그·이미지 범위는 해당 패키지 전용이다. 다른 릴리스에 날짜만 바꿔 적용하지 않는다. 이 장 자체에 백업이 포함되어 있다.

### 20260906 패키지 상세 안내

작성일: 2026-09-06. 대상: Linux x86_64, Docker Engine 및 Compose가 이미 설치된 서버.

- 기존 설치: `/home/user0/koda-suite`
- 압축파일 반입·해제: `/home/user0/koda-release`
- 백업: `/home/user0/koda-backups/<UTC 시각>`

**기존 설치를 삭제하거나 신규 설치하지 않습니다.** 수정된 애플리케이션 이미지를 `docker load`하고, 기존 이미지 참조에 연결한 다음 같은 데이터 저장소를 연결해 포털 컨테이너를 교체합니다. 실행 중인 컨테이너 내부에 `docker cp`로 파일을 덮어쓰는 방식은 사용하지 않습니다. 따라서 이후 재시작에도 패치가 유지됩니다.

### 1. 포함 범위와 호환 조건

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

### 2. 반입 및 압축 해제

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

### 3. 경로·상태·호환성 확인

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

### 4. 새 이미지 적재와 이전 이미지 보존 — 아직 서비스 중지 없음

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

### 5. 유지보수 중지와 데이터 백업

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

### 6. 기존 포털에 패치 적용

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

### 7. 적용 검증

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

### 8. 문제가 생겼을 때 이미지 롤백

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

### 9. 증상별 확인

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


## 6. SSL/TLS·DNS 설치 및 과거 장애조치

### 6.1 인증서와 실제 Nginx 설정 위치 확인

과거 기록에는 별도 OpenResty 컨테이너와 `/data/docker_data/volumes/nginx` bind mount가 있었다. 현재 서버에서 아래 명령으로 다시 찾는다.

```bash
TLS_CONTAINER=nginx
docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Ports}}'
docker inspect "$TLS_CONTAINER" --format '{{json .Mounts}}' | python3 -m json.tool
docker exec "$TLS_CONTAINER" nginx -T 2>&1 \
  | grep -nE 'server_name|ssl_certificate|include|listen|proxy_pass'
```

기대값: 443을 받는 실제 컨테이너, 호스트 영속 설정·인증서 경로, gateway upstream 식별.
`nginx -T`의 전체 출력은 설정의 민감한 헤더를 포함할 수 있어 외부 공유하지 않는다.

```bash
CERT=/실제/호스트/ssl/fullchain.pem
KEY=/실제/호스트/ssl/privkey.pem
openssl x509 -in "$CERT" -noout -subject -issuer -dates -ext subjectAltName
openssl x509 -in "$CERT" -checkend 2592000 -noout
openssl x509 -in "$CERT" -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum
sudo openssl pkey -in "$KEY" -pubout -outform DER | sha256sum
```

기대값: SAN에 접속 FQDN이 포함, 만료 전, 공개키 SHA-256 두 값 일치. `checkend` 실패는 30일 내 만료이거나 이미 만료됨을 뜻한다.
`*.ssis.or.kr`는 `koda.ssis.or.kr`에 맞지만 `ai.ssis.or.kr` 단독 인증서는 맞지 않는다.
컨테이너에만 남은 인증서를 회수해야 하면 제한된 디렉터리에 `docker cp -L "$TLS_CONTAINER:/실제/경로/fullchain.pem" ./fullchain.pem`으로 심볼릭 링크를 따라 복사한다. 개인키도 보호된 저장 위치에만 보관한다.

### 6.2 영속 설정에 TLS 적용

인증서 발급·CA 체인은 사내 발급 절차로 준비한다. 기존 다른 vhost를 보존하고 실제 include되는 `http {}` 내부에 해당 서버 블록을 반영한다.
다음은 **예시**이며 `koda.example.internal`, 인증서의 컨테이너 경로, upstream 주소를 실측값으로 바꾼다.
프록시가 별도 컨테이너면 `127.0.0.1:8088`은 호스트가 아니라 프록시 자신이므로 gateway에 도달 가능한 호스트 주소를 사용한다.

```nginx
server {
    listen 443 ssl;
    server_name koda.example.internal;
    ssl_certificate /etc/nginx/ssl/fullchain.pem;
    ssl_certificate_key /etc/nginx/ssl/privkey.pem;
    client_max_body_size 1g;
    location = /koda { return 308 /koda/; }
    location / {
        proxy_pass http://192.0.2.10:8088;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        client_body_timeout 1h;
        proxy_send_timeout 1h;
        proxy_read_timeout 1h;
        proxy_request_buffering off;
    }
}
```

외부 비표준 HTTPS 포트가 있으면 Host/origin에도 그 포트를 맞춘다. 내부 gateway 8088은 외부 인증 우회 접근이 불가능하도록 승인된 프록시 경로로 제한한다.
운영 `.env`: `TRACKER_ENVIRONMENT=production`, `GATEWAY_PUBLIC_SCHEME=https`, `TRACKER_SECURE_COOKIES=true`, `TRACKER_PUBLIC_ORIGIN=https://실제도메인`.

```bash
MAIN=/실제/호스트/nginx.conf
sudo cp -p "$MAIN" "$MAIN.before-koda.$(date -u +%Y%m%dT%H%M%SZ)"
sudo vi "$MAIN"
docker exec "$TLS_CONTAINER" nginx -t
docker exec "$TLS_CONTAINER" nginx -s reload
curl -fsS "$PUBLIC_ORIGIN/healthz"
```

기대값: `syntax is ok`, `test is successful`, 외부 HTTPS `ok`. 사설 CA는 `curl --cacert /실제/ca.pem`으로 검사한다. `-k` 성공은 인증서 검증 성공이 아니다.
변경 실패 시 저장한 설정을 영속 원본에 복구하고 `nginx -t` 성공 후 reload한다.

### 6.3 과거 장애별 분기

| 증상·과거 진단 | 서버 확인 명령 | 조치 | 기대값 |
|---|---|---|---|
| `/koda/`가 `http://...:8080/koda/login`으로 이동 | `curl -sS -D - -o /dev/null "$PUBLIC_ORIGIN/koda/"` | 실제 Location이 그 값일 때만 proxy location에 `proxy_redirect http://실제도메인:8080/ https://실제도메인/;` 추가, test/reload | Location이 HTTPS 외부 주소 또는 상대경로 |
| Nginx 수정 후 반영 안 됨 | 아래 host/container hash 비교 | 단일 파일 bind mount의 inode 교체 여부 확인, 원본 보존 후 실제 mount 재연결 또는 아래 동기화 | 두 hash 일치, active 설정과 외부 응답 일치 |
| SBOM 업로드 403 CSRF 오류 | `docker exec "$TLS_CONTAINER" nginx -T 2>&1 \| grep -n 'X-CSRF-Token'` | 과거 `proxy_set_header X-CSRF-Token $cookie_csrf_token;`가 원래 헤더를 지움. 해당 override 제거 후 test/reload, 재로그인 | override 없음, 정상 브라우저 업로드 성공 |
| `DNS_PROBE_FINISHED_NXDOMAIN` | `getent hosts "$FQDN"`; `nslookup "$FQDN"` | 내부 DNS에 실제 서버 A 레코드 등록, 클라이언트 DNS 배포 확인 | hosts 수동 설정 없이 의도한 IP 조회 |
| 인증서 오류 | 위 SAN/만료/키 확인, 아래 TLS handshake | 일치하는 인증서 및 intermediate fullchain·CA 신뢰 수정 | 검증 성공, 이름 일치 |

단일 파일 bind mount의 과거 inode 문제를 확인한 경우에만 다음을 사용한다. 컨테이너 경로는 inspect로 확인한 값이어야 한다.

```bash
CONTAINER_MAIN=/usr/local/openresty/nginx/conf/nginx.conf
sudo sha256sum "$MAIN"
docker exec "$TLS_CONTAINER" sha256sum "$CONTAINER_MAIN"
# mount가 쓰기 가능하고 실제 원본이 올바른 경우: 기존 mounted inode로 내용 전달.
sudo cat "$MAIN" | docker exec -u 0 -i "$TLS_CONTAINER" sh -c 'cat > "$1"' sh "$CONTAINER_MAIN"
docker exec "$TLS_CONTAINER" nginx -t
docker exec "$TLS_CONTAINER" nginx -s reload
```

읽기 전용 mount라면 쓰기를 강행하지 않고 원래 Compose/실행 설정과 모든 mount를 보존해 컨테이너 재생성으로 다시 연결한다.

```bash
SERVER_IP=192.0.2.10
curl --resolve "$FQDN:443:$SERVER_IP" -fsS "$PUBLIC_ORIGIN/healthz"
openssl s_client -connect "$FQDN:443" -servername "$FQDN" \
  -verify_hostname "$FQDN" -verify_return_error </dev/null
```

기대값: HTTPS 상태 정상, `Verify return code: 0 (ok)`. `--resolve` 성공은 DNS 등록 완료를 뜻하지 않는다. 일반 curl과 사용자 PC DNS도 별도 확인한다.

## 7. LDAP/LDAPS/StartTLS 설치 및 오류조치

### 7.1 설정 전 준비

LDAP host·포트, LDAPS/StartTLS 선택, CA 체인, bind DN, Base DN, 로그인·표시명·메일·그룹 속성, 그룹 역할 매핑, 승인 정책을 실제 디렉터리 관리자에게서 확인한다.
웹 HTTPS 인증서와 LDAP 서버 인증서/CA는 별개다. LDAP 암호화 키도 인증서가 아니다.

```bash
dc exec -T portal-api python -c 'import cryptography, ldap3; print("LDAP runtime OK")'
dc exec -T portal-api python - <<'CHECK'
import os
from cryptography.fernet import Fernet
key = os.environ.get('TRACKER_LDAP_ENCRYPTION_KEY', '')
assert key and not key.startswith('change-me'), 'LDAP key missing or placeholder'
Fernet(key.encode())
print('LDAP encryption key format OK')
CHECK
```

기대값: 두 OK. 기존 키는 보존한다. 값의 형식 검사는 DB에 저장된 bind 비밀번호의 복호화 성공까지 증명하지 않는다.
신규 설치이며 저장된 LDAP 비밀번호가 없을 때만 신규 키를 생성한다. 다음은 키를 화면에 표시하지 않고 `.env`에 넣으며 기존 실제 키가 있으면 중단한다.

```bash
python3 - "$ENV_FILE" <<'KEYGEN'
import base64, pathlib, secrets, sys
p = pathlib.Path(sys.argv[1])
lines = p.read_text().splitlines()
name = 'TRACKER_LDAP_ENCRYPTION_KEY'
old = [s.split('=', 1)[1].strip() for s in lines if s.startswith(name + '=')]
assert all(not x or x.startswith('change-me') for x in old), 'Existing key: preserve it'
lines = [s for s in lines if not s.startswith(name + '=')]
lines.append(name + '=' + base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())
p.write_text('\n'.join(lines) + '\n')
p.chmod(0o600)
print('LDAP key configured')
KEYGEN
dc up -d --no-build --pull never --no-deps --force-recreate portal-api portal-worker
```

gateway가 이전 API IP를 참조해 502/503이면 `dc restart gateway` 후 재검사한다. restart만으로 바뀐 환경변수가 반영되지는 않는다.

### 7.2 서버 및 컨테이너에서 연결 확인

```bash
LDAP_HOST=ldap.example.internal
LDAP_CA=/실제/호스트/ldap-ca.pem
getent hosts "$LDAP_HOST"
openssl s_client -connect "$LDAP_HOST:636" -servername "$LDAP_HOST" \
  -CAfile "$LDAP_CA" -verify_hostname "$LDAP_HOST" -verify_return_error </dev/null
# StartTLS를 쓰는 환경은 위 636 대신 다음 검사.
openssl s_client -starttls ldap -connect "$LDAP_HOST:389" -servername "$LDAP_HOST" \
  -CAfile "$LDAP_CA" -verify_hostname "$LDAP_HOST" -verify_return_error </dev/null
# 실제 portal-api 네트워크에서 DNS/TCP 접근 검사(LDAPS 예시).
dc exec -T portal-api python - "$LDAP_HOST" 636 <<'TCP'
import socket, sys
with socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=10):
    print('LDAP TCP OK')
TCP
```

기대값: 올바른 DNS, TLS 검증 성공, `LDAP TCP OK`. TCP 성공만으로 bind나 검색 성공을 판정하지 않는다.
CA 파일은 portal-api에 read-only 영속 mount하고 Tracker 설정에는 **컨테이너 내부 CA 경로**를 지정한다. 호스트 경로만 입력하면 컨테이너에서 읽을 수 없다.

서버에 승인된 `ldapsearch`가 설치된 경우 실제 bind·검색을 추가 검사한다. 비밀번호는 `-W` 프롬프트에 입력한다.

```bash
BIND_DN='cn=svc-koda,ou=service,dc=example,dc=internal'
BASE_DN='dc=example,dc=internal'
LDAPTLS_CACERT="$LDAP_CA" ldapsearch -x -H "ldaps://$LDAP_HOST:636" \
  -D "$BIND_DN" -W -b "$BASE_DN" '(sAMAccountName=approved-test-user)' dn
# StartTLS 환경은 -H "ldap://$LDAP_HOST:389"와 -ZZ를 사용.
```

기대값: 대상 사용자 DN 정확히 1개, LDAP result 0. 출력 DN은 내부 개인정보이므로 공유 시 가린다.
Tracker 관리자 `설정 → LDAP 로그인`에서 실제 TLS·검색필터·속성·그룹 매핑을 저장한다. 검색필터에는 `{username}`이 필요하다.

### 7.3 오류 분류

| 증상 | 확인 및 조치 | 기대값 |
|---|---|---|
| `ldap_not_configured`(구버전 501/현재 문서 503) | 관리자 설정 활성화, API 이미지와 암호화 키 전달 검사 | 구성 저장 및 LDAP 로그인 가능 |
| `ModuleNotFoundError` cryptography/ldap3 | runtime 검사 후 의존성 포함 API/Worker 호환 이미지 패치 | runtime OK; 컨테이너 안 임시 pip 설치로 끝내지 않음 |
| 인증서 검증 실패 | CA mount·읽기 권한·SAN·시간·TLS 모드 확인 | 검증 활성화 상태에서 연결 성공 |
| timeout/refused | host와 컨테이너 DNS·636/389 경로, 방화벽 확인 | TCP/TLS 및 실제 bind 성공 |
| LDAP result 49 | bind 계정 또는 사용자 비밀번호·잠김·만료 확인 | 올바른 계정으로 bind 성공 |
| 검색 0개/여러 개 | Base DN·검색필터·로그인 속성 수정 | 사용자 DN 1개 |
| 암호화/복호화 오류 | 이전 `.env` 키 복구; 키 분실 시 관리자 경로에서 bind 비밀번호 재등록 | 설정 읽기·로그인 성공 |
| 인증 성공 후 승인대기/403 | Tracker 활성화·역할 승인 및 KODA 프로젝트 역할 확인 | 승인 계정으로 재로그인 후 허용 화면 접근 |

LDAP 실패 시 로컬 비밀번호로 자동 우회하지 않는다. 별도로 승인된 로컬 관리자는 로그인 화면에서 로컬 경로를 명시적으로 선택해 관리한다.
인수검증은 LDAP 정상·잘못된 비밀번호·승인대기·권한 없는 프로젝트·로그아웃을 각각 확인한다.

## 8. 설치·분석 장애별 명령과 기대값

아래는 저장소의 기존 장애 대응 절차를 통합한 것이다. 예시 8088·user0·반입 경로를 현재값으로 치환한다.
원인 진단 기록과 모든 운영 서버에서의 재현·해결 완료를 동일하게 취급하지 않는다.

### 1. 먼저 확인할 공통 상태

```bash
PREFIX=/home/user0/koda-suite
ENV_FILE="$PREFIX/tracker/.env"

"$PREFIX/koda-suite" status

docker compose --project-directory "$PREFIX/tracker" \
  --env-file "$ENV_FILE" \
  -f "$PREFIX/tracker/compose.yaml" \
  -f "$PREFIX/tracker/compose.airgap.yaml" \
  -f "$PREFIX/tracker/compose.integration.yaml" \
  ps

curl -fsS http://127.0.0.1:8088/healthz
curl -fsS http://127.0.0.1:8088/api/v1/healthz
curl -fsS http://127.0.0.1:8088/koda/live
curl -fsS http://127.0.0.1:8088/dependency-track/api/version
curl -fsS http://127.0.0.1:8088/dependency-track/static/config.json \
  | python3 -m json.tool
```

정상 기준은 컨테이너가 `running` 또는 `healthy`이고, 다섯 HTTP 상태 경로가 성공하며,
`static/config.json`의 `API_BASE_URL`이 사용자의 브라우저에서 접근 가능한 서버
주소를 가리키는 것입니다. 원격 PC에서 접속하는데 `localhost` 또는 `127.0.0.1`이
보이면 잘못된 설정입니다.

컨테이너 로그는 다음처럼 확인합니다.

```bash
docker compose --project-directory "$PREFIX/tracker" \
  --env-file "$ENV_FILE" \
  -f "$PREFIX/tracker/compose.yaml" \
  -f "$PREFIX/tracker/compose.airgap.yaml" \
  -f "$PREFIX/tracker/compose.integration.yaml" \
  logs --tail=200 gateway portal-api portal-worker dtrack-frontend dtrack-apiserver
```

### 2. 압축 해제·설치 단계

### `gzip: unexpected end of file`, `tar: Unexpected EOF`

압축파일이 전송 중 잘렸거나 다른 파일의 SHA-256을 비교한 경우입니다. 설치를
계속하지 말고 반입 파일부터 다시 확인합니다.

```bash
cd /home/user0/koda
VERSION=0.1.0
ARCHIVE="koda-suite-offline-x86_64-${VERSION}.tar.gz"
sha256sum "$ARCHIVE"
gzip -t "$ARCHIVE"
sha256sum -c "${ARCHIVE}.sha256"
```

세 명령이 모두 성공하지 않으면 파일을 다시 반입합니다. 일부만 풀린 디렉터리는
새 파일 검증이 끝난 후에만 옆으로 이동합니다.

```bash
mv "koda-suite-offline-x86_64-${VERSION}" \
  "koda-suite-offline-x86_64-${VERSION}.incomplete"
```

### 설치 중 단독으로 `unexpected EOF`

`Air-gap preflight OK` 뒤에 셸의 `unexpected EOF`가 나오면 운영 `.env`의 닫히지
않은 작은따옴표·큰따옴표가 가장 흔한 원인입니다. 비밀값을 출력하지 않고 문법만
확인합니다.

```bash
bash -n /home/user0/koda/koda-suite.env
bash -n /home/user0/koda-suite/tracker/.env
```

오류가 표시된 줄의 따옴표를 맞춥니다. 값 뒤에 설명을 붙이거나 스마트 따옴표를
사용하지 않습니다. 수정 후 새 릴리스 디렉터리에서 다시 실행합니다.

```bash
chmod 600 /home/user0/koda/koda-suite.env
VERSION=0.1.0
cd "/home/user0/koda/koda-suite-offline-x86_64-${VERSION}"
cp /home/user0/koda/.env ./.env
cp /home/user0/koda/koda-suite.env ./koda-suite.env
./reset-install.sh --delete-all-koda-data --prefix /home/user0/koda-suite
```

### `tar: Ignoring unknown extended header keyword LIBARCHIVE.xattr...`

macOS가 붙인 확장 속성 경고입니다. 그 뒤 `./koda-suite verify`가 성공하면 파일
내용 손상은 아닙니다. `._` AppleDouble 파일, manifest 실패 또는 실제 EOF가 같이
나오면 새 전달물을 사용합니다. 최신 패키징 스크립트는 macOS 메타데이터를
제외합니다.

### `awk: regexp escape sequence ... is not a known regexp operator`

구형 `koda-suite`의 Linux awk 호환성 경고입니다. 서비스 장애 메시지는 아니지만
구형 launcher를 사용 중이라는 뜻입니다. 설치 디렉터리의 launcher만 임의 수정하지
말고 최신 통합 압축파일의 `reset-install.sh` 또는 검증된 그룹 `patch`를 사용합니다.

### `bash: [: missing ']'` 또는 `command not found`

여러 명령을 한 줄로 합치면서 `[` 조건식, 역슬래시 또는 프롬프트 문자까지 붙여
넣은 경우입니다. 앞에서 `suite stopped`가 출력됐다면 중지는 성공한 것입니다.
문서의 명령 블록 내부만 줄 단위로 다시 실행하고 `user@host:$`, `=` 같은 화면
문자는 입력하지 않습니다.

### `secure` 디렉터리가 없음

`/secure`은 예시일 뿐 필수 디렉터리가 아닙니다. 릴리스 디렉터리에 권한 600으로
만들어도 됩니다.

```bash
VERSION=0.1.0
cd "/home/user0/koda/koda-suite-offline-x86_64-${VERSION}"
cp .env.example ./.env
cp koda-suite.env.example ./koda-suite.env
chmod 600 ./.env ./koda-suite.env
vi ./koda-suite.env
```

### 3. 주소·HTTPS 설정

### `localhost`를 서버 IP로 바꿔야 하는 항목

원격 브라우저에서 접속한다면 다음 값은 `localhost`가 아니라 서버 IP 또는 내부
DNS 이름이어야 합니다.

```dotenv
TRACKER_PUBLIC_ORIGIN=https://koda.example.internal
DTRACK_API_BASE_URL=https://koda.example.internal/dependency-track
DTRACK_ADMIN_API_BASE_URL=https://koda.example.internal/dependency-track/api
KODA_SSBOM_TRACKER_URL=/
```

`DTRACK_API_BASE_URL`에는 `/api`를 붙이지 않습니다. Dependency-Track frontend가
자동으로 붙입니다. 관리자 자동화 주소인 `DTRACK_ADMIN_API_BASE_URL`에만 `/api`를
붙입니다. 내부 서비스 주소인 `dtrack-apiserver:8080`도 브라우저용 값으로 쓰지
않습니다.

내부 DNS가 없다면 서버 IP를 사용할 수 있지만, HTTPS 인증서의 SAN에 그 IP가
포함되어야 합니다. 임의 호스트 이름을 쓰려면 사용자 PC와 TLS reverse proxy가
같은 이름을 해석하고 인증서도 그 이름으로 발급되어야 합니다.

운영 모드는 외부 TLS 종료기가 필요합니다. Uvicorn을 별도로 띄우는 것은 HTTPS
구성 방법이 아닙니다. 테스트용 HTTP만 쓸 때는 폐쇄망·접근제어된 환경에서 다음
개발 설정을 명시합니다.

```dotenv
TRACKER_ENVIRONMENT=development
TRACKER_SECURE_COOKIES=false
GATEWAY_PUBLIC_SCHEME=http
TRACKER_PUBLIC_ORIGIN=http://<서버IP>:8088
DTRACK_API_BASE_URL=http://<서버IP>:8088/dependency-track
DTRACK_ADMIN_API_BASE_URL=http://<서버IP>:8088/dependency-track/api
```

### 4. KODA SBOM Tracker

### 수정한 UI가 아니라 예전 화면이 표시됨

브라우저 캐시 또는 이전 `portal-web` 이미지가 실행 중입니다. 먼저 강력 새로고침
또는 시크릿 창에서 확인합니다. 계속 같으면 현재 컨테이너가 사용하는 이미지와
생성 시각을 확인하고 통합본을 다시 설치합니다.

```bash
docker inspect koda-sbom-portal-web \
  --format 'image={{.Image}} created={{.Created}}'
```

소스 폴더만 교체해도 이미 만들어진 폐쇄망 이미지는 바뀌지 않습니다.

### 3MiB 파일인데 `413 Request Entity Too Large`

현재 Suite의 Tracker API 제한은 100MiB이고 KODA 입력 파일 제한은 1GiB입니다.
작은 파일에서 413이면 대부분 앞단 TLS reverse proxy 또는 구형 gateway가 더 작은
제한을 적용하고 있습니다.

```bash
grep '^UPLOAD_MAX_BYTES=' "$ENV_FILE"

docker compose --project-directory "$PREFIX/tracker" \
  --env-file "$ENV_FILE" \
  -f "$PREFIX/tracker/compose.yaml" \
  -f "$PREFIX/tracker/compose.airgap.yaml" \
  -f "$PREFIX/tracker/compose.integration.yaml" \
  exec gateway nginx -T 2>/dev/null | grep client_max_body_size
```

정상값은 Tracker의 `UPLOAD_MAX_BYTES=104857600`, 서버 기본값
`client_max_body_size 100m;`, `/koda/api/`의 `client_max_body_size 1g;`입니다. 외부
Nginx·Apache·L7 장비도 KODA 경로는 1GiB 이상이어야 합니다.
설정 변경 후 gateway와 API만 오프라인 모드로 재생성합니다.

```bash
docker compose --project-directory "$PREFIX/tracker" \
  --env-file "$ENV_FILE" \
  -f "$PREFIX/tracker/compose.yaml" \
  -f "$PREFIX/tracker/compose.airgap.yaml" \
  -f "$PREFIX/tracker/compose.integration.yaml" \
  up -d --no-build --pull never --force-recreate gateway portal-api
```

### KODA 입력 업로드에서 `503 authentication service unavailable`

KODA 애플리케이션의 파일 형식 오류는 `422`, 용량 초과는 `413`으로 응답합니다.
47바이트 JSON `{"detail":"authentication service unavailable"}`가 보이면 gateway의
인증 subrequest가 실패했거나, 구형 gateway가 대용량 요청의 기본 60초 timeout을
초과한 것입니다. 최신 통합본의 `/koda/api/`에는 1시간 body·proxy timeout과
`proxy_request_buffering off`가 있으므로 gateway 설정과 이미지를 함께 교체합니다.
새 통합 압축파일을 푼 디렉터리에서 다음처럼 gateway 그룹만 교체할 수 있습니다.

```bash
cd /home/user0/koda/koda-suite-offline-x86_64-NEW_VERSION_REPLACE
./koda-suite verify
./koda-suite patch --group gateway --prefix /home/user0/koda-suite
```

```bash
docker compose --project-directory "$PREFIX/tracker" \
  --env-file "$ENV_FILE" \
  -f "$PREFIX/tracker/compose.yaml" \
  -f "$PREFIX/tracker/compose.airgap.yaml" \
  -f "$PREFIX/tracker/compose.integration.yaml" \
  exec gateway nginx -T 2>/dev/null \
  | grep -E 'client_body_timeout|proxy_(connect|send|read)_timeout|proxy_request_buffering'

docker compose --project-directory "$PREFIX/tracker" \
  --env-file "$ENV_FILE" \
  -f "$PREFIX/tracker/compose.yaml" \
  -f "$PREFIX/tracker/compose.airgap.yaml" \
  -f "$PREFIX/tracker/compose.integration.yaml" \
  logs --tail=200 gateway portal-api portal-worker
```

외부 TLS reverse proxy를 별도로 사용하는 경우에도 `/koda/api/` location에 아래
설정을 추가합니다. 외부 proxy가 60초에 끊기면 내부 gateway 설정만으로는 고칠 수
없습니다.

```nginx
location ^~ /koda/api/ {
    client_max_body_size 1g;
    client_body_timeout 1h;
    proxy_connect_timeout 30s;
    proxy_send_timeout 1h;
    proxy_read_timeout 1h;
    proxy_request_buffering off;
    proxy_pass http://127.0.0.1:8088;
}
```

인증 subrequest 장애를 우회하기 위해 쿠키 검사나 `auth_request`를 제거하지
않습니다. 인증이 실제로 중단된 경우에는 보안상 업로드를 거부해야 합니다.

### 5. KODA 화면·로그인·권한

### 로그인 후 `접근 대기`, 계정 식별자(UUID)가 표시됨

현재 버전에서는 Tracker에서 승인된 계정이 KODA에도 자동 활성화됩니다. 이 화면이
계속 보이면 이전 KODA 이미지를 실행 중인 것입니다. 통합 Compose로 KODA 컨테이너를
재생성한 뒤 다시 확인합니다.

```bash
cd /home/user0/koda-suite
./koda-suite stop
./koda-suite start
```

KODA 최초 시스템 관리자 bootstrap은 설치 시 한 번만 필요합니다. 일반 사용자는
Tracker 승인 후 자동 활성화되고, KODA 관리자는 프로젝트 역할만 별도로 배정합니다.

### LDAP 체크 후 `503 ldap_not_configured` 또는 LDAP 연결 오류

LDAP은 Tracker 관리자의 `설정 → LDAP 로그인`에서 먼저 활성화해야 합니다. 서버·bind
DN·검색 기준 DN·TLS/CA·속성·그룹 매핑을 확인하고, `TRACKER_LDAP_ENCRYPTION_KEY`가
portal-api 컨테이너에 전달되는지 확인합니다. LDAP 실패 후 로컬 비밀번호로 자동
fallback되지 않으며, 통합 KODA는 Tracker의 검증된 세션을 사용합니다.

### KODA 웹에서 라이브러리 취약점이 0건

구형 KODA 이미지는 웹 스캔에서 오프라인 Grype DB를 호출하지 않았습니다. 최신
KODA 이미지에는 다음 환경값이 있어야 합니다.

```bash
docker inspect koda-dashboard \
  --format '{{range .Config.Env}}{{println .}}{{end}}' \
  | grep -E '^(KODA_GRYPE_BIN|GRYPE_DB_CACHE_DIR)='
```

`KODA_GRYPE_BIN=/opt/koda/tools/grype`와
`GRYPE_DB_CACHE_DIR=/opt/koda/grype-db/db`가 보여야 합니다. 새 KODA 전달물을 같은
prefix에 설치한 뒤 Suite를 재시작합니다. Tracker·Dependency-Track 이미지와 named
volume은 삭제하지 않습니다.

웹 의존성 검사는 `requirements.txt`, `package-lock.json`, `pom.xml`처럼 정확한
이름·버전 또는 PURL을 얻을 수 있는 manifest/lockfile을 대상으로 합니다.
JAR/WAR/EAR 내부 라이브러리는 기존 `jar-scan`을 사용합니다.

### 6. Dependency-Track 화면

### `/api/version`은 되지만 화면이 흰색

API 컨테이너는 살아 있지만 frontend 정적 설정, 공개 base URL 또는 브라우저 캐시가
잘못된 경우입니다. 다음 항목이 모두 200인지 확인합니다.

```bash
curl -I http://127.0.0.1:8088/dependency-track/
curl -I http://127.0.0.1:8088/dependency-track/static/config.json
```

HTML이 참조하는 `js/app.*.js`, `css/app.*.css`도 200이어야 합니다.
`static/config.json`이 404이면 구형 gateway가 public prefix를 제거하지 못한
것입니다. 최신 통합본의 gateway를 사용합니다.

구형 통합본에서 `DTRACK_BASE_PATH=/dependency-track`를 frontend에 그대로 넘기면
`<base href=/dependency-track>`가 되어 JS가 `/js/...`로 요청될 수 있습니다. 이때는
`tracker/compose.yaml`의 frontend `BASE_PATH`에만 `/`를 추가한 뒤 frontend와
gateway를 재생성합니다. 새 통합본에서는 이 보정이 포함됩니다.

`static/config.json`이 200이어도 `API_BASE_URL`이 `localhost`이면 원격 PC는 자기
PC의 8088로 접속하므로 로그인 요청이 `ERR_CONNECTION_REFUSED`가 됩니다. `.env`를
서버 IP/FQDN으로 고친 뒤 frontend와 gateway를 재생성합니다.

```bash
docker compose --project-directory "$PREFIX/tracker" \
  --env-file "$ENV_FILE" \
  -f "$PREFIX/tracker/compose.yaml" \
  -f "$PREFIX/tracker/compose.airgap.yaml" \
  -f "$PREFIX/tracker/compose.integration.yaml" \
  up -d --no-build --pull never --force-recreate dtrack-frontend gateway
```

그 뒤 `static/config.json`을 다시 확인하고 브라우저 시크릿 창에서 엽니다. HTML의
`<base href="/dependency-track/">`만 정상이라고 화면 전체가 정상인 것은 아닙니다.
개발자도구 Network에서 로그인/XHR URL까지 확인해야 합니다.

### Dependency-Track 로그인 계정

Dependency-Track UI 계정은 Tracker 계정과 별도입니다. 최초 Dependency-Track
관리자 계정으로 로그인하여 비밀번호를 변경하고 전용 automation team/API 키를
발급합니다. 이 UI 로그인은 KODA/Tracker SSO 대상이 아닙니다.

### 7. Dependency-Track API 키·분석 실패

### `TRACKER_DEPENDENCY_TRACK_API_KEY`에 넣는 값

Tracker가 BOM을 업로드하고 프로젝트·취약점·정책 결과를 조회할 전용
Dependency-Track team API 키입니다. Tracker의 서비스 API 토큰이나 사용자
비밀번호를 넣지 않습니다. 필요한 최소 권한은 다음과 같습니다.

- `BOM_UPLOAD`
- `PROJECT_CREATION_UPLOAD`
- `PORTFOLIO_MANAGEMENT_UPDATE`
- `VIEW_PORTFOLIO`
- `VIEW_VULNERABILITY`
- `VIEW_POLICY_VIOLATION`

team의 사용자 멤버가 0명이어도 API 키 인증에는 문제가 없습니다. team에 키와
권한이 있는지가 중요합니다.

### `HTTP 401 Unauthorized`

키가 틀렸거나, 다른 Dependency-Track 인스턴스에서 발급됐거나, `.env` 수정 후
`portal-api`와 `portal-worker`를 재생성하지 않은 경우입니다.

```bash
cd /home/user0/koda-suite/tracker
./scripts/verify-dtrack-connection.sh

docker compose --env-file .env \
  -f compose.yaml -f compose.airgap.yaml -f compose.integration.yaml \
  up -d --no-build --pull never --force-recreate portal-api portal-worker

./scripts/verify-dtrack-connection.sh
```

성공 기준은 `Dependency-Track connection OK`와 여섯 권한 목록입니다.

### `PUT v1/permission/team (HTTP 304)`

Dependency-Track가 권한이 이미 같은 상태라고 응답한 것입니다. 최신
`configure-dtrack-key.sh`는 이 응답을 성공으로 처리합니다. 구형 스크립트가
실패로 처리하면 최신 Tracker/통합 압축파일을 사용합니다. 관리자 키는 `.env`에
저장하지 않고 현재 셸에만 입력합니다.

```bash
read -rsp 'Dependency-Track 관리자 API 키: ' DTRACK_ADMIN_API_KEY; echo
export DTRACK_ADMIN_API_KEY
export DTRACK_ADMIN_API_BASE_URL=http://127.0.0.1:8088/dependency-track/api
DTRACK_TARGET_ENV_FILE=/home/user0/koda-suite/tracker/.env \
  ./scripts/configure-dtrack-key.sh
unset DTRACK_ADMIN_API_KEY
```

스크립트가 새 전용 키를 `.env`에 저장하면 `portal-api`와 `portal-worker`를 재생성한
뒤 연결 검사를 실행합니다. 기존 키가 있는 team은 의도치 않은 연동 단절을 막기
위해 자동 회전하지 않습니다.

### 분석 상태가 `failed`, `/api/v1/bom`이 HTTP 400

인증은 통과했지만 Dependency-Track가 SBOM 본문을 거부했습니다. 원본을 보존하고
다음을 확인합니다.

- JSON 최상위 `bomFormat`이 `CycloneDX`인지
- `specVersion`, `components`, 각 component의 필수 필드가 유효한지
- 파일 내용이 실제 UTF-8 JSON/XML인지
- Dependency-Track 버전이 해당 CycloneDX spec을 지원하는지

Tracker는 CycloneDX 1.4~1.7 입력을 보관할 수 있지만 Dependency-Track 5.0.3의
수용 범위와는 별도입니다. `specVersion` 문자열만 1.7에서 1.6으로 바꾸면 1.7 전용
필드가 남아 잘못된 문서가 될 수 있습니다. 연결망 PC에서 CycloneDX CLI로 1.6으로
검증·변환하거나 생성 도구에서 처음부터 1.6을 출력한 뒤 폐쇄망으로 반입합니다.

오프라인 Grype 분석이 `completed`라면 Tracker 내부 취약점 결과는 유효하며,
Dependency-Track 전송만 실패한 부분 성공 상태입니다. 원인을 고친 뒤 화면의
`DTrack 재시도`를 사용합니다.



### 추가: CycloneDX 자동 감지 실패

과거 `Unable to auto-detect input format`은 확장자 없는 임시 파일에 CLI 형식을 전달하지 않는 구버전 API 경로로 진단되었다.

```bash
dc exec -T portal-api sh -c "grep -n 'input-format' /app/koda_tracker/main.py /app/koda_tracker/sbom.py"
```

기대값: 형식 지정 구현이 확인됨. 코드 문자열만으로 처리가 검증되지는 않으므로 실제 CycloneDX JSON/XML로 새 업로드를 확인한다.
미포함이면 4장의 API/Worker 호환 그룹 또는 전체 릴리스 갱신을 사용한다. 5장의 web-only Tracker 패치는 이 API 오류를 고치지 못한다.
JSON은 `bomFormat: CycloneDX`, 지원 `specVersion`인지 검사한다. package-lock/SPDX를 확장자만 바꾸거나 버전 문자열만 낮추지 않는다.

### 추가: OOM·디스크·DB 준비 실패

```bash
df -h
df -i
docker system df
docker inspect koda-dashboard --format 'state={{.State.Status}} oom={{.State.OOMKilled}} exit={{.State.ExitCode}}'
dc logs --tail 100 postgres portal-api portal-worker dtrack-apiserver
docker logs --tail 100 koda-dashboard
```

기대값: 공간/inode 확보, OOM false, 반복 재시작·DB 접속 오류 없음. DTrack 초기 기동은 오래 걸릴 수 있으므로 로그와 readiness를 보고 판단한다.
DB 비밀번호를 `.env`만 바꾸면 기존 DB 계정 비밀번호는 자동 변경되지 않는다. 기존 자격증명 복원 또는 정식 DB 비밀번호 변경 절차로 맞춘다.
권한 오류는 실제 mount와 UID/GID를 확인해 필요한 경로만 조정하며 `chmod -R 777`을 사용하지 않는다.
공간 부족을 운영 volume 삭제나 `docker system prune --volumes`로 해결하지 않는다.

## 9. 공통 인수검증

```bash
"$PREFIX/koda-suite" status --prefix "$PREFIX"
dc ps
PORT=$(awk -F= '$1 == "PUBLIC_HTTP_PORT" {print $2; exit}' "$ENV_FILE")
: "${PORT:=8088}"
curl -fsS "http://127.0.0.1:$PORT/healthz"
curl -fsS "http://127.0.0.1:$PORT/api/v1/healthz"
curl -fsS "http://127.0.0.1:$PORT/koda/live"
curl -fsS "http://127.0.0.1:$PORT/dependency-track/api/version"
curl -fsS "http://127.0.0.1:$PORT/dependency-track/static/config.json" | python3 -m json.tool
curl -fsS "$PUBLIC_ORIGIN/healthz"
```

| 검사 | 기대값 |
|---|---|
| gateway `/healthz` | HTTP 200, `ok` |
| Tracker `/api/v1/healthz` | HTTP 200, `{"status":"ok"}` |
| KODA `/koda/live` | HTTP 200, `{"status":"live"}` |
| DTrack version/config | version JSON, 브라우저에서 접근 가능한 API_BASE_URL; base에 `/api` 중복 없음 |
| 외부 HTTPS | 인증서 검증 성공, 내부 HTTP 포트로 리다이렉트되지 않음 |
| 기존 데이터 | 계정·서비스·프로젝트·회차·입력·보고서 유지 |
| 실제 기능 | Tracker SBOM 업로드→분석 완료, KODA 작은 입력→결과→보고서 다운로드 |
| 인증 | 로컬/LDAP 정책대로 로그인, 승인·프로젝트 역할 적용, 중앙 로그아웃 |
| 취약점 데이터 | 반입 상태 동기화 후 기준일 확인, 새 회차에 적용 |
| GitLab | 기존 설정 보존; 실제 게시 검증은 승인된 테스트 프로젝트에서만 수행 |

health 성공은 실제 LDAP 로그인·분석·외부 TLS·GitLab 게시 성공의 대체 증거가 아니다.
검증 기록에는 일시, 작업자, 서버, 패키지 SHA-256, 이전/이후 이미지 ID, 백업 경로, 상태 응답, 실제 기능 결과를 남긴다.

## 10. 롤백 및 데이터 복원

5장 전용 이미지 롤백을 우선 사용한다. 일반 전체 갱신은 이전 릴리스와 DB 스키마 호환성을 확인한 뒤 복구한다.
아래 데이터 복원은 **현재 DB·volume을 이전 시점으로 덮어쓰는 별도 작업**이다. 복구 시점 이후 변경을 먼저 추가 백업하고 복구 대상·시점을 확정한 후 실행한다.
Tracker dump 형식 백업은 2장 backup-system.sh 결과에만 적용한다. 5장의 `postgres-all.sql` 백업을 restore-system.sh에 넣지 않는다.
복구 전에 동일 DB/volume 이름, 호환 PostgreSQL 버전·운영 설정·원래 LDAP 키, 백업 checksum을 확인한다.

### 데이터만 복원

KODA 포털 데이터만 되돌릴 때는 백업 해시를 확인하고 현재 디렉터리를 즉시 삭제하지
말고 옆으로 이동해 둡니다.

```bash
PREFIX="$HOME/koda-suite"
BACKUP_DIR=/media/koda-backup/UTC_REPLACE
(cd "$BACKUP_DIR" && sha256sum -c local-files.sha256)

"$PREFIX/koda-suite" stop
mv "$PREFIX/data/koda-portal" \
  "$PREFIX/data/koda-portal.before-restore.$(date -u +%Y%m%dT%H%M%SZ)"
tar -C "$PREFIX/data" -xzf "$BACKUP_DIR/koda-portal.tar.gz"
"$PREFIX/koda-suite" start
"$PREFIX/koda-suite" status
```

Tracker·Dependency-Track 데이터를 되돌릴 때는 백업 당시와 호환되는 릴리스와
`.env`를 먼저 준비합니다. 복원 스크립트는 현재 DB와 named volume을 교체하고
PostgreSQL만 기동한 상태로 끝나므로 Suite를 다시 시작해야 합니다.

```bash
PREFIX="$HOME/koda-suite"
TRACKER_BACKUP=/media/koda-backup/UTC_REPLACE/tracker/UTC_REPLACE

"$PREFIX/koda-suite" stop
ENV_FILE="$PREFIX/tracker/.env" \
  "$PREFIX/tracker/scripts/verify-backup.sh" "$TRACKER_BACKUP"
ENV_FILE="$PREFIX/tracker/.env" \
  "$PREFIX/tracker/scripts/restore-system.sh" "$TRACKER_BACKUP"
"$PREFIX/koda-suite" start
"$PREFIX/koda-suite" status
```

백업과 현재 `.env`의 `COMPOSE_PROJECT_NAME`, DB 이름, volume 이름이 다르면 임의로
복원하지 않습니다. 계정·권한·점검 정책을 관리자 화면에서 대량 변경하기 전에도
Tracker DB와 KODA 포털 디렉터리 중 해당 저장소를 먼저 백업합니다.


복원 스크립트의 성공 문구만으로 끝내지 않고 9장을 수행한다. PostgreSQL globals의 기존 role 충돌, pg_restore 오류가 있으면 로그를 확인하고 격리 복원에서 검증한다. 운영 DB에 실패한 복원을 반복하지 않는다.
KODA와 Tracker의 같은 시점 복원이 필요한 장애에서 한쪽 데이터만 되돌리면 계정·권한·업로드 연결이 불일치할 수 있다.

## 11. 근거와 적용 범위

현재 저장소에서 확인한 자료(배포본/설치본의 같은 파일을 대조):

- KODA `platforms/linux/suite/README.md`, `TROUBLESHOOTING.md`, `koda-suite`, `compose.integration.yaml`.
- KODA `platforms/linux/patch/README.md`: 20260906 전용 패치·이미지 보존·롤백.
- Tracker `docs/operations-ko.md`, `docs/troubleshooting-ko.md`, `apps/api/koda_tracker/ldap_auth.py`.
- Tracker `scripts/backup-system.sh`, `verify-backup.sh`, `restore-system.sh`, `lib.sh`, `install-airgap.sh`, `preflight-airgap.sh`.
- 2026-08-20~24 TLS·Nginx·CSRF·CycloneDX·DNS 진단 기록: 일부는 설정/소스 기반 진단이며 현 서버 해결 완료 증거는 별도 필요.

기존 작업 파일을 변경하지 않고 이 단일 운영서를 추가했다. Docker 자체 설치와 인증서 발급은 OS·사내 반입/발급 정책에 따라 달라지므로 승인된 패키지·인증서를 준비한 단계부터 실행한다.
