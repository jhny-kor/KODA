# KODA Suite 폐쇄망 설치 장애 대응서

대상은 KODA, KODA SBOM Tracker, Dependency-Track을 한 서버에서 운영하는
`koda-suite-offline-x86_64-<버전>.tar.gz` 통합본입니다. 기본 설치 경로는
`/home/user0/koda-suite`, 반입 파일을 푸는 경로는 `/home/user0/koda`로 가정합니다.

비밀번호와 API 키는 명령 출력, 화면 캡처, 메신저에 남기지 않습니다. 아래 명령은
값 대신 설정 키 이름과 상태만 확인합니다.

## 1. 먼저 확인할 공통 상태

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

## 2. 압축 해제·설치 단계

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

## 3. 주소·HTTPS 설정

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

## 4. KODA SBOM Tracker

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
cd /home/user0/koda/koda-suite-offline-x86_64-<새버전>
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

## 5. KODA 화면·로그인·권한

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

## 6. Dependency-Track 화면

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

## 7. Dependency-Track API 키·분석 실패

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

## 8. 이미지·데이터 삭제와 재설치

문제 해결을 위해 `docker system prune -a --volumes`를 실행하지 않습니다. 다른
서비스가 사용하는 PostgreSQL, Nginx, Alpine 이미지와 volume까지 삭제할 수
있습니다.

이미지 사용자를 먼저 확인합니다.

```bash
for image in postgres:16.10-alpine nginx:1.29.1-alpine alpine:3.22.1; do
  echo "=== $image ==="
  docker ps -a --filter "ancestor=$image" \
    --format '{{.ID}} {{.Names}} {{.Status}}'
done
```

출력이 없으면 현재 컨테이너가 그 이미지로 생성되지 않았다는 뜻일 뿐, 다른
Compose 파일이나 향후 재기동이 참조하지 않는다는 보장은 아닙니다. KODA reset이
목적이면 [README의 테스트 설치 완전 초기화](README.md#테스트-설치를-완전히-초기화할-때)에
기재된 정확한 제품 컨테이너·volume만 제거합니다.

전체 초기화는 복구할 데이터가 없다는 것을 확인한 테스트 환경에서만
`reset-install.sh --delete-all-koda-data`로 수행합니다. 이 경로는 백업 없이 기존
prefix와 KODA 소유 volume을 삭제합니다. 데이터를 보존해야 하면 그룹 `patch`만
사용합니다.

## 9. 정상 완료 체크리스트

- 반입 tar.gz SHA-256과 내부 `manifest.sha256`이 모두 일치한다.
- `koda-suite status`가 KODA 직접 공개 포트 없이 세 제품을 정상으로 표시한다.
- `/`, `/koda/`, `/dependency-track/`이 같은 서버 오리진에서 열린다.
- Tracker 로그인 후 `/koda/`로 이동하면 같은 계정 UUID가 전달된다.
- KODA pending 사용자를 승인하고 프로젝트 역할을 부여했다.
- Dependency-Track `static/config.json`과 로그인 XHR에 `localhost`가 없다.
- `verify-dtrack-connection.sh`가 키와 최소 권한을 확인한다.
- 테스트 SBOM 한 건이 오프라인 분석과 Dependency-Track 전송 모두 완료된다.
- 로그아웃 후 Tracker와 KODA 보호 화면이 모두 다시 로그인을 요구한다.
- 초기화 전에 `.env`와 `koda-suite.env`를 새 릴리스 루트에 복사했다.
