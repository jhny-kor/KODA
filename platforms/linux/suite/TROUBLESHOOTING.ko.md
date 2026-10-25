# KODA Suite 폐쇄망 설치·운영 장애 대응

대상은 KODA와 KODA SBOM Tracker 두 제품의 현행 통합본입니다. 아래 예시는 설치 경로 `/opt/koda-suite`, gateway 포트 `8088`을 사용합니다. 실제 설치 경로·포트는 해당 서버 설정에 맞춥니다. 비밀값은 지원 자료에 포함하지 않고 상태·오류 코드·시각·릴리스 식별자를 기록합니다.

## 1. 공통 상태부터 확인

```bash
PREFIX=/opt/koda-suite
ENV_FILE="$PREFIX/tracker/.env"
dc() {
  docker compose --project-directory "$PREFIX/tracker" \
    --env-file "$ENV_FILE" \
    -f "$PREFIX/tracker/compose.yaml" \
    -f "$PREFIX/tracker/compose.airgap.yaml" \
    -f "$PREFIX/tracker/compose.integration.yaml" "$@"
}
"$PREFIX/koda-suite" status --prefix "$PREFIX"
dc ps
curl -fsS http://127.0.0.1:8088/healthz
curl -fsS http://127.0.0.1:8088/api/v1/healthz
curl -fsS http://127.0.0.1:8088/koda/live
```

`status`는 두 제품과 worker 준비 상태를 확인합니다. gateway 응답만 성공해도 분석 worker가 준비되었다고 판단하지 않습니다. 컨테이너별 상태·종료 코드·재시작 횟수와 해당 시각의 로그를 함께 확인합니다.

```bash
dc logs --tail=100 gateway portal-api portal-worker portal-data-updater

docker logs --tail=100 koda-dashboard
docker logs --tail=100 koda-scan-worker
docker logs --tail=100 koda-delivery-worker
```

## 2. 압축 해제·검증·설치가 실패

- `verify` 실패: 전달물과 `.sha256`, 서명·검증 키, 내부 manifest를 확인하고 같은 릴리스의 완전한 파일을 다시 반입합니다. 검사 파일을 편집해 통과시키지 않습니다.
- `preflight` 실패: Linux x86_64, Docker/Compose v2, Python 3·Bash·sha256sum·flock과 디스크·inode 여유를 확인합니다.
- 환경 설정 오류: 실제 서버용 `.env`의 필수 DB·관리자·암호화 키와 공개 오리진을 확인합니다. 이전 릴리스의 예시값이나 포트 점유도 점검합니다.
- 이미지 없음: 전달물의 이미지 목록·태그·아키텍처와 Docker에 반입된 이미지를 비교합니다. 인터넷 pull에 의존해 설치 오류를 가리지 않습니다.

```bash
uname -m
docker version
docker compose version
df -h /opt/koda-suite
df -i /opt/koda-suite
```

새 전달물을 푼 디렉터리에서 `./koda-suite verify`와 `preflight`를 먼저 수행하고, 실패 원인을 해결한 뒤 같은 설치 경로로 `install`을 다시 실행합니다.

## 3. 로그인·세션·권한 오류

Tracker 로그인은 `/`, KODA 포털은 `/koda/`입니다. 운영 모드는 HTTPS와 Secure Cookie가 필요합니다. 로그인 직후 다시 로그인 화면이 나오면 브라우저가 실제 접속한 오리진, `TRACKER_PUBLIC_ORIGIN`, proxy의 HTTPS 전달 정보와 쿠키 설정을 맞춥니다.

| 현상 | 확인할 항목 |
| --- | --- |
| 401·로그인 반복 | 쿠키 저장 여부·만료, 실제 HTTPS 오리진, 세션과 계정 활성 상태 |
| 변경 요청 403 | 사용자 역할·기능 권한, CSRF 토큰, 동일 오리진 요청 여부 |
| KODA 프로젝트 404 | Tracker 로그인 외에 KODA 프로젝트 접근 권한이 부여되었는지 |
| 로그인 성공·일부 화면 없음 | 승인 상태와 화면·기능별 역할 정책 |
| LDAP 실패 | 승인된 내부 LDAP 목적지 연결, CA·bind 설정·암호화 키 보존 여부 |

운영 장애를 해결하려고 개발 모드나 임의 인증 헤더로 우회하지 않습니다. 서버 시각이 크게 틀리면 세션·서명·자료 유효기간 판정도 어긋나므로 호스트 시간을 함께 확인합니다.

## 4. DB 연결·부팅 실패

```bash
dc ps postgres portal-api portal-worker
dc logs --tail=100 postgres portal-api portal-worker
```

DB 준비 여부, `.env`의 DB 사용자·비밀번호·연결 문자열, 현재 설치의 volume 연결을 확인합니다. 기존 PostgreSQL volume에는 초기화용 비밀번호 변경이 자동 반영되지 않을 수 있으므로 운영 자격증명 변경 절차를 따릅니다.

DB 또는 artifact가 없다는 이유로 전체 볼륨 삭제나 초기화를 먼저 실행하지 않습니다. 백업과 설치 식별자를 확인하고 격리된 복원 대상으로 검증합니다. KODA SQLite와 Tracker PostgreSQL은 서로 다른 저장소입니다.

## 5. SBOM 업로드·정규화 실패

현재 지원하는 CycloneDX JSON/XML 또는 SPDX 2.3 JSON인지 확인합니다. 업로드 제한, 패키지 식별자·필수 필드, 중복 참조, 잘못된 해시·관계 대상, 선택적 스키마 검사 오류를 확인합니다.

- 거절된 원본은 별도로 보존하고 오류가 지목한 형식·필드를 수정합니다.
- 구성요소 수와 품질 진단은 중첩 구성까지 포함한 정규화 결과를 확인합니다.
- artifact 원본 해시·회차 ID와 정규화·분석 상태를 구분합니다. 업로드 접수만으로 취약점 분석 완료를 뜻하지 않습니다.
- 입력이 달라졌으면 새 SBOM 회차로 분석합니다. 과거 원본을 덮어써 결과를 맞추지 않습니다.

## 6. Grype 분석 대기·실패·결과 없음

Tracker의 작업·회차 상세와 `portal-worker` 로그, KODA의 `koda-scan-worker` 상태를 확인합니다. 반입한 Grype 실행 파일·DB의 호환 스키마, 활성 릴리스 경로·권한·기준일, 내부 디스크 여유를 점검합니다.

분석 실패와 정상 완료 후 발견 없음은 다른 상태입니다. DB 없음·지원하지 않는 버전·정규화 실패·자원 종료가 있으면 미평가이며 통과로 해석하지 않습니다. 인터넷 연결이나 자동 DB 갱신을 켜서 폐쇄망 설정을 우회하지 않습니다.

새 자료를 검증·반입한 뒤 필요한 회차에 새 분석 리비전을 생성하고, 결과의 실제 Grype 버전·데이터 기준일·정책 버전을 확인합니다. 발견이 달라질 때에는 PURL·버전·배포판 정보와 피드 기준일을 비교합니다.

## 7. CPE·EPSS·보강 자료가 없거나 오래됨

| 상태 | 확인·대응 |
| --- | --- |
| CPE unknown·incomplete | SBOM의 정확한 CPE와 NVD 적용 조건·버전 범위·환경 조건이 보존되었는지 확인 |
| 과거 문자열 전용 NVD | 현행 생성기로 적용 조건을 포함한 자료를 다시 준비 |
| EPSS missing·invalid | CSV(.gz) 형식·원본 날짜·모델 정보·확률 범위·중복/충돌·해시 확인 |
| EPSS stale | 실제 원본 기준일과 허용 일수를 확인하고 새 승인 자료 반입 |
| 보강 자료 검증 실패 | index와 원본 sidecar의 경로·크기·해시, schema·지원 종류·출처 날짜 확인 |
| 반입 성공·이전 결과 표시 | 활성 릴리스와 분석 리비전의 근거를 비교한 뒤 재분석 |

반입 시각을 최신 점수 기준일로 바꾸지 않습니다. 보강 자료의 원본과 분석 당시 출처 스냅샷을 보존합니다. 공급자 VEX의 영향 없음 주장이나 SSVC 참고 입력은 자동 억제·확정 결정을 의미하지 않습니다.

## 8. SSVC 저장 충돌·재평가 필요

SSVC는 정확한 회차·구성요소·버전·취약점과 분석 리비전에 연결됩니다. 저장 중 409가 나오면 현재 완료된 분석을 새로 조회하고 입력·근거를 다시 확인합니다. 대기·실패·보관된 회차에는 현재 판단을 새로 확정하지 않습니다.

새 분석, KEV·EPSS·CPE·보강 근거 변경이나 검토 기한 경과 시 재평가 표시가 생길 수 있습니다. 이전 판단을 지우거나 자동으로 더 낮은 우선순위로 바꾸지 말고 새 근거로 별도 판단을 기록합니다.

## 9. 느린 화면·작업 정체·OOM

```bash
docker stats --no-stream
docker inspect --format '{{.Name}} exit={{.State.ExitCode}} oom={{.State.OOMKilled}} restarts={{.RestartCount}}' \
  koda-dashboard koda-scan-worker koda-delivery-worker
```

KODA 웹·수동 분석·전달·예약 worker와 Tracker 분석 worker의 상태를 구분합니다. 실행 중인 작업의 경과 시간·heartbeat·대기열, 메모리·CPU·PID 한도와 디스크·inode 여유를 확인합니다.

KODA 자원은 `KODA_CPUS`·`KODA_MEMORY`, `KODA_SCAN_CPUS`·`KODA_SCAN_MEMORY`, `KODA_DELIVERY_CPUS`·`KODA_DELIVERY_MEMORY`, 예약 작업은 `KODA_SCHEDULE_*`로 제한합니다. 작업 시간 제한과 보고서 제한도 별도입니다. 호스트 여유 내에서 조정하고 컨테이너를 다시 만든 뒤 실제 한도를 확인합니다. OOM이나 시간 초과 작업을 성공으로 바꾸지 않습니다.

## 10. 패치·갱신·이전 설치 정리 중단

지원 패치 그룹은 `koda`, `gateway`, `portal-web`, `portal-api-worker`입니다. 계약·스키마가 호환되지 않으면 전체 설치 절차를 사용합니다. 웹과 분석·전달 worker의 KODA 이미지가 다르면 같은 릴리스로 함께 기동합니다.

과거 Dependency-Track 전용 자원은 현행 설치·갱신이 소유권 확인 후 정리합니다. 전용 컨테이너·볼륨·DB/role·이미지 태그·구형 설정·전용 파일이 대상이며 Tracker의 SBOM 원본은 보존합니다. 다른 프로젝트 공유 자원이거나 소유권을 증명할 수 없으면 중단합니다. 중단 원인을 검토하고 전용 자원임을 확인한 뒤 정식 절차를 다시 실행합니다.

이 문서 작업에서는 현재 Mac의 기존 자원 정리를 실행하지 않았습니다. `reset-install.sh --delete-all-koda-data`는 장애 우회 명령이 아니라 전체 데이터 파기 명령입니다.

## 11. 지원 요청 시 보존할 근거

전달물 버전·검증 결과, 설치 식별자, 발생 시각, 실패한 작업/회차 ID, 응답 코드, 해당 구간 로그와 컨테이너 상태를 모읍니다. SBOM·분석 원본 해시·과거 리비전·백업을 보존합니다. 비밀번호·토큰·개인정보는 공유 자료에서 제거합니다.

[설치·운영 안내](README.ko.md), [폐쇄망 데이터 안내](../../../docs/security/OFFLINE-DATASETS.ko.md), [운영 경계](../../../docs/security/OFFLINE-OPERATIONS.ko.md)를 함께 확인합니다. 실제 조직 LDAP, 운영 규모 부하·복원·폐쇄망 설치 성공 여부는 해당 환경에서 별도 검증해야 합니다.
