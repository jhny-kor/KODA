# KODA 스케줄 점검 — 폐쇄망 Docker 패치 (2026-09-10)

**기존 Linux x86_64 KODA Suite용 호환성 패치입니다.** Docker Engine, Compose v2, Python 3, Bash, `sha256sum`, `flock`이 설치되어 있어야 합니다. 2026-09-02 통합본과 호환되는 9월 6~7일 패치의 설치 계약을 검사하며, 다르면 적용 전에 중단합니다. 신규 설치용 DB·Dependency-Track 이미지는 포함하지 않습니다. 이 배포본은 반입할 파일 `koda-scheduled-offline-patch-x86_64-20260910.tar.gz`와 `.sha256` 파일을 사용합니다.

포함 이미지 3종은 KODA/스케줄 worker, Tracker API/worker, Tracker 화면에 사용됩니다. 실행에 필요한 기존 KODA 도구·취약점 DB와 Tracker 의존성이 이미지에 들어 있어 서버에서 다운로드하거나 빌드하지 않습니다. 취약점 데이터는 이번 패치에서 갱신하지 않았으며 KODA Grype DB 기준은 2026-09-01입니다. 작업 폴더의 검증된 변경을 포함한 스냅샷으로, 출처는 `provenance.json`과 `image-inventory.json`에 기록했습니다.

## 이번 UI 수정본의 설치 변경

공유 계정 선택 팝업·정렬 헤더·13px/42px 크기, GitLab 브랜치 선택/생성, 점검 기준·분류, MB 입력과 사이드바 애니메이션을 포함합니다. 이미지 태그는 `20260910-ui1`로 기존 반입본과 구분됩니다.

이전에 확인한 LDAP 네트워크 및 DNS 두 항목 추가, 검토된 이전 launcher와 이번 launcher는 사전 검사에서 허용합니다. 기존 compose.yaml이나 manifest.sha256를 복사·수정해 검사를 우회할 필요가 없습니다. 다른 설정 차이는 계속 중단하며, 차이를 확인한 후 별도로 처리해야 합니다.

Docker 27의 config digest와 새 Docker의 이미지 저장소 ID를 함께 검증합니다. 이미지 적재·검증은 서비스를 멈추기 전에 수행합니다. 이미 켜 둔 스케줄 활성화와 SSH 디렉토리 설정은 유지합니다. 신규 설치가 아닌 현재 `/home/user0/koda-suite` 업데이트용입니다.

## 반입·확인·적용

압축파일 `koda-scheduled-offline-patch-x86_64-20260910-ui1.tar.gz`와 `.sha256` 파일을 `/home/user0/koda-release`에 반입합니다. **기존 KODA 데이터 소유자(user0)로 실행하고 sudo/root로 바꾸지 않습니다.** `/home/user0/koda-suite`에 압축을 풀거나 기존 설치를 지우지 않습니다. 압축 해제·이미지 적재에 약 15GB와 DB 백업 크기만큼의 여유 공간을 준비합니다.

```bash
cd /home/user0/koda-release
sha256sum -c koda-scheduled-offline-patch-x86_64-20260910-ui1.tar.gz.sha256
test ! -e koda-scheduled-offline-patch-x86_64-20260910-ui1
tar -xzf koda-scheduled-offline-patch-x86_64-20260910-ui1.tar.gz
cd koda-scheduled-offline-patch-x86_64-20260910-ui1
sha256sum -c manifest.sha256
python3 preflight.py --prefix /home/user0/koda-suite
bash apply.sh --prefix /home/user0/koda-suite
```

적용 중 KODA·Tracker 접근이 잠시 중단됩니다. 스크립트는 애플리케이션을 정지하고 SQLite WAL을 반영한 백업과 PostgreSQL 덤프를 만든 후 이미지를 교체합니다. 기존 `.env`, 계정·프로젝트·결과·업로드·볼륨을 보존하며 PostgreSQL·Dependency-Track 이미지는 교체하지 않습니다. 백업은 `koda-suite/backups/scheduled-release/<UTC>`에 저장하고 이전 이미지도 롤백 태그로 유지합니다.

백업 실패 시 이미지를 교체하지 않고 중지합니다. 원인을 해결한 후 기존 `koda-suite start --prefix /home/user0/koda-suite`로 서비스를 재개할 수 있습니다. 이미지 교체 도중 실패하면 아래 롤백을 사용합니다. 호환성 검사는 우회하지 마십시오.

## 스케줄 활성화

예약 기능은 기본 비활성입니다. 최초 적용부터 SSH 연결 시험까지 준비하려면 위 `apply.sh` 명령에 `--enable-schedule --ssh-dir /home/user0/koda-schedule-ssh`를 추가할 수 있습니다. worker가 실행되어도 관리자 연동 설정의 전역 활성화를 켜기 전에는 점검을 시작하지 않습니다.

SSH 키·검증된 `known_hosts`는 별도 반입합니다. 디렉토리 700, 개인키 600 권한으로 기존 실행 계정이 읽을 수 있어야 합니다. 패키지에는 SSH 키나 GitLab/Tracker 토큰을 포함하지 않습니다. 설정 화면에서는 컨테이너 경로 `/run/koda/ssh/<키파일>`과 `/run/koda/ssh/known_hosts`를 사용합니다.

나중에 활성화하거나 재시작 후에도 유지하려면 기존 `/home/user0/koda-suite/tracker/.env`의 다음 항목만 추가/수정합니다. 기존 설정 전체를 덮어쓰지 않습니다.

```dotenv
KODA_SCHEDULE_ENABLED=1
KODA_SCHEDULE_SSH_DIR=/home/user0/koda-schedule-ssh
KODA_SCHEDULE_STATE_DIR=/home/user0/koda-suite/data/koda-schedule
KODA_SCHEDULE_CPUS=1
KODA_SCHEDULE_MEMORY=4g
```

SSH 마운트를 새로 추가할 때는 수동 작업이 없는 유지보수 시간에 KODA dashboard를 재생성합니다. 기존 자원 제한을 별도로 지정했다면 같은 환경변수를 유지합니다.

```bash
PREFIX=/home/user0/koda-suite
"$PREFIX/koda/koda-docker" dashboard stop
"$PREFIX/koda-suite" start --prefix "$PREFIX"
```

관리자 **연동 설정**에서 서버·디렉토리·규칙·GitLab 프로젝트/브랜치와 자원 제한을 설정하고, 연결/접근 시험 후 대상과 전역 스케줄을 활성화합니다. 서버 1대·디렉토리 1개로 먼저 확인합니다. worker state 디렉토리는 재시작 복구에 사용하므로 유지합니다. 서버 원본은 수정하지 않으며 임시 복사본 정리 확인 후 Tracker·GitLab으로 결과를 게시합니다.

## 폐쇄망 운영 확인

패치 후에는 기존 launcher와 Compose를 통해서만 기동합니다. 이미지 pull이나 build를 수행하지 않습니다.

```bash
PREFIX=/home/user0/koda-suite
"$PREFIX/koda-suite" status --prefix "$PREFIX"
docker ps --filter name=koda-schedule-worker --format 'table {{.Names}}\t{{.Status}}\t{{.Image}}'
docker logs --tail 200 koda-schedule-worker
docker compose --project-directory "$PREFIX/tracker" --env-file "$PREFIX/tracker/.env" \
  -f "$PREFIX/tracker/compose.yaml" -f "$PREFIX/tracker/compose.airgap.yaml" \
  -f "$PREFIX/tracker/compose.integration.yaml" ps
```

예약 기능은 기본 비활성입니다. KODA·Tracker 수동 점검과 상태를 먼저 확인한 뒤, 관리자 설정에서 서버 1대·디렉토리 1개를 등록하여 파일 수·실행 시간·자원 사용량을 측정합니다. 서버 연동에서 읽기 전용 계정, SSH 키 참조, 검증된 `known_hosts`, KODA 프로젝트 매핑을 저장하고 연결/접근 시험을 통과시킵니다. GitLab 연동에서는 저장소·브랜치·결과 게시 권한을 별도로 설정합니다.

SSH 키와 `known_hosts`는 패키지와 분리해 반입하고 컨테이너에는 읽기 전용으로 마운트합니다. 키 디렉토리 700, 개인키 600 권한을 확인합니다. 화면에는 호스트 경로가 아닌 `/run/koda/ssh/<파일>`을 입력합니다.

```bash
SSH_DIR=/home/user0/koda-schedule-ssh
test -d "$SSH_DIR" && test "$(stat -c '%a' "$SSH_DIR")" = 700
find "$SSH_DIR" -maxdepth 1 -type f \( -name '*.pem' -o -name 'id_*' \) -exec chmod 600 {} \;
```

파일럿 대상 1개만 활성화한 뒤 전역 활성화를 켜서 시험하고, 통과하면 대상을 늘립니다. 최초 패치 때 바로 활성화해야 한다면, 앞의 `apply.sh` 대신 다음 명령을 사용합니다. 이미 적용한 패치에는 이 명령을 반복하지 말고 `tracker/.env`에 필요한 환경변수만 추가한 뒤 launcher를 재시작합니다.

```bash
bash apply.sh --prefix "$PREFIX" --enable-schedule --ssh-dir "$SSH_DIR"
```

성공·실패·취소·시간 초과 후 임시 수집본이 삭제되고 대상 서버 원본이 변하지 않는지 확인합니다. KODA 소스 점검 결과는 Tracker로 전송하지 않으며, 원본 파일은 Tracker에 보관하지 않습니다. GitLab에는 지정 브랜치와 `.koda/scheduled-results/<target-id>/<run-id>.json` 및 기존 MR/Issue 정책에 따라 결과가 게시됩니다. 연결 단절·권한 오류·용량 초과 시 해당 대상만 실패하고 다음 대상이 순차 진행되는지 확인합니다.

로그에 SSH 키·PAT·Tracker 토큰·`.env` 값이 출력되면 즉시 중단합니다. 로컬 패키지 검증은 실제 원격 SSH 접근, 01:00 KST 예약 실행, GitLab 게시, Tracker 전송을 증명하지 않으므로 폐쇄망 파일럿 로그로 별도 남겨야 합니다.

## 재시작과 롤백

```bash
"$PREFIX/koda-suite" start --prefix "$PREFIX"
"$PREFIX/koda-suite" status --prefix "$PREFIX"
bash rollback.sh --prefix "$PREFIX"
```

롤백은 마지막 적용 백업의 이미지 태그와 launcher를 복원하고 worker를 정지합니다. 데이터베이스와 named volume은 자동 복원하지 않으며, 백업은 `$PREFIX/backups/scheduled-release/<UTC>`에 보관됩니다. SQL/SQLite 수동 복원은 이후 데이터가 사라질 수 있으므로 장애복구가 필요한 경우에만 별도로 수행합니다.

## 화면 설정 및 합격 기준

1. **서버 연동**: 서버 연결 설정에 주소·포트·읽기 전용 계정·키 경로·known_hosts 경로를 저장합니다. 서버 서비스 계정을 KODA 프로젝트에 연결합니다. 서버 스케줄에서 해당 프로젝트와 연결 서버, 디렉토리·제외 경로·규칙을 선택합니다.
2. **GitLab 연동**: 조회용/게시용 PAT와 저장소 연결을 확인합니다. GitLab 스케줄에서 저장소, 브랜치 또는 태그, 하위 디렉토리를 선택합니다. 결과 게시 매핑·대상 브랜치도 지정합니다.
3. 대상별 실행 시각은 한국시간이며 매일·매주 요일·N시간 주기를 선택합니다. 첫 시험은 현재보다 몇 분 뒤로 설정하고 대상 1개와 전역 활성화를 켭니다. 실제 운영 시각으로 돌리는 것을 잊지 마십시오.
4. 자원 설정은 처음 CPU 1코어, 메모리 4096MB, 전송 5MB/s, 작업 간 30초, 동시 작업 1을 유지합니다. 화면 값보다 Docker의 CPU·메모리 제한이 낮으면 Docker 제한이 우선합니다.
5. **기존 기능**: 로그인, 수동 소스/라이브러리 점검과 기존 결과 조회가 정상이고, 스케줄 결과가 수동 탭에 섞이지 않아야 합니다.
6. **예약/재시작**: 설정 시각에 1회 실행되고, 같은 예약 작업이 중복 생성되지 않아야 합니다. 진행 중 작업이 있으면 다음 예약이 쌓이지 않는지 확인합니다.
7. **원본 정리**: 실행 상세의 점검·원본 정리·Tracker·GitLab 상태를 각각 확인합니다. 원본 정리 완료 후 작업별 임시 폴더에 수집 파일이 남지 않아야 합니다. 대상 서버 원본은 유지되어야 합니다. 실패·시간 초과 때도 동일하게 확인합니다. worker 상태 폴더 전체를 삭제하지 마십시오.
8. **결과 분리**: 소스 취약점은 KODA와 GitLab에서만 확인합니다. Tracker는 라이브러리/SBOM을 받고 스케줄 결과를 별도 표시해야 합니다. 전체/변경분 환경도 분리되어야 합니다.
9. **GitLab 게시**: `koda/scheduled/<target-id>/<run-id>` 브랜치, `.koda/scheduled-results/<target-id>/<run-id>.json`, MR 및 취약점 Issue를 확인합니다. 동일 실행 재전송은 기존 결과·MR을 갱신하고 Issue를 중복 생성하지 않아야 합니다.
10. **전송 장애**: 시험용 Tracker/GitLab 연결을 일시 차단했다가 복구했을 때 저장된 결과로 재전송되는지 확인합니다. 임시 원본을 계속 보관해서는 안 됩니다. 변경분에서 발견이 없다는 이유로 기존 Issue가 자동 종료되어서는 안 됩니다.

활성화 후 자원·작업 폴더 확인 예시:

```bash
docker stats --no-stream koda-dashboard koda-schedule-worker
docker exec koda-schedule-worker sh -c 'find /var/lib/koda-schedule/work -type f | wc -l'
```

작업 중 파일 수는 0이 아닐 수 있습니다. 모든 시험 작업의 정리가 끝난 뒤 확인합니다. 로그를 전달할 때는 계정 토큰·키와 내부 민감정보를 제외하십시오.
