# KODA Linux 폐쇄망 설치 가이드

대상 패키지: `koda-scheduled-offline-patch-x86_64-20260916-limits1.tar.gz`

이 패키지는 **기존 Linux x86_64 KODA Suite를 업데이트하는 패치**입니다. 신규 서버 설치본이 아닙니다. 기본 설치 경로는 `/home/user0/koda-suite`이며, 다른 경로를 사용 중이면 아래 `PREFIX`만 실제 경로로 바꿉니다.

## 1. 반입 전에 준비할 것

- Docker Engine과 Docker Compose v2
- Python 3, Bash, `sha256sum`, `flock`
- 패키지 압축 해제와 이미지 적재용 약 15GB, 기존 DB·이미지 백업에 필요한 추가 공간
- 현재 KODA 데이터를 소유하고 실행하는 Linux 계정
- 패키지 파일과 SHA-256 파일

폐쇄망 서버에서 인터넷 다운로드, Docker build, image pull을 실행하지 않습니다. 기존 `.env`, 데이터베이스, 업로드, Docker named volume을 삭제하거나 덮어쓰지 않습니다.

반입 파일:

```text
koda-scheduled-offline-patch-x86_64-20260916-limits1.tar.gz
koda-scheduled-offline-patch-x86_64-20260916-limits1.tar.gz.sha256
```

빌드 시 확인한 SHA-256은 다음과 같습니다.

```text
fc22650476ab45e4eada83998fdb458c64c76996964798d7baed0b27c8efd8ae
```

## 2. 서버 상태와 여유 공간 확인

기존 KODA 실행 계정으로 로그인합니다. `sudo`나 root 계정으로 바꾸어 적용하지 않습니다.

```bash
PREFIX=/home/user0/koda-suite
RELEASE_DIR=/home/user0/koda-release

test -x "$PREFIX/koda-suite"
test -f "$PREFIX/tracker/.env"
docker info >/dev/null
docker compose version
df -h "$PREFIX" "$RELEASE_DIR"
"$PREFIX/koda-suite" status --prefix "$PREFIX"
```

기존 서비스가 비정상이거나 공간이 부족하면 먼저 원인을 해결합니다. 기존 Suite의 Compose나 manifest를 임의로 수정해 사전 검사를 우회하지 않습니다.

## 3. 파일 반입과 외부 체크섬 확인

USB 등 승인된 반입 수단으로 압축 파일과 `.sha256` 파일을 `/home/user0/koda-release`에 복사합니다.

```bash
mkdir -p /home/user0/koda-release
cd /home/user0/koda-release

ARCHIVE=koda-scheduled-offline-patch-x86_64-20260916-limits1.tar.gz
sha256sum -c "$ARCHIVE.sha256"
```

반드시 다음과 같이 표시되어야 합니다.

```text
koda-scheduled-offline-patch-x86_64-20260916-limits1.tar.gz: OK
```

`FAILED`가 나오면 압축을 풀거나 적용하지 말고 파일을 다시 반입합니다.

## 4. 압축 해제와 내부 파일 검증

기존 설치 경로가 아니라 반입 디렉터리에서 압축을 풉니다.

```bash
test ! -e "${ARCHIVE%.tar.gz}"
tar -xzf "$ARCHIVE"
cd "${ARCHIVE%.tar.gz}"
sha256sum -c manifest.sha256
bash test.sh
```

모든 내부 파일이 `OK`이고 마지막에 다음 문구가 나와야 합니다.

```text
scheduled-release script guards passed
```

`provenance.json`, `image-inventory.json`, `VALIDATION.txt`도 함께 보관합니다. 이 파일들은 소스 리비전, 포함 이미지, 로컬 검증 범위를 기록합니다.

## 5. 읽기 전용 사전 검사

사전 검사는 서비스를 변경하지 않습니다.

```bash
python3 preflight.py --prefix "$PREFIX"
```

사전 검사가 실패하면 `apply.sh`를 실행하지 않습니다. 오류에 나온 기존 설치 계약, 이미지, Compose 또는 권한 문제를 먼저 해결합니다.

## 6. 패치 적용

예약 점검을 아직 켜지 않을 경우 다음 명령을 실행합니다.

```bash
bash apply.sh --prefix "$PREFIX"
```

적용 스크립트는 다음 순서로 처리합니다.

1. 사전 검사와 포함 이미지 검증
2. SQLite, PostgreSQL, Tracker Compose·gateway·`.env`, 기존 launcher 백업
3. Tracker 취약점 데이터 volume 백업과 기존 이미지 롤백 태그 보존
4. KODA, Tracker API/worker, Tracker 웹 이미지 교체
5. 기존 환경 설정을 보존하면서 기본 100MiB 업로드 설정만 500MiB로 이관
6. KODA JSON 기본값이 없으면 500MiB 설정 추가
7. 서비스 기동과 상태 확인

백업은 다음 경로에 생성됩니다.

```text
/home/user0/koda-suite/backups/scheduled-release/<UTC 시각>
```

적용 중 KODA와 Tracker 접속이 잠시 중단됩니다. 백업이 실패하면 이미지 교체 전에 중단됩니다.

## 7. 예약 서버 점검을 함께 활성화하는 경우

SSH 개인키와 검증된 `known_hosts`는 패키지에 포함되지 않으므로 별도로 반입합니다.

```bash
SSH_DIR=/home/user0/koda-schedule-ssh
test -d "$SSH_DIR"
chmod 700 "$SSH_DIR"
find "$SSH_DIR" -maxdepth 1 -type f \( -name '*.pem' -o -name 'id_*' \) -exec chmod 600 {} \;

bash apply.sh \
  --prefix "$PREFIX" \
  --enable-schedule \
  --ssh-dir "$SSH_DIR"
```

화면에는 호스트 경로 대신 컨테이너 경로 `/run/koda/ssh/<키파일>`과 `/run/koda/ssh/known_hosts`를 입력합니다. 관리자 화면에서 서버 연결 시험과 디렉터리 접근 시험을 통과한 뒤 대상 하나만 먼저 활성화합니다.

## 8. 적용 후 확인

```bash
"$PREFIX/koda-suite" status --prefix "$PREFIX"

docker ps --filter name=koda-dashboard \
  --filter name=koda-schedule-worker \
  --filter name=koda-sbom \
  --format 'table {{.Names}}\t{{.Status}}\t{{.Image}}'

grep -E '^(UPLOAD_MAX_BYTES|KODA_JSON_MAX_BYTES)=' \
  "$PREFIX/tracker/.env"

docker exec koda-sbom-gateway nginx -T 2>/dev/null \
  | grep client_max_body_size
```

기본 이관 대상 설치에서는 다음 값이 확인되어야 합니다.

```text
UPLOAD_MAX_BYTES=524288000
KODA_JSON_MAX_BYTES=524288000
```

운영자가 이전에 별도 값을 설정했다면 그 값은 보존됩니다. gateway에는 Tracker 경로 `501m`, KODA 업로드 경로 `2049m`가 보여야 합니다.

## 9. 기능 확인 순서

1. KODA와 Tracker 로그인 및 기존 결과 조회
2. 작은 소스 디렉터리 수동 점검
3. 작은 SBOM 업로드와 라이브러리 취약점 상세 보고서 연결
4. 서버 1대·작은 디렉터리로 예약 점검 실행
5. 완료·실패·취소 후 임시 수집 파일 정리 확인
6. 실제 대형 디렉터리 실행 시 파일 수, 처리 시간, 메모리, 디스크 사용량 기록

이번 리비전의 기본 상한은 다음과 같습니다.

| 항목 | 기본 상한 |
|---|---:|
| KODA JSON API | 500MiB |
| KODA 직접 업로드 | 2GiB |
| 압축 해제 | 4GiB / 400,000개 |
| 예약 서버 대상 | 4GiB / 200,000개 / 24시간 |
| Tracker SBOM 업로드 | 500MiB |
| Tracker 변경 파일 메타데이터 | 20,000개 |

처음부터 최대 크기로 실행하지 말고 작은 대상부터 단계적으로 늘립니다. 압축 폭탄, 경로 이탈, 단일 비정상 목록 행에 대한 안전 검사는 계속 적용됩니다.

## 10. Grype DB와 Tracker vuln-data 갱신

애플리케이션 패치와 취약점 데이터 갱신은 서로 독립적입니다. 이번 패키지는 별도 업로드·검증·적용·롤백 기능을 포함하지만 외부 취약점 피드를 새로 내려받은 데이터 파일은 포함하지 않습니다.

연결망에서 별도로 만든 `grype-db` 또는 `vuln-data` 압축파일을 관리자 화면의 **취약점 데이터 업데이트**에서 종류별로 업로드합니다. 검증 결과가 성공한 파일만 **적용**하여 활성화합니다. 실패한 파일은 현재 데이터에 영향을 주지 않습니다. 적용 후 **취약점 데이터 → 반입 상태 동기화**를 실행하고 새 분석 회차를 시작합니다. 기존 완료 결과는 자동 재분석되지 않습니다.

## 11. 롤백

적용 후 서비스 이상이 확인되면 같은 압축 해제 디렉터리에서 실행합니다.

```bash
cd /home/user0/koda-release/koda-scheduled-offline-patch-x86_64-20260916-limits1
bash rollback.sh --prefix "$PREFIX"
"$PREFIX/koda-suite" status --prefix "$PREFIX"
```

롤백은 이전 launcher, Compose·gateway 설정과 애플리케이션 이미지 태그를 복원하고 예약 worker를 정지합니다. 데이터베이스와 named volume은 삭제하지 않습니다. SQL이나 SQLite 백업의 수동 복원은 패치 이후 데이터를 잃을 수 있으므로 별도 장애복구 판단이 있을 때만 수행합니다.

## 12. 금지 사항

다음 명령이나 조치는 적용·복구 절차에 사용하지 않습니다.

```text
docker compose down -v
docker volume rm ...
docker system prune
chmod -R 777 ...
```

- 기존 `/home/user0/koda-suite`를 삭제하거나 그 안에 배포 압축을 풀지 않습니다.
- 기존 `.env` 전체를 새 파일로 덮어쓰지 않습니다.
- 폐쇄망 서버에서 image pull이나 Docker build를 실행하지 않습니다.
- `manifest.sha256`, Compose, gateway 설정을 수정해 사전 검사를 우회하지 않습니다.

## 13. 폐쇄망 합격 기준

- 외부 체크섬과 내부 manifest 검증 성공
- 사전 검사 성공
- KODA·Tracker 서비스 정상 기동
- 기존 사용자, 프로젝트, 결과, 업로드, 데이터 volume 보존
- 수동 소스·라이브러리 점검과 상세 보고서 연결 정상
- 서버 1대 파일럿 예약 점검 완료
- 임시 수집본 정리와 대상 서버 원본 보존 확인
- 필요 시 롤백 실행 가능 및 백업 경로 확인

로컬 빌드와 패키지 검증은 폐쇄망 서버 적용 성공을 대신하지 않습니다. 최종 합격은 위 항목을 실제 서버에서 확인한 기록으로 판단합니다.
