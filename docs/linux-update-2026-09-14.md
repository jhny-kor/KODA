# Linux 오프라인 업데이트 패치 (2026-09-14)

리비전 `20260914-ui-data1`은 Linux x86_64용 KODA/Tracker 이미지와 함께 Tracker의 Grype DB·NVD/KEV 데이터를 별도 업로드할 수 있는 구성, KODA의 공유 취약점 데이터 볼륨 연결, 라이브러리 점검 취약점별 상세 보고서 링크를 포함합니다. 운영 서버에서 인터넷 다운로드나 Docker build는 수행하지 않습니다.

## 인터넷 연결 호스트에서 데이터 패키지 만들기

```bash
python3 scripts/build-data-update.py grype-db \
  --download --cache .data-update-cache \
  --output dist/grype-db-20260914.tar.gz
python3 scripts/build-data-update.py vuln-data \
  --download --koda-repo /path/to/security --cache .data-update-cache \
  --output dist/vuln-data-20260914.tar.gz
```

Grype 명령은 `grype db update`와 `grype db status -o json`으로 실제 import 결과를 만들며, NVD/KEV 패키지는 공식 피드와 SHA-256 manifest를 기록합니다. 생성된 `.tar.gz`와 `.sha256`만 폐쇄망으로 반입합니다.

## 이미지 패치 만들기

기존 `20260910-ui1` 이미지가 로컬에 필요합니다. KODA 빌드는 security, API·웹 빌드는 security-sbom-dependecy 디렉터리에서 실행합니다. 웹 이미지는 `apps/web`에서 `npm ci && npm run build`로 생성한 dist를 사용합니다. 아래 빌드는 linux/amd64를 대상으로 합니다.

```bash
docker build --platform linux/amd64 -f platforms/linux/update-release/Dockerfile.koda \
  -t local/koda-scheduled:20260914-ui-data1 .
docker build --platform linux/amd64 -f /path/to/security/platforms/linux/update-release/Dockerfile.api \
  -t local/koda-tracker-api-scheduled:20260914-ui-data1 .
docker build --platform linux/amd64 -f /path/to/security/platforms/linux/update-release/Dockerfile.web \
  -t local/koda-tracker-web-scheduled:20260914-ui-data1 apps/web/dist
python3 platforms/linux/package-scheduled-patch.py \
  --output-dir dist --tracker-repo /path/to/security-sbom-dependecy \
  --revision 20260914-ui-data1 --image-tag 20260914-ui-data1
```

패키지에는 이미지 inventory, manifest, Compose 데이터 업데이트 마이그레이션, 외부 데이터 생성 도구, 기존 백업·롤백 스크립트가 들어갑니다. `package-scheduled-patch.py`는 동일한 출력 디렉터리의 기존 리비전을 덮어쓰지 않습니다.

## 폐쇄망 적용 순서

```bash
sha256sum -c koda-scheduled-offline-patch-x86_64-20260914-ui-data1.tar.gz.sha256
tar -xzf koda-scheduled-offline-patch-x86_64-20260914-ui-data1.tar.gz
cd koda-scheduled-offline-patch-x86_64-20260914-ui-data1
sha256sum -c manifest.sha256
python3 preflight.py --prefix /home/user0/koda-suite
bash apply.sh --prefix /home/user0/koda-suite
```

적용 전 SQLite/PostgreSQL, 기존 이미지 태그, Tracker compose와 `.env`를 백업합니다. 적용 시 기존 Tracker 취약점 데이터 named volume을 검색해 `VULN_DATA_VOLUME_NAME`과 `KODA_VULN_DATA_VOLUME`만 `.env`에 추가하고, 볼륨 내용은 삭제하지 않습니다. 새 data-updater는 Tracker 애플리케이션과 분리된 서비스로 시작하며, 정상 API/worker는 취약점 데이터 볼륨을 읽기 전용으로 사용합니다.

## 데이터 업로드와 복원

관리자 화면의 취약점 데이터 업데이트에서 `grype-db` 또는 `vuln-data` 압축파일을 업로드한 뒤 검증 결과를 확인하고 **적용**을 눌러야 활성화됩니다. 검증 실패 파일은 활성 데이터에 영향을 주지 않습니다. 하나의 공통 릴리스가 두 데이터셋 버전을 함께 고정하며 관리 화면에서 종류별 롤백할 수 있습니다. 데이터 적용은 이후 스캔부터 사용하고 기존 결과를 재분석하지 않습니다.

패치 실패 시 서비스를 정지한 상태에서 다음을 실행합니다.

```bash
bash rollback.sh --prefix /home/user0/koda-suite
```

롤백은 백업한 이미지, launcher, Tracker compose, gateway 설정과 `.env`를 복구합니다. named volume과 원본 KODA/Tracker 데이터는 삭제하지 않습니다. 운영 서버 적용 여부는 폐쇄망 운영 로그로 별도 확인해야 하며, 이 저장소의 패키지 self-check는 실제 서버 수용을 대신하지 않습니다.

## 반영 항목과 검증 범위

| 구분 | 반영 내용 |
| --- | --- |
| 계정 | Tracker 승인 사용자 주기 동기화, KODA 자체 비활성화·삭제 상태 보존 |
| 연동 | 기존 GitLab·서버 매핑 체크, 조회 중 전체 선택·해제, 숨겨진 선택 보존 |
| 보고서 | 저장된 소스 문맥, 라이브러리 9열, CVE 상세 HTML·상대 링크·ZIP, 실제 심각도 집계 |
| 비교·조회 | 확인된 압축 루트만 제외한 저장소 상대 경로 비교, 삭제 후 검색·정렬·페이지 유지 |
| 권한 | 프로젝트 기존 사용자 체크·역할 보존, 화면별 권한 아코디언, 권한관리 명칭 |
| 결과 브랜치 | 프로젝트·날짜·회차를 포함한 읽을 수 있는 브랜치명 |
| Tracker | 그래프 공통 Y축, 페이지 분할 전 KEV→CVSS→심각도→구성요소 정렬 |
| 취약점 데이터 | 종류별 생성·업로드·검증·적용·복원, 공유 릴리스 고정, 별도 updater |

실제 `linux/amd64` 컨테이너를 `--network none`으로 실행해 데이터별 적용·복원, 이전 릴리스 경로 유지, 두 Grype 바이너리(0.109.1/0.115.0)의 실제 Log4j 탐지(각 7건)를 확인했습니다. 일반 Tracker UID로 공유 데이터 읽기와 두 바이너리 검증도 통과했습니다. 실제 KODA 점검 결과 ZIP은 HTML 3개를 포함하며, 메인 9열과 CVE 상세 링크 7개를 검사했습니다.

이 패치는 최신화 **기능**을 제공합니다. 포함한 이미지의 Grype DB 기준일은 `2026-09-10T06:30:24Z`이며, 이번 작업에서 최신 외부 피드 전체 다운로드를 수행하지 않았습니다. 운영자가 인터넷 호스트에서 위 생성 명령으로 최신 패키지를 만들어 반입할 수 있습니다.

메모리 검증 한계: Docker VM 메모리 약 6.2 GiB에서 전체 NVD 문맥을 유지한 채 업데이트 검증을 중첩한 실험은 메모리 부족으로 종료됐습니다. 문맥 보존 경로와 개별 갱신은 각각 확인했지만, 운영 환경의 동시 스캔·업데이트 최대 부하는 별도 용량 검증이 필요합니다. 실패한 실험에서도 마지막 정상 활성 릴리스는 유지됐습니다.

회귀 검증: Tracker 백엔드 97개, 웹 30개 테스트 통과 및 TypeScript·웹 빌드 성공. KODA 527개 중 520개 통과·7개 건너뜀, 최종 보고서 변경 집중 테스트 5개 통과. 실제 회사 서버에는 아직 적용하지 않았습니다.
