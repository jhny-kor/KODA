# KODA + KODA SBOM Tracker 폐쇄망 통합본

KODA와 KODA SBOM Tracker는 별도 저장소·배포물·데이터베이스로 유지합니다. 이 묶음은 두 전달물을 공통 gateway로 연결합니다. Tracker는 `/`, KODA는 `/koda/`에서 제공하며 PostgreSQL은 Tracker의 데이터를 보관합니다.

분석은 반입한 Grype·NVD·KEV·선택적 EPSS 및 보강 자료를 사용합니다. OSV 온라인 조회는 사용하지 않습니다. Tracker가 로그인·세션을 관리하고 KODA는 자체 프로젝트 권한을 적용합니다.

## 설치 준비

Linux x86_64, Docker Engine, Compose v2, Python 3, Bash, sha256sum, flock이 필요합니다. 연결망 빌드 호스트에서 호환되는 KODA·Tracker 전달물과 취약점 데이터를 묶고, 전달물의 서명·manifest·체크섬을 검증합니다. 실제 비밀번호·키는 서버 전용 `.env`에 보관합니다.

운영 TLS는 gateway 앞의 HTTPS 종료 지점에서 처리합니다. 외부 reverse proxy는 HTTPS 오리진과 호스트를 보존해야 합니다. 운영 모드에는 Secure Cookie를 사용하며 KODA 내부 포트 8765는 외부에 공개하지 않습니다.

## 설정과 설치

`.env.example`을 서버 전용 `.env`로 복사하고 DB 비밀번호·관리자 초기 비밀번호·LDAP 암호화 키·공개 HTTPS 오리진을 설정합니다. `koda-suite.env.example`은 gateway와 KODA worker 자원 한도의 예시입니다. 예시 파일에 비밀값을 넣어 다시 배포하지 않습니다.

```text
TRACKER_OFFLINE_MODE=true
TRACKER_PACKAGE_METADATA_ENABLED=false
TRACKER_EPSS_POLICY_MAX_AGE_DAYS=7
```

반입 파일을 푼 디렉터리에서 실행합니다.

```bash
./koda-suite verify
./koda-suite preflight --env-file .env --prefix /opt/koda-suite --require-vulnerability-data
./koda-suite install --env-file .env --prefix /opt/koda-suite
./koda-suite status --prefix /opt/koda-suite
```

`install`은 전달물을 검증하고 두 제품을 설치한 뒤 기동합니다. 같은 설치 경로의 갱신도 새 전달물의 설치 절차를 사용하며, 설치 전 백업과 호환성 확인이 필요합니다. 호환되는 개별 이미지 패치에는 `patch --group`을 사용합니다.

앱과 수집 프로세스는 기본적으로 내부 Docker 네트워크를 사용합니다. 내부 GitLab·LDAP·스캔 대상의 추가 연결은 조직 방화벽과 통합 목적지 설정으로 제한합니다.

## 점검과 자료 반입

- Tracker는 CycloneDX·SPDX SBOM 회차, Grype 취약점·정책, VEX·SSVC·대응 이력을 관리합니다.
- 명시된 CPE는 로컬 NVD 적용 조건으로 보완하고 미지원 조건·범위 누락을 표시합니다. 과거 문자열 목록만 있는 NVD 자료는 판정 조건을 보존하는 생성기로 다시 준비합니다.
- EPSS CSV(.gz)와 보강 자료를 승인·검증 후 반입하고 영향 회차를 재분석합니다. 원본 기준일·출처·해시와 과거 분석은 보존합니다.
- KODA Java·라이브러리 결과에서도 로컬 EPSS 상태와 보강 근거를 표시합니다. 취약점 데이터는 분석 동안 하나의 활성 릴리스로 고정합니다.
- 공급자 VEX와 SSVC 참고 자료는 담당자의 검토 근거입니다. 반입만으로 취약점을 자동 억제하거나 조직 대응 결정을 확정하지 않습니다.

자료 갱신은 manifest·서명 검증과 원자적 활성화 절차를 따릅니다. 반입 시각을 원본 기준일로 바꾸지 않으며 자료 없음·오래됨·불완전 판정은 안전을 뜻하지 않습니다.

## 유지보수와 자원

지원 패치 그룹은 `koda`, `gateway`, `portal-web`, `portal-api-worker`입니다. Compose 계약이 다르면 패치를 중단하고 전체 설치 절차로 전환합니다. `stop`은 데이터를 보존합니다.

```bash
/opt/koda-suite/koda-suite stop --prefix /opt/koda-suite
/opt/koda-suite/koda-suite start --prefix /opt/koda-suite
/opt/koda-suite/koda-suite status --prefix /opt/koda-suite
```

KODA 웹·수동 분석·전달 worker는 분리합니다. `KODA_CPUS`·`KODA_MEMORY`, `KODA_SCAN_CPUS`·`KODA_SCAN_MEMORY`, `KODA_DELIVERY_CPUS`·`KODA_DELIVERY_MEMORY`로 각 한도를 설정합니다. 예약 작업은 `KODA_SCHEDULE_*` 한도를 사용합니다. 한도 변경 뒤에는 현행 설치·기동 절차로 해당 컨테이너를 다시 만들고 실제 한도를 확인합니다.

백업은 KODA 이력·입력, Tracker DB·SBOM artifact, 취약점 릴리스와 운영 설정을 포함합니다. 복원은 격리된 대상에서 먼저 검증합니다. `reset-install.sh --delete-all-koda-data`는 전체 데이터 파기를 위한 명시적 명령입니다.

## 이전 설치의 폐기 서비스 정리

Dependency-Track은 제품에서 제거되었습니다. 설치·갱신 과정은 소유권이 확인된 기존 전용 컨테이너·볼륨·DB/role·이미지 태그·구형 설정·전용 파일을 정리합니다. Tracker의 SBOM 원본과 자체 운영 데이터는 보존합니다. 다른 프로젝트와 공유하는 자원이거나 소유권을 확인할 수 없으면 중단합니다. 이전 서비스를 되살리거나 임의로 전체 볼륨을 삭제해 중단을 우회하지 않습니다.

이 안내와 로컬 코드 검증은 현재 Mac의 기존 Docker 자원을 실제 정리했다는 뜻이 아닙니다. 운영 설치 전에는 백업과 정리 대상 확인이 필요합니다.

## 상세 안내

- [설치·로그인·분석 장애 대응](TROUBLESHOOTING.ko.md)
- [폐쇄망 운영](../../../docs/security/OFFLINE-OPERATIONS.ko.md)
- [반입 보강 자료](../../../docs/security/OFFLINE-DATASETS.ko.md)
- [Docker 날짜 태그·부분 패치 정책](../../../docs/install/linux-image-tags.ko.md)
- [SPDX 2.3 내보내기](../../../docs/security/SPDX-2.3.ko.md)

Tracker 전달물의 `docs/ssvc-offline-ko.md`, `docs/offline-cpe-ko.md`, `docs/offline-intelligence-ko.md`, `docs/operations-ko.md`도 함께 참고합니다.

## 승인 데이터만 사용하는 Linux 실행 계약

KODA와 Tracker는 `.env`의 `VULN_DATA_VOLUME_NAME`(기본 `koda-sbom-vuln-data`)을 공유합니다. Suite는 이 이름을 KODA에 자동 전달하고 다른 데이터 볼륨으로 지정하면 중단합니다. KODA 웹·분석·예약 프로세스는 `/var/lib/koda-vuln-data`에 읽기 전용으로 연결하고 승인된 `current`만 읽습니다. 직접 Docker CLI도 같은 기본 볼륨이 존재하면 읽기 전용으로 연결합니다. Linux 네이티브 설치는 `KODA_VULN_DATA_ROOT`에 같은 승인 데이터 루트를 지정해야 합니다.

Linux는 직접 Python 모듈을 실행할 때도 관리 데이터 필수 모드가 기본이며, 런처와 이미지에도 동일하게 적용됩니다. 승인 데이터가 없거나 삭제되면 과거 이미지·설치 폴더·Grype 캐시·환경변수의 개별 NVD/EPSS 경로로 돌아가지 않습니다. 새 이미지에서는 내장 DB·취약점 자료도 제거합니다. 기존 보관 산출물과 사용자 DB·점검 결과는 삭제하지 않습니다. macOS 개발 환경에서 공통 관리 루트를 지정하지 않은 명시적 로컬 파일 작업은 유지합니다.

공통 루트의 `.managed.json`은 `koda-managed-vulnerability-data-v1` 형식, `active`/`purging`/`purged` 상태를 보존합니다. KODA는 활성 버전과 `current` 폴더명이 같은지 확인합니다. `.release.lock` 파일을 읽기 전용으로 열어 전체 분석 동안 공유 잠금을 유지합니다. Tracker의 적용·삭제는 배타 잠금을 요구하므로 진행 중인 읽기가 있으면 재시도해야 합니다. 잠금 중이거나 승인 자료가 없으면 CVE 비교는 `unavailable`/오류이며 0건으로 성공 처리하지 않습니다. Java 보고서의 CVE 통계는 JSON `null`, 화면 “점검 불가”로 표시하고 종료 코드는 2입니다. SBOM과 비CVE 분석은 계속 만들 수 있습니다. 기존 분석 시점의 저장 결과와 사용자 정보는 유지합니다.

서명 검증 공개키는 설치 전에 `TRACKER_DATA_UPDATE_VERIFY_KEY_FILE`에 등록합니다. 절대경로 또는 `.env` 디렉터리를 기준으로 한 상대경로이며, API와 데이터 갱신 프로세스에 `/run/secrets/tracker-data-update-verify.pub:ro`로 연결합니다. 승인된 PEM 공개키만 지정하고 개인 서명키는 폐쇄망 서버에 복사하지 않습니다. 키가 없거나 잘못되면 설치·갱신을 명확한 오류로 중단하며 임의 키를 생성하지 않습니다. 기존 실행 인스턴스와 저장된 결과를 삭제하지 않습니다. 공개키와 `.managed.json`·`.release.lock`, 릴리스 디렉터리는 KODA 컨테이너 사용자(UID 1000 및 실행 UID)가 읽을 수 있어야 합니다. 잠금 파일의 기본 권한은 0644입니다.

이 계약은 로컬 회귀 테스트와 Docker 실행 인자/설치 계약으로 검증합니다. 실제 Linux 서버의 UID·공유 볼륨 파일 시스템에서 `flock`과 읽기 권한이 동작하는지, 최종 서명 이미지로 반입→분석→잠금 충돌→삭제→재반입이 되는지는 운영 인수 점검에 포함해야 합니다.

승인 파일의 원본 증거 `approved-metadata.env`·`approved-manifest.sha256`·서명은 활성 릴리스에 보존됩니다. KODA도 같은 공개키를 읽기 전용으로 연결하여 원본 서명과 파일 해시, 런타임 데이터 선택 메타데이터를 확인합니다. 삭제 상태나 승인 근거 누락·변조, 등록 키 누락은 모두 `unavailable`입니다. 새 원본은 최초 분석 때 전체 해시를 확인하며 이후에는 읽기 전용·불변 릴리스의 파일 장치/파일번호·크기·mtime·ctime·권한과 검증키·승인 증거의 동일성을 검사해 같은 결과를 제한된 캐시에 재사용합니다. 변경이 하나라도 있으면 캐시를 사용하지 않습니다. 이 캐시는 데이터 삭제 뒤 과거 자료를 선택하는 경로가 아닙니다. 직접 Docker CLI는 `KODA_DATA_UPDATE_VERIFY_KEY_FILE`, 네이티브 Linux는 `KODA_DATA_UPDATE_VERIFY_KEY`에 승인 공개키 경로를 지정합니다. Suite는 등록된 Tracker 키를 자동 연결하며 개인키는 연결하지 않습니다.
