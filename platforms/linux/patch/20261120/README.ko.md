# KODA Suite Linux x86_64 통합 패치 2026-11-20

기존 Docker 기반 KODA Suite를 업데이트하는 폐쇄망 반입본입니다. 패치 대상은 `/home/user0/koda-suite`입니다. Tracker의 화면 개선과 업로드 변경, 대용량 CycloneDX 분할 처리, KODA 점검 화면 개선을 포함합니다. 설치 서버에 있는 취약점 자료와 검증키를 계속 사용합니다.

## 1. 반입과 사전 검사

`koda-suite-linux-patch-20261120.tar.gz`와 `koda-suite-linux-patch-20261120.tar.gz.sha256`을 서버의 같은 폴더에 둡니다. 설치 디렉터리를 소유하고 Docker에 접근할 수 있는 `user0` 계정으로 실행합니다. Linux x86_64, Docker Engine, Docker Compose v2, tar, sha256sum과 TAR 안전 필터를 지원하는 Python 3.10 이상이 필요합니다.

```bash
uname -m
id
docker info >/dev/null && docker compose version
python3 --version
python3 -c 'import sys, tarfile; assert sys.version_info >= (3, 10) and hasattr(tarfile, "data_filter")'
df -h . /home/user0
docker info --format 'Docker 데이터 저장 경로 {{.DockerRootDir}}'
```

반입 파일이 있는 폴더에서 아래 명령을 실행합니다. 체크섬 검사가 성공해야 다음 명령이 실행됩니다.

```bash
archive=koda-suite-linux-patch-20261120.tar.gz
stage=$(mktemp -d ./koda-patch-20261120.XXXXXX)

sha256sum -c "$archive.sha256" &&
  tar -xzf "$archive" -C "$stage" &&
  cd "$stage/koda-suite-linux-patch-20261120" &&
  PREFIX=/home/user0/koda-suite &&
  python3 ./apply.py --prefix "$PREFIX" --check
```

사전 검사는 반입본 내부 파일의 SHA-256, 기존 설치 경로, Compose 서비스 구성과 기존 데이터 볼륨을 확인합니다. 기존 설치 구조나 게이트웨이 구성이 호환 조건에 맞지 않으면 적용 전에 멈춥니다.

## 2. 전체 백업

진행 중인 SBOM 분석, KODA 점검, 자료 반입 작업이 끝난 유지보수 시간에 실행합니다. 백업 도중 쓰기 프로세스가 잠시 정지합니다. 압축을 푸는 경로와 Docker 데이터 저장 경로의 여유를 각각 확인합니다. 이미지 반입에는 압축파일과 별도로 Docker가 이미지 레이어를 푸는 공간이 필요합니다.

```bash
sh ./handover/backup.sh --prefix "$PREFIX" \
  --backup-root /home/user0/koda-suite-backups
```

백업에는 Tracker PostgreSQL 덤프, 기존 설치 파일과 KODA 데이터, 연결된 키·토큰 파일, Tracker 원본 SBOM·취약점 자료·자료 반입 볼륨이 포함됩니다. 백업 완료 메시지에 표시된 폴더를 확인한 뒤 아래 명령의 `BACKUP`에 실제 경로를 넣습니다.

```bash
BACKUP=/home/user0/koda-suite-backups/실제-백업-폴더
sh ./handover/verify-backup.sh --backup "$BACKUP"
```

백업은 설치 서버에서 비공개로 보관합니다. 이전 Docker 이미지도 복구가 끝날 때까지 보관합니다.

## 3. 패치 적용

사전 검사와 전체 백업 검증이 모두 성공하면 같은 폴더에서 실행합니다.

```bash
python3 ./apply.py --prefix "$PREFIX" --apply &&
  "$PREFIX/koda-suite" status --prefix "$PREFIX"
```

패치는 동봉 이미지를 불러와 Linux x86_64 이미지인지 검사합니다. 기존 `tracker/.env`에서 PostgreSQL 접속, LDAP, 외부 주소, 키와 토큰 설정을 읽습니다. 패치에 필요한 이미지 참조와 게이트웨이 업로드 설정을 반영하고, 기존 서비스와 데이터 볼륨을 다시 연결해 기동합니다. 새 DB 테이블과 열은 기존 행을 유지하면서 추가합니다. 기존에 더 크게 구성된 업로드 한도는 유지합니다. 설정 복구 경로를 패치 출력에서 기록해 둡니다.

## 4. 적용 후 확인

1. 기존 운영 주소에서 Tracker와 `/koda/`에 로그인합니다. 이전 프로젝트, 점검 결과, SBOM 회차와 원본 내려받기를 확인합니다.
2. Tracker에서 기존에 활성화된 취약점 자료의 상태와 기준일을 확인합니다.
3. 대용량 업로드는 KODA SBOM Maker가 내보낸 `sbom.cdx.json` 또는 `sbom.cdx-1.7.json` 하나를 사용합니다. ZIP이나 TAR.GZ에 담을 경우 압축파일 안에 SBOM 문서 한 개만 둡니다. 업로드 후 회차에서 처리 완료, 구성요소와 의존 관계, 분석 및 품질 진단을 확인합니다.

일반 설정에서 업로드와 압축 해제 후 크기는 각각 최대 5 GiB입니다. 공백 정리 후 128 MiB를 넘는 CycloneDX 1.6·1.7 UTF-8 JSON은 구성요소와 의존 관계를 분할 저장하고 Grype로 분석합니다. 개별 항목에는 8 MiB 한도가 적용됩니다. 외부 프록시가 있다면 실제 운영 주소에서 요청 크기와 타임아웃을 확인합니다. Suite 게이트웨이의 기본 SBOM 업로드 응답 대기는 1시간이며, 외부 프록시의 응답 제한도 파일 전송 뒤 스키마 검증에 필요한 시간을 허용해야 합니다.

CycloneDX 1.7 원본은 그대로 보관하며 기존 오프라인 Grype에는 1.6 분석용 문서를 전달합니다. 같은 이름·버전·유형의 패키지가 서로 다른 조건으로 여러 분석 구간에 나뉘면 일부 취약점이 추가로 표시될 수 있습니다.

## 5. 설정과 이미지 되돌리기

문제가 발생하면 패치 도구가 출력한 **설정 복구 경로**를 지정합니다. 2절의 전체 백업 경로와 구분해서 사용합니다.

```bash
PATCH_BACKUP=/home/user0/koda-suite/backups/patch-20261120/실제-설정-복구-폴더
python3 ./apply.py --prefix "$PREFIX" --rollback "$PATCH_BACKUP" &&
  "$PREFIX/koda-suite" status --prefix "$PREFIX"
```

롤백은 이전 환경 설정, 게이트웨이 설정, 이미지 참조를 복원해 서비스를 다시 기동합니다. 패치 이후 기록한 DB 행과 원본 파일은 현재 볼륨에 남습니다. 대용량 분할 회차 등 새 형식으로 데이터가 작성된 뒤 이전 버전으로 돌아갈 때는 해당 회차의 이전 버전 호환성을 확인합니다. DB·볼륨을 패치 전 시점으로 복구해야 할 때는 2절의 검증한 전체 백업을 사용합니다.

## 검증 범위

격리된 Linux x86_64 환경에서 2026-11-06 Suite를 `/home/user0/koda-suite`에 구성해 전체 백업, 백업 검증, 패치 적용과 롤백을 실행했습니다. 기존 계정, LDAP 설정, 연동 토큰, Tracker 회차와 SBOM 원본, KODA 점검 이력, 취약점 데이터 볼륨과 사용자 지정 게이트웨이 설정을 대조했습니다. 적용과 롤백 후 Tracker·KODA·게이트웨이가 정상 응답했고 기존 SBOM을 같은 해시로 내려받았습니다. 롤백 뒤 이전 환경 파일, 게이트웨이 설정과 이미지 참조가 복원된 것도 확인했습니다.

대용량 처리는 격리된 Linux 환경의 PostgreSQL, CycloneDX 검증기와 오프라인 Grype에서 검증했습니다. KODA SBOM Maker 출력 구조를 기반으로 만든 압축 해제 후 3,000,477,232바이트 파일에서 업로드, 원본 SHA-256, 구성요소 및 의존 관계의 분할 저장, 분석·정책·품질 완료를 확인했습니다. 폐쇄망 운영 서버의 적용은 1절 사전 검사부터 시작합니다.
