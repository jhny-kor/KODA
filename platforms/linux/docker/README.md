# KODA 폐쇄망 Docker 전달물

Linux x86_64 폐쇄망 서버에서 KODA JAR/WAR/EAR SBOM·취약점 점검을 Docker로
실행하기 위한 단일 전달물입니다. Docker Engine은 서버에 이미 설치되어 있어야
하며, 이 전달물은 Docker나 호스트 설정을 변경하지 않습니다.

## 구성

```text
koda-docker-offline-x86_64-<version>/
├── install.sh          # 폐쇄망 설치 스크립트
├── koda-docker.sh      # 실행 래퍼 (설치 후 <prefix>/koda-docker)
├── README.md
├── image-ref.txt       # koda-offline:<version>
├── versions.txt        # Syft/Grype/DB/NVD/CISA 기준 정보
├── manifest.sha256     # 전체 파일 SHA-256
└── image/
    └── koda-offline-amd64.tar
```

이미지에는 KODA 소스, Syft, Grype, import 완료된 Grype DB, NVD 피드,
CISA KEV, Playwright Chromium(PDF 렌더러)이 포함됩니다.

## 설치

전달 파일은 `koda-docker-offline-x86_64-<version>.tar.gz` 하나입니다. Docker
Engine이 미리 설치된 Linux x86_64 서버로 이 파일만 이동하면 됩니다.

```bash
# 1) 반입한 파일의 체크섬을 연결된 빌드 PC에서 전달받은 값과 비교(권장)
sha256sum koda-docker-offline-x86_64-<version>.tar.gz

# 2) 원하는 사용자 소유 경로에서 압축 해제
mkdir -p /home/user0/projects/koda
cd /home/user0/projects/koda
tar -xzf koda-docker-offline-x86_64-<version>.tar.gz
cd koda-docker-offline-x86_64-<version>
bash install.sh --prefix /home/user0/projects/koda
# 또는 KODA_DOCKER_PREFIX=/srv/koda bash install.sh

# 이후 명령은 --prefix로 지정한 경로의 실행 래퍼를 사용합니다.
export KODA_CLI=/home/user0/projects/koda/koda-docker
```

설치 스크립트는 manifest 검증 → Docker 확인 → `docker load` → 아키텍처·라벨
확인 → 무통신 스모크 테스트 → 래퍼 복사 순서로 동작합니다. 같은 버전
재설치는 안전하며 기존 보고서·실행 중 대시보드는 건드리지 않습니다.

## 실행

모든 CLI 실행은 기본적으로 `--network none`, read-only rootfs, 비루트,
capability 제거, CPU/메모리/PID 제한이 적용됩니다. `--target`/`--sbom`/
`--baseline-sbom`은 읽기 전용, `--output-dir`/`--output`만 쓰기 가능으로
동일 절대경로에 자동 마운트됩니다.

```bash
# JAR 취약점 분석
"$KODA_CLI" jar-scan \
  --target /jeus/domains/domain1/applications \
  --target /jeus/domains/domain2/applications \
  --sbom-format nis-1.0 \
  --output-dir /home/user0/projects/koda/reports/java-scan

# 승인 SBOM과 실제 배포 파일 비교
"$KODA_CLI" sbom-verify \
  --target /jeus/domains/domain1/applications \
  --sbom /home/user0/projects/koda/reports/approved-sbom.cdx.json \
  --output-dir /home/user0/projects/koda/reports/sbom-verification \
  --strict-hash --fail-on-version-conflict --fail-on-untracked --fail-on-mismatch

# 승인 SBOM + 실제 JAR + 취약점 통합 점검 (jar-scan --verify-sbom 조합)
"$KODA_CLI" audit \
  --target /jeus/domains/domain1/applications \
  --baseline /home/user0/projects/koda/approved/production-sbom.cdx.json \
  --reports /home/user0/projects/koda/reports/production
```

종료 코드: `0` 기준 통과, `1` 취약점/SBOM 불일치, `2` 입력·도구·실행 오류.

`--sbom-format nis-1.0`은 기존 `server-sbom.cdx.json`과 함께
`server-sbom.nis.csv`를 생성합니다. CSV는 2024년 합동
[SW 공급망 보안 가이드라인 1.0](https://www.krcert.or.kr/kr/bbs/view.do?bbsId=B0000127&menuNo=205021&nttId=71432&pageIndex=1)의
기본 20개 필드를 유지하고, 점검으로 확인하지 못한 값은 비워 둡니다. 이는
형식 지원이며 국정원 인증이나 준수 판정이 아닙니다.

기본적으로 한 번에 하나의 스캔만 실행됩니다(flock). 병렬 실행이 꼭 필요하면
`KODA_ALLOW_CONCURRENT=1`을 지정하십시오.

자원 제한 조정: `KODA_CPUS`(기본 2), `KODA_MEMORY`(4g),
`KODA_PIDS_LIMIT`(256), `KODA_TMPFS_SIZE`(512m). 추가 docker 옵션은
`KODA_DOCKER_EXTRA_ARGS`(공백 구분)로 제한적으로 전달합니다.

## 인증 Linux 포털

운영 화면은 [KODA + KODA SBOM Tracker 통합본](../suite/README.md)의 동일
오리진 `/koda/` 경로를 사용합니다. 통합본에서는 `KODA_PUBLISH_DASHBOARD=0`으로
8765 포트를 게시하지 않고 gateway가 전용 Docker 네트워크로만 접근합니다.
완료된 분석 회차에서는 **SBOM 다운로드**에서
**국정원 NIS-SBOM 1.0 (CSV)**를 선택할 수 있습니다. 프로젝트 접근 권한이 있는
로그인 사용자에게만 `koda-round-<회차>-nis-sbom-1.0.csv`를 반환합니다.

아래 단독 실행은 로컬 개발·호환성 확인용입니다.

```bash
"$KODA_CLI" dashboard start [--reports /home/user0/projects/koda/reports]
"$KODA_CLI" dashboard status
"$KODA_CLI" dashboard logs [-f]
"$KODA_CLI" dashboard stop
```

기본 바인딩은 `127.0.0.1:8765`입니다. 원격 접속은 SSH 터널을 사용합니다.

포트는 실행할 때 `--port`로 바꾸거나 `KODA_PORT`로 지정합니다. 컨테이너 내부
포트는 항상 `8765`이고, 바뀌는 값은 호스트 공개 포트입니다.

```bash
# 호스트의 9876 포트로 공개
"$KODA_CLI" dashboard start --port 9876
# 또는
KODA_PORT=9876 "$KODA_CLI" dashboard start
```

```bash
ssh -L 9876:127.0.0.1:9876 user0@<server-ip>
# http://127.0.0.1:9876/koda/login
```

직접 접속이 승인된 경우에만 `KODA_DASHBOARD_BIND=0.0.0.0`을 명시적으로
지정합니다. 래퍼가 `koda-dashboard` 전용 브리지를 새로 만들 때는 IP
masquerade를 비활성화해 컨테이너 발신 트래픽을 차단합니다. 같은 이름의 기존
네트워크가 있으면 래퍼가 재사용하므로 사용 전
`com.docker.network.bridge.enable_ip_masquerade` 옵션을 확인해야 합니다.
(`--internal` 네트워크는 포트 공개까지 차단하므로 사용하지 않습니다.)

GitLab 서비스 계정으로 접근 가능한 저장소를 포털에서 선택해 점검하려면
[GitLab 저장소 연동 지침](../../../docs/gitlab-integration.md)에 따라 관리자 화면에서
URL·조회용 PAT·결과 저장용 PAT·선택적 CA를 저장합니다. 운영자가 웹 변경을 잠글 때만
`read_api` 조회 토큰과 같은 계정의 `api` 쓰기 토큰 파일, CA 파일을 읽기 전용으로
마운트합니다. KODA는 Tracker가 발급한
저장소별 전송 토큰을 전용 읽기·쓰기 디렉터리에 저장합니다. 허용 목적지만 도달하는 별도 Docker 네트워크는
`KODA_GITLAB_NETWORK`로 연결합니다.

### KODA SBOM Tracker 통합

운영에서는 KODA·Tracker·Dependency-Track을 한 압축파일로 묶은 통합 gateway를
사용합니다. 연결된 빌드 PC에서 검증된 두 전달물을 다음처럼 포장합니다.

```bash
KODA_TRACKER_BUNDLE=/path/to/koda-sbom-tracker-airgap-linux-amd64.tar.gz \
  bash platforms/linux/package-suite-offline.sh
```

폐쇄망 Linux x86_64 서버에서는 압축 해제 후 `./koda-suite verify`,
`config/koda-suite.env.example`을 권한 `600`의 `koda-suite.env`로 복사해 실제
운영값을 입력하고 `./koda-suite install --env-file ./koda-suite.env`을 실행합니다. 이후
`koda-suite start|status|stop`이 세 서비스를 함께 관리합니다. Tracker가 계정과
세션을 관리하고 KODA는 전달받은 UUID에 자체 승인·프로젝트 역할을 적용합니다.
한쪽 로그아웃은 Tracker의 현재 브라우저 세션을 폐기하므로 양쪽에 함께
적용됩니다.

기본 gateway 호스트 포트는 `8088`입니다. 운영 환경에서는 TLS reverse proxy
뒤의 동일 HTTPS 오리진으로 `/`(Tracker), `/koda/`(KODA),
`/dependency-track/`(Dependency-Track)을 제공합니다. KODA의 8765 포트는
호스트에 게시하지 않습니다.

아래 별도 포트 연결은 통합본이 아닌 단독 호환성 확인용입니다. 포털의
`compose.yaml` 기본 공개 포트가 `8088`이므로 같은 서버에서 다음처럼 연결할 수
있습니다.

```bash
# security-sbom-dependecy가 http://127.0.0.1:8088/ 에서 동작하는 경우
export KODA_SSBOM_TRACKER_URL=http://127.0.0.1:8088/
"$KODA_CLI" dashboard stop       # 이미 실행 중이면 환경변경 반영을 위해 재시작
"$KODA_CLI" dashboard start --port 9876
```

원격 PC에서 두 서비스를 모두 SSH 터널로 열 경우에는 두 포트를 함께
전달합니다.

```bash
ssh -L 9876:127.0.0.1:9876 -L 8088:127.0.0.1:8088 user0@<server-ip>
```

사용자 PC의 브라우저에서 `http://127.0.0.1:9876/koda/login`을
열면 버튼으로 `http://127.0.0.1:8088/` 포털을 새 탭에서 열 수 있습니다. 서버
호스트명이 브라우저에서 직접 해석되는 환경이면 `http://tracker.internal/`처럼
그 주소를 지정하십시오. 이 기능은 브라우저 이동 링크이며, KODA가 Tracker의
API 키나 SBOM을 자동으로 전달하지는 않습니다. SBOM 업로드는 기존
`upload-sbom`/Tracker API 경계를 그대로 사용합니다.

대시보드와 Tracker 양방향 버튼이 필요하면 Tracker 웹 앱에도 동일한 방식으로
`VITE_KODA_DASHBOARD_URL` 환경변수를 추가하고, React 상단 네비게이션에
`<a href={...} target="_blank" rel="noreferrer">KODA 대시보드</a>`를 조건부
렌더링합니다. 이때 포털 컨테이너 내부 주소가 아니라 **사용자 브라우저가
접속할 수 있는 주소**를 넣어야 합니다.

## 갱신과 롤백

갱신은 새 전달물 반입으로만 수행합니다. 컨테이너의 인터넷 업데이트는
비활성화되어 있습니다.

```bash
# 연결된 빌드 PC
bash platforms/linux/package-docker-offline.sh --refresh

# 폐쇄망 서버
tar -xzf koda-docker-offline-x86_64-<new-version>.tar.gz
cd koda-docker-offline-x86_64-<new-version> && bash install.sh
```

이전 버전 이미지는 롤백을 위해 보관됩니다. 롤백은 `image-ref.txt`를 이전
버전 태그로 되돌리거나 `KODA_IMAGE=koda-offline:<old-version>`으로
실행하면 됩니다. 검증 완료 후 구버전은 `docker image rm`으로 정리합니다.

## GitLab 적재 (선택)

폐쇄망 내 다른 서버에 GitLab이 있으면 전달물을 두 가지 방식으로 적재할 수
있습니다. 두 방식 모두 스캔 컨테이너의 `--network none` 격리와는 무관하게
호스트에서 수행하는 작업입니다.

### 1) GitLab Container Registry에 이미지 push (권장)

GitLab에 Container Registry가 활성화되어 있어야 합니다.

```bash
docker login registry.gitlab.example.internal
docker tag koda-offline:<version> \
  registry.gitlab.example.internal/<group>/koda/koda-offline:<version>
docker push registry.gitlab.example.internal/<group>/koda/koda-offline:<version>
```

다른 서버에서는 `docker pull` 후 `image-ref.txt`(또는 `KODA_IMAGE`)를 해당
레퍼런스로 지정하면 래퍼가 그대로 동작합니다. 사설 CA를 쓰는 경우 각 Docker
호스트에 `/etc/docker/certs.d/<registry>/ca.crt`를 배치해야 하며,
`--insecure-registry` 설정은 권장하지 않습니다.

### 2) Generic Package Registry에 tar.gz 업로드

Registry가 없거나 파일 그대로 보관하려는 경우:

```bash
curl --header "PRIVATE-TOKEN: <token>" \
  --upload-file koda-docker-offline-x86_64-<version>.tar.gz \
  "https://gitlab.example.internal/api/v4/projects/<id>/packages/generic/koda-docker-offline/<version>/koda-docker-offline-x86_64-<version>.tar.gz"
```

주의: GitLab 저장소(git)에 544MB+ tar.gz를 직접 커밋하지 마십시오. 서버
기본 업로드 제한(`max_import_size`, nginx `client_max_body_size`)보다 큰
파일은 업로드 전에 관리자 설정 확인이 필요합니다. 토큰은 만료 기한이 있는
프로젝트 전용(Deploy Token / Project Access Token, `write_registry` 또는
`api` 최소 범위)을 사용하십시오.

### 스캔 결과 적재

보고서(JSON/HTML/Markdown)를 GitLab CI 아티팩트나 저장소로 적재하려면
`platforms/linux/examples/gitlab-ci.yml`을 참고해 러너에서
`koda-docker jar-scan ... --output-dir "$CI_PROJECT_DIR/reports"`를 실행하고
`artifacts: paths: [reports/]`로 수집하면 됩니다.

## 보안 기본값 확인

```bash
docker inspect <container> --format \
  '{{.HostConfig.NetworkMode}} {{.HostConfig.ReadonlyRootfs}} {{.HostConfig.CapDrop}} {{.HostConfig.SecurityOpt}} {{.HostConfig.PidsLimit}} {{.HostConfig.Memory}} {{.HostConfig.NanoCpus}} {{.Config.User}}'
```

Docker socket 마운트, privileged, host network/PID/IPC는 사용하지 않습니다.
