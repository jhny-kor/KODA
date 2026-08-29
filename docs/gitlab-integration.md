# GitLab 저장소 연동 운영 지침

KODA Linux 포털은 GitLab CE `19.2.2`의 서비스 계정이 접근할 수 있는 프로젝트를
관리자가 선택해 KODA 프로젝트에 연결합니다. GitLab Runner `18.10.0`은 이 흐름에
사용하지 않으므로 버전 변경이나 Runner 등록이 필요하지 않습니다.

## 1. GitLab 준비

1. 자동 점검 전용 서비스 계정을 만들고 대상 그룹·프로젝트에 저장소 조회는
   `Reporter` 이상으로 추가합니다. 비공개 취약점 Issue 작성·댓글에는 Reporter가
   충분하지만, Tracker 결과 브랜치와 Merge Request까지 저장하려면 `Developer` 이상이
   필요합니다.
2. 저장소 조회용 Personal Access Token은 `read_api`, 결과 저장용 PAT는 `api`
   범위로 각각 발급합니다. `write_repository`는 REST API Issue 쓰기 권한을 제공하지
   않습니다. 두 PAT는 반드시 같은 GitLab 계정에서 발급합니다.
3. `설정 → 연동 설정`에서 HTTPS URL과 두 PAT를 저장합니다. 읽기 PAT로
   계정 연결을 확인하고, 쓰기 PAT는 `/personal_access_tokens/self` 응답의 `api` 범위와
   동일 계정 여부를 확인합니다. 사설 CA를 사용하면 PEM 인증서도 함께 입력합니다.

웹에서 저장한 PAT와 CA는 KODA 영구 데이터 디렉터리의 `integrations` 아래에
`0600` 파일로 분리 저장됩니다. PAT는 화면·API·DB·감사 로그에 반환하지 않으며 저장
후에는 새 PAT로 교체만 할 수 있습니다. 저장 즉시 적용되므로 재시작은 필요하지 않습니다.

운영자가 웹 변경을 막아야 하는 환경에서는 다음 환경변수 방식을 대신 사용합니다.
환경변수가 하나라도 설정되면 이 설정이 우선하고 웹 입력은 잠깁니다.

```bash
sudo install -d -o "$(id -u)" -g "$(id -g)" -m 0700 /etc/koda/secrets
printf %s "$GITLAB_READ_TOKEN" > /etc/koda/secrets/gitlab.token
printf %s "$GITLAB_WRITE_TOKEN" > /etc/koda/secrets/gitlab-write.token
chmod 0400 /etc/koda/secrets/gitlab*.token
```

## 2. 운영자 잠금 설정 (선택)

```bash
export KODA_GITLAB_URL=https://gitlab.example.internal
export KODA_GITLAB_TOKEN_FILE=/etc/koda/secrets/gitlab.token
export KODA_GITLAB_WRITE_TOKEN_FILE=/etc/koda/secrets/gitlab-write.token
export KODA_GITLAB_CA_FILE=/etc/koda/secrets/internal-ca.pem   # 사설 CA일 때만
export KODA_GITLAB_NETWORK=koda-integration                    # 미리 만든 제한 네트워크

export KODA_TRACKER_URL=http://koda-sbom-gateway:8080
export KODA_TRACKER_TOKEN_DIR=/etc/koda/secrets/tracker
export KODA_TRACKER_PROVISIONING_TOKEN_FILE=/etc/koda/secrets/tracker-provisioning.token
export KODA_TRACKER_RESULT_TIMEOUT_SECONDS=900
./koda-docker.sh dashboard start
```

웹 설정을 사용할 때는 위의 `KODA_GITLAB_URL`, `KODA_GITLAB_TOKEN_FILE`,
`KODA_GITLAB_WRITE_TOKEN_FILE`, `KODA_GITLAB_CA_FILE`을 비워 둡니다. `KODA_GITLAB_NETWORK`은 KODA가 GitLab 주소에만 통신할 수 있도록 호스트 방화벽과
함께 제한합니다. 통합 Suite에서는 Tracker gateway와 KODA가 이미 전용
`koda-dashboard` 네트워크를 공유하므로 내부 gateway 주소를 그대로 사용합니다.
Compose 프로젝트명을 변경했다면 gateway 이름도 함께 바꿉니다. GitLab PAT와
프로비저닝 토큰은 읽기 전용으로, 저장소별 Tracker 토큰 디렉터리는 KODA가 토큰을
원자적으로 회전할 수 있도록 실행 계정 전용 읽기·쓰기로 마운트합니다.

## 3. 관리자 연결

1. `설정 → 연동 설정`에서 URL·읽기 PAT·결과 저장 PAT·선택적 CA를 저장합니다. 이 화면은 시스템 관리자만 접근하며 PAT와 CA는 write-only입니다.
2. `저장소 불러오기`를 누르고 서비스 계정이 접근 가능한 목록에서 저장소를 선택합니다.
3. KODA 프로젝트를 고르고 연결합니다. KODA가 Tracker에 저장소 정보를 보내 저장소별
   서비스를 생성하거나 재사용하고, `gitlab-source` 환경과 서비스 전용 전송 토큰을
   자동 준비합니다. Tracker UUID나 토큰 파일명은 화면에서 입력하지 않습니다.

전체 GitLab 목록은 매번 API로 조회하며 DB에 캐시하지 않습니다. 선택한 연결만
저장됩니다. 저장소 하나는 한 KODA 프로젝트에만 연결할 수 있습니다.

## 4. 사용자 점검

라이브러리 또는 소스코드 점검 화면에서 `GitLab 저장소`를 선택하고 브랜치나 태그를
고릅니다. KODA는 선택한 ref를 전체 commit SHA로 확정한 뒤 그 SHA의 tar.gz
아카이브를 다운로드합니다. LFS blob은 포함하지 않으며, 압축 1 GB·해제 4 GB·파일
20만 개 제한과 기존 경로 이탈 방어를 적용합니다. 해제 작업은 `/var/lib/koda` 볼륨을
사용하므로 최소 4 GB 이상의 여유 공간을 확보합니다. 결과에는 저장소, ref, commit SHA,
아카이브 SHA-256이 불변 스냅샷으로 남습니다.

완료된 CycloneDX 결과는 KODA-SBOM-Tracker로 자동 전송됩니다. GitLab API를 호출하는
주체는 KODA뿐이며 Tracker는 PAT를 보관하거나 GitLab에 직접 연결하지 않습니다. KODA는 Tracker 분석이
끝날 때까지 기다린 뒤 `.koda/sbom-tracker/<commit-sha>.json`을
`koda/sbom-results/<commit-sha-앞12자리>` 브랜치에 저장하고 기본 브랜치 대상 Merge
Request를 생성하거나 기존 항목을 재사용합니다. CVE가 있으면 같은 commit당 하나의
비공개 요약 Issue를 생성하며, 재시도해도 MR·Issue를 중복 생성하지 않습니다. 전송·분석
조회·GitLab 게시 중 하나가 실패하면 KODA 회차 자체는 보존됩니다. 결과 화면에서는
`Tracker 전송`과 `GitLab 결과 등록` 상태를 별도로 확인하며, 실패한 단계만 각각 재시도할
수 있습니다. GitLab 결과 등록은 commit SHA를 기준으로 결과 브랜치를 유지하고 MR과
요약 Issue를 중복 없이 재사용합니다.

KODA가 직접 `confirmed`로 확정한 코드·비밀정보·보안설정·예방통제
취약점은 항목당 하나의 비공개 Issue로 생성합니다. 동일 취약점의 열린 Issue가 있으면
새 회차·ref·commit SHA를 댓글로 추가하고, 닫힌 Issue는 재개방하지 않고 새 Issue를
만듭니다. 품질·검토 필요·미검증 결과는 등록하지 않으며 KODA가 Issue를 자동으로
닫지는 않습니다. 배포 전에 완료된 기존 회차는 소급 등록하지 않습니다.
라이브러리 취약점은 Tracker의 commit별 CVE 요약 Issue에만 포함해 중복 등록하지
않습니다.

항목별 GitLab 4xx는 해당 항목만 실패로 기록하고, 인증 실패·요청 제한·GitLab 장애는
남은 배치를 중단합니다. 어떤 경우에도 KODA 점검 완료 상태나 Tracker 전송 상태를
실패로 바꾸지 않습니다. 시스템 관리자는 결과 화면의 `실패 항목 재시도`로 실패·미처리
항목만 다시 보낼 수 있습니다.

## 5. 점검 체크리스트

- 서비스 계정이 허용된 저장소만 목록에 보이는지 확인
- 일반 사용자가 자신에게 배정된 KODA 프로젝트의 연결만 보는지 확인
- ref 이동 후에도 기존 회차의 commit SHA가 변하지 않는지 확인
- Tracker 중단 시 KODA 회차가 보존되고 연동 상태만 `failed`인지 확인
- 같은 취약점 재점검에서 열린 Issue에 댓글이 추가되고, 닫힌 Issue는 새로 생성되는지 확인
- 전송 중 KODA를 재시작해도 처리 마커로 비공개 Issue가 중복 생성되지 않는지 확인
- 토큰 문자열이 화면·감사 로그·컨테이너 환경 변수에 노출되지 않는지 확인
