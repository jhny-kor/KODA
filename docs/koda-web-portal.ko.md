# KODA 웹 포털 화면과 기능

> 현행화 기준: 2026-10-11 로컬 소스 checkout(개발 중 변경 포함). 이 문서의
> 게시가 해당 소스 변경의 게시나 GitHub main·기존 배포 이미지 반영을 뜻하지
> 않습니다. 아래 checkout 동작을 운영에 적용하기 전에 설치 버전과 대응 번들의
> 재빌드·검증 여부를 확인해야 합니다.

Linux KODA는 Tracker의 SBOM 관리 화면이 아니라 KODA 보안·품질 점검 기능을
브라우저에서 사용하는 포털입니다. 프로젝트별 입력과 분석 회차를 보관하고,
메뉴에서 라이브러리 취약점과 소스코드 취약점을 각각 실행합니다. 완료 결과 안에서는
기존 라이브러리·소스코드·품질 분류 탭도 함께 제공합니다. 사이드바 하단의
`사용 가이드`는 KODA 기능·보안 용어·지원 기준을 설명하고, 우측 상단 계정 메뉴는
현재 사용자 정보와 로그아웃을 제공합니다.

## Checkout의 권한·업로드·내보내기 계약

아래는 2026-10-11 checkout에 있는 개발 중 변경이며 기존 배포 이미지의
반영 여부는 확인되지 않았습니다. 화면 접근과 서버 측 기능 실행 권한을 분리합니다.

| 기능 | 실행 권한 |
| --- | --- |
| 입력 등록 | `input.manage` |
| 라이브러리 점검 | `scan.library.create` |
| 소스코드 점검 | `scan.source.create` |
| 전체 점검 | 위 두 점검 권한 모두 |
| 프로젝트 생성 / 삭제 | `project.create` / `project.delete` |
| 결과 내보내기 / 회차 삭제 | `runs.export` / `runs.delete` |
| Tracker / GitLab 결과 / Issue 게시 | `runs.tracker.publish` / `runs.gitlab.result.publish` / `runs.gitlab.issues.publish` |

각 화면에는 별도의 `.view` 권한도 필요합니다. legacy `scan.create` 정책은
scope별 실행 권한으로 마이그레이션되며 시스템 관리자는 모든 기능을 사용할 수
있습니다. 라이브러리 실행을 소스코드 실행 허용으로 간주하지 않습니다.

파일당 스트리밍 한도는 정확히 2 GiB(2,147,483,648 bytes)이고 화면에서는 `2 GB`로
표시합니다. 입력 보관소는 기본 10 GiB이며 `KODA_PORTAL_UPLOAD_QUOTA_BYTES`의
양의 정수 bytes로 조정합니다. 남아 있는 입력과 진행 중인 예약 용량을 합산해
허용하고 초과하면 `413 upload_quota_exceeded`를 반환합니다. 일반 포털 JSON은
1 MiB이며 내부 스케줄 API는 기본 500 MiB(`KODA_JSON_MAX_BYTES`)입니다.

인증된 포털 요청은 Tracker의 identity 헤더와 게이트웨이가 덮어쓰는
`X-KODA-Gateway-Proof`를 함께 검증합니다. Suite는 공유 비밀
`KODA_GATEWAY_PROOF`를 `.env`에 생성하며 직접 포털 접속은 이 경계를 우회할 수
없습니다. 단독 loopback dashboard 시작만으로 보호 포털의 로그인 계약이 갖춰지지
않으므로 운영은 통합 Suite 경로를 사용합니다.

NIS-SBOM과 회차 비교 CSV는 모든 셀을 인용하고, 공백·BOM·NUL 뒤의
`=`, `+`, `-`, `@` 및 전각 변형으로 시작하는 값 앞에 tab을 붙여 스프레드시트
수식 해석을 방지합니다. CSV에서 보이는 tab은 이 표현 변경의 일부이며
CycloneDX/JSON의 원래 값에는 적용하지 않습니다.

## 다중 사용자 점검 대기

현재 로컬 개발 소스는 서버 점검 엔진을 한 번에 하나만 실행하고 수동 요청을
접수 순서대로 처리합니다. 실행 중인 예약이 있으면 수동 요청은 대기하며 예약은
수집·분석·원본 정리까지 완료합니다. 상세 우선순위·취소·복구·검증 범위는
[Linux 점검 순차 실행](linux-scan-queue.ko.md)을 확인하세요. 운영 서버에 반영하려면
해당 코드의 별도 이미지 빌드·배포가 필요합니다.

## 2026-10-11 실행 검증 범위

현재 소스로 만든 `linux/amd64` 시험 이미지에서 설치·실행을 확인했습니다.
Debian 12·Python 3.12.15 환경이며 Apple Silicon의 Docker LinuxKit VM에서
amd64 사용자 공간을 에뮬레이션했습니다. 물리 x86_64 서버나 네이티브 x86_64
커널의 성능·호환성을 검증한 결과는 아닙니다. Linux ARM64는 검증 대상이 아닙니다.

- `platforms/linux/install.sh --no-link`로 소스 설치본을 실제 설치하고 CLI·미인증
  API 거부를 확인했습니다. Docker 전달물의 `docker/install.sh` 전체 반입 절차를
  실행한 결과는 아닙니다.
- 실제 Docker 런처가 웹·분석·전송 컨테이너를 만들고 ZIP 업로드→점검→JSON/PDF
  다운로드를 완료했습니다. PDF는 29,020바이트, 두 워커는 healthy, 잔여 작업 폴더는
  0개였습니다. 시험 컨테이너는 종료·제거했습니다.
- Syft 1.46.0·Grype 0.115.0을 네트워크 차단·4 GiB 제한에서 실행했습니다.
  합성 `log4j-core 2.14.1` JAR에서 취약점 7건·경고 0건을 확인했으며
  `--fail-on high`가 종료 코드 `1`로 차단했습니다.
- 전체 회귀는 **768개 중 767개 통과·실패 0개·로컬 LLM 연동 1개 건너뜀**입니다.
- 실제 Nginx gateway 로그인, 외부 Tracker/GitLab 전송, 강제 OOM 복구와 운영 Suite
  업그레이드·롤백은 미검증입니다. 설치·롤백 unittest는 Docker test double을
  사용하는 계약 검사이며 실제 운영 업그레이드를 뜻하지 않습니다.

이번 GitHub 문서 게시는 실행 소스 게시나 운영 이미지 배포를 포함하지 않습니다.
[검증 요약](verification-2026-10-11.ko.md)을 확인하고 설치된 버전과
대응 번들을 따로 확인하세요.

## 화면 예시

### 대시보드

[![KODA 프로젝트와 최근 점검 회차를 보여주는 대시보드](assets/koda-web/koda-dashboard.png)](assets/koda-web/koda-dashboard.png)

### 라이브러리·소스코드 점검

[![KODA 프로젝트와 입력 파일을 선택하는 라이브러리 CVE 점검 화면](assets/koda-web/koda-new-scan.png)](assets/koda-web/koda-new-scan.png)

사이드바에서 `라이브러리 취약점` 또는 `소스코드 취약점`을 선택합니다. 라이브러리
화면은 SBOM·manifest·lockfile·JAR/WAR와 오프라인 취약점 DB를 사용하고, 소스코드
화면은 코드·비밀정보·보안설정·예방통제 카테고리를 실행합니다. 라이브러리 점검은
검사 기준과 범위를 고르지 않고 `CVE 점검`으로 고정하며, CVE가 연결된 Grype 결과만
남깁니다. 소스코드 점검은 `전체` 또는 지원 기준·범위를 선택합니다. 입력은 최대
`2 GB` 파일을 스트리밍 등록하거나, 관리자가 연결한 GitLab 저장소의 브랜치·태그를
선택할 수 있습니다. GitLab 입력은 실행 전에 commit SHA로 고정됩니다. 오프라인 취약점 DB를 사용할 수 없으면
라이브러리 화면에서 실행 전에 `점검 불가`와 원인을 표시합니다.

### 결과 탭

[![KODA 결과 화면에서 라이브러리 취약점 탭을 선택한 예시](assets/koda-web/koda-result-tabs.png)](assets/koda-web/koda-result-tabs.png)

위 이미지는 실제 KODA 결과 화면을 대표 점검 데이터로 렌더링한 예시입니다.
점검 결과는 같은 회차 안에서 다음 탭으로 분류됩니다.

- `라이브러리 취약점`: manifest·lockfile 등에서 식별한 구성요소와 PURL을 번들된
  오프라인 Grype DB로 대조한 결과입니다.
- `소스코드 취약점`: 코드, 비밀정보, 보안설정, 예방통제 규칙의 결과입니다.
- `품질 점검`: 화면 품질과 접근성 규칙의 결과입니다.
- `전체`: 위 결과를 한 번에 조회합니다.

탭을 바꿔도 제목·규칙 ID·파일 검색과 심각도 필터, 상세 증거·조치 방법은 그대로
사용합니다. 라이브러리 회차의 `라이브러리 취약점 보고서`는 구성요소·버전·취약점
식별자 중심의 메인·상세 HTML을 표시합니다. 완료 회차에서는 HTML ZIP·PDF·Excel·
JSON·Markdown과 CycloneDX 1.6·국정원 NIS-SBOM 1.0을 내려받을 수 있습니다.

### 회차 비교와 접근 관리

[![KODA 두 점검 회차의 신규, 해결, 유지 항목 비교](assets/koda-web/koda-comparison.png)](assets/koda-web/koda-comparison.png)

[![KODA 공유 계정의 접근 허용, 시스템 관리자와 프로젝트 역할 설정](assets/koda-web/koda-admin-access.png)](assets/koda-web/koda-admin-access.png)

비교 결과는 항목별 검색·상태 필터와 CSV·JSON 내보내기를 제공합니다. KODA 관리자는
공유 계정의 KODA 접근·시스템 관리자 여부와 사용자별 프로젝트 역할을 설정합니다.
`설정 > 연동 설정`에서는 시스템 관리자만 서비스 계정이 접근 가능한 저장소를 KODA 프로젝트에 연결합니다.
Tracker 서비스·환경·전송 토큰은 연결 시 자동 생성 또는 재사용됩니다. 시스템 관리자는
GitLab HTTPS URL, 조회용 `read_api` PAT와 결과 저장용 `api` PAT를 분리해 저장·교체할
수 있으며 PAT와 사설 CA는 다시 표시되지 않는 write-only 값입니다. GitLab API 호출은
KODA 웹·전송 워커만 수행하고 Tracker에는 GitLab 자격증명을 저장하지 않습니다.

### 오프라인 취약점 DB 상태

[![KODA 오프라인 취약점 DB 상태와 점검 가능 여부](assets/koda-web/koda-admin-vulnerability-db.png)](assets/koda-web/koda-admin-vulnerability-db.png)

개발 환경처럼 Grype 실행 파일이나 DB가 없으면 `점검 불가`로 실패 폐쇄합니다.
폐쇄망 배포 이미지에서는 번들된 Grype 버전과 DB 메타데이터가 이 화면에 표시되어야
하며, 이 정보가 확인되지 않으면 라이브러리 취약점 점검을 시작하지 않습니다.

## 기능 흐름

[![KODA 입력, 점검 분기, 회차 저장, 결과 활용 흐름](assets/koda-web/koda-functional-flow.svg)](assets/koda-web/koda-functional-flow.svg)

라이브러리 점검은 CVE 기준으로 고정되고, 소스코드 점검 사용자는 검사 기준과 범위를
선택합니다. 관리자는 활성 규칙 정책을 관리합니다.
실행 시점의 입력 해시·정책 버전·요청 계정·스캐너 정보는 회차 스냅샷에 함께
저장되므로 결과를 다시 열거나 이전 회차와 비교할 수 있습니다.

점검 중에는 준비·스캔·마무리 단계와 진행률을 표시하며 취소할 수 있습니다. 점검이
완료·실패·취소되면 회차 스냅샷과 결과만 보관하고 원본 입력 파일은 삭제합니다. 분석 프로세스의 종료를 확인하지 못한 경우에는
작업 공간과 실행 상태를 보존하고 워커가 추가 분석을 시작하지 않습니다. 원본이
필요한 새 점검은 파일을 다시 등록해야 하며 결과 화면에는 다시 실행 버튼이 없습니다.
라이브러리 단계에는 실제 사용한 Grype 버전, 오프라인 DB 메타데이터, 조회 구성요소 수와 경고를
표시하므로 `취약점 0건`과 `DB 점검 실패`를 구분할 수 있습니다. KODA 입력 파일은
브라우저 메모리에 Base64로 올리지 않고 화면 안내 기준 최대 2 GB까지 스트리밍 업로드합니다.
GitLab 회차에는 저장소·ref·commit SHA·아카이브 해시를 기록합니다. 완료 CycloneDX를
Tracker로 전송해 분석 결과를 받은 뒤 GitLab 결과 브랜치·Merge Request와 commit당
하나의 비공개 CVE 요약 Issue를 생성하며, 결과 화면에는 `Tracker 전송`과 `GitLab 결과
등록`을 분리한 상태·링크·재시도 기능을 함께 표시합니다. 이 흐름과 별도로 KODA가 확정한 코드·비밀정보·보안설정·예방통제
취약점은 항목별 비공개 Issue로 관리합니다. 열린 동일 Issue에는 새 회차 댓글을
추가하고 닫힌 Issue는 새로 생성하며, 품질·검토 필요·미검증 결과는 제외합니다. GitLab
쓰기 실패는 점검이나 Tracker 전송 상태를 변경하지 않습니다. 라이브러리 CVE는 Tracker
요약 Issue에만 포함합니다.

계정 가입과 승인은 KODA-SBOM-Tracker가 단일 원본으로 관리합니다. KODA 관리자 화면은
공유 계정의 KODA 접근 차단·허용, 시스템 관리자 여부, 사용자별 프로젝트 역할을
관리합니다. 전역 역할 정책은 화면 접근 권한과 기능 실행 권한으로 나누고, 점검 규칙은
기준별 카드에서 규칙별 활성 체크박스로 설정합니다.

기능도는 [diagram-design](https://github.com/cathrynlavery/diagram-design)의
정보 밀도, 제한된 강조색, 정적 SVG 접근성 원칙을 참고해 KODA 문서용으로 새로
작성했습니다. 외부 스크립트나 이미지 의존성은 없습니다.

## 관련 문서

- [Linux 설치·운영](install/linux.ko.md)
- [통합 폐쇄망 설치](../platforms/linux/suite/README.ko.md)
- [GitLab 저장소 연동](gitlab-integration-ko.md)
- [KODA 리포트 계약](report-contract.ko.md)
