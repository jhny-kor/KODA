# KODA 현재 구현·검증 상태

기준일: **2026-10-11 (Asia/Seoul)** · [English](current-status.en.md)

검증 당시 로컬 작업 트리의 소스 점검·오류 수정·빌드·실행 검증 결과다. **이번 GitHub
게시에는 검증한 제품 소스·테스트·빌드 스크립트와 문서를 포함한다. Java 자산·앱
바이너리·Docker 이미지·원시 로그는 로컬에 보존한다.** GitHub 소스 게시가 기존
설치본·App Store 앱·운영 서버의 업데이트나 같은 취약점 데이터 제공을 뜻하지 않는다.

## 소스와 게시 범위

| 대상 | 확인한 상태 | 해석 |
| --- | --- | --- |
| 검증 당시 GitHub `main` 소스 기준 | `4efb0bce1e0f5a00a078c77d9f91608d5127a757` | 이번 검증은 이 리비전과 로컬 미커밋·신규 소스를 합친 상태 |
| 앞선 문서 게시 | `f1f040193ae74609e089b4af486dd46dca0bc2d4` | 문서만 게시한 기록. 아래 소스 게시가 이후 추가됨 |
| 이번 게시 | GitHub 제품 소스·테스트·빌드 스크립트·문서 갱신 | Java 자산·바이너리·이미지·원시 로그 제외. 운영·App Store 배포와 별개 |
| macOS | Java 포함 universal Release 앱 빌드·분석, ARM 실제 실행 | 별도 검증 앱. 기존 App Store 설치본을 교체하지 않음 |
| Linux | 현재 소스를 설치한 amd64 이미지와 web/scan/delivery worker 실행 | Apple Silicon의 Docker LinuxKit VM에서 amd64 사용자 공간 에뮬레이션 |
| Windows | 소스·패키징 의존성·PowerShell·프로세스 회귀 확인 | 실제 Windows 실행은 사용자 지시로 제외 |
| 운영 설치본·날짜별 전달물 | 각 버전·문서에 적힌 시점의 기록 | 현재 작업 트리나 이번 검증 결과와 동일하지 않음 |

## 기능별 현행 안내

[OS별 전체 기능 구현표](platform-feature-matrix.ko.md)는 126개 기능을
macOS·Windows·Linux x86_64 열에 O/X로 표시한다. O는 구현 여부이며 실기 검증·
전체 보안 기준 준수·모든 입력의 탐지 성공을 의미하지 않는다.

| 영역 | 현재 로컬 소스에서 확인한 동작 | 상세 문서 |
| --- | --- | --- |
| 실행 경로 | macOS Swift 네이티브 앱, Windows Full 대시보드/CLI, Linux 호스트/Docker/인증 포털 | [구현표](platform-feature-matrix.ko.md), [설치 인덱스](README.md) |
| 기본 소스 점검 | 코드·설정·비밀값·의존성·품질·예방 통제, 변경 파일 검사와 기준별 결과 | [공통 사용법](usage.ko.md) |
| 공통 AI | 기본 OFF, 설명·오탐 검토·조치 제안·요약. 원래 심각도 유지. 사용자 지정 API base는 원격 가능 | [개인정보 정책](../PRIVACY.ko.md), [사용법](usage.ko.md) |
| macOS 로컬 AI 개발 | localhost 연결·모델 목록·키체인, 수정 후보·재점검·테스트/영향 초안·AI 보고서. 원본과 후보 분리 | [로컬 AI](macos-local-ai.ko.md) |
| Java | 번들/설정한 Syft·Grype·DB·NVD·CISA, 한국어 SBOM/취약점 보고서 | [Java 런북](security/java-sbom-vulnerability-scan.md) |
| 검사 실패 | 없는 소스 대상은 오류. Java 판정 gate 요청 시 비교 도구 부재는 종료 코드 2. 명시적 gate 없는 SBOM-only는 허용 | [사용법](usage.ko.md), [Java 런북](security/java-sbom-vulnerability-scan.md) |
| 프로세스·압축 | 정상 빈 DEFLATE 허용, 손상·자원 제한 거부. Syft 양쪽 출력 수집·전체 timeout, macOS Java helper 실행 중 출력 소비 | [검증 요약](verification-2026-10-11.ko.md) |
| Linux 포털·worker | gateway proof·기능 권한·입력 quota, 수동/예약 단일 실행권, 외부 scan/delivery worker·취소·복구 | [포털](koda-web-portal.ko.md), [순차 실행](linux-scan-queue.ko.md) |
| 웹 | origin별 인증·렌더 경계, 선택형 능동/침투/영향 실증, 공통 CLI의 승인 프로필 기반 21개 통제 | [웹 런북](security/WEB_AUDIT.ko.md) |
| 보고서 | 플랫폼별 형식과 NIS-SBOM CSV 수식 보호. CodeQL은 직접 실행하지 않고 preflight/SARIF import 범위를 구분 | [리포트 계약](report-contract.ko.md), [구현표](platform-feature-matrix.ko.md) |

거부·미지원·불완전 상태는 정상 성공과 구분한다. AI 후보의 구문·보안 재점검은
실제 기능 동등성을 증명하지 않으며 별도 검토·회귀 테스트가 필요하다.

## 최신 검증 결과

[2026-10-11 검증 요약](verification-2026-10-11.ko.md)과
[기계 판독 요약](verification-2026-10-11.json)에 실행 조건·소스 식별자를 기록했다.
아래 검증에 사용한 제품 소스·테스트·빌드 스크립트는 이번 GitHub 게시에 포함된다.
같은 결과를 재현하려면 기록된 도구·Java 자산·환경을 별도로 준비해야 한다.

| 검증 | 관찰한 결과 | 조건 |
| --- | --- | --- |
| Linux 전체 Python | 768개: **767 통과, 0 실패, 1 건너뜀**, 198.051초 | Debian 12, Python 3.12.15, 실제 linux/amd64 컨테이너 |
| macOS 호스트 전체 Python | 768개: **760 통과, 0 실패, 8 건너뜀**, 142.730초 | Python 3.14.6, 앞선 수정 단계 |
| Python 3.12 집중 회귀 | **214개 통과** | CLI·Java·웹·네트워크·Syft·패키징·worker |
| macOS 검증 harness | **10개 실행 스크립트 모두 성공** | 로컬 AI 7종, 압축, Java 프로세스, 자산 패키징 |
| macOS Java 포함 Release | **arm64+x86_64 build/analyze 성공** | 개발자 서명·공증 없는 검증 빌드 |
| macOS Java 실제 실행 | **영어 UI 설정 및 네트워크 차단 한국어 설정 모두 exit 0** | ARM 실제 앱·번들 helper·Syft·Grype 사용 |
| Linux 실제 설치·포털 | **설치·CLI·ZIP 업로드·worker 검사·JSON/PDF 생성 성공** | web/scan/delivery 컨테이너 3개, 시험 종료 후 모두 정지·제거 |
| Linux Java 실제 실행 | **DB import 0, 취약점 gate 1** | network none, 4GiB 제한 |
| 합성 Java 입력 | 양쪽 **구성요소 1개·취약점 7개·KEV 1개·경고 0개** | Log4j 2.14.1 메타데이터만 포함, Java 코드 실행 없음 |
| Windows | 신규 회귀 8개·PowerShell 2개 문법 검사 통과 | macOS에서 계약 검증, Windows 실기 실행 아님 |
| 정적·문서 검사 | Ruff F/E9·shell 문법·diff 검사 통과. 이번 문서 링크·O/X 형식도 게시 전 확인 | 소스 실행·배포와 별개 |

Linux의 skip 1개는 로컬 LLM 연동이다. 앞선 macOS 실행의 skip 8개는 로컬 LLM 1,
Linux 자원 제한 1, Linux 설치/롤백 5, Chromium PDF 1이다. 마지막 Linux 실행은
자원 제한·설치/롤백 계약·실제 Chromium PDF 테스트를 포함한다. 설치/롤백 unittest는
Docker double을 사용하는 계약 테스트로 운영 Suite의 실제 업그레이드·복구 증거가 아니다.

## 남은 검증 범위

- Intel Mac 실제 실행: 바이너리·링크는 확인했지만 이 호스트에서는 `Bad CPU type in executable`로 실행 불가.
- 물리 x86_64 서버/네이티브 x86_64 커널·운영 부하·실제 OOM/장애 복구.
- 실제 Windows EXE 생성·설치·WebView2·Syft 실행.
- 운영 Nginx gateway 로그인·실제 Tracker/GitLab 전송·운영 Suite 업그레이드/롤백.
- 개발자 서명·공증·App Store 제출 및 기존 배포본 반영.
- 실제 외부 웹 대상의 탐지 성능, 실제 로컬 모델 생성 품질과 AI 후보 기능 동등성.

## 이전 기록

2026-10-02 문서 갱신의 최종 결과는 623개 중 616 통과·7 건너뜀이었다.
그보다 앞선 `e322fd6`에는 609개 중 600 통과·2 실패·7 건너뜀이 기록됐다.
이 수치는 당시 개발 체크아웃의 역사 기록이며 위 2026-10-11 결과로 갱신한
현재 상태와 구분한다. 날짜별 전달물·로드맵·설계 문서는 원래 시점의 기록을 유지한다.

[한국어 문서 인덱스](README.md) · [OS별 구현표](platform-feature-matrix.ko.md)
