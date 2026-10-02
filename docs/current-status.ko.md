# KODA 현재 구현·검증 상태

기준일: **2026-10-02 (Asia/Seoul)** · [English](current-status.en.md)

이 문서는 문서 현행화 시 확인한 코드·검증의 스냅샷입니다. 버전 번호가 같은
설치본이라도 빌드 리비전·데이터 패키지를 따로 확인해야 합니다.

## 소스와 게시 범위

| 대상 | 확인한 상태 | 해석 |
| --- | --- | --- |
| GitHub `main` 기준 리비전 | 현행화 시작 시 `e322fd6816ea4d37cfc46820b5717794db4cf938` | 아래 개발 변경 전의 게시 소스 기준 |
| 이번 현행화 | 문서만 게시 | 아래 로컬 개발 코드·테스트·실행 스크립트는 이번 문서 커밋에 포함하지 않음 |
| Linux 순차 실행 | 수동·예약 점검의 공통 실행권과 다중 사용자 대기열을 로컬에서 구현·검증 | 이번 게시에는 안내 문서만 포함. 이미지 재빌드·Linux 실배포 미검증 |
| macOS 로컬 AI | 개발 작업 트리에 구현 파일·fixture·개발 앱 스크립트 존재 | GitHub 신규 clone·App Store에서 제공된다는 의미가 아님 |
| 보안 경계 보강 | 포털·gateway·웹·Java·리포트와 관련 회귀 검증이 로컬에서 변경됨 | 기존 설치본에 반영됐는지 확인하지 않음 |
| 과거 폐쇄망 전달물·날짜별 문서·검증 로그 | 각 문서에 적힌 시점의 기록 | 현재 배포 성공·전체 테스트 통과의 근거로 재사용하지 않음 |

개발 전용 문단은 필요한 구현 파일이 있는 작업 트리에서만 적용됩니다. 이 문서의
테스트 결과도 GitHub `main`만의 결과가 아니라 기존 미커밋 변경을 포함한
로컬 체크아웃의 결과입니다.

## 기능별 현행 안내

| 영역 | 코드에서 확인한 동작 | 상세 문서 |
| --- | --- | --- |
| macOS와 공통 엔진 | macOS는 Swift, Linux·Windows·CI·서버는 공통 Python 엔진 | [설치 문서 인덱스](README.md) |
| 공통 AI 분류 | 기본 OFF, `triage_*`만 추가, 원래 심각도 유지. Ollama 기본 주소는 loopback이나 사용자 지정 API base는 원격도 허용 | [개인정보 정책](../PRIVACY.ko.md), [로드맵](roadmap-ai-augmentation.md) |
| macOS 별도 로컬 AI 개발 | loopback OpenAI 호환 연결, 설명·오탐 검토·수정 제안·재점검·테스트/영향 초안·AI 보고서. 원본과 후보를 분리 | [로컬 AI 개발 가이드](macos-local-ai.ko.md) |
| 개발 포털·gateway | gateway proof, 프로젝트/기능별 권한, 요청 origin, 업로드·JSON·아카이브 자원 제한 | [포털](koda-web-portal.ko.md), [통합 suite](../platforms/linux/suite/README.ko.md) |
| 개발 Linux 점검 대기열 | 점검 엔진과 예약 수집·분석·정리를 한 번에 하나씩 실행. 수동은 사용자·프로젝트 간 FIFO, 다음 작업 선택은 수동 우선 | [순차 실행 안내](linux-scan-queue.ko.md) |
| 개발 로컬 대시보드 | 작업 POST에 same-origin·세션 토큰 요구. 내장 화면이 자동 전달 | [공통 사용법](usage.ko.md) |
| 개발 웹 경계 | origin별 자격증명·리디렉션 제한, 렌더링 경계·WebSocket 차단 기능이 없으면 중단 | [웹 점검 런북](security/WEB_AUDIT.ko.md) |
| 개발 Java 점검 | 아카이브·메타데이터·Syft 출력 제한, 자원 제한으로 불완전한 점검은 정상 성공 대신 종료 코드 2 | [Java 런북](security/java-sbom-vulnerability-scan.md) |
| 개발 NIS-SBOM CSV | 수식 시작 문자 보호 탭·셀 인용. 원래 문자열이 필요한 기계 처리는 JSON/CycloneDX 사용 | [리포트 계약](report-contract.ko.md) |

보안 경계 보강은 동작에 영향을 줍니다. 인증 헤더·권한·origin이 맞지 않는 요청,
제한을 초과한 업로드·아카이브, 다른 origin으로 자격증명을 전달하는 요청은
거부되거나 불완전으로 표시됩니다. 보안·구문 검사를 통과한 AI 수정안도 실제
기능 보존은 회귀 테스트와 검토로 확인해야 합니다.

## 최신 검증 결과

저장소 루트의 로컬 개발 작업 트리에서 2026-10-02 실행했습니다. 아래 명령의
신규 테스트 파일·수정 소스는 이번 문서 게시에 포함하지 않으므로 GitHub 신규
clone에서 동일한 결과를 재현할 수 있다는 뜻은 아닙니다.

```bash
PYTHONPATH=platforms/shared/python python3 -m unittest discover -s tests -q
PYTHONPATH=platforms/shared/python:tests python3 -m unittest test_scan_serialization -q
PYTHONPATH=platforms/shared/python:tests python3 -m unittest test_project_deletion_and_schedule_labels test_scan_serialization test_schedule_gitlab_api -q
git diff --check
```

| 검증 | 관찰한 결과 |
| --- | --- |
| 공통 Python 전체 | 623개: **616 통과, 0 실패, 7 건너뜀**. 실행 70.018초, 종료 코드 0 |
| 순차 실행 회귀 | 11개 통과. DB 연결 간 실행권 경쟁, 수동 FIFO, 예약 정리 후 재개, 취소, 중복 워커·소유권 인계 검증 |
| 삭제 UI·순차 실행·GitLab 예약 API 최종 재실행 | 29개 통과. 실행 4.949초 |
| 건너뜀 | macOS에서 Linux 전용 6개, Playwright 미설치로 PDF 렌더러 1개 |
| 이번 문서 검증 | 9개 문서의 상대 파일·이미지 대상 180개, 내부 anchor 5개 확인. `git diff --check` 통과 |
| macOS fixture·아카이브 | 같은 날 최초 현행화 때 7개 Swift fixture 성공(프로세스 종료 코드 0), 아카이브 unittest 5개 통과. 순차 실행 변경 후 별도 재실행하지 않음 |

### 최초 실패와 후속 수정

앞선 문서 커밋 `e322fd6`에는 609개 중 600 통과·2 실패·7 건너뜀을 기록했습니다.
후속 로컬 변경에서 두 원인을 수정했고, 위 전체·개별 재실행에서 통과했습니다.

- 삭제 UI 테스트는 실제 삭제 버튼 대신 CSS 선택자의 문자열까지 일치시켰습니다.
  실제 HTML 요소·속성을 검사하도록 테스트를 교정했으며 삭제 권한의 제품 동작은
  이 교정으로 변경하지 않았습니다.
- GitLab 예약 수집은 아카이브 다운로드가 작은 제어 요청과 같은 슬롯을 점유해
  heartbeat가 HTTP 429로 거부됐습니다. 아카이브와 제어 슬롯을 분리했고,
  느린 전송 중 heartbeat 성공·두 번째 아카이브 거부를 검증했습니다.

최신 통과 결과는 로컬 작업 트리의 결과이며 이미지·설치본·운영 서버의 배포
준비를 증명하지 않습니다. 실행 정책과 자원 한도는 [순차 실행 안내](linux-scan-queue.ko.md)에 있습니다.

## 확인하지 않은 범위

- 실제 Docker/Nginx gateway 설치·로그인·운영 및 기존 서버로의 배포
- 실제 Playwright Chromium의 네트워크·렌더링 동작
- 현재 App Store 앱·Windows 설치본·폐쇄망 압축파일의 기능 및 데이터 최신성
- 이번 현행화에서의 Xcode 앱 빌드, 실제 로컬 모델 응답·생성 품질, Java 포함 macOS 빌드
- AI 수정안의 기능 동등성·모든 사용 사례의 호환성

GitHub 비공개 취약점 신고는 기준일 확인 시 비활성화 상태였습니다. 확인된
신고 경로와 민감한 내용의 취급은 [보안 정책](../SECURITY.ko.md)을 따릅니다.
