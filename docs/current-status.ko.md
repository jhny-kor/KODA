# KODA 현재 구현·검증 상태

기준일: **2026-10-02 (Asia/Seoul)** · [English](current-status.en.md)

이 문서는 문서 현행화 시 확인한 코드·검증의 스냅샷입니다. 버전 번호가 같은
설치본이라도 빌드 리비전·데이터 패키지를 따로 확인해야 합니다.

## 소스와 게시 범위

| 대상 | 확인한 상태 | 해석 |
| --- | --- | --- |
| GitHub `main` 기준 리비전 | 현행화 시작 시 `95297eb76c781cbe579b41b5e3f2b91bcd13e9ee` | 아래 개발 변경 전의 게시 소스 기준 |
| 이번 현행화 | 문서만 게시 | 아래 로컬 개발 코드·테스트·실행 스크립트는 이번 문서 커밋에 포함하지 않음 |
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
| 개발 로컬 대시보드 | 작업 POST에 same-origin·세션 토큰 요구. 내장 화면이 자동 전달 | [공통 사용법](usage.ko.md) |
| 개발 웹 경계 | origin별 자격증명·리디렉션 제한, 렌더링 경계·WebSocket 차단 기능이 없으면 중단 | [웹 점검 런북](security/WEB_AUDIT.ko.md) |
| 개발 Java 점검 | 아카이브·메타데이터·Syft 출력 제한, 자원 제한으로 불완전한 점검은 정상 성공 대신 종료 코드 2 | [Java 런북](security/java-sbom-vulnerability-scan.md) |
| 개발 NIS-SBOM CSV | 수식 시작 문자 보호 탭·셀 인용. 원래 문자열이 필요한 기계 처리는 JSON/CycloneDX 사용 | [리포트 계약](report-contract.ko.md) |

보안 경계 보강은 동작에 영향을 줍니다. 인증 헤더·권한·origin이 맞지 않는 요청,
제한을 초과한 업로드·아카이브, 다른 origin으로 자격증명을 전달하는 요청은
거부되거나 불완전으로 표시됩니다. 보안·구문 검사를 통과한 AI 수정안도 실제
기능 보존은 회귀 테스트와 검토로 확인해야 합니다.

## 이번에 실행한 검증

저장소 루트에서 2026-10-02 실행했습니다.

```bash
PYTHONPATH=platforms/shared/python python3 -m unittest discover -s tests -q
python3 -m unittest discover -s platforms/macos/tests -q
PYTHONPATH=platforms/shared/python python3 -m unittest discover -s tests -p test_project_deletion_and_schedule_labels.py -q
PYTHONPATH=platforms/shared/python python3 -m unittest discover -s tests -p test_schedule_gitlab_api.py -q
git diff --check
```

| 검증 | 관찰한 결과 |
| --- | --- |
| 공통 Python 전체 | 609개: **600 통과, 2 실패, 7 건너뜀**. 실행 65.021초, 종료 코드 1 |
| 프로젝트 삭제·예약 라벨 모듈 재실행 | 8개 중 7 통과·1 실패. `test_project_delete_is_only_on_admin_detail_page`: 목록 HTML에 `data-delete-project` 문자열이 포함됨 |
| GitLab 예약 API 모듈 재실행 | 2개 중 1 통과·1 실패. `test_gitlab_http_collection_analysis_persist_and_cleanup`: 기대 `completed`, 실제 `queued` |
| macOS fixture | 연결·프로필·AI 보고서·수정 게이트·영향 분석·테스트 초안·오탐 검토의 7개 Swift fixture 성공 메시지, 프로세스 종료 코드 0 |
| macOS 아카이브 | unittest 5개 통과 |
| 문서 | 29개 문서: 상대 파일·이미지 대상 235개, 내부 anchor 5개 통과. `git diff --check` 통과 |

두 실패는 개별 재실행에서도 재현됩니다. 원인 수정은 이번 문서 게시에 포함하지
않았으며, 전체 검증이 통과했다거나 배포 준비가 완료됐다고 해석하지 않습니다.

## 확인하지 않은 범위

- 실제 Docker/Nginx gateway 설치·로그인·운영 및 기존 서버로의 배포
- 실제 Playwright Chromium의 네트워크·렌더링 동작
- 현재 App Store 앱·Windows 설치본·폐쇄망 압축파일의 기능 및 데이터 최신성
- 이번 현행화에서의 Xcode 앱 빌드, 실제 로컬 모델 응답·생성 품질, Java 포함 macOS 빌드
- AI 수정안의 기능 동등성·모든 사용 사례의 호환성

GitHub 비공개 취약점 신고는 기준일 확인 시 비활성화 상태였습니다. 확인된
신고 경로와 민감한 내용의 취급은 [보안 정책](../SECURITY.ko.md)을 따릅니다.
