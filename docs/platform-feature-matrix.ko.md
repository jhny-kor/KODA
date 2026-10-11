# KODA OS별 전체 기능 구현표

기준일: **2026-10-11 (Asia/Seoul)**. 현재 로컬 작업 트리의 소스와 사용자에게 제공되는 실행 경로를 기준으로 한다. 기능은 메뉴·명령·포털 작업 단위로 정리했으며, 개별 탐지 규칙을 모두 별도 행으로 나열하지 않는다. **이번 GitHub 게시에는 표에 반영된 제품 소스·테스트·빌드 스크립트와 문서를 포함한다. Java 자산·바이너리·Docker 이미지·원시 로그는 제외하며 운영·App Store 배포와는 별개다.** [현재 상태](current-status.ko.md)와 [검증 기록](verification-2026-10-11.ko.md)을 함께 확인한다.

**O = 해당 OS의 제품 실행 경로에 구현됨. X = 해당 실행 경로에 구현되지 않음.** O는 실제 OS에서의 실행 검증 완료, 모든 입력의 탐지 성공 또는 보안 기준 전체 준수를 의미하지 않는다. 계획·체크리스트 생성은 해당 문서 생성 기능만 O로 표시한다.

열의 범위는 다음과 같다.

- **macOS:** Swift 네이티브 직접배포 앱과 번들 Java helper. 현재 작업 트리에 있는 로컬 AI 개발 기능도 포함한다.
- **Windows:** Full 설치본의 데스크톱 대시보드와 공통 Python CLI. SourceOnly 설치본의 기능 범위는 더 좁다.
- **Linux:** **x86_64만** 대상으로 호스트 CLI·설치본·인증 포털·Docker/Suite 실행 경로를 포함한다.

## 기능 구현 여부

| 전체 기능 | macOS | Windows | Linux x86_64 |
| --- | :---: | :---: | :---: |
| 실행 화면 — 로컬 데스크톱 점검 화면 | O | O | O |
| 실행 화면 — 전용 네이티브 앱 창 | O | O | X |
| 실행 화면 — 브라우저 대시보드 | X | O | O |
| 입력 — 로컬 폴더·파일 선택 및 검사 | O | O | O |
| 입력 — 파일 업로드 검사 | O | O | O |
| 입력 — 여러 검사 대상 처리 | O | O | O |
| 입력 — ZIP·JAR/WAR/EAR·TAR/GZIP 압축 입력 검사 | O | O | O |
| 입력 — 압축 경로·깊이·개수·확장 용량 제한 | O | O | O |
| 입력 — 하위 프로젝트 루트 자동 발견 (`discover`) | X | O | O |
| 입력 — 검사 대상·설정 재사용 | O | O | O |
| 입력 — 네이티브 프로젝트 프로필 저장·불러오기 UI | O | X | X |
| 소스 — API 키·토큰·비밀번호·개인키 탐지 | O | O | O |
| 소스 — 의존성 manifest·lockfile 식별 및 설정 점검 | O | O | O |
| 소스 — 보안 설정·컨테이너·CI/IaC 파일 점검 | O | O | O |
| 소스 — 위험한 코드 패턴·파일 근거 기반 정적 점검 | O | O | O |
| 소스 — 화면 품질·접근성 점검 | O | O | O |
| 소스 — 예방 통제·보안 문서 누락 점검 | O | O | O |
| 소스 — OWASP·CWE·개발보안49 기준별 결과 분류 | O | O | O |
| 소스 — 기준별 지원·부분 지원·수동 검토 상태 표시 | O | O | O |
| 소스 — Git 변경 파일만 검사 | O | O | O |
| 소스 — 경로 제외·ignore 설정 | O | O | O |
| 소스 — 심각도 기준 실패 게이트 | O | O | O |
| 소스 — 이전 JSON 결과 대비 신규 발견만 실패 게이트 | X | O | O |
| 소스 — 외부 SAST의 SARIF 결과 가져오기 | X | O | O |
| 소스 — KODA가 CodeQL 분석을 직접 실행 | X | X | X |
| 의존성 — OSV 온라인 취약점 조회 | O | O | O |
| 의존성 — CISA KEV·FIRST EPSS 우선순위 보강 | O | O | O |
| 의존성 — Python/JS import 기반 도달성 보강 | O | O | O |
| 의존성 — 소스 manifest·lockfile의 Grype 오프라인 취약점 비교 | X | O | O |
| Java — JAR/WAR/EAR 및 중첩 라이브러리 인벤토리 | O | O | O |
| Java — Syft 기반 SBOM 생성·내장 식별기 fallback | O | O | O |
| Java — Grype 오프라인 DB 취약점 비교 | O | O | O |
| Java — NVD·CISA KEV 오프라인 데이터 보강 | O | O | O |
| Java — 여러 배포 경로의 통합·중복 제거 보고서 | O | O | O |
| Java — 라이브러리/설치 버전별 CVE 통합 | O | O | O |
| Java — Fixed·Final 후보 버전 표시 및 Grype 재검증 | O | O | O |
| Java — 검사 실패·불완전 결과의 종료 상태 전달 | O | O | O |
| Java — 승인 SBOM과 실제 배포 아카이브 비교 (`sbom-verify`) | X | O | O |
| Java — SBOM 버전 충돌·미추적 파일·hash 불일치 게이트 | X | O | O |
| Java — 심각도·KEV 기준 CLI 실패 게이트 | X | O | O |
| 웹 — HTTP 보안 헤더·TLS·쿠키·CORS 점검 | O | O | O |
| 웹 — 같은 대상의 페이지·링크 크롤링 | O | O | O |
| 웹 — SPA/JavaScript 렌더링 및 상호작용 탐색 | O | O | O |
| 웹 — JS asset·fetch/XHR·robots/sitemap 경로 탐색 | O | O | O |
| 웹 — JS 번들의 노출 비밀값·민감 경로 확인 | O | O | O |
| 웹 — 로그인·쿠키·헤더를 사용하는 인증 점검 | O | O | O |
| 웹 — 비인증/다른 계정 응답 비교 및 접근 통제 단서 | O | O | O |
| 웹 — XSS·SQLi·SSTI·LFI·CRLF·리다이렉트 능동 검증 | O | O | O |
| 웹 — 시간 기반 블라인드 SQLi·명령 삽입 검증 | O | O | O |
| 웹 — 확인된 삽입점의 제한된 읽기 전용 영향 실증 | O | O | O |
| 웹 — OpenAPI 명세를 입력해 API/form surface 확장 | X | O | O |
| 웹 — 저장형/2차 XSS 및 JSON 쓰기 endpoint 퍼징 | X | O | O |
| 웹 — OAST/OOB callback 기반 블라인드 SSRF/RCE 검증 | X | O | O |
| 웹 — JWT none 알고리즘·만료 누락 점검 | O | O | O |
| 웹 — JWT의 약한 HMAC 서명 키 확인 | X | O | O |
| 웹 — 승인 프로필 기반 21개 통제 `web-audit` | X | O | O |
| 웹 — `web-audit` 승인 서명·일회성 nonce·dry-run | X | O | O |
| 웹 — 공격 경로 상관 분석 (`attack-path.*`) | X | O | O |
| 웹 — ZAP baseline 계획 생성·실행 | O | O | O |
| 웹 — ZAP 능동 검사·로그인·AJAX spider 연동 | O | O | O |
| 네트워크 — TCP 포트·배너 점검 (`net-scan`) | X | O | O |
| 네트워크 — 비웹 서비스 TLS·기본 자격증명 점검 | X | O | O |
| 호스트 — OS별 보안 상태 점검 | O | O | O |
| 호스트 — 이전 보안 상태 대비 drift 탐지 | X | O | O |
| 호스트 — 설치 앱 인벤토리·EOL·CVE 보강 | X | O | O |
| 결과 — 심각도·분류·규칙·파일 검색/필터 | O | O | O |
| 결과 — HTML 메인·상세 보고서 | O | O | O |
| 결과 — Markdown 보고서 | O | O | O |
| 결과 — PDF 보고서 | O | O | O |
| 결과 — Excel/XLSX 보고서 | O | O | O |
| 결과 — 일반 소스 검사 JSON 파일 내보내기 | X | O | O |
| 결과 — Java SBOM·취약점 JSON 파일 생성 | O | O | O |
| 결과 — SARIF 보고서 | X | O | O |
| 결과 — HWPX 보고서 | X | O | O |
| 결과 — CycloneDX SBOM | O | O | O |
| 결과 — NIS-SBOM 1.0 CSV | X | O | O |
| 결과 — CycloneDX VEX 검토 초안 | O | O | O |
| 결과 — 공유 보고서의 민감정보 마스킹 | O | O | O |
| 결과 — 발견 건수 변화 비교 | O | O | O |
| 결과 — 네이티브 위험점수 추이·이력 비교 | O | X | X |
| 결과 — 항목별 신규·해결·유지 비교 | X | O | O |
| 결과 — SBOM·VEX·발견·체크리스트·checksum 릴리스 패키지 | O | O | O |
| 결과 — 배포 파일 SHA-256 manifest 생성·비교 | X | O | O |
| 연동 — Dependency-Track 업로드 명령 생성·SBOM 전송 | X | O | O |
| AI — 선택적 발견 항목 설명·오탐/위험 검토 | O | O | O |
| AI — 조치·수정 방향 제안 | O | O | O |
| AI — 점검 결과의 AI 요약·설명 보고서 | O | O | O |
| AI — 자연어 질의로 발견 항목 선택 | X | O | O |
| AI — CWE 매핑 제안 | X | O | O |
| AI — localhost 연결 프로필·모델 목록·키체인 UI | O | X | X |
| AI — 원본과 분리한 수정 소스 후보 생성 | O | X | X |
| AI — 수정 후보 구문/보안 검증 및 최대 3회 재생성 | O | X | X |
| AI — 수정 후보 변경 영향 분석·테스트 계획 초안 | O | X | X |
| 예방 — 지원하는 자동 수정안 선택·파일 적용 | O | O | O |
| 예방 — 보안 템플릿 생성·기존 파일 보호 | O | O | O |
| 예방 — pre-commit 보안 게이트 설치 | O | O | O |
| 예방 — ignore 템플릿 생성 | O | O | O |
| 예방 — SECURITY·Dependabot·보안 CI 템플릿 | O | O | O |
| 예방 — 저장소 보안 설정 체크리스트 | O | O | O |
| 예방 — SSDF·Secure by Design·위협 모델 문서 | O | O | O |
| 예방 — 비밀값 사고 대응·교체 절차 문서 | O | O | O |
| 예방 — AI/LLM·모바일·API 보안 계획 | O | O | O |
| 예방 — NIST CSF·CISA 개발 확인서·SCVS 계획 | O | O | O |
| 예방 — 개인정보 데이터 맵·보안 로드맵·증적 보관대장 | O | O | O |
| 예방 — 보안 헤더·컨테이너·Cloud/IaC 기준 문서 | O | O | O |
| 예방 — SLSA/Sigstore 릴리스 서명 계획 | O | O | O |
| 포털 — 다중 사용자 인증·gateway proof | X | X | O |
| 포털 — 프로젝트·구성원·역할별 기능 권한 관리 | X | X | O |
| 포털 — 관리자 규칙 선택·사용자 접근 관리 | X | X | O |
| 포털 — 프로젝트/회차 이력·검색·통계 | X | X | O |
| 포털 — 라이브러리·소스·전체 검사 범위별 실행 | X | X | O |
| 포털 — GitLab 저장소/브랜치/태그 입력·commit SHA 고정 | X | X | O |
| 포털 — GitLab 브랜치 생성·결과/Issue 게시·재시도 | X | X | O |
| 포털 — Tracker 결과 전송·진행 상태·재시도 | X | X | O |
| 포털 — SSH/원격 디렉터리·GitLab 예약 수집 | X | X | O |
| 포털 — 수동·예약 FIFO 대기열·순차 검사 | X | X | O |
| 포털 — 별도 scan/delivery worker·healthcheck | X | X | O |
| 포털 — 검사 진행·취소·중복 실행 방지·재시작 복구 | X | X | O |
| 포털 — 입력 quota·보관 및 원본/workspace 자동 정리 | X | X | O |
| 포털 — 프로젝트·회차·입력 삭제와 권한 검사 | X | X | O |
| 운영 — Python 별도 설치가 필요 없는 데스크톱 번들 | O | O | X |
| 운영 — Windows EXE·Inno Setup 설치본 빌드 | X | O | X |
| 운영 — Linux x86_64 오프라인 설치·Docker/Suite 패키지 | X | X | O |
| 운영 — KODA·Tracker·Dependency-Track 통합 gateway | X | X | O |
| 운영 — Docker CPU·메모리·PID·네트워크·읽기 전용 제한 | X | X | O |
| 운영 — Suite 사전 점검·백업·업데이트·롤백 스크립트 | X | X | O |

## 표를 읽을 때 필요한 조건

1. **구현과 검증:** Windows O는 소스·Full 패키징 경로 기준이다. 이번 작업에서는 Windows 실기 실행을 제외했다. macOS는 Java 포함 universal 빌드와 ARM 실행을 검증했고 Intel 실행은 미검증이다. Linux는 Apple Silicon에서 실제 amd64 컨테이너를 에뮬레이션해 실행했으며 물리 x86_64 서버의 검증은 아니다.
2. **macOS 제품 경계:** X인 공통 CLI 기능도 Python 엔진을 별도로 실행하면 사용할 수 있다. 이 표는 네이티브 앱의 실행 경로를 기준으로 하며, 내부 helper에 Python 코드가 들어 있다는 이유만으로 모든 CLI 기능을 macOS O로 표시하지 않는다. 일반 소스 JSON·SARIF·HWPX·NIS-SBOM 직접 내보내기와 Java CLI 게이트 옵션은 네이티브 UI에 제공되지 않는다.
3. **App Store판:** macOS 열의 웹 로그인·능동/침투·영향 실증·ZAP O는 직접배포판 기준이다. `KODA_APP_STORE` 빌드는 GET/HEAD 중심 읽기 전용 웹 점검으로 제한하며 ZAP와 능동 점검을 실행하지 않는다.
4. **Windows SourceOnly:** Java·오프라인 라이브러리 도구·실시간 웹·Playwright/Chromium 자산을 제외한다. `web-audit`은 누락된 capability를 `UNSUPPORTED`로 반환한다. 표의 Windows 열은 Full 설치본을 기준으로 한다.
5. **Linux 실행 경로:** 호스트 점검·웹/네트워크 점검·ZAP O는 해당 기능을 실행할 수 있는 호스트 CLI 경로를 포함한다. 폐쇄망 Docker 래퍼는 네트워크 차단·읽기 전용 제한 때문에 같은 기능을 그대로 허용하지 않는다. 포털/Suite O는 Tracker 계정·gateway·DB·worker 등 필요한 구성이 갖춰진 경우다.
6. **선택 기능:** OSV·KEV/EPSS 온라인 보강, AI, Playwright/WKWebView 렌더링, ZAP, Git/SSH, 외부 서비스 전송은 해당 도구·모델·데이터·권한 설정이 필요하다. 코드가 구현됐어도 미설정 또는 지원하지 않는 입력은 경고·미지원·미점검으로 표시할 수 있다.
7. **기능의 깊이:** 정적 점검·도달성·AI 제안은 구현된 언어·규칙 범위의 근거를 제공한다. 보안 기준의 모든 통제를 자동 검증하지 않는다. VEX·위협 모델·서명 계획·규정 문서는 검토용 초안이며 실제 서명·인증·기능 동등성 검증을 자동 완료하지 않는다. CodeQL은 현재 사전 조건 확인까지 구현됐으므로 직접 분석 실행은 X다.

## 소스 근거와 상세 안내

- macOS 기능 진입점: [ContentView.swift](../platforms/macos/app/KODA/KODA/ContentView.swift), [ScannerBridge.swift](../platforms/macos/app/KODA/KODA/ScannerBridge.swift), [NativeSecurityScanner.swift](../platforms/macos/app/KODA/KODA/NativeSecurityScanner.swift), [BundledJavaArchiveScanner.swift](../platforms/macos/app/KODA/KODA/BundledJavaArchiveScanner.swift).
- macOS 로컬 AI: 이번 GitHub 게시에 포함된 개발 소스 `LocalAIView.swift`와 `NativeLocalAI*` 구현은 [로컬 AI 가이드](macos-local-ai.ko.md)에 설명한다.
- Windows/Linux 공통 기능: [cli.py](../platforms/shared/python/security_scanner/cli.py), [scanner.py](../platforms/shared/python/security_scanner/scanner.py), [server.py](../platforms/shared/python/security_scanner/server.py), [toolkit.py](../platforms/shared/python/security_scanner/toolkit.py), [공통 사용법](usage.ko.md).
- 보고서·SBOM: [reporting.py](../platforms/shared/python/security_scanner/reporting.py), [리포트 계약](report-contract.ko.md), [Java 런북](security/java-sbom-vulnerability-scan.md).
- 웹·네트워크: [web.py](../platforms/shared/python/security_scanner/web.py), [web_audit.py](../platforms/shared/python/security_scanner/web_audit.py), [netprobe.py](../platforms/shared/python/security_scanner/netprobe.py), [웹 점검 런북](security/WEB_AUDIT.ko.md).
- Linux 전용 운영: [포털 가이드](koda-web-portal.ko.md), [순차 실행 안내](linux-scan-queue.ko.md), [통합 Suite](../platforms/linux/suite/README.ko.md).
- 배포판 조건: [macOS 패키징](../platforms/macos/packaging/README.ko.md), [Windows Full/SourceOnly](../platforms/windows/README.ko.md), [Linux 호스트 설치](install/linux.ko.md), [Linux Docker](../platforms/linux/docker/README.md).

[한국어 문서 인덱스](README.md) · [현재 구현·검증 상태](current-status.ko.md)
