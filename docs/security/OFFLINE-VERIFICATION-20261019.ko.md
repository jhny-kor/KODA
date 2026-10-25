# 폐쇄망 기능 구현 검증 — 2026-10-19

검증 대상은 현재 작업 폴더의 소스입니다. 시작 전부터 있던 미커밋 변경은 보존했으며
Git 커밋·푸시나 운영 서버 배포는 수행하지 않았습니다. KODA와 Tracker는 별도 저장소로
유지했습니다. 이번 작업에 추가한 운영 안내는 [폐쇄망 운영](OFFLINE-OPERATIONS.ko.md)입니다.

## KODA

아래 unittest 묶음을 함께 실행해 **116개 통과**했습니다.

```text
test_closed_network.py
test_offline*.py
test_data_release.py
test_linux_report_regressions.py
test_java_scan*.py
test_cli_reports.py
test_linux_suite_contract.py
```

CPE 원본/압축 인덱스, nested SBOM CLI, 버전 경계, AND/OR·negate·환경 조건,
손상·복잡도 초과·미판정, EPSS 과거 기준일·중복·손상·압축 한도·출처,
스캔 결과와 HTML 내보내기의 점수 보존, 외부 조회 차단, 두 제품 Linux 구성 계약을
검증했습니다. 로컬 소켓/HTTP를 막은 테스트도 포함합니다.

추가로 Linux amd64 컨테이너를 `--network none`으로 실행해 CPE/EPSS 엔진·CLI
**21개**, 라이브러리 보고서 회귀 **6개**를 통과했습니다. Tracker gateway와 KODA
Suite gateway는 로컬 upstream으로 렌더링한 설정을 같은 네트워크 차단 컨테이너에서
`nginx -t`로 검사했고 모두 통과했습니다. Python compileall, 변경 파일의
`bash -n`, `git diff --check`, 새 문서 상대 링크 검사도 통과했습니다.

## Tracker

이 저장소와 합치지 않고 Tracker의 현재 소스를 읽기 전용으로 컨테이너에 연결했습니다.
기존 Linux 검증 이미지의 Python 3.12·Java 런타임을 이용하고 검증용 이미지에
프로젝트의 기존 test extra인 pytest를 설치했습니다. 테스트 실행은 모두
`--network none`에서 수행했습니다.

- 전체 backend: **713 passed, 22 skipped**.
- 마지막 연결 상태 회귀 추가 후 SSVC·CPE·EPSS·차단 경로 재검증: **37 passed, 1 skipped**.
- 호스트에서 같은 핵심 묶음: **38 passed**. Compose 명령이 있는 호스트에서 제외 서비스와
  네트워크 격리 계약도 검사했습니다.
- 프런트엔드: **116 passed**, TypeScript·Vite production build 성공.
- ESLint: 오류 0개, 기존 App.tsx의 `onSync` 의존성 경고 1개.
- API wheel 생성 성공, SSVC 결정표 CSV·provenance.json·LICENSE와 CPE/EPSS 모듈 포함 확인.

전체 backend의 22개 생략은 컨테이너에 없는 JDK 컴파일러를 요구하는 테스트 19개,
Docker Compose CLI를 요구하는 2개, PowerShell을 요구하는 1개입니다. Java 정규식 정책
회귀는 기존 컴파일 matcher와 Linux Java 런타임을 사용해 통과했습니다.

## 적용 경계

CPE는 검토된 CPE 2.3 식별자와 지원하는 숫자 점 구분 버전 범위를 사용합니다.
제품명을 통한 임의 추론, 벤더 전용 버전 체계, 누락된 환경 조건을 안전으로 확정하지
않습니다. 과거 조건 생략 인덱스는 새 생성기로 다시 만들어야 합니다.

EPSS 파일 해시는 원본 무결성 근거이며 공급자 인증 서명이 아닙니다. 승인된 반입
절차로 파일을 확보해야 하고, Tracker 정책 판정 갱신에는 새 분석 리비전이 필요합니다.

운영 서버의 실제 SBOM·대규모 자료·LDAP·GitLab 연결, 기존 설치의 업그레이드와
최종 Linux 배포 묶음 재생성은 이번 검증에 포함하지 않았습니다. 기존 운영 데이터나
컨테이너는 변경하지 않았습니다.
