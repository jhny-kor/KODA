# 오프라인 보강 자료·SPDX 검증 — 2026-10-19

## 변경 범위

KODA와 KODA SBOM Tracker는 독립 저장소·실행 의존성을 유지한다. OSV 직접 연동을 제외한 두 제품 Linux 폐쇄망 구성을 유지했다. 이번 작업은 로컬 소스 구현과 검증이며 실제 운영 배포나 전체 취약점 피드 다운로드를 수행한 기록이 아니다.

- 외부 수집 전용 CLI와 11종 원본 자료 정규화: EPSS, CISA Vulnrichment, CSAF, VEX, Ubuntu OVAL, lifecycle, CPE Dictionary, CPE Match, CWE, SPDX License List, 패키지 메타데이터.
- 원본/기준일/수집일/모델/스키마/해시/자료별 최신성 보존, 원본 재파싱 결과 대조, 임의 편집·손상·누락·압축 확장 한도 검사.
- 기존 Grype/NVD/KEV 번들과 선택적 EPSS·보강 자료 결합. 데이터 교체·선택 자료 제거·롤백과 DB 반영 실패 보상.
- Tracker의 원본 장기 보관·재검증 다운로드, 불변 반입 이력, 현재 소스, 재평가 요청, 분석 당시 근거 보존.
- KODA CVE 결과와 HTML/Markdown/JSON에 오프라인 보강 근거 표시, EOL 로컬 조회, 전체 점검 동안 같은 데이터 릴리스 고정.
- SSVC 추천 근거와 재검토 표시, 공급자 VEX 충돌, 라이선스·CWE·CPE·수명주기·버전 정보, 프로젝트 영향·담당자·기한·대응 이력.
- KODA SPDX 2.3 JSON 생성·다운로드·내보내기·CPE 점검 입력과 Tracker 인증 업로드·정규화 연결.

## 최종 검증

| 검증 | 결과 |
|---|---|
| KODA 선택 회귀 테스트 | 210 passed, 25.308초 |
| Tracker 선택 백엔드 테스트 | 110 passed, 3.66초 |
| Tracker 관련 UI 테스트 | 4개 파일, 34 passed |
| Tracker 프런트엔드 | `npm run build`의 TypeScript 검사와 Vite build 통과 |
| Tracker 린트 | 오류 0, 기존 App.tsx `onSync` 의존성 경고 1 |
| Python 컴파일·셸 문법 | 통과 |
| 두 저장소 `git diff --check` | 통과 |
| 독립 복사된 보강 자료 파서·OVAL 모듈 | 현재 파일 내용 동일, 런타임 상호 import 없음 |

KODA 테스트에는 공식 SPDX 2.3 JSON Schema 검증, SPDX/CPE CLI, 실제 HTTP 인증·다운로드, 기존 Java/CVE/보고서·포털·Linux 배포 계약, 오프라인 EPSS/외부 호출 차단, 원본 전송·포장 실패 복구, OVAL subset을 포함한다. 테스트용 완료 결과를 직접 주입하는 포털 fixture는 실제 작업자와 경쟁하지 않도록 정리했다. 실제 HTTP 요청을 통한 작업자 실행 테스트는 유지했다.

Tracker 테스트에는 11종 원본 파싱, 원본 위조/메타데이터 불일치 거절, 실제 인증 반입·원본 다운로드, 데이터 교체/롤백/보상, 수동 자료 보호, SPDX 업로드, SSVC·정책 평가를 포함한다. 별도 배포 계약 테스트에서는 설치된 릴리스에 파서가 포함되고 포장된 검증 도구가 실행되는 것을 모의 Docker 환경으로 확인했다.

최종 테스트 로그는 실행 환경의 `/tmp/koda-offline-verification-20261019.log`, `/tmp/koda-tracker-offline-verification-20261019.log`에 기록했다. `/tmp` 로그는 영구 보관을 보장하지 않으며 이 문서에 결과를 요약했다.

## 독립 검토 후 보완

- 패키지 메타데이터는 전체 PURL과 현재 버전이 일치할 때만 연결한다. 배포판·아키텍처·subpath가 다른 구성요소로 정책 값이 넘어가지 않도록 회귀 검증했다.
- 과거 번들로 롤백할 때 더 최신인 수동 반입 소스와 EPSS를 보존한다. 번들 소유 자료의 명시적 롤백과 수동 보강 자료를 구분한다.
- 과거 릴리스 디렉터리가 삭제된 후에도 반입 원본을 내용 해시 기반 artifact 저장소에서 확인할 수 있다.
- 공급자 VEX가 기존 Grype/CPE 결과를 자동으로 제외하거나 심각도를 변경하지 않는다. SSVC 추천값은 담당자의 최종 결정과 구분한다.
- 근거 평가가 한도로 잘렸다면 표시하고 SSVC 추천을 차단한다. 프로젝트 현황은 페이지 범위와 전체 프로젝트 수를 구분한다.

## 검증 경계

- 실제 Linux 폐쇄망 서버 설치, 실제 운영 브라우저 흐름, 실제 Docker 릴리스 빌드, 모든 공급자의 대용량 피드 성능 측정은 수행하지 않았다.
- Ubuntu OVAL은 고정 dpkginfo 조건의 검토용 subset이다. 정확한 Ubuntu 플랫폼·인벤토리·로컬 dpkg가 없거나 미지원 조건이면 `unknown`이다. 범용 OVAL 점검 완료를 의미하지 않는다.
- 대형 CPE Match 전체 덤프는 크기 한도상 지원하지 않으며 대상 제품의 제한된 API 페이지를 반입한다. 미지원 CSAF/VEX 관계·범위는 확정 판정으로 바꾸지 않는다.
- SPDX 2.3 패키지와 명시적인 DEPENDS_ON/DEPENDENCY_OF를 정규화한다. 기타 파일·외부 문서·포함 관계의 원본 근거는 보존하지만 모두 의존 관계로 해석하지 않는다.
- 원본 해시는 공급자 서명 인증이 아니다. 승인된 원본 수집과 기존 서명 번들 반입 절차를 유지한다.

운영 방법은 [오프라인 자료 운영](OFFLINE-DATASETS.ko.md), [SPDX 출력](SPDX-2.3.ko.md)을 참고한다. Tracker 상세 운영 문서는 별도 저장소의 `docs/offline-intelligence-ko.md`에 있다.
