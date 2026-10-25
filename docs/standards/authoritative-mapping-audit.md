# 공식 보안 기준 매핑 점검

최종 점검일: 2026-07-24

이 문서는 KODA의 기준 이름·기준 항목·탐지 룰이 공식 발행기관의 현재 공개
분류와 일치하는지 점검한 결과를 정리합니다. KODA의 결과는 정적 휴리스틱과
선택형 외부 점검에서 얻은 **증거**이며, 특정 기준의 인증이나 완전 준수를
의미하지 않습니다. 탐지 0건도 준수의 증명이 아닙니다.

## 국내 기준

| KODA 프로파일 | 공식 기준과의 관계 | KODA 점검 범위 | 판정 |
| --- | --- | --- | --- |
| 소프트웨어 개발보안 49 | 행정안전부·KISA 2021 가이드의 구현단계 7개 유형·49개 보안약점을 개별 통제로 등록 | 49개 통제마다 자동·부분 자동·수동 검토·미지원 상태를 구분 | 공식 분류와 일치 |
| 소프트웨어 보안 7가지 유형 | 위 49개 항목을 공식 7개 상위 유형으로 집계 | 연결된 49개 통제의 증거를 상위 유형별로 표시 | 공식 분류와 일치 |
| KISA 소프트웨어 보안약점 진단가이드 2021 | KISA가 2021-11-30 발행한 공식 가이드의 7개 유형·49개 구현단계 보안약점 | 49개 통제마다 자동·부분 자동·수동 검토·미지원 상태를 구분 | 공식 분류와 일치 |

행정안전부는 2021년 소프트웨어 개발보안 가이드와 진단원 양성 기준을
공개했고, KISA도 같은 시기의 소프트웨어 보안약점 진단가이드를 제공합니다.
KODA의 상세 49개 항목과 지원 수준은
[소프트웨어 개발보안 49 매핑](sw-development-security-49.md)에서 확인할 수
있습니다.

공식 원문:

- [행정안전부 소프트웨어 개발보안 가이드(2021)](https://www.mois.go.kr/frt/bbs/type001/commonSelectBoardArticle.do?bbsId=BBSMSTR_000000000015&nttId=88956)
- [KISA 소프트웨어 보안약점 진단가이드(2021)](https://www.kisa.or.kr/2060204/form?page=1&postSeq=9)
- [KISA Python 시큐어코딩 가이드(2022)](https://www.kisa.or.kr/2060204/form?postSeq=13)

KISA Python 시큐어코딩 가이드는 언어별 참고자료입니다. 현재
`kisa-secure-coding-guide` 프로파일이 이 문서 전체를 독립적으로 구현했다는
의미는 아닙니다.

## OWASP 기준

| KODA 프로파일 | 공식 분류 확인 결과 | KODA 점검 범위와 한계 |
| --- | --- | --- |
| OWASP Top 10:2025 | 현재 공식 10개 위험 범주와 일치 | 범주와 직접 관련된 룰만 연결. A04에 키 길이·난수·인증서 검증·비밀번호 해시 규칙, A05에 LDAP·XML·CRLF·포맷 문자열 삽입 규칙을 포함 |
| OWASP Proactive Controls 2024 | 공식 C1~C10 이름으로 수정 | 예방적 통제의 일부 저장소 증거만 확인 |
| OWASP ASVS 5.0.0 | 공식 17개 장으로 수정 | 15개 장에 관련 정적 증거가 있으며 V10 OAuth/OIDC와 V17 WebRTC는 미지원. 요구사항 단위 준수 판정은 하지 않음 |
| OWASP WSTG v4.2 | 공식 12개 테스트 영역으로 수정 | 9개 영역에 정적 단서를 연결. 정보수집·식별관리·비즈니스 로직은 미지원이며 실대상 동적 테스트가 필요 |
| OWASP API Security Top 10:2023 | 공식 API1~API10과 일치 | 소스·설정 단서만 제공하며 실행 중 API 권한·비즈니스 흐름 검증은 별도 필요 |
| OWASP Mobile Top 10:2024 | 공식 M1~M10과 일치 | 모바일 소스·Manifest·plist 단서 중심. 실행 시점과 배포 환경 검증은 별도 필요 |
| OWASP MASVS | 공식 8개 통제 그룹과 일치하도록 수정 | 저장·암호·인증·네트워크·플랫폼·코드·회복탄력성·개인정보 관련 로컬 증거만 연결 |
| OWASP SAMM 2 | 공식 5개 비즈니스 기능으로 수정 | Governance·Design·Implementation·Verification·Operations 증거를 표시하지만 15개 보안 관행이나 성숙도 점수는 판정하지 않음 |
| OWASP SCVS | 공식 6개 통제군과 일치 | 공급망 저장소 증거와 선택형 SBOM/VEX 연동 범위만 확인 |
| OWASP LLM Top 10:2025 | 공식 LLM01~LLM10과 일치 | LLM 관련 코드·설정 단서만 확인하며 모델·프롬프트의 실제 공격 검증은 별도 필요 |
| Dependency-Check baseline | OWASP 프로젝트를 활용하기 위한 KODA 준비성 프로파일 | OWASP가 발행한 별도 준수 표준으로 주장하지 않음 |

### 소스 판정 방식

- 소스 규칙은 파일을 한 줄씩 독립 판정하지 않습니다. 파일 전체에서 외부 입력의 대입과 별칭, 정제 함수, 전역 인증·rate limit 설정, 인접한 timeout·디버그 가드 등을 먼저 수집합니다.
- 동일 파일에서 외부 입력이 정제되지 않은 채 SQL, HTML, 명령 실행, 파일, eval, HTTP 요청, redirect, LDAP, 응답 헤더, 역직렬화, 업로드 저장, mass assignment 또는 포맷 문자열 sink에 도달할 때만 `confirmed`로 판정합니다.
- 위험 API나 설정 한 줄만 발견되고 데이터 흐름을 증명할 수 없으면 `needs_review`로 남기며 위험 점수와 실패 게이트에 포함하지 않습니다.
- 함수 간·파일 간 호출, 프레임워크 전역 정책, 객체 수준 인가, 비즈니스 흐름, 운영 배포 설정은 정적 파일 분석만으로 최종 판정하지 않습니다. ASVS 요구사항 준수와 WSTG·SAMM 완료 여부도 별도 설계·실행·증적 검토가 필요합니다.

공식 원문:

- [OWASP Top 10:2025](https://owasp.org/Top10/2025/0x00_2025-Introduction/)
- [OWASP Proactive Controls 2024](https://top10proactive.owasp.org/the-top-10/)
- [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/)
- [OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP API Security](https://owasp.org/API-Security/)
- [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/2023-risks/)
- [OWASP MASVS](https://mas.owasp.org/MASVS/)
- [OWASP SAMM](https://owaspsamm.org/model/)
- [OWASP SCVS](https://scvs.owasp.org/scvs/using-scvs/)
- [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/)

## CWE 기준

| KODA 프로파일 | 공식 기준과의 관계 | KODA 점검 범위 |
| --- | --- | --- |
| CWE Top 25:2025 | MITRE의 공식 순서·CWE ID·이름 25개와 일치하도록 수정 | 직접 대응하는 로컬 룰이 있는 18개에 증거를 연결하고, 메모리 안전성·의미 분석이 필요한 7개는 미지원. CWE-476은 Java/Kotlin 동일 파일 후보만 부분 지원 |

공식 원문:

- [MITRE CWE Top 25:2025](https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html)

공식 출처나 현재 판본을 확인할 수 없는 프로파일, 이전판, 기관에서 발행하지
않은 KODA 자체 분류는 기준 선택 목록에 포함하지 않습니다. CLI 도움말과 macOS
설정 화면에는 등록된 기준의 발행기관·판본·발행연도 또는 발행일을 표시합니다.

## 판정 해석

- `automated`: 연결된 휴리스틱이 해당 기준의 점검 가능한 부분을 자동 확인합니다.
- `partial`: 일부 패턴만 확인하므로 탐지 0건이어도 추가 검토가 필요합니다.
- `manual-review`: 설계·업무 흐름·실행 환경 증거를 사람이 확인해야 합니다.
- `unsupported`: KODA가 해당 항목을 판정하지 않습니다.
- 정적 소스 점검에서 선택 가능한 기준과, 대시보드에서 참고용으로 보여주는 외부
  기준은 구분됩니다. WSTG·MASVS·SAMM 같은 검증 체계는 정적 결과만으로
  준수 판정을 내리지 않습니다.
