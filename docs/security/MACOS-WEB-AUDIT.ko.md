# macOS Swift 웹 정밀 점검

macOS KODA의 **동적 점검 (DAST) → 웹 정밀 점검 (API·권한·시나리오)**에서 실행합니다.
웹 점검 런타임은 Swift와 Foundation으로 구현되어 Python·Docker·외부 검사 서버를
설치하지 않아도 됩니다. 기존 웹사이트 점검과 ZAP 메뉴는 유지합니다.

## 실행

1. 점검할 HTTP/HTTPS URL을 입력하고 대상 소유 또는 점검 권한을 확인합니다.
2. 필요한 경우 기본 계정·비교 계정의 Authorization 값을 입력합니다. 비밀값은
   메모리에서만 사용하며 점검 보고서에 저장하지 않습니다.
3. OpenAPI 3 또는 Swagger 2 **JSON** 파일을 선택하거나, 계정·리소스·시나리오를
   정의한 프로필을 가져옵니다. 가져온 프로필의 권한 확인란은 다시 확인합니다.
4. 링크로 도달하지 않는 로그인 후 화면·API가 있으면 **브라우저 기록(HAR) 선택**으로
   개발자 도구에서 저장한 HAR 파일(최대 100 MB)을 추가합니다. 로그인 세션을
   쓰려면 민감한 데이터를 포함해 내보냅니다.
5. 전체 요청·시간 한도와 요청당 시간 제한을 정하고 보고서 저장 폴더를 선택하여
   점검합니다. 요청당 시간 제한은 전체 시간의 1/3을 넘지 않게 조정됩니다.
6. 21개 통제 항목별 판정, 증거, 실행 공백을 확인합니다. 결과 폴더의
   `audit.json`, `audit.html`, `audit.md`가 같은 점검 결과를 담습니다.

점검 대상 계정의 실제 권한과 데이터 구조는 서비스마다 다르므로 기대 응답을
프로필에 지정해야 합니다. 통제 판정은 다음과 같이 읽습니다.

| 판정 | 의미 |
|---|---|
| **VULNERABLE** | 재현한 증거로 취약점을 확정 |
| **NEEDS_REVIEW** | 사람이 확인해야 할 신호 (예: CSRF 토큰 없는 폼, TRACE 허용) |
| **PASS** | 선언한 경로·계정·기대 응답 범위에서만 통과 |
| **NO_FINDING** | 자동 검사를 실행했지만 탐지가 없음. 사유에 검사 종류와 건수를 적으며, 검사한 경로·입력 밖의 안전은 보장하지 않음 |
| **NOT_SCANNED** | 검사하지 못했거나 자동 판정 대상이 아님. 사유에 입력값 없음, 능동 검사 꺼짐, Set-Cookie·Allow 헤더 미관측, 시나리오 필요 등을 적음 |

## 지원 범위

| 기능 | 구현 범위 |
|---|---|
| HTTP 요청 통제 | 단일 origin의 scheme·host·실효 port, 경로·메서드 제한, 전체 요청·시간·RPS·업로드·응답 크기 제한 |
| 인증 | 기본 계정과 추가 계정별 Authorization·쿠키·환경변수 참조, 계정별 ephemeral 세션, 익명 격리 |
| 크롤링 | 동일 origin HTML 링크, 범위 안 리다이렉트 추적(범위 밖 이동은 미완료로 기록하고 새 URL 표시), 페이지·깊이·대기열 제한 |
| HAR 가져오기 | 범위 안 GET 페이지를 크롤링 시작점에 추가, 폼·JSON POST 본문을 검사 대상으로 사용하고 기록된 `X-` 헤더 유지. 기록된 Cookie·Authorization은 운영자가 비워 둔 경우에만 HTTPS·loopback에서 사용하고 보고서에서 제거 |
| 수동 응답 분석 | HTTP/HSTS/CSP/MIME·클릭재킹 방어, 서버 버전·X-Powered-By, 쿠키 속성, 와일드카드 CORS와 자격증명, JWT 형식, 상세 오류, 디렉터리 목록 신호. 페이지 보호 헤더는 렌더링된 2xx 페이지만 판정 |
| CSRF·메서드 | 토큰 필드·헤더가 없는 폼 방식 POST, OPTIONS 응답 Allow 헤더의 TRACE·PUT·DELETE 등을 검토 필요로 기록 |
| 능동 입력 검사 | 기존 query parameter, GET 폼 필드, 링크 없이 반사되는 숨은 매개변수, HAR 요청 필드. 상태 변경 승인이 있으면 POST 폼·HAR POST도 검사. XSS 반사·SQL 오류 차등·재현한 불리언 블라인드 SQLi·SSTI 산술식·경로 조작·CRLF·외부 리다이렉트·임의 Origin 반사 CORS. 로그인·업로드 폼은 제출하지 않음 |
| 내장 규칙 | Git 설정·환경 설정·디버그 정보 노출, 같은 디렉터리의 임의 경로 응답과 차등 비교 |
| 추가 규칙 | JSON 형식 HTTP 응답 상태·본문·헤더 matcher. 자동 확정 대신 검토 필요 후보로 기록 |
| API | OpenAPI 3/Swagger 2 JSON, 로컬 참조, query/path 표본, 제한된 JSON·urlencoded 입력과 음성 표본 |
| API 응답 | 문서화 상태, 제한된 required/type 검사. 위반은 견고성·정합성 검토 신호로 기록 |
| 권한·업무 절차 | 계정×리소스 기대 상태·본문 marker, 선언한 순서의 시나리오와 정리 응답 검증 |
| 중지와 정리 | 일반 점검용 예산과 정리용 예산 예약, 취소 후에도 동일 계정·쿠키로 제한된 정리 수행. 요청 하나가 시간 초과·오류여도 그 대상만 건너뛰고 계속 점검. 연속 3회 응답이 없으면 중단하고 원인(시간 초과·연결 거부·DNS·TLS)을 기록 |
| 보고서 | 21개 항목 상태, 원본 규칙 ID·URL·증거 해시 참조, 토큰 제거, HTML/Markdown escape |

## 프로필 예제

앱의 **프로필 예제 저장**으로 전체 기본값을 포함한 예제를 저장할 수 있습니다.
간단한 프로필은 다음처럼 작성합니다. 환경변수 값에는 `Bearer ...`를 포함한
전체 헤더 값을 지정합니다. Finder로 실행한 앱은 셸의 환경변수를 자동으로
상속하지 않으므로 이 경우 앱의 계정 입력란을 사용합니다.

```json
{
  "schemaVersion": 1,
  "target": "https://staging.example.com",
  "authorized": false,
  "active": false,
  "limits": {"maxRequests": 300, "maxDuration": 120, "requestsPerSecond": 5},
  "accounts": [
    {"id": "userA", "headers": {"Authorization": "${ENV:KODA_USER_A}"}},
    {"id": "userB", "headers": {"Authorization": "${ENV:KODA_USER_B}"}}
  ],
  "resources": [{
    "id": "private-record",
    "path": "/api/records/100",
    "controlID": "web.authorization",
    "expectations": {
      "anonymous": {"statusCodes": [401, 403]},
      "userA": {"statusCodes": [200], "bodyContains": "record-owned-by-A"},
      "userB": {"statusCodes": [403, 404]}
    }
  }]
}
```

로그인 화면의 HTTP 200만으로 권한 우회를 확정하지 않습니다. 거부되어야 할
계정의 응답에 허용 계정용으로 선언한 보호 데이터 marker가 나타나는 경우를
확정 증거로 사용합니다. marker가 적절한지 운영자가 확인해야 합니다.

상태 변경은 `active: true`, `allowStateChanges: true`, `allowedMethods`에
해당 메서드가 있고 정리 절차가 선언되어야 합니다. API 쓰기는 `apiWriteCleanup`,
업무 시나리오는 `cleanup`을 지정합니다. 자동 생성 API 요청에서는 DELETE를
제외하고, 정리 절차의 DELETE는 명시적으로 허용한 경우에만 실행합니다.
정리 응답이 기대 상태·본문과 다르거나 시간·요청 예산이 부족하면 미완료로
기록합니다. 예산을 넘어서 무조건 정리 성공을 보장하는 기능은 아닙니다.

## 재현 가능한 앱 실행

빌드한 앱의 실행 파일에도 동일한 점검 경로가 포함됩니다.

```bash
KODA_WEB_AUDIT_PROFILE=/absolute/path/profile.json \
KODA_WEB_AUDIT_OUTPUT_DIR=/absolute/path/reports \
  /absolute/path/KODA.app/Contents/MacOS/KODA
```

프로필의 `authorized`가 true여야 하며, 선택적으로
`KODA_WEB_AUDIT_API_SPEC=/absolute/path/openapi.json`을 지정할 수 있습니다.
결과는 지정한 폴더 아래 `KODA-web-audit/`에 저장합니다. 종료 코드는 실행 완료 0,
확정 취약점 발견 1, 입력 오류·실행 미완료 2입니다. 검토 필요 후보만 있는
경우에도 종료 코드가 0일 수 있으므로 `controls`와 `observations`를 확인합니다.

## 경계와 미지원 사항

- 이 기능은 Nuclei/ZAP/Schemathesis 전체 엔진이나 템플릿 호환 구현이 아닙니다.
  외부 템플릿·코드·공개 OAST·업데이트·클라우드 업로드를 실행하지 않습니다.
- API YAML, GraphQL, 외부 `$ref`, 파일 업로드 표본, 합성 JSON schema의 완전한
  해석은 지원하지 않습니다. 응답 schema 검사는 깊이 4, 속성 32개, 배열 앞
  8개로 제한합니다. API operation은 40개·생성 요청은 120개로 제한합니다.
- TLS 인증서의 정상 검증은 URLSession 기본 정책을 사용합니다. hostname의
  DNS 해석 IP를 고정하는 기능이나 모든 하위 브라우저 요청의 검사는 제공하지
  않습니다. SPA 렌더링이 필요하면 기존 웹사이트 점검 메뉴의 별도 범위를 확인합니다.
- 리다이렉트는 크롤링에서 프로필 범위 안일 때만 따라갑니다. HTTPS에서 HTTP로
  이동하거나 다른 origin에 자격증명을 전달하지 않습니다.
- HAR의 로그인 요청(비밀번호 필드 포함), PUT·PATCH·DELETE, 정적 파일, 다른
  origin 요청은 재전송하지 않으며, 건너뛴 POST와 상태 변경 요청 수를 보고서
  경고로 남깁니다. HAR은 앱 화면에서만 선택할 수 있고 아래 환경변수 실행은
  지원하지 않습니다.
- App Store 빌드는 GET/HEAD 기반 읽기 점검으로 제한하며 능동 검사·상태 변경을
  허용하지 않습니다. 직접 배포판과 다른 실행 범위입니다.
- 실제 서비스의 비밀번호 정책·복구·자동화 방어·SSRF 등은 서비스별 시나리오와
  검증 가능한 oracle 없이는 안전 판정을 내릴 수 없습니다.

## 검증 명령

```bash
python3 -m unittest tests.test_native_web_transport tests.test_native_web_rules -v
python3 platforms/macos/tests/test_native_web_audit.py
KODA_TEST_APP_BINARY=/absolute/path/KODA.app/Contents/MacOS/KODA \
  python3 platforms/macos/tests/test_native_web_audit.py
```

테스트는 생산 Swift 파일을 Swift 6으로 직접 컴파일하고 로컬 HTTP fixture로
취약/정상 차등, 인증·쿠키 격리, 범위·예산·취소·정리, 오탐과 보고서 노출을
확인합니다. 외부 실제 서비스의 탐지율이나 운영 부하를 측정하는 벤치마크는
아닙니다.

현재 검증 결과와 남은 공백은
[2026-10-22 검증 기록](MACOS-WEB-AUDIT-VERIFICATION-20261022.ko.md)을 확인하세요.
