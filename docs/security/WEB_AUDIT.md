# KODA 21개 웹취약점 자동 점검

`web-audit`은 프로필에 선언된 대상·리소스·정상/거부 oracle만 실행합니다.
ZAP·Playwright·BOAST가 없거나 oracle/cleanup이 완전하지 않으면 PASS로 올리지
않습니다. 대상 소유 또는 명시적 점검 권한이 있는 staging/테스트 환경에서만
사용하세요.

## 실행 흐름

```bash
export KODA_APPROVAL_KEY='operator-managed-secret'
# BOAST /events 인증 secret(base64)은 승인서나 결과에 넣지 않습니다.
export KODA_OAST_SECRET='base64-secret-from-boast'

koda web-audit plan \
  --profile profile.json \
  --out approval-request.json

koda web-audit approve \
  --request approval-request.json \
  --approver '홍길동' \
  --out approval.json

koda web-audit run \
  --profile profile.json \
  --approval approval.json \
  --confirm-origin https://staging.example.com \
  --format json \
  --output reports/web-audit.json
```

`plan`은 프로필 검증과 DNS/IP 확인만 수행합니다. `approve`는 HMAC-SHA256
승인서를 만들고, `run`은 프로필 hash·origin·현재 해석 IP·범위·제한·서명·만료를
검증한 뒤 `~/.koda/web-audit-nonces.sqlite3`에서 nonce를 한 번만 소비합니다.
따라서 승인서 재사용, DNS rebinding, 다른 origin 실행은 거부됩니다.

## 최소 프로필

아래 origin은 예시이므로 실제 승인된 staging origin으로 바꾸세요.

```json
{
  "schema_version": 1,
  "target": {
    "environment": "staging",
    "origins": ["https://staging.example.com"],
    "include_paths": ["/"],
    "exclude_paths": [],
    "allowed_cidrs": [],
    "scopes": ["passive", "state_change_free"],
    "read_only_resources": ["home"],
    "platform": "shared",
    "distribution": "direct",
    "zap": {"enabled": false}
  },
  "limits": {
    "requests": 1000,
    "max_response_bytes": 2097152,
    "max_upload_bytes": 1048576,
    "timeout_seconds": 900,
    "max_rps": 5,
    "redirects": 3,
    "idempotent_retries": 1,
    "state_change_retries": 0,
    "oast_poll_seconds": 120,
    "cleanup_seconds": 30,
    "zap_rps": 2,
    "zap_threads_per_host": 1,
    "zap_minutes": 15,
    "zap_rule_minutes": 2
  },
  "accounts": {
    "userA": {
      "role": "user",
      "headers": {"Authorization": "${ENV:KODA_USERA_AUTH}"}
    }
  },
  "auth": {},
  "resources": [
    {
      "id": "home",
      "path": "/",
      "methods": ["GET"],
      "actors": ["anonymous"],
      "access": {"anonymous": "allow"},
      "read_only": true,
      "state_change_free": true
    }
  ],
  "scenarios": [
    {
      "id": "home-is-available",
      "title": "정상 공개 페이지 응답",
      "control_id": "web.plaintext-transmission",
      "required": true,
      "strategies": ["koda-scenario"],
      "steps": [
        {
          "id": "home",
          "resource": "home",
          "method": "GET",
          "assertions": [{"type": "status_in", "values": [200, 204]}]
        }
      ],
      "mutations": [],
      "cleanup": [],
      "oracle": {}
    }
  ],
"oast": {},
"applicability": {}
}
```

SSRF·코드 삽입에서 실제 callback을 확인하려면 `target.scopes`에 `oast`를
추가하고 다음처럼 BOAST control plane과 승인 IP/CIDR를 선언합니다. KODA는 승인 IP로 고정된
`GET /events`를 등록·polling하며, 새 event가 있으면 `VULNERABLE`, polling이
끝나고 없으면 다른 oracle이 완전한 경우에만 `PASS`입니다. BOAST secret이
없거나 control plane/IP 검증이 실패하면 `UNSUPPORTED` 또는 `NOT_SCANNED`로
남습니다.

```json
"oast": {
  "control_plane_origin": "https://boast.example.net",
  "callback_domain": "callbacks.example.net",
  "allowed_ips": ["203.0.113.10"],
  "poll_seconds": 10
}
```

시나리오의 요청 값에는 `${CAPTURE:OAST_PAYLOAD}`를 사용합니다. 이 값은 실행
중 등록된 BOAST test ID와 callback domain으로만 생성되며, 임의 URL이나 shell을
실행하지 않습니다.

실제 점검에서는 `resources`와 `scenarios`를 21개 표준 ID에 맞춰 확장합니다.
시나리오에 여러 `strategies`를 선언하면 모두 실행하고, 각 전략의 PASS가
확인될 때만 composite coverage를 완료합니다. 지원 전략은 `koda-scenario`,
`passive`, `browser`/`playwright`, `oast`, `zap`/`zap-active`,
`access-control`/`matrix`, `timing`, `state`, `http-methods`, `upload`입니다.
HTTP 메서드 점검처럼 실제 허용 목록 밖의 verb를 안전하게 시험할 때는
리소스의 `probe_methods`에만 추가합니다. 일반 `methods`와 중복할 수 없습니다.
`web.authentication`, `web.authorization`, `web.csrf`, `web.password-recovery`,
`web.process-validation`, `web.file-upload` 등 상태·계정·복구가 관련된 항목은
정상 응답뿐 아니라 거부 응답과 상태 불변 assertion, cleanup을 모두 선언해야
PASS가 됩니다. JSON 로그인은 `auth.token_json_path`와 환경변수 기반
`username_env`/`password_env`를 선언하고, 파일 업로드는 `multipart` body와
cleanup을 함께 선언해야 합니다. 만료/재사용 시간 검사는 step의 제한된
`delay_seconds`로 수행하며 전체 timeout을 넘으면 PASS가 아니라 검토 상태입니다.
적용되지 않는 항목은 다음처럼 사유를 적습니다.

```json
"applicability": {
  "web.password-recovery": {
    "status": "NOT_APPLICABLE",
    "reason": "이 서비스는 사용자 비밀번호 복구 기능을 제공하지 않음"
  }
}
```

## 상태 의미

| 상태 | 의미 |
| --- | --- |
| `VULNERABLE` | 검증된 취약 응답, 상태 위반, callback 증거가 있음 |
| `PASS` | 선언된 필수 전략·oracle·cleanup이 모두 완료되고 취약 증거가 없음 |
| `NEEDS_REVIEW` | oracle·OAST·cleanup·일부 표면이 완전하지 않음 |
| `NOT_APPLICABLE` | 프로필이 사유와 함께 명시적으로 제외 |
| `UNSUPPORTED` | 현재 배포판에 필요한 capability가 없음 |
| `NOT_SCANNED` | 승인·프로필·인증·preflight 문제로 실행하지 않음 |

공개 결과에는 `web.*` ID, 상태, coverage, 표면, evidence ID만 남습니다. 쿠키,
토큰, 비밀번호, raw 요청/응답, ZAP plugin ID는 포함하지 않습니다. 기능이 제한된
배포판은 웹 21개 항목을 실제 실행하지 않고 capability 경계를
`UNSUPPORTED(package_capability_missing)` 또는 검토 상태로 표시합니다.

ZAP 이미지와 add-on manifest는 사전에 digest로 고정해야 하며, web-audit 실행은
Docker image를 자동 pull하지 않습니다. 이미지·Playwright browser·BOAST가 없으면
해당 capability를 `UNSUPPORTED` 또는 `NOT_SCANNED`로 남깁니다.
ZAP Automation Framework plan에는 spider/activeScan 제한과 `exitStatus` 결과 검사가
포함되며, ZAP 종료 코드만으로 21개 항목 PASS를 만들지는 않습니다.

## 21개 항목별 coverage 계약

아래 ID는 결과에 항상 포함되는 공개 표준 ID입니다. 표의 내용은 해당 항목을
`PASS`로 닫기 위해 프로필에 선언해야 하는 최소 oracle 계약입니다. 일반
crawl/ZAP 경고가 없다는 이유만으로 미선언 항목을 PASS로 만들 수 없습니다.

| 번호 | ID | PASS를 위해 선언할 범위 |
| ---: | --- | --- |
| 1 | `web.code-injection` | bounded canary/input sink, 응답·상태 oracle, 필요 시 승인된 OAST |
| 2 | `web.ssrf` | 모든 URL sink, BOAST control plane, callback polling, callback 부재 oracle |
| 3 | `web.file-download` | 다운로드 리소스, traversal/LFI·object ID 변형, 비인가 거부 oracle |
| 4 | `web.sql-injection` | 파라미터, KODA/ZAP 전략, 응답·시간·데이터·상태 기준선 |
| 5 | `web.session-management` | 로그인 전후 세션, cookie 속성, logout 재사용, 만료 또는 검토 상태 |
| 6 | `web.directory-indexing` | 디렉터리 표면, non-listing status/body oracle |
| 7 | `web.password-policy` | disposable 계정, 약한/정상 비밀번호, cleanup·복구 |
| 8 | `web.plaintext-transmission` | 페이지·asset·form 전체 표면, HTTPS/redirect/mixed content/cookie oracle |
| 9 | `web.error-pages` | 안전한 malformed 요청, stack/path/SQL/secret 금지 패턴과 일반 오류 oracle |
| 10 | `web.authentication` | 정상 로그인 성공 및 비인증·우회 거부 검사 |
| 11 | `web.cookie-tampering` | session/role cookie 삭제·변경·교환 및 보호 리소스·상태 oracle |
| 12 | `web.information-disclosure` | seed/API/JS/header/민감 경로와 forbidden pattern/passive 결과 |
| 13 | `web.authorization` | anonymous/userA/userB/admin 및 object ID 접근 행렬 |
| 14 | `web.admin-exposure` | 관리자 경로의 anonymous/non-admin 검사; 미선언 발견 경로는 검토 |
| 15 | `web.xss` | reflected/stored/DOM 전략, canary/browser 필요 여부, stored cleanup |
| 16 | `web.password-recovery` | disposable 계정·test inbox, 계정 열거·token binding/만료/1회 사용 |
| 17 | `web.automated-attacks` | 제한된 login/recovery 시도, throttle/lock/CAPTCHA threshold, unlock cleanup |
| 18 | `web.csrf` | 정상 상태 snapshot, token/Origin/Referer 변형, 거부 및 상태 불변 |
| 19 | `web.process-validation` | 정상 sequence와 skip/reorder/replay mutation, 거부 및 상태 불변 |
| 20 | `web.http-methods` | `methods`/`probe_methods`, TRACE/override/금지 verb; OPTIONS만으로 취약 판정하지 않음 |
| 21 | `web.file-upload` | inert 확장자/MIME/HTML/SVG canary, 거부·격리·비실행·비공개·cleanup |

지원 전략 이름은 `koda-scenario`, `passive`, `browser`, `playwright`, `dom`,
`browser-canary`, `oast`, `ssrf-oast`, `callback`, `zap`, `zap-active`,
`zap-passive`, `access-control`, `authorization`, `matrix`, `timing`, `state`,
`http-methods`, `upload`입니다. 하나의 필수 시나리오에 여러 전략을 선언하면 모두 실행되며,
하나라도 미완료이면 항목은 PASS가 되지 않습니다.

`timing`은 명명된 기준 응답과 응답시간 차이 assertion을 요구합니다. `state`는
`{"type":"state_unchanged","snapshot":"baseline"}`처럼 이전 단계의
snapshot과 변경 시도 후 상태를 직접 비교하며, 상태변경 요청에는 cleanup이
필수입니다. 접근 행렬은 `state_resource`와 `state_account`를 선언하면 actor
요청 전후의 상태를 자동 비교합니다. `http-methods`는 선언된 `probe_methods`만
실행하며 OPTIONS 성공 자체는 허용하고, 예상하지 않은 `Allow` 메서드 또는 금지
verb 수락만 취약으로 판정합니다. `upload`는 `KODA-INERT-CANARY...` 내용만
전송하며 업로드 후 GET/HEAD 검증과 cleanup이 모두 있어야 PASS가 가능합니다.

## 대시보드 API와 인증 경계

대시보드에서도 CLI와 같은 승인 게이트를 사용합니다.

| API | 목적 | 본문 필드 |
| --- | --- | --- |
| `POST /api/web-audit/plan` | 프로필 검증·무트래픽 계획 | `profile` |
| `POST /api/web-audit/approve` | HMAC 승인서 생성 | `request`, `approver` |
| `POST /api/web-audit/run` | 승인된 1회 실행 | `profile`, `approval`, `confirm_origin`, 선택 `dry_run` |

서버와 클라이언트는 `127.0.0.1`, `localhost`, `::1` 중 loopback이어야 합니다.
POST에는 대시보드 HTML 응답의 프로세스별 `X-KODA-Session` 값과 정확한
`Origin: http://127.0.0.1:<port>`가 필요합니다. 외부 주소로 바인딩하면 세 API는
403으로 비활성화됩니다. `OPTIONS`도 origin 검사를 통과해야 하며, 세션 token은
보고서·프로필·승인서에 복사하지 않습니다.

결과에는 21개 `web.*` 항목, `status`, `executed`, `reason_code`,
`coverage.required/completed`, `surfaces_tested`, `strategy_results`,
`evidence_ids`가 포함됩니다. raw 요청/응답·header·cookie·credential·token·
password·ZAP plugin ID는 공개 결과에서 제거됩니다.

CLI 종료 코드는 top-level `VULNERABLE`이면 1, 프로필·승인·실행 오류이면 2,
`PASS`·`NEEDS_REVIEW`·`UNSUPPORTED`·`NOT_APPLICABLE`·`NOT_SCANNED`이면 0입니다.
따라서 종료 코드 0을 21개 전부 PASS로 해석하지 말고 각 항목의 coverage를
확인하세요.

## 배포판 capability 경계

| 배포판 | 웹 감사 범위 | 외부 capability |
| --- | --- | --- |
| 공유 Python CLI/server | stdlib native 전략 포함 | Playwright/ZAP/BOAST는 preflight 후 fail-closed |
| Windows Full | 공통 web-audit 엔진 포함 | Chromium, digest 고정 ZAP/Docker, BOAST 사전 설치 필요 |
| Windows SourceOnly | `UNSUPPORTED(package_capability_missing)` | Java/library/web/Playwright/취약점 데이터 제외 |
| macOS 직접배포판 | 지원 | 외부 도구를 자동 다운로드하지 않음 |
| 제한된 배포판 | GET/HEAD native read-only만 | POST·능동 probe·ZAP·상태 변경 profile은 거부/검토 |

ZAP은 `@sha256:<digest>` 이미지와 `sha256:<64자리 소문자 hex>` add-on
manifest를 요구하고 Docker image를 자동 pull하지 않습니다. 기본 제한은 native
1,000 request/2 MiB response/1 MiB upload/900초/redirect 3/OAST 120초/cleanup
30초, ZAP 2 RPS·host당 1 thread·15분·rule당 2분입니다. 최대값을 넘는 프로필은
검증에서 거부되고 상태 변경 request retry는 0입니다.

## 실행 후 확인

1. 결과 JSON/Markdown을 저장하고 21개 항목이 모두 존재하는지 확인합니다.
2. 필수 항목마다 `coverage.completed == coverage.required`인지 확인하고,
   `NEEDS_REVIEW`/`UNSUPPORTED`/`NOT_SCANNED` 사유를 별도 기록합니다.
3. disposable 계정, 비밀번호, 업로드, 세션, lock, callback event 등 cleanup
   대상을 확인합니다.
4. 구현 회귀 검증은 저장소 루트에서 다음 명령으로 실행합니다.

```bash
PYTHONPATH=platforms/shared/python python3 -m unittest -q \
  tests.test_web_audit tests.test_cli_reports tests.test_settings_and_exports
python3 -m compileall -q platforms/shared/python/security_scanner
```

이 검증은 profile canonicalization, HMAC/만료/nonce, redaction, 네트워크 고정,
상태 집계, 패키지 capability, 리포트 export를 확인하지만 실제 대상에 대한
점검 권한이나 애플리케이션별 oracle을 대신하지 않습니다.
