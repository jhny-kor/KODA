# KODA CLI 및 로컬 사용법

이 문서는 Linux·Windows·CI·서버에서 사용하는 공통 Python 엔진의 한국어
사용 안내입니다. 모든 명령은 저장소 루트에서 실행하고 `PYTHONPATH`에
`platforms/shared/python`을 추가합니다.

## 시작

```bash
export PYTHONPATH="$PWD/platforms/shared/python"
python3 -m security_scanner app
```

대시보드는 기본적으로 `127.0.0.1:8765`에만 바인딩됩니다. 명령별 전체 옵션은
`python3 -m security_scanner <command> --help`로 확인하세요.

### 개발 대시보드 접근 경계 — 2026-10-11

이번 GitHub 게시에 포함된 보안 경계 구현에서는 점검·폴더 선택·내보내기·예방 템플릿·
웹·ZAP POST 요청에 `Origin: http://<Host>`와 `/api/health` 응답의
`X-KODA-Session` 값이 필요합니다. 내장 화면은 이를 자동으로 전달합니다.
오래된 내보내기 화면 또는 헤더를 생략한 직접 API 호출은 HTTP 403을 받으므로
실행 중인 동일 서버가 제공하는 화면을 사용하세요. `web-audit`은 서버와 클라이언트가
loopback이어야 합니다. 게시·검증 범위는 [현재 상태](current-status.ko.md)를 따릅니다.

## 주요 명령

```bash
python3 -m security_scanner scan --target /path/to/project --format html
python3 -m security_scanner scan --target /path/to/project --standard owasp-asvs-5 --format html --output reports/source.html
python3 -m security_scanner scan --target /path/to/project --standard sw-dev-security-49 --standard-category input-validation-expression --format html --output reports/sw49-input.html
python3 -m security_scanner scan --target /path/to/project --format sarif --fail-on high
python3 -m security_scanner jar-scan --target /deploy/apps --target /deploy/worker-apps --fail-on high --fail-on-kev
python3 -m security_scanner sbom-verify --target /deploy/apps --sbom approved.cdx.json
```

`jar-scan`의 `--target`은 반복 지정할 수 있습니다. 여러 폴더를 지정하면 모든
아카이브·컴포넌트·취약점·SBOM을 중복 제거하여 하나의 라이브러리 메인/상세 리포트로
생성합니다.

JAR 보고서는 현재 HTML과 Markdown 모두 한국어로 생성되며 `--language`는
`ko`만 지원합니다. 취약점은 라이브러리·설치 버전별로
통합되고 `Fixed`와 Grype DB 재검증 결과인 `Final`이 함께 표시됩니다.

없는 소스 `--target` 경로는 입력 오류로 종료 코드 `2`를 반환합니다. 정상
대상에 발견이 없으면 `--fail-on high`에서도 `0`이지만, 없는 경로를 빈 결과로
성공 처리하지 않습니다.

`jar-scan --fail-on` 또는 `--fail-on-kev`는 Grype가 없거나 `--no-grype`로
비교를 끄면 경고와 종료 코드 `2`를 반환합니다. 취약점 게이트 없이
`--builtin-only --no-grype`로 SBOM만 생성하는 정상 실행은 `0`입니다.
macOS Java helper의 보고서도 UI 언어와 무관하게 한국어입니다.

소스코드 분석에서 `--standard`로 등록된 기준을 하나 선택할 수 있습니다. 예를 들어
`owasp-asvs-5`, `owasp-proactive-controls`, `sw-dev-security-49`,
`sw-dev-security-7-types`를 사용할 수 있으며, `--standard-category`로 해당
기준의 지원 범주를 더 좁힐 수 있습니다. HTML은 지정한 경로를 요약(메인)으로
생성하고 같은 폴더에 `-detail.html` 상세 보고서를 함께 생성합니다. 기준 프로파일은
KODA가 구현한 정적 룰 매핑 범위이며 전체 SAST 또는 공식 준수 판정을 의미하지 않습니다.

외부 CodeQL 연동은 사전 점검(preflight)과 관리자가 생성한 Java SARIF의
positive-only 가져오기를 구현합니다. KODA가 CodeQL을 직접 다운로드·실행하는
경로는 지원하지 않으며 실행 요청은 `SKIPPED`/`NOT_SCANNED`로 남깁니다.
깨끗한 SARIF를 가져와도 미발견 영역의 점검 완료나 PASS를 증명하지 않습니다.

[2026-10-11 검증 기록](verification-2026-10-11.ko.md)은 실제 실행한 OS와
조건을 설명합니다. 구현 여부는 [OS별 기능표](platform-feature-matrix.ko.md)를 보세요.

## 로컬 SpotBugs와 Semgrep CE

소스 폴더 한 개를 선택해 설치된 SpotBugs와 Semgrep CE를 같이 실행하거나 각각 실행할 수 있습니다. 도구 설치는 별도로 진행합니다.

- SpotBugs를 쓸 때는 `KODA_SPOTBUGS_JAR`에 배포판의 `lib/spotbugs.jar` 경로를 지정합니다. Java는 `KODA_JAVA_BIN`, `JAVA_HOME`, `PATH` 순으로 찾습니다. 점검에 빌드된 JAR, `.class` 또는 클래스 폴더를 사용합니다. Java 소스가 `src/main/java` 밖에 있으면 `--spotbugs-source-root`로 선택한 소스 폴더 안의 패키지 루트를 지정하세요.
- Semgrep CE는 `PATH`에서 찾거나 `KODA_SEMGREP_BIN`에 실행 파일 경로를 지정합니다. 규칙 입력은 로컬 YAML 파일 한 개입니다. 검사 중 Semgrep 계정 설정을 읽지 않고 원격 규칙 조회와 메트릭을 사용하지 않는 실행 옵션을 적용합니다.
- Windows PowerShell에서 환경 변수는 `$env:KODA_SPOTBUGS_JAR = 'C:\tools\spotbugs\lib\spotbugs.jar'`처럼 설정한 뒤 같은 터미널에서 KODA를 실행합니다. Mac에서는 `koda-local dashboard`를 도구 환경 변수를 설정한 터미널에서 시작할 수 있습니다.

```bash
python -m security_scanner scan --target ./project --spotbugs-input ./project/build/classes --semgrep-rules ./team-rules.yml --format json --output ./koda-report.json
```

도구 환경을 설정한 터미널에서 Mac의 `koda-local dashboard` 또는 Windows의 `KODA.exe`를 시작합니다. **SpotBugs · Semgrep CE**에 로컬 절대 경로를 입력하고 **보안 점검**을 누르면 같은 분석을 실행합니다. 두 분석기는 GitHub 연동 없이 동작합니다. 별도로 생성한 SARIF 2.1.0은 **외부 SARIF 파일** 또는 `--source-analyzer-sarif`로 열 수 있습니다. 한 회차에서 외부 SARIF 파일과 로컬 실행 중 하나를 선택합니다.

SpotBugs의 Java null 역참조는 개발보안 49의 C-01 검토 후보로 표시합니다. 나머지 SpotBugs 발견과 Semgrep 로컬 규칙 발견은 **전체** 기준에서 검토할 수 있습니다. SpotBugs가 일부 클래스를 해석하지 못하면 분석 상태를 `PARTIAL`, SARIF에 실행 실패가 기록되어 있으면 `FAILED`로 표시합니다. 파일 위치가 선택한 소스 폴더에 속하는 발견을 반영하고, 빈 SARIF만으로는 전체 검사 범위나 통제 통과를 판정할 수 없습니다.

## 안전 경계

일반 스캔과 `sbom-verify`는 읽기 전용입니다. `fix --apply`, 템플릿 생성,
`web-scan`, `net-scan`, `zap-run`은 파일을 변경하거나 외부 시스템에
접근할 수 있으므로 승인된 대상에서만 사용하세요.

`net-scan`은 비웹 네트워크 표면을 다룹니다 — 엄선된 TCP 포트/배너 스윕, 능동 TLS
점검(폐기된 TLS 1.0/1.1·약한 암호·인증서 유효성), HTTP Basic 공개 기본 자격증명
점검(브루트포스 아님). 대상에 능동 접속하므로 `--authorize-active`가 필요합니다:

```bash
python3 -m security_scanner net-scan --host 10.0.0.10 --tls --authorize-active
python3 -m security_scanner net-scan --host 10.0.0.10 --default-creds-url https://10.0.0.10/admin --authorize-active
```

## 승인된 웹 점검

`web-scan`은 기본적으로 제한된 posture 점검만 수행합니다. `--active`나
`zap-run --mode full`처럼 요청 범위를 넓히는 옵션은 소유하거나 명시적 권한을
받은 대상에서만 사용하고, ZAP 활성 모드에는 `--authorize-active`를 지정하세요.

`web-scan`은 명시적 opt-in 단계로 공격성을 높입니다 — 패시브(기본), `--active`
(쿼리 파라미터·폼·`--api-spec` 표면에 검증형 페이로드: 반사/JS컨텍스트 XSS,
멀티엔진 SSTI, SQLi, LFI, 오픈 리다이렉트, CRLF, 헤더 삽입), `--intrusive`
(시간기반 블라인드 SQLi/OS 명령어 삽입, JSON 쓰기 엔드포인트 퍼징, 저장형 XSS
추가. `--oob-listen HOST:PORT`로 블라인드 SSRF/RCE를 확인하는 내장 수집기 기동).
`--intrusive`는 `--active`가 필요하고 상태 변경 요청을 보내므로 승인된 staging
전용입니다. `--exploit`(`--intrusive` 필요)는 영향 실증을 추가합니다 — 확인된
삽입점에서 읽기전용 증거 1건(DB 버전, `id` 출력, 평가된 식)만 추출하고 멈추며
덤프·셸·파괴는 없습니다. 어떤 단계도 데이터 파괴 페이로드를 보내지 않습니다. 범위는
`--max-params`·`--max-form-fields`로 조정하고 `--delay 0`으로 처리량을 최대화할
수 있습니다. 전체 단계표와 `web-audit`·`zap-run --mode full`로의 확대 기준은
[web-scan 점검 단계](security/WEB_AUDIT.ko.md#web-scan-점검-단계티어)를 보세요.

`--active` 단계는 추가로 다음을 점검합니다.

- **Boolean 기반 블라인드 SQL 삽입**: 따옴표로 SQL 오류가 보이지 않을 때 참·거짓
  조건을 비교합니다. 참 조건이 기준 페이지를 재현하고 거짓 조건만 응답을 바꿀 때만
  보고합니다(기준 페이지 2회 수신, 거짓 결과 재현 확인, 반사된 페이로드 제외).
- **숨은 파라미터 발견**: 공통 이름과 페이지의 링크·스크립트에서 쓰는 이름을 고유
  마커와 함께 한 번의 요청으로 보내고, 페이지가 반사한 이름은 링크에 없어도 능동
  점검합니다.
- `--render`와 함께 쓰면 **DOM 기반 XSS**: 인라인 스크립트가 `location`/`document.URL`을
  읽어 `innerHTML`·`document.write`·`eval` 등에 쓰는 페이지를 URL 프래그먼트로
  점검합니다. 브라우저는 렌더링과 같은 origin 경계 안에서만 동작하며, 외부 번들에만
  있는 source는 분석하지 않습니다.

`--crawl`의 기본 상한은 50페이지·깊이 3이며 `--max-pages`와 `--max-depth`로
조정할 수 있습니다. KODA는 중복 URL을 제거하고 별도의 요청 안전 한도를
적용합니다. 페이지·깊이·요청 상한, 응답 읽기 제한, 렌더링 실패 때문에 확인하지
못한 표면은 PASS로 숨기지 않고 경고와 미점검 URL 수로 남깁니다. `--timeout`은
각 요청의 연결·유휴 읽기 제한이며 전체 점검의 절대 실행 시간 제한은 아닙니다.

로컬 대시보드의 `전체 선택`은 웹 점검 옵션에만 적용되고 ZAP 옵션은 별도로
유지됩니다. 전체 선택에는 능동 검증도 포함되므로 승인된 대상에서만 사용하세요.
대시보드는 능동 점검 전에 loopback 세션 토큰을 자동으로 전달합니다. API를 직접
호출하면 `/api/health` 응답의 `X-KODA-Session` 값과 정확한 loopback `Origin`을
함께 보내야 합니다.

21개 웹취약점 항목을 프로필·승인·일회성 nonce로 실행하려면 `web-audit`을
사용합니다. 프로필에는 대상 origin/CIDR, 리소스, 정상·거부 oracle, cleanup,
N/A 사유를 명시해야 하며, 선언되지 않은 표면은 PASS가 되지 않습니다.

```bash
export KODA_APPROVAL_KEY='operator-managed-secret'
koda web-audit plan --profile profile.json --out approval-request.json
koda web-audit approve --request approval-request.json --approver 'name' --out approval.json
koda web-audit run --profile profile.json --approval approval.json \
  --confirm-origin https://staging.example.com --format markdown --output reports/web-audit.md
```

`plan`은 대상 DNS/IP만 확인하고 트래픽을 보내지 않습니다. `run`은 승인서의
프로필 hash·origin·현재 IP·만료·서명을 검증하고 승인서를 한 번만 소비합니다.
자격증명은 `${ENV:NAME}` 또는 환경변수 이름으로만 참조하세요. 프로필 예시와
21개 상태 판정은 [웹취약점 자동 점검 런북](security/WEB_AUDIT.ko.md)에 있습니다.

실행 전에는 `--dry-run`으로 승인서·프로필·현재 capability만 확인할 수 있습니다.
이 모드는 대상 요청을 보내지 않고 nonce도 소비하지 않습니다.

```bash
python3 -m security_scanner web-audit run \
  --profile profile.json \
  --approval approval.json \
  --confirm-origin https://staging.example.com \
  --dry-run
```

프로필은 다음 순서로 작성합니다.

1. `target.origins`에 정확한 scheme/host/port를 적고 `include_paths`,
   `exclude_paths`, `allowed_cidrs`, `scopes`를 최소 범위로 선언합니다.
2. `resources`에 리소스 ID·허용 메서드·`read_only`·actor별 `access` 기대값을
   등록합니다. 시나리오에서 임의 URL이나 등록되지 않은 리소스 ID는 사용할 수 없습니다.
3. `scenarios`에 하나 이상의 `web.*` `control_id`, 전략, 단계, mutation,
   cleanup, 정상/거부 oracle을 선언합니다. 각 필수 전략이 완료되어야 해당 항목이
   PASS가 됩니다.
4. 계정·로그인 값은 `${ENV:NAME}` 또는 환경변수 이름만 사용합니다. 비밀번호,
   쿠키, token, shell/eval/callback 코드는 JSON에 넣지 않습니다.
5. 제공하지 않는 기능은 `applicability.<web.*>`에 `NOT_APPLICABLE`과 사유를
   명시합니다. 단순히 시나리오를 생략한 항목은 N/A가 아니라 `NOT_SCANNED`입니다.

대시보드 API를 사용할 때도 실행 게이트는 동일합니다. 서버는 loopback으로만
바인딩해야 하며, 요청에는 대시보드 응답의 `X-KODA-Session` 값과 정확한
`Origin: http://127.0.0.1:<port>`(또는 해당 loopback 주소)가 필요합니다.

| API | 목적 | 본문 핵심 필드 |
| --- | --- | --- |
| `POST /api/web-audit/plan` | 프로필 검증·무트래픽 계획 | `profile` |
| `POST /api/web-audit/approve` | HMAC 승인서 생성 | `request`, `approver` |
| `POST /api/web-audit/run` | 승인된 1회 실행 | `profile`, `approval`, `confirm_origin`, 선택 `dry_run` |

외부 주소로 서버를 바인딩하면 위 세 실행 API는 403으로 비활성화됩니다.
결과에는 21개 항목이 항상 포함되며, `web.*` ID·상태·coverage·표면·evidence ID만
공개됩니다. 원문 요청/응답, 쿠키, token, 비밀번호, ZAP plugin ID는 보고서에 넣지 않습니다.

CLI 종료 코드는 `VULNERABLE`일 때 1, 승인·프로필·capability 오류일 때 2,
그 외 결과(`PASS`, `NEEDS_REVIEW`, `UNSUPPORTED`, `NOT_SCANNED`)는 0입니다.
따라서 CI에서 성공을 “전체 21개 PASS”로 해석하지 말고 결과 JSON의 각 항목과
`coverage.completed == coverage.required`를 함께 확인하세요.

## AI 어시스트 (옵트인)

모든 AI 기능은 기본 꺼짐이며 심각도·게이트 결과를 바꾸지 않습니다. `--llm`/`KODA_LLM`로
백엔드를 고르고, 미설정 시 경고 한 줄과 함께 graceful하게 넘어갑니다. `secrets`
findings는 원문 시크릿·소스를 전송하지 않습니다.

| 플래그 | 효과 | 적용 |
| --- | --- | --- |
| `--ai-triage` | findings를 likely_true/likely_false/uncertain로 라벨 | scan, web-scan, net-scan |
| `--ai-remediate` | 각 finding에 구체적 수정안 추가 | scan, web-scan, net-scan |
| `--ai-explain` | 고위험 finding에 영향 서술 1~2문장 추가 | web-scan, net-scan |
| `--ai-map` | CWE 없는 finding에 CWE/OWASP 매핑 제안 | web-scan, net-scan |
| `--ai-summary` | findings 경영 요약 출력 | scan, web-scan, net-scan |
| `--ai-query "<질문>"` | 질문에 관련된 finding만 출력(읽기전용) | scan, web-scan, net-scan |

로컬 Ollama 백엔드를 쓰면 데이터가 기기 밖으로 나가지 않습니다. `anthropic/<model>`·
`openai/<model>` 등 클라우드 백엔드는 명시적 외부 전송이며 API 키가 필요합니다.
클라우드 사용 전 [개인정보 정책](../PRIVACY.md)을 확인하세요.

### 로컬 OpenAI 호환 서버 (LM Studio·llama.cpp·vLLM)

`openai` 백엔드를 OpenAI API를 말하는 로컬 서버로 가리킬 수 있습니다. 키는 SDK가
요구하지만 서버는 무시하므로 아무 placeholder나 되고, loopback 주소는 로컬로
간주돼 외부 전송 경고가 뜨지 않습니다:

```bash
export KODA_LLM=openai/qwen3.8-27b-uncensored-mlx   # GET /v1/models 의 id
export KODA_LLM_API_BASE=http://localhost:1234/v1    # LM Studio 기본
export KODA_LLM_API_KEY=local                        # placeholder, 서버가 무시
python3 -m security_scanner scan --target . --ai-triage --ai-remediate --llm-timeout 180
```

대형 로컬 모델(예: LM Studio의 27B)은 느리므로 `--llm-timeout`(기본 120초)을 올려
타임아웃을 피하세요. `localhost`·`127.0.0.1`·`::1`만 동일 기기로 보고, LAN 주소는
여전히 "기기 밖으로 나감" 경고가 뜹니다.

## 신규만 게이트 (baseline)

`--baseline REPORT`를 주면 `--fail-on`이 **이전 JSON 보고서에 없는 신규 finding**에만
발동합니다(rule id/target/path/line 기준). 기존 백로그로 CI가 실패하지 않으면서
새로 생긴 문제만 막을 수 있습니다. `scan`·`web-scan`·`net-scan`에서 사용 가능하고,
baseline 파일이 없으면 아무것도 숨기지 않습니다. web-scan/net-scan findings는
상위 `attack-path.*`(예: SSRF→메타데이터 자격탈취, Docker API 노출→호스트 탈취)로
상관되어 end-to-end 영향이 우선순위화됩니다.

## Python 소스 분석과 정적·동적 교차확증

Python 파일은 라인 룰 위에 구문 분석(표준 라이브러리 `ast`) 기반 taint 엔진으로
판정합니다. 별칭, f-string, 문자열 결합/`format`/`%`, 보조 함수의 반환값, import
별칭을 따라가고, 숫자 변환, `shlex.quote`, `basename`/`secure_filename`, 스캐너의
validate*/escape* sanitizer, 허용 목록·`re.fullmatch` 가드를 인식합니다. 엔진이
sink가 안전함을 증명할 때만 라인 finding을 제거하고, 요청 → sink 흐름을 증명할 때만
확정합니다. 판단할 수 없는 경우는 라인 엔진 결과를 그대로 둡니다. 함수 *매개변수*로
전달되는 taint(예: FastAPI 라우트 인자)는 추적하지 않으며 `needs_review` 후보로 남습니다.

`tests/test_python_taint_bench.py`가 엔진 이후에 작성한 held-out 세트를 포함한 라벨
코퍼스로 이를 측정합니다(확정 기준 precision 1.00, recall 0.96; held-out F1은 라인
룰만 0.50 → 0.95). 표는 직접 실행해 확인합니다:

```bash
python3 tests/test_python_taint_bench.py
```

`correlate`는 소스 점검 보고서와 웹 점검 보고서를 교차확증합니다. 같은 약점(SQL 삽입,
명령어·템플릿 삽입, XSS, 경로 조작, SSRF, 오픈 리다이렉트)으로 일치하는 finding은
교차확증되고, 코드 파일이 선언한 라우트 경로가 점검 URL과 일치하면(Flask/FastAPI
데코레이터, Django `path()`, Express) 동일 엔드포인트로 표시됩니다 — 우선 조치 대상입니다:

```bash
python3 -m security_scanner scan --target . --format json --output code.json
python3 -m security_scanner web-scan --url https://staging.example.com --crawl --active --format json --output web.json
python3 -m security_scanner correlate --source code.json --web web.json
```

보고서는 정적만 탐지된 약점(동적 재현 시험 권장)과 동적만 탐지된 약점(이 소스
트리에서 sink 위치 미확인)도 함께 나열합니다.

- [한국어 문서 인덱스](README.md)
- [English CLI and local usage](usage.md)
