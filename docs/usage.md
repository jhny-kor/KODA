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

소스코드 분석은 `--standard`로 등록된 기준을 하나 선택해야 합니다. 예를 들어
`owasp-asvs-5`, `owasp-proactive-controls`, `sw-dev-security-49`,
`sw-dev-security-7-types`를 사용할 수 있으며, `--standard-category`로 해당
기준의 지원 범주를 더 좁힐 수 있습니다. HTML은 지정한 경로를 요약(메인)으로
생성하고 같은 폴더에 `-detail.html` 상세 보고서를 함께 생성합니다. 기준 프로파일은
KODA가 구현한 정적 룰 매핑 범위이며 전체 SAST 또는 공식 준수 판정을 의미하지 않습니다.

## 안전 경계

일반 스캔과 `sbom-verify`는 읽기 전용입니다. `fix --apply`, 템플릿 생성,
`web-scan`, `zap-run`, `upload-sbom`은 파일을 변경하거나 외부 시스템에
접근할 수 있으므로 승인된 대상에서만 사용하세요.

## 승인된 웹 점검

`web-scan`은 기본적으로 제한된 posture 점검만 수행합니다. `--active`나
`zap-run --mode full`처럼 요청 범위를 넓히는 옵션은 소유하거나 명시적 권한을
받은 대상에서만 사용하고, ZAP 활성 모드에는 `--authorize-active`를 지정하세요.

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
21개 상태 판정은 [웹취약점 자동 점검 런북](security/WEB_AUDIT.md)에 있습니다.

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

- [한국어 문서 인덱스](README.md)
- [English CLI and local usage](usage.md)
