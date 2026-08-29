# KODA 리포트 계약

Linux·Windows·CI·서버는 공통 Python 엔진을 사용하고, macOS 앱은 네이티브
Swift 스캐너를 사용합니다. 소비자는 읽는 산출물의 계약을 선택해야 하며, 아래
필드는 공통 엔진의 `scan --format json` 결과를 기준으로 합니다.

## Finding 필드

공통 Python 엔진의 `scan --format json` finding은 다음 키를 항상 포함합니다.

| 필드 | 설명 |
| --- | --- |
| `rule_id`, `category`, `severity`, `title` | 안정적인 룰 ID, 분류, 소문자 심각도, 제목 |
| `target`, `path`, `line` | 논리 대상, 파일 경로, 1부터 시작하는 줄 번호 또는 `null` |
| `evidence`, `description`, `recommendation` | 비밀값을 제거한 근거와 설명·조치 안내 |
| `resource` | 호스트 finding의 안정적인 리소스 ID. 파일 finding은 빈 문자열 |
| `reachable` | 빈 문자열 또는 `reachable`, `unreachable`, `unknown` |
| `verification_status`, `verification_note` | `confirmed`/`needs_review`/`unverified` 판정과 근거. `unverified`는 점검 자체를 수행하지 못한 상태(조회 수단 없음·차단)로, 위험 판정이 아니라 근거 공백이며 점수와 게이트에 반영하지 않음. 알 수 없는 외부 값은 `needs_review`로 처리 |
| `triage_verdict`, `triage_confidence`, `triage_note` | 선택적 AI 분류 결과. 심각도나 게이트 판정을 바꾸지 않음 |
| `analyzer`, `analyzer_version`, `analyzer_rule_id` | 분석기 식별자·버전·원본 룰 ID |
| `cwe_ids`, `evidence_kind`, `trace` | CWE 목록, 근거 종류, 순서가 있는 추적 근거 |
| `evidence_id`, `issue_key` | 근거 및 이슈 상관관계 식별자 |
| `standard_mappings` | 선택한 표준·범주 매핑. 없으면 빈 배열 |

줄 번호가 있는 파일 finding에는 `source_context`가 추가될 수 있습니다. 소비자는
새 필드가 추가되어도 실패하지 않아야 합니다.

## 다른 JSON 산출물

- `release-package`의 `scan-findings.json`은 핵심 finding·검증·분석기 근거
  필드만 기록합니다. `target`, `resource`, 도달 가능성/AI 분류,
  `standard_mappings`, `source_context`는 포함하지 않습니다.
- `web-audit`은 [WEB_AUDIT.md](security/WEB_AUDIT.md)의 21개 항목별
  상태·coverage·evidence 계약을 사용합니다.
- Java 아카이브와 SBOM 검증 JSON은 워크플로 전용 스키마를 사용하므로
  [Java 런북](security/java-sbom-vulnerability-scan.md)을 따릅니다.

## 분류와 플랫폼 규칙

- 기본 파일 점검: `secrets`, `dependencies`, `configuration`, `code`, `prevention`
- 별도 선택 분류: `screen_quality`, `host`
- 승인된 웹 posture 점검은 `web`을 사용합니다.
- 심각도는 `info`, `low`, `medium`, `high`, `critical` 순서의 소문자 값입니다.
- CI 게이트는 번역된 라벨이나 UI 문구가 아니라 `severity`를 사용합니다.
- `rule_id`, `category`, `severity` 같은 공통 필드는 플랫폼에서 같은 의미를
  유지하지만 산출물별 스키마가 완전히 같지는 않습니다.
- 필드를 바꾸거나 삭제하지 말고 호환되는 새 필드를 추가합니다.

JSON·HTML·Markdown·SARIF·CycloneDX 변환은 원본 finding의 식별자와 경로를
보존해야 합니다. 빈 결과는 대상에 위험이 없다는 보장이 아닙니다.

Java 리포트는 라이브러리·설치 버전별로 취약점을 통합하고, `Fixed`와 동일한
Grype DB로 검증한 `Final` 후보를 별도 필드로 제공합니다.

## 검증

공통 Python 직렬화 함수는 `security_scanner.reporting._finding_payload`입니다.
finding 직렬화나 리포트 내보내기를 변경한 뒤 `tests.test_source_analysis`,
`tests.test_sw49_standards`, `tests.test_settings_and_exports`를 실행합니다.

- [한국어 문서 인덱스](README.md)
- [English report contract](report-contract.md)
