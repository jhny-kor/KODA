# KODA 구현 명세 — 정적 스캐너를 넘어서기

> **문서 확인: 2026-10-02.** 아래 2026-06-17 구현·123개 테스트·빌드 기록은
> 당시의 기록이며 현재 전체 검증 결과가 아닙니다. 공통 CLI의 현행 동작은
> [사용법](usage.ko.md), 별도 로컬 AI 개발 구현은
> [macOS 로컬 AI](macos-local-ai.ko.md), 게시·검증 범위는
> [현재 상태](current-status.ko.md)를 따릅니다. Python과 Swift의 내부 검사 통과만으로
> 기능 동등성을 보장하지 않습니다. 공통 Ollama 제공자의 API base는 원격 HTTP(S)도
> 허용하며, `koda[ai]` extra는 현재 pyproject에 정의되어 있지 않습니다.


> 목적: [roadmap-ai-augmentation.md](roadmap-ai-augmentation.md)의 4대 축을 **실제로 구현 가능한 수준**으로 구체화한다.
> 업계 기법(Strix·XBOW·Endor·Copilot Autofix·Semgrep Assistant)을 분석해 KODA에 맞게 채택/변형/기각한 결정을 코드 스켈레톤과 함께 기록한다.
> 상태: 설계(Design) + 일부 구현. 함수 시그니처·모듈 경계·CLI/Config 스키마는 구현 시작 기준점이다.
> 구현 진행:
> - **C1 LLM Provider ✅ 구현 완료**(`platforms/shared/python/security_scanner/ai/provider.py`: `KODA_LLM` 규약, ollama=stdlib/전송0, anthropic·openai=lazy extra).
> - **C2 AI Triage ✅ 구현 완료**(`platforms/shared/python/security_scanner/ai/triage.py`: FP/TP 라벨, 심각도 불변, 시크릿 원문 미전송, graceful degrade, `--ai-triage`/`--llm`, JSON `triage_*` 필드, PRIVACY.md 갱신).
> - **C3 Reachability ✅ 구현 완료**(`platforms/shared/python/security_scanner/reachability.py`, `--reachability`/`--reachable-only`, JSON `reachable` 필드).
> - **C5 CI/CD diff-scope ✅ 구현 완료**(`platforms/shared/python/security_scanner/git_changes.py`, `--changed-only`/`--base`, git 실패 시 전체 스캔 폴백, 배포형 composite action `.github/actions/koda/action.yml`, README CI 섹션).
> - **C4 Auto-Fix ✅ 구현 완료**(`platforms/shared/python/security_scanner/fixes/`: 결정론적 line-scoped fixer[weak-hash, yaml.load], `fix` CLI 기본 dry-run diff + `--apply` 백업·구문검증 게이트, `--rule`/`--no-backup`).
> - 테스트: reachability 10 + provider 5 + triage 7 + diff-scope 5 + auto-fix 5 = 32종 추가(전체 123 통과). **C1·C2·C3·C4·C5 전부 구현 완료(Python).**
> - **네이티브 Swift 앱 포팅 ✅ 완료** (`platforms/macos/app/KODA/KODA/ScannerBridge.swift` 등): C4 `SecurityCodeFixer`(+`.replaceFile` 백업), C3 `NativeReachability`(OSV 발견 라벨), C2 `NativeLLMProvider`+`NativeAITriage`(로컬 Ollama/클라우드, "AI 오탐 검토" 버튼), C5 `NativeGitChanges`("변경 파일만 점검" 버튼). 각 기능 `xcodebuild` BUILD SUCCEEDED. 동작 의미는 Python 구현(테스트 통과)과 동일.
> 최종 갱신: 2026-06-17

---

## 0. 설계 원칙 (모든 기능에 관통)

1. **오프라인이 기본, 외부는 opt-in.** 신규 기능은 전부 `enable_*` 플래그 기본 `False`. 기존 `enable_osv`/`enable_vuln_intel`/`enable_host_*` 패턴 복제(`models.ScannerConfig`).
2. **로컬 경로는 표준 라이브러리만.** 로컬 LLM(Ollama)·reachability·auto-fix·diff-scope는 **추가 의존성 없이**(`urllib`/`ast`/`subprocess`) 동작. 클라우드 LLM SDK는 선택적 extra(`pip install koda[ai]`)로 격리해 KODA의 "설치 없이 실행" 원칙 유지.
3. **탐색과 검증을 분리(XBOW/Strix 핵심 교훈).** LLM·휴리스틱은 **탐색·제안**만. 차단·강등·적용 같은 **판정은 결정론적 게이트**가 내린다. LLM은 절대 단독으로 "차단" 결정을 못 내린다.
4. **쓰기는 항상 dry-run → 승인 → 적용.** auto-fix는 KODA에서 가장 침습적 → 기본 미적용. `koda-ignore.yml` 거버넌스와 동일 철학.
5. **전송 데이터를 명시.** 네트워크 백엔드가 코드를 외부로 보낼 때 어떤 데이터가 어디로 가는지 발견·로그·`PRIVACY.md`에 1:1로 표기.

---

## 1. 업계 기법 분석 → KODA 채택 결정

| 기법 (출처) | 핵심 메커니즘 | KODA 채택 결정 |
|---|---|---|
| **Strix** 에이전트 툴킷 (proxy/browser/terminal/python, Docker 샌드박스) | 동적 실행으로 실제 익스플로잇 | **부분 기각** — 무거운 런타임·공격 실행은 오프라인/읽기전용 정체성과 충돌. CLI/env/CI 규약만 차용 |
| **Strix** LLM 설정 (`STRIX_LLM`, `LLM_API_KEY`, `LLM_API_BASE`, litellm provider 문자열, Ollama/LMStudio 지원) | provider 프리픽스 문자열 + 로컬 base URL | **채택** — `KODA_LLM`, `KODA_LLM_API_BASE` 동일 규약. 로컬은 stdlib `urllib`로 직접 호출 |
| **Strix** scope/CI (`--scan-mode quick`, `--scope-mode diff --diff-base`, `-n` 비대화형, 비-제로 exit) | PR diff-scope + 헤드리스 | **채택** — KODA `--changed-only --base`, 기존 `--fail-on` 재사용 |
| **XBOW** 2-layer (자율 탐색 + **결정론적 validator**가 exploitability 확정) | 탐색/검증 분리, non-destructive 확인 | **채택(핵심)** — 원칙 #3. validator = 결정론적 후처리 |
| **Endor Labs** reachability (call graph, function-level, 미사용 취약점 강등, 92~97% 노이즈 감소; pre-computed manifest 기반 / full build 기반) | 도달 가능성으로 우선순위 | **채택** — 빌드 없는 KODA엔 **pre-computed(import 기반)** 먼저, call-graph는 후속 |
| **Copilot Autofix** (CodeQL SARIF + source/sink 주변 스니펫 + query help → LLM → 패치 + 자연어 설명, 자동적용 안 함) | 결정론 탐지 + LLM 패치 + 사람 승인 | **채택** — 결정론적 fix 우선, 미해결만 LLM 패치 제안, 항상 승인 게이트 |
| **Semgrep Assistant** (결정론 분석 + LLM, FP/TP **별도 프롬프트 체인**, 95% FP 정확도, "Memories"로 조직 컨텍스트 학습, FP 시스템만 액션 허용) | triage 자동화 + 학습 메모리 | **채택** — FP/TP 프롬프트 분리, `koda-ignore.yml`을 "Memories-lite"로 활용 |
| **로컬 LLM 2026** (Qwen3-Coder / Qwen2.5-Coder 32B, Ollama `localhost:11434`, thinking/non-thinking) | 완전 로컬·전송 0 | **채택** — 로컬 백엔드를 1급 시민으로, 기본 권장 모델 제시 |

---

## 2. 전체 데이터 흐름

```
                                  ┌─────────────────────────────────────────┐
  파일/호스트 스캔 (기존)  ──▶ findings: list[Finding]                       │
                                  │                                          │
                                  ▼                                          │
                    ┌──────────────────────────┐                            │
                    │  후처리 파이프라인 (신규)   │   ← 전부 opt-in, 순서 고정 │
                    │  1) reachability  (C3)    │   결정론적: 도달불가 강등   │
                    │  2) ai_triage     (C2)    │   탐색: FP신뢰도·근거 라벨  │
                    │  3) validator     (검증)   │   결정론적: 판정 확정       │
                    └──────────────────────────┘                            │
                                  │                                          │
            ┌─────────────────────┼──────────────────────┐                  │
            ▼                     ▼                      ▼                  │
   리포트(HTML/MD/SARIF)   fix 제안(C4, dry-run)   CI 게이트(C5, --fail-on)  │
            │                     │                      │                  │
            └──────────── diff/score/ignore (기존 재사용) ───────────────────┘
```

핵심: 신규 단계는 모두 **발견 수집 후 · 리포트 전**에 1회 끼어드는 후처리. OFF면 무동작 → 기존 경로 완전 불변.

---

## 3. C1 — LLM Provider 추상화 (`platforms/shared/python/security_scanner/ai/provider.py`)

Strix의 litellm 규약을 따르되 **로컬 경로는 stdlib만** 사용한다.

### 환경변수 규약 (Strix 호환 네이밍)
```
KODA_LLM            예) "ollama/qwen2.5-coder:32b"  "anthropic/claude-sonnet-4-6"  "openai/gpt-5.4"
KODA_LLM_API_KEY    클라우드 백엔드 키 (로컬은 불필요)
KODA_LLM_API_BASE   로컬/프록시 base URL (기본 http://localhost:11434)
KODA_LLM_TIMEOUT    기본 30초
```

### 인터페이스 (vuln_intel의 warnings 패턴 복제)
```python
from __future__ import annotations
from dataclasses import dataclass

@dataclass(frozen=True)
class LLMResult:
    text: str
    backend: str            # "ollama" | "anthropic" | "openai"
    sent_externally: bool   # 프라이버시 표기용 (로컬=False)

class LLMUnavailable(RuntimeError): ...

def complete(prompt: str, *, system: str = "", json_mode: bool = False,
             timeout_seconds: float = 30.0) -> LLMResult:
    """단일 진입점. 백엔드는 KODA_LLM 프리픽스로 분기.
    - ollama/*  : urllib로 POST {API_BASE}/api/generate (stdlib, 전송 0=로컬)
    - anthropic/*: optional extra(anthropic SDK), 없으면 LLMUnavailable
    - openai/*  : optional extra(openai SDK), 없으면 LLMUnavailable
    실패는 예외로 올리지 않고 호출부에서 warnings로 격리(스캔 무중단)."""
```

- 로컬(Ollama)은 `urllib.request`로 `localhost:11434/api/generate` 직접 호출 → **신규 의존성 0**.
- 클라우드 백엔드는 `try: import anthropic` 식 지연 import. 미설치 시 명확한 안내 후 triage 스킵(스캔은 계속).
- 권장 로컬 모델: `qwen2.5-coder:32b`(정확도) / `qwen2.5-coder:7b`(경량). thinking 모드 모델은 깊은 분석용 옵션.

---

## 4. C2 — AI Triage (`platforms/shared/python/security_scanner/ai/triage.py`)

Semgrep Assistant 교훈: **FP 판정과 TP 근거 생성을 별도 프롬프트 체인으로** 분리하고, LLM은 **강등 라벨만** 달되 심각도 원본은 보존한다.

### Finding 모델 비파괴 확장 (`models.py`)
```python
@dataclass(frozen=True)
class Finding:
    ...                              # 기존 필드 불변
    triage_verdict: str = ""         # "" | "likely_true" | "likely_false" | "uncertain"
    triage_confidence: float | None = None   # 0.0~1.0
    triage_note: str = ""            # 한 줄 근거 (사람용)
    reachable: str = ""              # "" | "reachable" | "unreachable" | "unknown" (C3)
    fixable: bool = False            # C4: 결정론적 fix 존재 여부
```
frozen dataclass + 기본값이라 **리포트/SARIF/diff/ignore 모두 무변경으로 호환**(host 로드맵의 `resource` 추가와 동일 방식).

### 두 갈래 프롬프트 체인
```python
def triage_findings(findings, *, code_context, language="en"):
    """배치로 LLM 호출. 반환은 (findings_with_triage, warnings)."""
    # 체인 A (FP 게이트): "이 발견이 오탐일 수 있는 근거만 제시" → likely_false 후보
    # 체인 B (TP 근거):   "진짜라면 악용 경로를 한 줄로"        → likely_true 근거
    # 두 체인 합의 + 신뢰도 → triage_verdict. 의견 충돌 시 uncertain(보수적).
```

### 안전 규칙 (원칙 #3)
- `likely_false`라도 **심각도는 절대 안 내린다.** 라벨·신뢰도만 부여. 강등/숨김은 사용자가 `koda-ignore.yml`로 결정.
- 차단(`--fail-on`) 판정은 **원본 severity 기준** — LLM verdict가 게이트를 바꾸지 못함.
- 코드 컨텍스트는 Copilot Autofix처럼 **발견 주변 스니펫 + 파일 상단 ~10줄**만 전송(전체 파일 X) → 전송 최소화.

### "Memories-lite" (Semgrep Memories의 경량판)
- 사용자가 triage에서 오탐 처리하면 → `koda-ignore.yml`에 `rule`/`path`/`reason`/`until` 자동 제안.
- 다음 스캔부터 동일 패턴 자동 억제. 별도 LLM 학습 없이 **결정론적 규칙으로 codify** → 재현성 보장.

### scanner 훅 (`scanner.py`)
```python
findings = collect_findings(...)            # 기존
if config.enable_ai_triage:                 # 신규, 기본 False
    findings, warns = triage_findings(findings, code_context=ctx,
                                      language=config.report.language)
    report_warnings.extend(warns)
# 이후 기존 리포트 경로 그대로
```

---

## 5. C3 — Reachability (`platforms/shared/python/security_scanner/reachability.py`)

Endor Labs 교훈: 빌드 없이도 가능한 **pre-computed(매니페스트/import 기반)** 부터. KODA는 소스만 읽으므로 여기에 정확히 맞는다.

### 1단계 — import 기반 (stdlib `ast`, 의존성 0)
```python
def imported_packages(target: Path) -> set[str]:
    """Python: ast로 import/from 수집. JS/TS: require()/import 구문 정규식.
    SBOM(dependency_inventory)에 있으나 실제 import 안 한 패키지를 식별."""

def annotate_dependency_reachability(findings, imported):
    """의존성 CVE 발견에 reachable 라벨:
    - 패키지를 import조차 안 함  → reachable="unreachable" (강등 신호)
    - import 있음               → reachable="reachable"
    - 판단 불가(동적 import 등)  → reachable="unknown" (보수적, 강등 안 함)"""
```

### 2단계 — 취약 심볼 호출 여부 (후속, call graph)
- OSV 권고가 명시한 **취약 함수/심볼**을 사용자 코드가 호출하는지까지 확인(Endor의 function-level).
- 빌드/완전 call-graph는 KODA 범위 밖 → **휴리스틱 호출 매칭**으로 근사, 신뢰도 표기.

### 판정 규칙 (결정론적, 원칙 #3)
- `unreachable` → 리포트에 "도달 불가(미사용 의존성)" 배지 + 우선순위 하향. **단 발견 자체는 삭제 안 함**(오탐 역설 방지).
- `--fail-on`에 `--reachable-only` 옵션 추가 시에만 게이트에서 unreachable 제외(명시적 선택).

---

## 6. C4 — Auto-Fix (`platforms/shared/python/security_scanner/fixes/`)

Copilot Autofix 교훈: **결정론적 fix 우선**, 미해결만 LLM 패치, **항상 사람 승인**.

### 모듈 구성
```
fixes/
  __init__.py        # rule_id -> Fixer 레지스트리
  deterministic.py   # AST/정규식 기반 안전 치환
  llm_patch.py       # (opt-in) C1로 패치 제안 — 결정론 fix 없을 때만
  apply.py           # dry-run diff 생성 + 승인 게이트 + 적용/백업
```

### 우선 등록할 결정론적 fix (안전·멱등 위주)
| rule_id (예) | 변환 | 방식 |
|---|---|---|
| `code.unsafe-deserialization.yaml-load` | `yaml.load(x)` → `yaml.safe_load(x)` | AST |
| `code.weak-hash.md5` | `hashlib.md5(` → `hashlib.sha256(` (+검토 주석) | AST |
| `code.request-no-timeout` | `requests.get(...)` → `..., timeout=10)` | AST |
| `configuration.debug-true` | `DEBUG = True` → 환경변수 게이트 | 정규식+주석 |
| `code.csrf-disabled` | 비활성 토글 제거/주석 | 정규식 |

### 적용 흐름 (원칙 #4)
```python
def plan_fixes(findings) -> list[FixProposal]:        # 변경 안 함
    """각 fixable 발견 → unified diff 생성(메모리상)."""

def apply_fixes(proposals, *, approved: bool, target: Path) -> ApplyResult:
    """기본 dry-run: diff만 출력.
    --apply + git working tree clean 검사 통과 시에만 쓰기. 원본 .bak 백업.
    구문 보존 검증(ast.parse 재파싱) 실패 시 해당 fix 롤백."""
```
- CLI: `python -m security_scanner fix --target . [--rule <id>] [--apply]` (기본 dry-run).
- CI(C5) 연계 시 자동 머지 금지 — **별도 제안 커밋/PR**로만.

---

## 7. C5 — CI/CD 네이티브 통합

가장 기반이 탄탄(SARIF·`--fail-on` 보유). 신규 LLM/쓰기 없이 빠른 승리.

### diff-scope (Strix `--scope-mode diff` 대응)
```python
def changed_files(base_ref: str) -> set[Path]:
    """git diff --name-only {base}...HEAD (stdlib subprocess)."""
```
CLI: `scan ... --changed-only --base origin/main` → 변경 파일 + 변경 라인만 발견 필터. 기존 `diffing.py`로 신규/해결 비교.

### 배포형 GitHub Action (`.github/actions/koda/action.yml`)
```yaml
name: KODA Security Scan
inputs:
  target: { default: "." }
  fail-on: { default: "high" }
  changed-only: { default: "true" }
runs:
  using: composite
  steps:
    - run: python -m security_scanner scan --target ${{ inputs.target }}
           --format sarif --output koda.sarif
           --fail-on ${{ inputs.fail-on }}
           ${{ inputs.changed-only == 'true' && '--changed-only --base origin/${{ github.base_ref }}' || '' }}
      shell: bash
    - uses: github/codeql-action/upload-sarif@v3
      with: { sarif_file: koda.sarif }
```
- 사용자 워크플로: `uses: jhny-kor/KODA@v1`.
- PR 인라인 코멘트: SARIF → 신규 발견만 리뷰 코멘트(GitHub API 또는 reviewdog). 기존 `diffing` 재사용해 노이즈 억제.
- AI triage는 CI에서 **기본 OFF**(키 없음·재현성). 켤 경우 verdict는 코멘트 보조 정보로만, 게이트는 결정론 severity.

---

## 8. 검증(Validation) 레이어 — XBOW식 탐색/검증 분리

후처리 파이프라인의 3단계 `validator`는 **결정론적 스크립트**다. LLM/휴리스틱이 "있을 수 있다"고 한 것을 KODA가 **안전하게 확인 가능한 범위에서만** 확정한다.

| 발견 유형 | non-destructive 검증 | 결과 |
|---|---|---|
| 의존성 CVE | C3 reachability + lockfile 정확버전 매칭 | reachable+정확버전 → 확정 / unreachable → 강등 |
| 하드코딩 시크릿 | 엔트로피 + 알려진 prefix(`sk-`, `ghp_`) + 형식 검증 | 형식 일치 → 확정 / 플레이스홀더 패턴 → 강등 |
| 웹 취약점(선택) | 기존 `dast.py` ZAP baseline(권한 URL만) | 응답 확인 → 확정 |

- "실제 익스플로잇 실행"은 KODA 범위 밖. **non-destructive 신호만** 사용(시크릿 형식, 도달성, 버전 매칭).
- 검증 결과는 리포트에 `확정 / 미검증 / 도달불가` 3-state로 표기, VEX `in_triage` 흐름과 연계.

---

## 9. 신규 CLI / Config 표면 (요약)

### CLI
```bash
# C2 AI triage (opt-in)
scan --target . --ai-triage --llm ollama/qwen2.5-coder:32b
# C3 reachability
scan --target . --reachability [--reachable-only]
# C4 auto-fix
fix  --target . [--rule <id>] [--apply]
# C5 CI diff-scope
scan --target . --changed-only --base origin/main --format sarif --fail-on high
```

### ScannerConfig 신규 필드 (`models.py`, 전부 기본 OFF)
```python
enable_ai_triage: bool = False
llm_model: str | None = None          # KODA_LLM 환경변수로도 설정 가능
enable_reachability: bool = False
reachable_only_gate: bool = False
```

---

## 10. 프라이버시·거버넌스 매트릭스

| 기능 | 백엔드 | 외부 전송 | 전송 데이터 | 기본값 |
|---|---|---|---|---|
| 파일/호스트 스캔 | 로컬 | 없음 | — | ON |
| C3 reachability | 로컬(ast) | 없음 | — | OFF |
| C2 AI triage (ollama) | 로컬 | **없음** | — | OFF |
| C2 AI triage (anthropic/openai) | 클라우드 | 있음 | 발견 주변 스니펫 + 파일 상단 ~10줄 | OFF |
| C4 LLM patch (ollama) | 로컬 | 없음 | — | OFF |
| C4 LLM patch (클라우드) | 클라우드 | 있음 | 대상 함수 스니펫 | OFF |
| OSV/KEV/EPSS (기존) | 클라우드 | 있음 | 패키지명+버전 | OFF |

- 클라우드 백엔드 활성 시 첫 실행에서 1회 경고 출력 + `PRIVACY.md`에 항목 추가.
- 로컬(Ollama) 경로를 항상 제공 → "전송 0" 선택지 보장.

---

## 11. 단계별 구현 순서 (테스트 포함)

| 순서 | 범위 | 핵심 테스트 | 의존성 |
|---|---|---|---|
| 1 | C5 diff-scope + Action | changed_files 교집합, SARIF 업로드, 신규발견만 코멘트 | 0 (stdlib) |
| 2 | C1 provider + C2 triage | provider mock(전송0), OFF시 발견불변, FP/TP 체인, severity 보존, warnings 격리 | 0 (local) / extra (cloud) |
| 3 | C3 reachability | import 수집 정확도, unreachable 강등, unknown 보수성, reachable-only 게이트 | 0 (ast) |
| 4 | C4 deterministic fix | 멱등성, dry-run 무변경, 미승인 미적용, 구문 보존, git clean 검사 | 0 |
| 5 | 검증 레이어 + LLM patch | 3-state 표기, non-destructive만, VEX 연계 | C1 |

각 단계는 기존 테스트(현재 87+종) 전부 통과 유지 + 신규 테스트 추가. 모든 신규 기능 OFF 시 기존 출력 바이트 동일.

---

## 12. 참고 자료 (Sources)

- [Strix — Open-source AI hackers](https://github.com/usestrix/strix) — 에이전트 툴킷, `STRIX_LLM`/`LLM_API_BASE` 규약, `--scan-mode`/`--scope-mode diff`/`-n`, Docker 샌드박스, GitHub Action.
- [XBOW — Autonomous Offensive Security Platform](https://xbow.com/platform) — 자율 탐색 + **결정론적 validator** 2-layer, exploitability 확정 후 surfacing.
- [Deterministic + Agentic AI: The Architecture Exposure Validation Requires (The Hacker News)](https://thehackernews.com/2026/04/deterministic-agentic-ai-architecture.html) — pre/post-execution 결정론적 validator 패턴.
- [Endor Labs — Reachability analysis (docs)](https://docs.endorlabs.com/scan/sca/reachability-analysis/) · [Pre-computed Reachability](https://docs.endorlabs.com/scan/sca/reachability-analysis/pre-computed-reachability/) — call graph, 미사용 의존성 강등, 92~97% 노이즈 감소, 빌드 없는 manifest 기반.
- [GitHub Copilot Autofix for CodeQL (docs)](https://docs.github.com/en/code-security/concepts/code-scanning/copilot-autofix-for-code-scanning) · [Found means fixed (GitHub Blog)](https://github.blog/news-insights/product-news/found-means-fixed-introducing-code-scanning-autofix-powered-by-github-copilot-and-codeql/) — SARIF + source/sink 스니펫 + query help → LLM 패치 + 자연어 설명, 자동적용 안 함.
- [Semgrep — Zero false positive SAST with AI-powered memory](https://semgrep.dev/blog/2025/making-zero-false-positive-sast-a-reality-with-ai-powered-memory/) · [Customize Assistant](https://semgrep.dev/docs/semgrep-assistant/customize) — 결정론+LLM, FP/TP 별도 프롬프트 체인, 95% FP 정확도, Memories.
- [Top Ollama models for coding/agents (2026)](https://www.morphllm.com/best-ollama-models) · [Best Open-Source LLM for Cybersecurity 2026](https://www.siliconflow.com/articles/en/best-open-source-LLM-for-Cybersecurity-Threat-Analysis) — Qwen2.5/3-Coder, `localhost:11434`, thinking/non-thinking, 로컬 프라이버시.
- [Inside AWS Security Agent: multi-agent pentesting (AWS)](https://aws.amazon.com/blogs/security/inside-aws-security-agent-a-multi-agent-architecture-for-automated-penetration-testing/) — 결정론적 validator + LLM 검증 이중화.
