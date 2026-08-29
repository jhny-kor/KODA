# KODA AI 증강 · 자동 교정 · CI/CD 로드맵 (Strix 벤치마킹)

> 목적: 오픈소스 자율 AI 펜테스트 도구 [Strix](https://github.com/usestrix/strix)의 강점을 분석하고,
> **KODA의 "오프라인·읽기 전용·프라이버시·컴플라이언스" 정체성을 깨지 않으면서** 흡수할 4대 발전 축을 정의한다.
> 상태: 계획(Planning). 이 문서는 추후 구현의 기준 로드맵이다(무엇을·왜·우선순위).
> 구현 명세(어떻게·코드 스켈레톤·CLI/Config·프롬프트 체인): [spec-beyond-static-scanner.md](spec-beyond-static-scanner.md)
> 최종 갱신: 2026-06-14

> **문서 상태:** 이 문서는 구현 전 기획과 의사결정 이력입니다. 현재는 AI triage,
> reachability, 자동 교정, changed-file CI action이 구현되어 있습니다. 현재 사용법은
> [CLI 및 로컬 사용법](usage.md)을, 구현 세부는
> [구현 명세](spec-beyond-static-scanner.md)를 기준으로 확인하세요. 아래의 미구현
> 표현과 체크박스는 당시 계획 상태를 보존한 것입니다.

---

## 0. 두 도구의 성격 차이 (벤치마킹 근거)

| 축 | KODA (현재) | Strix |
|---|---|---|
| 탐지 방식 | 정적 **휴리스틱/패턴 매칭** (AI 추론 레이어 없음) | 자율 **AI 멀티에이전트** ("Graph of Agents") |
| 검증 | 없음 → 오탐 가능 (룰에 "검증 권고" 문구로 회피) | **실제 익스플로잇 PoC로 검증** → 오탐 최소화 |
| 실행 모델 | **읽기 전용·오프라인 우선·로컬 전용** | 동적 실행 (HTTP 프록시·브라우저·터미널·Python 런타임) |
| 교정 | 가이드 **문서 생성**만 (auto-fix = 가드레일 파일 생성 수준) | **1-click auto-fix PR** |
| 강점 | 표준 매핑(KISA·ISMS-P·전자금융·NIST·CIS), 거버넌스 산출물, 한국 시장 | 공격 시뮬레이션 깊이, 개발자 워크플로 통합 |
| 전제 | API 키 불필요, 데이터 외부 전송 없음 | **클라우드 LLM 필수** (코드를 외부로 전송) |

### 핵심 방침
Strix를 그대로 복제하지 않는다. Strix는 ① 코드를 클라우드 LLM으로 보내고 ② 실제 공격을 실행하는데, 이는 KODA의
오프라인·프라이버시·읽기전용 DNA와 정면충돌한다. 따라서 모든 확장은 **opt-in(기본 OFF)** 으로 설계하고,
외부 전송이 발생하는 항목은 `PRIVACY.md`에 명시한다. 이는 기존 `enable_osv` / `enable_vuln_intel` /
`enable_host_*` 옵션이 따른 패턴과 동일하다.

---

## 0-1. 현재 KODA 기능 요약 (재사용 가능한 자산)

- 점검 카테고리: `secrets`, `dependencies`, `configuration`, `code`, `prevention`, `host`
  (`models.FILE_CATEGORIES`/`HOST_CATEGORIES`). 파일 단위 `check_file(path)` + `prevention.check_project` + `host` 1회 실행.
- **opt-in 외부 조회 패턴**: `enable_osv`/`enable_vuln_intel`/`enable_host_*`이 모두 `ScannerConfig`에서 기본 `False`
  (`models.py`, `config.py`). 네트워크 호출은 `vuln_intel.query_vulnerability_intel`처럼 **타임아웃·예외 격리·warnings 누적** 패턴.
- 발견 모델: `Finding`(rule_id, category, severity, path, line, evidence, recommendation, resource) — `models.py`.
- 리포트: Markdown / JSON / **SARIF 2.1.0** / CycloneDX(SBOM·VEX) — `reporting.py`, `sbom.py`, `vex.py`. 조치 가이드(remediation) 카드 구조 보유.
- 운영: 대시보드/서버(`server`, `app`), 점수 이력·리포트 diff(`diffing`), 예외 거버넌스(`ignore`, `koda-ignore.yml`),
  증거 레지스터(`evidence`), 릴리스 패키지(`release`).
- 가벼운 DAST: OWASP ZAP baseline 실행(`dast.py`, subprocess 사용).
- CI 기반: `--fail-on <severity>` 비-제로 종료 코드, SARIF 출력 → GitHub Code Scanning 업로드 가능.
- 배포: macOS 네이티브(Swift, MAS) + Windows(WebView2 단일창).

---

## 1. 이번 확장 범위 (4대 축)

| 축 | 이름 | Strix 대응 역량 | ROI | 정체성 충돌 위험 |
|---|---|---|---|---|
| **④** | CI/CD 네이티브 통합 | CI/CD 게이트, PR diff-scope, 인라인 코멘트 | ★★★ (빠른승리) | 낮음 |
| **①** | AI triage 레이어 | AI 추론·오탐 검증 | ★★★ (차별화) | 중간(opt-in으로 해소) |
| **②** | 자동 교정(Auto-Fix) | 1-click fix PR | ★★ | 중간(읽기전용 기본 유지) |
| **③** | 검증(Validation) 레이어 | PoC 검증·reachability | ★ | 높음(범위 제한 필요) |

권장 순서: **④ → ① → ② → ③** (탄탄한 기반부터, 충돌 위험 낮은 순).

---

## 2. 부족분 (Gap Analysis)

### G1. AI 추론 주입 지점 부재 — ① 선결
- 현재 발견은 룰이 만든 정적 `Finding`이 그대로 리포트로 감. **발견 후 재평가(re-triage) 훅이 없음.**
- 대응: `scanner.py`의 발견 수집 직후, 리포트 직전에 **선택적 후처리 파이프라인**(`ai_triage`) 삽입.
  `vuln_intel`이 CVE를 enrich하듯 `Finding`에 `triage` 메타(신뢰도·오탐여부·근거)를 덧붙인다.

### G2. LLM 추상화 계층 부재 — ① 핵심
- KODA에는 LLM 클라이언트가 전혀 없음(코드 내 `anthropic`/`openai` 매칭은 전부 **탐지 룰 문자열**이지 호출 아님 — 확인함).
- 대응: `ai/provider.py` 단일 인터페이스(`complete(prompt) -> text`) + 백엔드 3종:
  `local`(Ollama, 전송 0), `anthropic`, `openai`. 키는 환경변수(`*_API_KEY`)만 사용, 코드에 저장 금지.
  네트워크 백엔드는 `enable_ai_triage` + 명시적 provider 선택 시에만 활성.

### G3. 결정론적 fix 매핑 부재 — ② 핵심
- 룰은 발견만 하고 **고치는 변환 규칙이 없음.** `recommendation`은 사람이 읽는 텍스트.
- 대응: 룰 ID → fix 변환기 레지스트리(`fixes/`). 안전하게 자동화 가능한 것만 등록
  (예: `yaml.load`→`yaml.safe_load`, `hashlib.md5`→`sha256`, requests `timeout=` 추가, `DEBUG=True`→환경변수).
  나머지는 "수동 권고"로 남김.

### G4. 안전한 쓰기/승인 게이트 부재 — ② 정체성 보호
- KODA는 읽기 전용이 기본(prevention 가드레일만 예외적 쓰기). auto-fix는 소스 코드를 수정하므로 **명시적 게이트 필수.**
- 대응: `--fix`는 항상 **dry-run diff 먼저 출력 → 사용자 승인 → 적용**. `koda-ignore.yml` 거버넌스와 동일 철학.
  적용 전 원본 백업 또는 git working tree 깨끗함 검사.

### G5. PR diff-scope 부재 — ④
- 현재 스캔은 폴더 전체. CI에서 매 PR 전체 스캔은 노이즈·느림.
- 대응: `--changed-only --base <ref>`로 `git diff --name-only` 결과만 스캔. 변경 라인 기준 발견 필터.

### G6. 배포형 GitHub Action 부재 — ④
- `init-security`가 워크플로 yml을 **생성**하지만, 마켓플레이스 재사용 액션(`uses: jhny-kor/koda-action@v1`)은 없음.
- 대응: `action.yml`(composite) + SARIF 업로드 + PR 인라인 코멘트 게시(`reviewdog` 또는 GitHub API) 레인.

### G7. reachability/검증 데이터 부재 — ③
- 의존성 CVE는 "설치됨" 기준이지 "실제 사용됨" 기준이 아님 → SBOM에 있으나 import 안 하는 패키지도 동일 취급.
- 대응: import/호출 그래프로 **도달 가능성** 표기(사용 안 함 → 심각도 강등). `dast.py`는 인증 세션(grey-box) 옵션으로 확장.

---

## 3. 아키텍처 설계 (제안)

```
platforms/shared/python/security_scanner/
  ai/
    __init__.py
    provider.py        # (①) LLM 추상화: local(Ollama)/anthropic/openai, 키=env only
    triage.py          # (①) Finding 후처리: 오탐분류·신뢰도·컨텍스트 추가탐지
  fixes/
    __init__.py        # (②) rule_id -> fix 변환기 레지스트리
    deterministic.py   # (②) 안전한 결정론적 치환 (yaml.safe_load, sha256, timeout ...)
    apply.py           # (②) dry-run diff 생성 + 승인 게이트 + 적용/백업
  reachability.py      # (③) import/호출 그래프 기반 도달 가능성 (강등 신호)
.github/
  actions/koda/action.yml  # (④) 배포형 composite action
```

- `Finding`에 선택 필드 추가: `triage_confidence: float|None`, `triage_note: str`, `fixable: bool`.
  (호스트 로드맵이 `resource` 필드를 추가한 것과 동일한 비파괴 확장 방식.)
- 새 CLI:
  - `scan ... --ai-triage --ai-provider local|anthropic|openai` (①)
  - `fix --target . [--rule <id>] [--apply]` (기본 dry-run) (②)
  - `scan ... --changed-only --base origin/main` (④, G5)
- `ScannerConfig` 신규 opt-in 플래그: `enable_ai_triage`, `ai_provider`, `ai_base_url`(로컬), `enable_reachability`.
- 출력: 기존 Markdown/JSON/SARIF/HTML + triage·fix·reachability 메타를 리포트/diff/예외에 그대로 흘려보냄.

---

## 4. 단계별 실행 계획 (ROI순)

### Phase 0 — ④ CI/CD 네이티브 통합 (빠른 승리) — ☐
가장 기반이 탄탄(SARIF·`--fail-on` 보유). 신규 LLM/쓰기 없음 → 정체성 충돌 0.
- [ ] G5: `--changed-only --base <ref>` — `git diff --name-only` 교집합만 스캔 + 변경 라인 발견 필터.
- [ ] G6: `.github/actions/koda/action.yml` composite 액션(setup → scan → SARIF). README에 `uses:` 예시.
- [ ] PR 인라인 코멘트: SARIF→리뷰 코멘트(GitHub API 또는 reviewdog). 신규 발견만 코멘트(기존 `diffing` 재사용).
- [ ] 문서: `docs/ci-integration.md` + `init-security` 워크플로 템플릿을 배포형 액션 호출로 갱신.
- 검증: 본 저장소(`.github/`)에서 셀프 도그푸드 → PR에 KODA 발견 코멘트 노출 확인.

### Phase 1 — ① AI triage 레이어 (차별화 핵심) — ☐
오탐 제거 = 사용자 체감 가치 최대. **기본 OFF, opt-in.**
- [ ] G2: `ai/provider.py` — `complete(prompt)` 단일 인터페이스 + `local`(Ollama `http://localhost:11434`)/`anthropic`/`openai`.
      키는 env(`ANTHROPIC_API_KEY` 등)만. 타임아웃·예외 격리·warnings(`vuln_intel` 패턴 복제).
- [ ] G1: `ai/triage.py` — 발견 배치를 LLM에 보내 ㉠오탐 분류 ㉡신뢰도(0~1) ㉢근거 한 줄. `Finding.triage_*`에 기록.
- [ ] `scanner.py` 후처리 훅: 발견 수집 후·리포트 전 1회. OFF면 무동작(기존 경로 불변).
- [ ] CLI `--ai-triage --ai-provider ...` + `ScannerConfig.enable_ai_triage`. 대시보드 "AI 검증" 토글 + 신뢰도 뱃지.
- [ ] **프라이버시**: 네트워크 백엔드 사용 시 "코드 일부가 <provider>로 전송됨" 경고 + `PRIVACY.md` 갱신. 로컬 백엔드=전송 0 명시.
- [ ] 한국어 조치 가이드: triage 통과 시 `recommendation`을 LLM이 컨텍스트 맞춰 재작성(옵션).
- [ ] 테스트: provider mock(네트워크 0), OFF 시 발견 불변, 신뢰도 임계값 필터, warnings 격리.

### Phase 2 — ② 자동 교정(Auto-Fix) — ☐
실제 코드 수정. **읽기전용 기본 유지, 명시적 `--fix` + diff 승인.**
- [ ] G3: `fixes/deterministic.py` — rule_id별 안전 치환 5~10종 우선(역직렬화·약한해시·timeout·debug flag·CSRF off).
- [ ] G4: `fixes/apply.py` — 기본 dry-run **unified diff** 출력 → `--apply` + 승인 시에만 쓰기. git clean 검사·백업.
- [ ] CLI `fix --target . [--rule <id>] [--apply]`. `--fix`를 `scan`에 붙이면 스캔→fix 제안 연계.
- [ ] (①ON일 때) 패턴 미적용 케이스는 LLM이 패치 제안 → 동일 diff 승인 게이트 통과.
- [ ] ④ 연계: CI에서 fix를 **별도 PR/제안 커밋**으로(자동 머지 금지).
- [ ] 테스트: 각 fix 멱등성, dry-run이 파일 미변경, 승인 없을 때 미적용, 구문 보존.

### Phase 3 — ③ 검증(Validation) 레이어 — ☐
정확도 보강. 범위 제한(전체 익스플로잇 X).
- [ ] G7: `reachability.py` — Python/JS import·호출 그래프로 "사용 안 함" 의존성 CVE 강등 신호.
- [ ] `dast.py` 확장: 인증 세션(grey-box) 헤더/쿠키 주입 옵션. "권한 있는 시스템만" 경고 유지.
- [ ] 리포트에 "검증됨/미검증/도달불가" 상태 표기. VEX `in_triage` 흐름과 연계.

---

## 5. 향후 확장 후보 (이번 범위 외, 참고)

- 멀티에이전트 오케스트레이션(Strix "Graph of Agents")은 KODA의 단일 패스 모델과 거리가 멀어 후순위.
- 브라우저 자동화 기반 클라이언트 사이드(DOM XSS) 동적 탐지 — 무거운 런타임 의존.
- 조직 단위 대시보드(여러 호스트/레포 집계) — 현재 로컬 전용 정체성과 별도 트랙.
- 자동 PoC 생성 — 안전·법적 경계가 커서 "권한 있는 대상 + 명시 동의" 게이트 필수.

---

## 6. 위험·주의

- **프라이버시(최우선)**: AI/검증 백엔드 중 네트워크형은 코드를 외부로 보냄 → 기본 OFF, 사용 시 명시 경고 + `PRIVACY.md`.
  로컬(Ollama) 경로를 1급 시민으로 두어 "전송 0" 옵션을 항상 제공.
- **읽기전용 원칙**: auto-fix는 KODA에서 가장 침습적 기능 → dry-run 기본 + 승인 게이트 + git clean 검사 없이는 적용 금지.
- **LLM 비결정성**: triage·fix 제안은 비결정적 → 신뢰도 표기·사람 승인 전제. CI 게이트의 **차단 판정은 결정론적 룰만** 사용(LLM은 보조).
- **오탐 역설**: AI triage가 진짜 취약점을 오탐으로 강등할 위험 → 강등은 "참고"로, 심각도 자체는 보존하고 라벨만 부여.
- **공급망**: 네트워크 LLM SDK 추가는 KODA 자체 SBOM/의존성을 늘림 → 로컬 우선, SDK는 선택적 extra로 격리(`pip install koda[ai]`).
- **법적 경계**: ③의 DAST/PoC는 "소유·허가 시스템만" — 기존 ZAP 경고 문구 패턴 재사용.
