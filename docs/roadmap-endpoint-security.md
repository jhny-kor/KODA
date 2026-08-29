# KODA 엔드포인트(호스트) 보안 점검 로드맵

> **문서 상태:** 이 문서는 호스트 점검 기능의 설계·구현 이력입니다. 현재 지원되는
> `host-scan` 명령과 설치·운영 절차는 [CLI 및 로컬 사용법](usage.md)과
> [Linux 설치·운영](install/linux.md)을 기준으로 확인하세요. 아래의 진행 상태와
> 미구현 항목은 기록 시점의 계획 상태입니다.

> 목적: KODA를 "소스코드/레포 스캐너"에서 **설치된 컴퓨터(엔드포인트)의 보안 상태를 점검하는 도구**로 확장한다.
> 상태: 계획(Planning). 이 문서는 추후 구현의 기준 로드맵이다.
> 계획 기록: 2026-06-07 · 현재 구현 정정: 2026-08-07

---

## 0. 현재 KODA 기능 요약 (재사용 가능한 자산)

- 점검 카테고리: `secrets`, `dependencies`, `configuration`, `code`, `prevention` (모두 **파일 단위** `check_file(path)` 실행, `prevention`만 `check_project` 보유).
- 취약점 인텔리전스: OSV.dev 조회(`osv_vulnerabilities.query_osv_findings`) + CISA KEV + FIRST EPSS 우선순위(`vuln_intel`).
- 의존성 인벤토리: requirements/poetry/Pipfile/package-lock/yarn/pnpm 등 파싱(`dependency_inventory`).
- 리포트: Markdown / JSON / SARIF / CycloneDX(SBOM·VEX) (`reporting`, `sbom`, `vex`).
- 표준 매핑: OWASP Top 10, CWE Top 25, ISMS-P 2.8, 행안부/KISA, NIST SSDF/CSF 2.0, OWASP ASVS/WSTG/MASVS/LLM/SCVS, CISA KEV/EPSS·Secure by Design, SLSA/Sigstore 등(`standards.py`).
- 운영: 대시보드/서버(`server`, `app`), 점수 이력·리포트 diff(`diffing`), 예외 거버넌스(`ignore`, `koda-ignore.yml`), 증거 레지스터(`evidence`), 릴리스 패키지(`release`).
- 가벼운 DAST: OWASP ZAP baseline 실행(`dast`).
- 배포: macOS 네이티브(Swift, MAS) + Windows(WebView2 단일창 + 브라우저 폴백), 양쪽 모두 Python 런타임 동봉.

---

## 1. 이번 확장 범위 (A · B · C · E)

설치된 컴퓨터의 보안 상태(posture)를 읽어 점검·리포트·표준 매핑한다. 기본은 **읽기 전용·로컬 전용**.

### A. 시스템 무결성 & 부팅 보안
| 항목 | macOS 수집원 | Windows 수집원 |
|---|---|---|
| 디스크 암호화 | FileVault (`fdesetup status`) | BitLocker (`Get-BitLockerVolume`) |
| 시큐어 부트 | `system_profiler`, Startup Security | UEFI Secure Boot (`Confirm-SecureBootUEFI`) |
| 시스템 무결성 보호 | SIP (`csrutil status`) | Core Isolation / HVCI (레지스트리) |
| 하드웨어 신뢰 루트 | Secure Enclave 유무 | TPM 2.0 (`Get-Tpm`) |
| 자격증명 보호 | — | Credential Guard / Device Guard |
| 코드 서명 강제 | Gatekeeper (`spctl --status`), 공증 | SmartScreen, AppLocker/WDAC |

### B. 패치 & 소프트웨어 최신성
- OS 버전·빌드 + **EOL(지원종료) 판정** (endoflife.date 데이터셋).
- 미설치 보안 업데이트(`softwareupdate -l` / Windows Update API), 자동 업데이트 설정.
- **설치 앱 인벤토리 수집 → CVE 매핑** (macOS `system_profiler SPApplicationsDataType`, Windows 레지스트리 Uninstall 키 + winget).
- 브라우저 및 확장프로그램 버전/취약 확장.

### C. 네트워크 노출면
- 방화벽 상태 (macOS `socketfilterfw`/pf, Windows Defender Firewall 3개 프로파일).
- 열린 리스닝 포트·외부 바인딩 서비스 (`lsof -i` / `Get-NetTCPConnection`).
- 원격 접속 서비스: SSH(Remote Login), 화면공유/RDP, 파일공유(SMB/AFP).
- Wi-Fi 보안(개방형 경고), DNS·프록시·hosts 변조 탐지.

### E. 멀웨어/위협 방어 상태
- macOS: XProtect·MRT 시그니처 최신성, Gatekeeper.
- Windows: Defender 실시간 보호·시그니처 날짜·Tamper Protection, Security Center AV 등록 상태(`Get-MpComputerStatus`, WMI `SecurityCenter2`).
- 알려진 악성 persistence 휴리스틱(추후 F 카테고리와 연계).

---

## 2. 기존 기능의 부족분 (Gap Analysis)

A/B/C/E를 붙이기 전에 메워야 할 구조적 공백.

### G1. 호스트 점검용 실행 경로 부재 — **필수 선결**
- 현재 `CHECKS`는 전부 파일 반복(`check_file(path)`) 기반. 호스트 점검은 파일이 아니라 OS 상태 조회라 **파일 루프 밖에서 1회 실행되는 "system check" 경로**가 없음.
- 대응: `scanner.py`에 호스트 점검 단계 추가(파일 스캔 전/후 1회). `prevention.check_project` 패턴 참고.

### G2. `Finding` 모델이 파일/라인 전제 — **모델 보강**
- `Finding`은 `path: Path`, `line: int|None` 필수 지향. 호스트 발견은 파일·라인이 없음.
- 대응: 호스트 발견에 합성 경로(예: `host://firewall`) 또는 `resource`/`scope` 필드 추가. 리포트·SARIF·diff·ignore가 `path` 키에 의존하는지 점검 필요(`reporting`, `diffing`, `ignore`).

### G3. OS 명령 실행 계층 부재 — **공용 유틸 필요**
- `dast.py`만 `subprocess` 사용. 호스트 점검은 다수 OS 명령을 안전하게(타임아웃·실패 격리·권한 구분) 호출해야 함.
- 대응: `host/runner.py` 공용 커맨드 러너(allowlist 기반, stdout 파싱, 권한 필요 항목 표시).

### G4. 데스크톱 앱 CVE 매핑 수단 부재 — **B의 핵심 공백**
- OSV는 ecosystem(PyPI/npm/…) 기반이라 "설치된 .app / .exe"에 직접 매핑 불가. 데스크톱 앱은 **CPE 기반 NVD/Vulners 조회**가 필요.
- 대응: `cpe_lookup` 모듈 신설(앱명·버전→CPE 추정→NVD 조회) 또는 EOL 판정 우선 도입. 기존 KEV/EPSS 우선순위 로직(`vuln_intel`)은 CVE만 확보되면 재사용 가능.

### G5. CIS Benchmark 표준 미보유 — **컴플라이언스 격상 공백**
- `standards.py`에 엔드포인트 표준(CIS macOS/Windows Benchmark)이 없음. 호스트 점검 결과를 매핑할 권위 있는 기준이 비어 있음.
- 대응: `CIS_MACOS_BENCHMARK`, `CIS_WINDOWS_BENCHMARK`(Level 1/2) 프로파일 추가. ISMS-P 단말 보호·NIST CSF는 일부 재사용 가능.

### G6. 권한·프라이버시 거버넌스 공백 — **정책**
- 현재는 읽기 전용 파일 스캔. 호스트 점검 일부는 관리자 권한이 필요하고, 설치 앱/권한 목록은 프라이버시 민감.
- 대응: 비-admin 기본, admin 필요 항목 명시·선택적 상승. 결과 로컬 전용 원칙 유지(PRIVACY.md 갱신). CVE/CPE 조회 시 전송 데이터 명시.

### G7. 플랫폼 분기 부재
- 기존 점검은 OS 무관. 호스트 점검은 macOS/Windows 분기 필수(Linux는 후순위).
- 대응: `host/host_macos.py`, `host/host_windows.py`, 공용 `host/common.py`. 미지원 OS는 graceful skip.

---

## 3. 아키텍처 설계 (제안)

```
platforms/shared/python/security_scanner/
  checks/
    host/
      __init__.py        # register host checks, OS 분기
      runner.py          # 안전한 OS 명령 러너 (allowlist, timeout, 권한구분)
      common.py          # HostFinding→Finding 변환, 공용 파서
      host_macos.py      # A/C/E + B(수집) macOS 구현
      host_windows.py    # A/C/E + B(수집) Windows 구현
  cpe_lookup.py          # (B) 앱명/버전 → CPE → NVD CVE (신규)
  eol_data.py            # (B) OS/앱 EOL 판정 (endoflife.date)
```

- 새 카테고리: `host`(또는 `endpoint`)를 `models.CATEGORIES`에 추가.
- 새 CLI: `python -m security_scanner host-scan [--include A,B,C,E] [--allow-admin]`.
- 대시보드: 기존 카테고리 탭에 `host` 결과 통합, CIS Benchmark 표준 선택 추가.
- 출력: 기존 Markdown/JSON/SARIF/HTML + 증거·예외·diff 재사용.

---

## 4. 단계별 실행 계획 (우선순위 ROI순)

### Phase 0 — 기반 (G1·G2·G3·G7 해소) — ✅ 완료 (2026-06-07)
- [x] `checks/host/runner.py` 안전 명령 러너 (allowlist·timeout·실패 격리).
- [x] `Finding`에 `resource` 필드 추가 + `host_finding()`가 `path`에 미러링 → 리포트/SARIF/diff/ignore 호환.
- [x] `models`에 보안 기본 카테고리/파일 카테고리/호스트 카테고리 분리 → `host`와 `screen_quality`는 **opt-in**(보안 기본 스캔 불변). `scanner._scan_host()` 1회 실행 경로.
- [x] OS 분기(`checks/host/__init__.py` 디스패처) + 미지원 OS graceful skip(경고만).
- [x] CLI `host-scan` 명령 + 서버/대시보드 기본값을 `DEFAULT_CATEGORIES`로 (host 미포함).
- [x] 테스트 9종 추가(allowlist 우회 차단, 미지원 OS, 프로브 실패 격리, opt-in 보장 등) — 전체 73 테스트 통과.
- [x] macOS 참조 체크 4종 동작 확인: SIP·FileVault·Gatekeeper(A) + Application Firewall(C).

사용: `python3 -m security_scanner host-scan --language ko --min-severity info [--format markdown|json|sarif|html]`

### Phase 1 — A·C·E 핵심 posture (CIS L1 매핑) — 🟡 진행 (2026-06-07)
- [x] A(macOS): FileVault, SIP, Gatekeeper. A(Windows): BitLocker, Secure Boot — **Windows 미검증**.
- [x] C(macOS): Application Firewall, 방화벽 스텔스 모드. C(Windows): 방화벽 프로파일 — **Windows 미검증**.
- [x] E(macOS): 자동 보안 응답/시스템 파일 설치(ConfigDataInstall+CriticalUpdateInstall). E(Windows): Defender 실시간 보호 — **Windows 미검증**.
- [x] G5: `CIS_MACOS_BENCHMARK` / `CIS_WINDOWS_BENCHMARK` 표준 추가 + 매핑 + 등록(SECURITY_STANDARDS, external coverage). 대시보드에서 CIS 표준 선택 시 host 점검 자동 실행·rule_id 필터 확인.
- [x] 테스트 4종 추가(스텔스 off, 보안업데이트 양키 요구, CIS 등록/해석, CIS rule_id 필터) — 전체 77 테스트 통과.
- [ ] **Windows 실측 검증** → `docs/windows-host-verification.md` 참조 (별도 트랙).
- [ ] (후속) macOS XProtect 시그니처 최신성, 리스닝 포트/원격접속(SSH·화면공유) — admin/정확도 이슈로 후순위.

공통 Python 엔진의 macOS `host-scan`은 현재 9개 항목을 점검합니다: 기존
6개(SIP·FileVault·Gatekeeper, Application Firewall·Stealth, Auto Security
Updates)에 자동 로그인·게스트 계정·화면 잠금이 추가되었습니다. Windows
`host-scan`은 BitLocker·Defender·Secure Boot·방화벽 프로파일·자동 로그인·게스트
계정·화면 잠금 7개 프로브를 구현했지만 실제 Windows 장치 검증은 완료되지
않았습니다.

### Phase 2 — B 소프트웨어 최신성 — 🟡 진행 (2026-06-07)
- [x] 설치 앱 인벤토리 수집 `inventory.py` (macOS `system_profiler -json`, Windows 레지스트리 Uninstall). 오프라인, 386개 수집 확인.
- [x] OS EOL 판정 `eol_data.py` (endoflife.date, opt-in 네트워크). macOS 26 지원중 실시간 확인.
- [x] `cpe_lookup.py` → NVD CVE 키워드+버전범위 매칭(opt-in, rate-limit 보수적, 오탐 가능 표기). CVSS→심각도 매핑.
- [x] host 통합 `checks/host/inventory_checks.py` (인벤토리 요약/OS EOL/앱 CVE 발견) + `HostScanOptions` 옵션 게이팅.
- [x] CLI 플래그: `--inventory`, `--eol`, `--check-cve`, `--nvd-api-key-env`. `ScannerConfig`에 host 옵션 추가.
- [x] 테스트 10종 추가(인벤토리 파싱·미지원OS, EOL 날짜 로직 3종, CPE 버전매칭 3종, OS EOL 발견, 대시보드 토글) — 전체 87 통과.
- [ ] (후속·G4) NVD CVE를 기존 `vuln_intel`(KEV/EPSS)로 추가 enrich — 현재는 CVSS 기반. CVE→KEV/EPSS 연결은 다음 단계.
- [ ] (후속) 미설치 보안 업데이트 목록(`softwareupdate -l` / Windows Update).
- [ ] **Windows 인벤토리/CVE 실측 검증** → `docs/windows-host-verification.md`.

주의: NVD는 익명 5req/30s 제한 → `--check-cve`는 버전 있는 앱 최대 20개로 제한, `--nvd-api-key-env`로 키 사용 권장. 키워드 매칭 특성상 오탐 가능(발견에 검증 권고 문구 포함).

### macOS — Swift 네이티브 앱에 host posture 추가 — ✅ (2026-06-07)
> 방침: macOS는 **Swift 네이티브 KODA 앱**(`platforms/macos/app/KODA`)으로 구동된다. host posture는 별도 Python 앱/창이 아니라 **기존 Swift 앱의 네이티브 스캐너에 직접 추가**한다. PyInstaller/pywebview 방향은 폐기(되돌림).
- [x] `NativeSecurityScanner.swift`에 `scanHost()` + 읽기전용 `Process` 러너 추가. 비샌드박스 실행은 macOS 점검 9종(기존 6종 + 자동 로그인·게스트 계정·화면 잠금)을 엄격한 성공 출력만으로 판정합니다. 제한된 실행 권한에서는 시스템 명령 오류를 OFF/활성으로 오인하지 않고 9개 항목을 `미확인`으로 반환합니다.
- [x] `category="host"` 라벨(ko/en) 추가 — 기존 리포트(HTML/MD/PDF/점수)에 그대로 통합.
- [x] `ScannerBridge.swift`: `runHostScan(language:)` + `runHostScanCommand()` — 기존 리포트/점수 스냅샷 파이프라인 재사용(타깃 선택 불필요).
- [x] `ContentView.swift`: 메뉴에 "이 컴퓨터 점검 (호스트 보안)" 버튼 추가(OSV 조회 옆). `AppLanguage.runHostScanTitle`(ko/en).
- [x] 절대경로 사용(`/usr/bin/csrutil`,`/usr/bin/fdesetup`,`/usr/sbin/spctl`,`/usr/libexec/ApplicationFirewall/socketfilterfw`,`/usr/bin/defaults`).
- [x] 2026-08-09 Release 빌드·Apple Development 서명·`/Applications/KODA.app` 설치·실행 및 deep codesign 검증 완료.
- 주의(후속): KODA.entitlements는 제한된 실행 권한을 사용합니다. 시스템 상태를 자동 확정할 수 없는 경우 `미확인`과 설정 조치 경로를 제공합니다. 앱 내부에서 실제 값을 자동 확정하려면 별도의 권한 있는 helper/XPC 경로가 필요합니다.

### macOS PyInstaller 레인 — 참고만(host posture는 Swift로 이관)
- PyInstaller 레인(`build-koda-app.command`)은 레거시 실험용. `--collect-submodules security_scanner`만 유지(지연 임포트 모듈 번들). 엔트리포인트는 원복(`sec-chk-app.py`).

### Dashboard UI — 🟡 진행 (2026-06-07)
- [x] host 카테고리 라벨(en/ko), JSON `resource` 노출(Phase 0/1).
- [x] CIS macOS/Windows 벤치마크가 표준 드롭다운에 노출 + 선택 시 host 점검 자동 실행(Phase 1).
- [x] **"이 컴퓨터 점검 (호스트 보안 상태)" 체크박스** 추가 — 표준과 무관하게 host posture 포함. 서버 `include_host` 파라미터로 처리, 표준 rule_id 필터에서도 host 발견 보존.
- [ ] (후속) host 결과 전용 시각 섹션/패스 항목 강조, 대시보드에서 인벤토리/EOL/CVE 토글 노출.

### Phase 3 — 거버넌스·UX 완성
- [ ] G6: 권한·프라이버시 정책 반영, PRIVACY.md 갱신, admin 항목 표시.
- [ ] 원클릭 교정 안내(FileVault 켜기, 방화벽 활성화 등) — 기존 remediation/auto-fix 패턴.
- [ ] CIS Level 2 항목 확장.

### Phase 4 — 동적/지속 점검 (별도 로드맵과 연계)
- [ ] 상주 데몬 주기 재점검 + 점수 이력·diff로 **posture 드리프트** 감지·알림.
- [ ] 베이스라인 스냅샷 저장 후 변경분 보고.
- [ ] F(persistence)·G(홈 디렉터리 secrets)·H/I 항목으로 범위 확대.

---

## 5. 향후 확장 후보 (이번 범위 외, 참고)
- D. 계정·권한(자동로그인, admin 계정, 비밀번호/잠금 정책).
- F. 지속성(시작 프로그램, LaunchAgents/서비스, 예약 작업).
- G. 디스크 상 자격증명(홈 디렉터리 secrets 확장, passphrase 없는 SSH 키).
- H. 로깅·감사·백업·시간 동기화.
- I. 프라이버시 권한(macOS TCC: 카메라/마이크/전체 디스크 접근).

---

## 6. 위험·주의
- 일부 항목은 관리자 권한 필요 → 기본 비-admin, 선택적 상승.
- 설치 앱/권한 목록은 프라이버시 민감 정보 → 로컬 전용, 외부 전송 항목 명시.
- CPE→CVE 매핑은 오탐 가능 → 신뢰도 표기 및 예외 거버넌스 적용.
- macOS MAS 샌드박스 제약으로 네이티브 앱에서 일부 시스템 조회 제한 가능 → Python 런타임 경로 병행 검토.
