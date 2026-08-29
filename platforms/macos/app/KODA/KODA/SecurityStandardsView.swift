import SwiftUI

/// A categorized group of prevention-kit feature descriptions for the help panel.
struct PreventionKitGroup: Identifiable {
    let id = UUID()
    let title: String
    let items: [String]
}

enum AppLanguage: String, Hashable, Sendable {
    case ko
    case en

    var backTitle: String {
        switch self {
        case .ko: return "목록"
        case .en: return "Back"
        }
    }

    var helpTitle: String {
        switch self {
        case .ko: return "도움말"
        case .en: return "Help"
        }
    }

    var remediationGuideTitle: String {
        switch self {
        case .ko: return "조치 가이드"
        case .en: return "Remediation Guide"
        }
    }

    var findingsTitle: String {
        switch self {
        case .ko: return "발견 항목"
        case .en: return "Findings"
        }
    }

    var riskScoreTitle: String {
        switch self {
        case .ko: return "위험 점수"
        case .en: return "Risk Score"
        }
    }

    var scopeTitle: String {
        switch self {
        case .ko: return "점검 범위"
        case .en: return "Scope"
        }
    }

    var automationTitle: String {
        switch self {
        case .ko: return "자동화 수준"
        case .en: return "Automation"
        }
    }

    var publicationTitle: String {
        switch self {
        case .ko: return "발행기관 / 판본"
        case .en: return "Issuer / Release"
        }
    }

    var criteriaTitle: String {
        switch self {
        case .ko: return "점검 기준"
        case .en: return "Criteria"
        }
    }

    var referenceTitle: String {
        switch self {
        case .ko: return "공식 웹사이트"
        case .en: return "Official Sites"
        }
    }

    var riskFormulaTitle: String {
        switch self {
        case .ko: return "위험점수 계산"
        case .en: return "Risk Score Formula"
        }
    }

    var riskFormulaDescription: String {
        switch self {
        case .ko: return "위험 점수는 치명 100점, 높음 40점, 중간 10점, 낮음 3점, 정보 1점을 발견 항목별로 더한 값입니다."
        case .en: return "Risk score is the sum of each finding: critical 100, high 40, medium 10, low 3, and info 1."
        }
    }

    var severityDistributionTitle: String {
        switch self {
        case .ko: return "위험군별 분포"
        case .en: return "Severity Distribution"
        }
    }

    var checkedItemsTitle: String {
        switch self {
        case .ko: return "이 기준에서 확인하는 항목"
        case .en: return "Checks Covered By This Standard"
        }
    }

    var checkMethodTitle: String {
        switch self {
        case .ko: return "점검 방식"
        case .en: return "Check Method"
        }
    }

    var detailedChecksTitle: String {
        switch self {
        case .ko: return "세부 확인 항목"
        case .en: return "Detailed Checks"
        }
    }

    var evidenceSourceTitle: String {
        switch self {
        case .ko: return "확인 근거"
        case .en: return "Evidence Used"
        }
    }

    var noCheckedItemsTitle: String {
        switch self {
        case .ko: return "표시할 점검 항목이 없습니다."
        case .en: return "No check items to display."
        }
    }

    var localCheckBadge: String {
        switch self {
        case .ko: return "자동 점검"
        case .en: return "Automatic"
        }
    }

    var evidenceRequiredBadge: String {
        switch self {
        case .ko: return "증적 확인 필요"
        case .en: return "Evidence required"
        }
    }

    var externalIntegrationBadge: String {
        switch self {
        case .ko: return "외부 연동 필요"
        case .en: return "External integration"
        }
    }

    func severityLabel(_ severity: String) -> String {
        switch (self, severity) {
        case (.ko, "critical"): return "치명"
        case (.ko, "high"): return "높음"
        case (.ko, "medium"): return "중간"
        case (.ko, "low"): return "낮음"
        case (.ko, _): return "정보"
        case (.en, "critical"): return "Critical"
        case (.en, "high"): return "High"
        case (.en, "medium"): return "Medium"
        case (.en, "low"): return "Low"
        case (.en, _): return "Info"
        }
    }

    var helpGuideTitle: String {
        switch self {
        case .ko: return "점검 가이드"
        case .en: return "Check Guide"
        }
    }

    var guideSummaryTitle: String {
        switch self {
        case .ko: return "가이드 요약"
        case .en: return "Guide Summary"
        }
    }

    var guideUsageTitle: String {
        switch self {
        case .ko: return "결과 해석"
        case .en: return "How To Read Results"
        }
    }

    var guideUsageDescription: String {
        switch self {
        case .ko: return "파일 기반 정적 점검으로 확인 가능한 항목은 자동 점검으로 표시됩니다. 실행 대상, 외부 취약점 피드, 저장소 메타데이터가 필요한 항목은 외부 연동 필요로, 조직 정책과 운영 기록이 필요한 항목은 증적 확인 필요로 표시됩니다."
        case .en: return "Locally mappable static checks are marked automatic. Live targets, vulnerability feeds, and repository metadata are marked as external integration; organizational policy and operating records are marked as evidence required."
        }
    }

    var appSubtitle: String {
        switch self {
        case .ko: return "로컬 프로젝트 보안 점검"
        case .en: return "Local Project Security Scan"
        }
    }

    var openInBrowserTitle: String {
        switch self {
        case .ko: return "외부 브라우저로 열기"
        case .en: return "Open in Browser"
        }
    }

    var targetsTitle: String {
        switch self {
        case .ko: return "점검 대상"
        case .en: return "Scan Targets"
        }
    }

    var chooseFolderTitle: String {
        switch self {
        case .ko: return "폴더 선택"
        case .en: return "Choose Folder"
        }
    }

    var uploadFilesTitle: String {
        switch self {
        case .ko: return "파일 업로드"
        case .en: return "Upload Files"
        }
    }

    var clearSelectionTitle: String {
        switch self {
        case .ko: return "선택 초기화"
        case .en: return "Clear Selection"
        }
    }

    var preventionToolkitTitle: String {
        switch self {
        case .ko: return "예방 키트"
        case .en: return "Prevention Kit"
        }
    }

    var mainHelpTitle: String {
        switch self {
        case .ko: return "도움말"
        case .en: return "Help"
        }
    }

    var mainHelpSubtitle: String {
        switch self {
        case .ko: return "KODA는 폴더나 파일을 선택해 로컬 보안 위험을 점검하고, 예방 키트로 보안 가드레일과 릴리스 산출물을 준비하는 앱입니다. 아래 순서대로 진행하면 처음 사용하는 경우에도 점검부터 결과 다운로드까지 이어갈 수 있습니다."
        case .en: return "KODA scans selected folders or files for local security risks and uses the Prevention Kit to prepare security guardrails and release artifacts. Follow the steps below to move from the first scan to downloadable results."
        }
    }

    var firstRunGuideTitle: String {
        switch self {
        case .ko: return "처음 사용하는 순서"
        case .en: return "First Run"
        }
    }

    var firstRunGuideItems: [String] {
        switch self {
        case .ko:
            return [
                "메인 화면에서 폴더 선택을 눌러 프로젝트 폴더를 추가합니다. 단일 파일, 여러 파일, 압축 파일을 점검하려면 파일 업로드를 사용합니다.",
                "보안 점검 실행을 누르면 KODA가 비밀값, 의존성, 설정, 코드 패턴, 예방 가드레일을 로컬에서 점검합니다.",
                "점검 결과 조회에서 전체 결과를 보거나, OWASP, CWE, ISMS-P 같은 보안 기준별 결과 카드로 들어가 상세 항목을 확인합니다.",
                "각 상세 화면의 도움말 버튼을 누르면 해당 기준에서 어떤 항목을 확인하는지와 자동 점검, 외부 연동 필요, 증적 확인 필요 상태를 볼 수 있습니다.",
            ]
        case .en:
            return [
                "On the main screen, choose folders to add project directories. Use file upload when you want to scan single files, multiple files, or archives.",
                "Run Security Scan to check secrets, dependencies, configuration, code patterns, and prevention guardrails locally.",
                "Use Scan Results to view all findings, or open standard-specific cards such as OWASP, CWE, and ISMS-P for detailed results.",
                "Use the Help button on each detail screen to see what the standard checks and whether it is automatic, external integration required, or evidence review required.",
            ]
        }
    }

    var preventionKitAboutTitle: String {
        switch self {
        case .ko: return "예방 키트란?"
        case .en: return "What It Does"
        }
    }

    var preventionKitUsageTitle: String {
        switch self {
        case .ko: return "사용법"
        case .en: return "How To Use"
        }
    }

    var preventionKitAboutItems: [String] {
        switch self {
        case .ko:
            return [
                "예방 키트는 취약점을 찾은 뒤 고치는 것에 그치지 않고, 프로젝트에 기본 보안 장치를 미리 갖추도록 돕는 기능 묶음입니다.",
                "자동 수정 마법사는 SECURITY.md, Dependabot 설정, CI 보안 점검 workflow, CODEOWNERS, .dockerignore, .env.example 같은 파일을 만들거나 부족한 줄을 추가합니다.",
                "기존 파일을 무작정 덮어쓰지 않고, 적용 전에 변경 후보를 보여주므로 필요한 항목만 선택해서 적용할 수 있습니다.",
                "팀이나 릴리스 과정에서 필요한 SBOM, VEX, 저장소 보안 체크리스트, SSDF/Secure by Design 계획, 릴리스 보안 패키지도 같은 메뉴에서 생성합니다.",
            ]
        case .en:
            return [
                "The Prevention Kit is a set of actions that helps you prepare baseline security controls, not just find issues after they happen.",
                "The Auto-Fix Wizard creates or updates files such as SECURITY.md, Dependabot configuration, CI security workflows, CODEOWNERS, .dockerignore, and .env.example.",
                "It previews candidate changes before applying them, so you can select only the guardrails you want instead of overwriting files blindly.",
                "The same menu can also generate SBOM, VEX, repository security checklists, SSDF/Secure by Design plans, and release security packages for team and release workflows.",
            ]
        }
    }

    var preventionKitItemsTitle: String {
        switch self {
        case .ko: return "예방 키트에 포함된 항목"
        case .en: return "What's Included"
        }
    }

    var preventionKitItems: [String] {
        switch self {
        case .ko:
            return [
                "자동 수정 마법사: 선택한 폴더의 누락된 예방 가드레일을 계산해 목록으로 보여줍니다. 새 파일 생성과 기존 파일 보수적 줄 추가를 구분해서 표시하므로, 운영 중인 프로젝트에서는 이 항목으로 변경 내용을 먼저 검토한 뒤 필요한 것만 적용합니다.",
                "선택 폴더에 예방 설정 적용: 새 프로젝트나 보안 기준 파일이 거의 없는 폴더에 기본 예방 파일을 한 번에 생성합니다. SECURITY.md, Dependabot, KODA 보안 workflow, release provenance workflow, CODEOWNERS, .dockerignore, .env.example, pre-commit 안내, 저장소 보안 체크리스트, ZAP/Dependency-Track/VEX/SLSA/SSDF/Secure by Design 문서가 포함됩니다.",
                "커밋 전 보안 차단 설치: Git 저장소의 .git/hooks/pre-commit에 KODA hook을 설치합니다. commit 직전에 앱 내장 스캐너가 로컬 점검을 실행하고, 기본적으로 high 이상 발견 항목이 있으면 commit을 막습니다. 차단 기준은 KODA_PRE_COMMIT_FAIL_ON으로 조정합니다.",
                "SBOM 생성: 선택한 프로젝트의 의존성을 CycloneDX JSON으로 저장합니다. requirements, pyproject/poetry, Pipfile.lock, package-lock, yarn.lock, pnpm-lock 같은 lockfile 기반 의존성 목록을 릴리스 검토 자료로 남길 때 사용합니다.",
                "OSV/CVE + KEV/EPSS 조회: 고정 버전이 있는 의존성을 OSV.dev로 조회하고, CVE가 있으면 CISA KEV와 FIRST EPSS 우선순위를 덧붙입니다. 네트워크 조회가 필요하므로 오프라인 기본 스캔과 분리되어 있습니다.",
                "VEX 문서 생성: OSV/CVE 조회 결과를 CycloneDX VEX 초안으로 저장합니다. 실제 영향 없음, 수정됨, 검토 중 같은 상태를 릴리스 산출물로 추적하기 위한 시작점이며 최종 판단은 사람이 확인해야 합니다.",
                "ZAP DAST 계획 생성: 운영 승인 전 단계에서 허가된 URL, 실행 명령, 결과 저장 위치, 주의사항을 Markdown 계획으로 만듭니다. 아직 실제 HTTP 요청을 보내지 않으므로 점검 승인 문서화에 적합합니다.",
                "ZAP DAST 실행: Docker 기반 OWASP ZAP baseline을 실행해 실제 웹 URL에 요청을 보냅니다. 소유하거나 명시적으로 허가받은 staging/local URL에만 사용하고, 운영 시간대와 범위를 확인한 뒤 실행합니다.",
                "수동 증적 체크리스트: ASVS, WSTG, ISMS-P, NIST SSDF, OWASP SAMM처럼 로컬 파일만으로 전부 입증할 수 없는 기준의 확인 질문과 증적 칸을 생성합니다. 정책, 승인 기록, 운영 절차 검토에 사용합니다.",
                "릴리스 보안 패키지 생성: SBOM, VEX, 점검 결과, 수동 증적 체크리스트, checksum, manifest를 한 폴더에 묶습니다. 배포 전 보안 검토 자료나 릴리스 승인 첨부 자료로 사용합니다.",
                "릴리스 서명 계획 생성: SLSA/Sigstore 관점에서 산출물 checksum, cosign sign/verify, provenance 게시 절차를 Markdown 계획으로 저장합니다. 실제 키와 CI 신원은 프로젝트 릴리스 체계에 맞게 채웁니다.",
                "점검 변경 리포트: 최근 점검과 이전 점검의 위험점수, 심각도 분포, 새로 생긴 발견 항목과 해결된 항목을 비교합니다. 수정 전후 검증이나 정기 보안 추이 확인에 사용합니다.",
                "예외 파일 생성: 오탐이나 의도적으로 수용한 항목을 koda-ignore.yml 템플릿으로 만듭니다. rule, path, reason, until을 기록해 임시 예외가 영구 방치되지 않도록 관리합니다.",
                "저장소 보안 설정 체크리스트: GitHub 같은 저장소 호스팅 화면에서 켜야 하는 branch protection, required review, secret scanning, Dependabot alerts, Actions 최소 권한 설정을 체크리스트로 저장합니다.",
                "NIST SSDF 워크플로 계획: Prepare, Protect, Produce, Respond 단계별로 KODA 점검과 팀 증적을 연결합니다. 개발보안 프로세스를 문서화하거나 내부 감사 준비에 사용합니다.",
                "Secure by Design 예방 계획: CISA Secure by Design 원칙에 맞춰 고객 보안 결과 책임, 안전한 기본값, 투명성, 경영진 주도 지표를 기록합니다. 제품 보안 개선 로드맵으로 사용합니다.",
                "위협 모델 마법사: 로그인, 개인정보, 결제, 관리자, 공개 API, 파일 처리, AI/LLM, 모바일, 클라우드 특성을 선택해 위협 모델 초안과 권장 통제를 만듭니다.",
                "기준 준수 현황: OWASP, CWE, ISMS-P, NIST, CISA 등 보안 기준별로 자동 확인, 조치 필요, 증적 보완 상태를 한 화면에서 확인합니다.",
                "비밀값 회전 절차: 실제 키나 토큰이 발견됐을 때 폐기, 재발급, 사용 이력 감사, 재점검 순서를 runbook으로 저장합니다.",
                "AI/LLM 보안 계획: OWASP LLM Top 10 기준으로 프롬프트 인젝션, 민감정보 전달, 도구 권한, 모델/SDK 공급망, 적대적 테스트를 정리합니다.",
                "모바일 보안 계획: OWASP MASVS 기준으로 Android Manifest, iOS plist, 저장소, 통신, 플랫폼 상호작용, 릴리스 서명, 기기 테스트 항목을 기록합니다.",
                "NIST CSF 2.0 프로파일과 CISA 확인서 체크리스트: 조직 위험관리와 보안 소프트웨어 개발 확인에 필요한 증적 위치, 담당자, 검토 항목을 정리합니다.",
                "API/SCVS/개인정보/Cloud-IaC 보안 계획: API 인벤토리와 권한, 공급망 구성요소 검증, 개인정보 데이터 맵, 클라우드 노출·IAM·암호화 기준을 문서화합니다.",
                "보안 로드맵과 증적 보관대장: 개선 backlog, 위험 수용, 점검 리포트, SBOM, VEX, DAST, 승인 기록을 한 곳에서 추적합니다.",
                "보안 헤더와 컨테이너 하드닝 기준: CSP/HSTS 같은 웹 헤더와 non-root, capability drop, seccomp, NetworkPolicy 같은 배포 기본값을 정리합니다.",
                "보안 점수 추적: 점검 때마다 위험점수와 발견 항목 수를 저장해 시간 흐름에 따른 개선/악화를 봅니다. 특정 수정이 실제로 위험점수를 낮췄는지 확인할 때 유용합니다.",
                "현재 대상을 프로파일로 저장 / 프로젝트 프로파일: 자주 점검하는 여러 폴더와 파일 묶음을 이름 붙여 저장하고 다시 불러옵니다. 반복 점검 대상이 많은 경우 매번 폴더를 다시 선택하지 않아도 됩니다.",
                "보안 예방 키트 파일로 저장: 실제 파일을 프로젝트에 쓰지 않고, 예방 키트 전체 내용을 하나의 Markdown 문서로 내보냅니다. 팀 공유, 리뷰, 사전 검토가 필요할 때 사용합니다.",
            ]
        case .en:
            return [
                "Auto-Fix Wizard: calculates missing prevention guardrails for selected folders and previews them as a selectable list. It separates new file creation from conservative line additions, so use it on existing projects when you want to review changes before applying them.",
                "Apply Guardrails to Folders: creates the baseline prevention files at once for new or lightly configured projects. It includes SECURITY.md, Dependabot, KODA security workflow, release provenance workflow, CODEOWNERS, .dockerignore, .env.example, pre-commit guide, repository security checklist, and ZAP/Dependency-Track/VEX/SLSA/SSDF/Secure by Design documents.",
                "Install Pre-Commit Gate: writes a KODA hook to .git/hooks/pre-commit. Before commit, the built-in app scanner runs a local scan and blocks the commit when high-or-higher findings are present by default. Adjust the threshold with KODA_PRE_COMMIT_FAIL_ON.",
                "Generate SBOM: saves project dependencies as CycloneDX JSON. Use it to keep release review material for requirements, pyproject/poetry, Pipfile.lock, package locks, yarn.lock, and pnpm-lock dependency sources.",
                "Run OSV/CVE + KEV/EPSS: queries OSV.dev for exact-version dependencies and enriches CVEs with CISA KEV and FIRST EPSS priority when available. It requires network access, so it is separate from the offline default scan.",
                "Generate VEX: writes a CycloneDX VEX draft from OSV/CVE lookup results. Use it as a starting point to track not affected, fixed, in triage, or other reviewed vulnerability states; a human must confirm final status.",
                "Create ZAP DAST Plan: writes a Markdown plan with authorized URL, run command, output location, and cautions before active testing. It does not send HTTP requests, so it is useful for approval documentation.",
                "Run ZAP DAST: runs Docker-based OWASP ZAP baseline and sends real requests to a web URL. Use it only against owned or explicitly authorized staging/local URLs after confirming scope and timing.",
                "Manual Evidence Checklist: creates questions and evidence fields for standards that cannot be fully proven from local files, such as ASVS, WSTG, ISMS-P, NIST SSDF, and OWASP SAMM. Use it for policy, approval, and operating-procedure review.",
                "Create Release Security Package: bundles SBOM, VEX, scan results, manual evidence checklist, checksums, and a manifest into one folder. Use it for pre-release security review or release approval attachments.",
                "Create Release Signing Plan: saves SLSA/Sigstore-oriented checksum, cosign sign/verify, and provenance publication guidance as Markdown. Fill in real keys and CI identities according to the project release process.",
                "Scan Change Report: compares the latest scan with the previous scan across risk score, severity distribution, newly introduced findings, and resolved findings. Use it to validate remediation or monitor security trends.",
                "Create Ignore File: creates a koda-ignore.yml template for false positives or explicitly accepted findings. Record rule, path, reason, and until date so temporary exceptions do not become permanent.",
                "Repository Security Checklist: exports hosted-repository controls such as branch protection, required reviews, secret scanning, Dependabot alerts, and least-privilege Actions permissions.",
                "NIST SSDF Workflow Plan: maps KODA checks and team evidence to Prepare, Protect, Produce, and Respond activities. Use it to document secure-development process and internal audit readiness.",
                "Secure by Design Plan: records CISA Secure by Design work across customer security outcomes, secure defaults, transparency, and executive ownership. Use it as a product-security improvement roadmap.",
                "Threat Model Wizard: selects login, PII, payment, admin, public API, file handling, AI/LLM, mobile, and cloud traits to generate a threat-model draft and recommended controls.",
                "Compliance Dashboard: shows automatic, needs-action, and evidence-needed status by security standard across OWASP, CWE, ISMS-P, NIST, and CISA views.",
                "Secret Rotation Runbook: saves the revoke, rotate, audit, and re-scan steps to follow when a real key or token is found.",
                "AI/LLM Security Plan: records OWASP LLM Top 10 controls for prompt injection, sensitive-data flow, tool authority, model/SDK supply chain, and adversarial tests.",
                "Mobile Security Plan: records OWASP MASVS work for Android manifests, iOS plists, storage, network, platform interaction, release signing, and device tests.",
                "NIST CSF 2.0 Profile and CISA Attestation Checklist: organize evidence locations, owners, and review items for organizational risk management and secure software development attestation.",
                "API/SCVS/Privacy/Cloud-IaC Plans: document API inventory and authorization, software component verification, privacy data maps, and cloud exposure/IAM/encryption baselines.",
                "Security Roadmap and Evidence Register: track improvement backlog, risk acceptance, scan reports, SBOM, VEX, DAST, and approval evidence in one place.",
                "Security Headers and Container Hardening: record web headers such as CSP/HSTS plus deployment defaults such as non-root users, capability drops, seccomp, and NetworkPolicies.",
                "Security Score History: stores risk score and finding count after scans so you can see improvement or regression over time. It helps verify whether a remediation actually lowered risk.",
                "Save Current Targets as Profile / Project Profiles: save frequently scanned folder and file sets by name and load them later. This avoids repeatedly selecting the same targets for recurring reviews.",
                "Save Security Prevention Kit: exports the full prevention kit as one Markdown document without writing files into the project. Use it for team sharing, review, or pre-approval.",
            ]
        }
    }

    /// The flat `preventionKitItems` list grouped into functional categories so
    /// the help panel reads as a small set of themed blocks instead of one long
    /// wall of items. Items are sliced by index from `preventionKitItems`, so the
    /// localized descriptions are reused without duplication.
    var preventionKitGroups: [PreventionKitGroup] {
        let items = preventionKitItems
        func pick(_ indices: [Int]) -> [String] {
            indices.compactMap { items.indices.contains($0) ? items[$0] : nil }
        }
        let definitions: [(ko: String, en: String, indices: [Int])] = [
            ("적용 & 차단", "Apply & Block", [1, 2, 13, 12]),
            ("점검 & 추이", "Scan & Trends", [0, 17, 11, 25]),
            ("의존성 & 공급망", "Dependencies & Supply Chain", [3, 4, 5, 9, 10]),
            ("동적 점검 (DAST)", "Dynamic Testing (DAST)", [6, 7]),
            ("거버넌스 & 컴플라이언스 문서", "Governance & Compliance Docs", [8, 14, 15, 16, 18, 19, 20, 21, 22, 23, 24]),
            ("작업 효율", "Productivity", [26, 27]),
        ]
        return definitions.compactMap { definition in
            let groupItems = pick(definition.indices)
            guard !groupItems.isEmpty else { return nil }
            return PreventionKitGroup(title: self == .ko ? definition.ko : definition.en, items: groupItems)
        }
    }

    var preventionKitUsageItems: [String] {
        switch self {
        case .ko:
            return [
                "먼저 점검 대상 폴더나 파일을 선택하고 보안 점검 실행을 누릅니다. 발견 항목을 본 뒤 예방 키트에서 필요한 조치만 선택하면 과도한 파일 생성이나 설정 변경을 줄일 수 있습니다.",
                "초기 프로젝트에는 선택 폴더에 예방 설정 적용으로 기본 파일을 빠르게 깔고, 이미 운영 중인 프로젝트에는 자동 수정 마법사로 변경 후보를 확인한 뒤 필요한 항목만 적용하는 방식을 권장합니다.",
                "Git 저장소에는 커밋 전 보안 차단 설치를 적용합니다. 설치 후 commit 시 KODA가 로컬 스캔을 실행하며, 기준 심각도는 KODA_PRE_COMMIT_FAIL_ON 환경변수로 조정할 수 있습니다.",
                "릴리스 전에는 SBOM 생성, VEX 문서 생성, 릴리스 보안 패키지 생성, 릴리스 서명 계획 생성을 순서대로 사용하면 의존성, 검토 상태, 체크섬, 서명 계획을 한 묶음으로 정리할 수 있습니다.",
                "OSV/CVE 조회와 ZAP DAST 실행은 외부 네트워크나 Docker가 필요합니다. 사내망, 운영 서버, 고객 시스템에는 승인된 범위와 시간대를 확인한 뒤 실행합니다.",
            ]
        case .en:
            return [
                "First choose folders or files and run a security scan. Review the findings, then use the Prevention Kit for the specific actions you need instead of creating every artifact blindly.",
                "For new projects, use Apply Guardrails to Folders to lay down the baseline quickly. For existing projects, use the Auto-Fix Wizard so you can review candidate changes before applying them.",
                "For Git repositories, install the Pre-Commit Gate. After installation, KODA runs a local scan before commit, and you can adjust the blocking threshold with KODA_PRE_COMMIT_FAIL_ON.",
                "Before release, use Generate SBOM, Generate VEX, Create Release Security Package, and Create Release Signing Plan to collect dependencies, review status, checksums, and signing guidance together.",
                "OSV/CVE lookup and ZAP DAST require external network access or Docker. For internal networks, production servers, or customer systems, confirm the approved scope and time window first.",
            ]
        }
    }

    var resultDownloadGuideTitle: String {
        switch self {
        case .ko: return "결과 다운로드와 활용"
        case .en: return "Download And Use Results"
        }
    }

    var resultDownloadGuideItems: [String] {
        switch self {
        case .ko:
            return [
                "상세 결과 화면의 다운로드 메뉴에서 HTML, PDF, Markdown 리포트를 저장할 수 있습니다.",
                "SBOM 생성은 의존성 목록을 CycloneDX 형식으로 내보내며, VEX 문서는 취약점 검토 상태를 릴리스 산출물로 남기는 데 사용합니다.",
                "릴리스 보안 패키지는 SBOM, VEX, 점검 결과, 증적 체크리스트, 체크섬을 한 폴더에 모아 배포 전 검토 자료로 사용할 수 있게 합니다.",
                "점검 변경 리포트는 최근 두 번의 점검 결과를 비교해 새로 생긴 위험과 해결된 위험을 확인할 때 사용합니다.",
            ]
        case .en:
            return [
                "Use the download menu in detail views to save HTML, PDF, and Markdown reports.",
                "Generate SBOM exports dependencies in CycloneDX format, while VEX records vulnerability review status for release artifacts.",
                "Create Release Security Package bundles SBOM, VEX, scan results, evidence checklists, and checksums into one review folder.",
                "Scan Change Report compares the latest two scans so you can see newly introduced and resolved risks.",
            ]
        }
    }

    var safetyGuideTitle: String {
        switch self {
        case .ko: return "주의할 점"
        case .en: return "Important Notes"
        }
    }

    var safetyGuideItems: [String] {
        switch self {
        case .ko:
            return [
                "기본 보안 점검은 로컬 파일을 읽어 분석합니다. 예방 설정 적용과 자동 수정 마법사는 사용자가 선택한 항목만 실제 파일로 작성합니다.",
                "ZAP DAST는 실행 중인 웹 서비스를 점검하므로, 반드시 소유하거나 명시적으로 허가받은 URL에만 실행해야 합니다.",
                "자동 점검은 빠른 예방과 위험 발견을 돕지만, 운영 정책, 승인 기록, 인증 증적이 필요한 기준은 증적 확인 필요 상태로 표시됩니다.",
            ]
        case .en:
            return [
                "The default security scan reads local files. Applying guardrails and using the Auto-Fix Wizard writes only the selected items.",
                "ZAP DAST tests a running web service, so run it only against URLs you own or are explicitly authorized to test.",
                "Automatic checks help prevent and find risks quickly, but standards requiring policies, approvals, and certification evidence are marked as evidence review required.",
            ]
        }
    }

    var exportPreventionToolkitTitle: String {
        switch self {
        case .ko: return "보안 예방 키트 파일로 저장"
        case .en: return "Save Security Prevention Kit"
        }
    }

    var applyPreventionToolkitTitle: String {
        switch self {
        case .ko: return "선택 폴더에 예방 설정 적용"
        case .en: return "Apply Guardrails to Folders"
        }
    }

    var installPreCommitHookTitle: String {
        switch self {
        case .ko: return "커밋 전 보안 차단 설치"
        case .en: return "Install Pre-Commit Gate"
        }
    }

    var autoFixWizardTitle: String {
        switch self {
        case .ko: return "자동 수정 마법사"
        case .en: return "Auto-Fix Wizard"
        }
    }

    var autoFixWizardSubtitle: String {
        switch self {
        case .ko: return "선택한 폴더에 적용할 보안 예방 수정사항을 미리 보고 원하는 항목만 적용합니다. 기존 파일은 필요한 줄만 추가하거나 없는 파일만 생성합니다."
        case .en: return "Preview security guardrail changes for selected folders and apply only the items you choose. Existing files are merged conservatively."
        }
    }

    var noAutoFixesTitle: String {
        switch self {
        case .ko: return "적용할 자동 수정 항목이 없습니다."
        case .en: return "No auto-fix items available."
        }
    }

    var noAutoFixesSubtitle: String {
        switch self {
        case .ko: return "먼저 점검 대상 폴더를 선택하거나 이미 기본 예방 설정이 존재하는지 확인하세요."
        case .en: return "Choose target folders first, or verify that baseline guardrails already exist."
        }
    }

    var applySelectedFixesTitle: String {
        switch self {
        case .ko: return "선택 항목 적용"
        case .en: return "Apply Selected"
        }
    }

    var cancelTitle: String {
        switch self {
        case .ko: return "취소"
        case .en: return "Cancel"
        }
    }

    var closeTitle: String {
        switch self {
        case .ko: return "닫기"
        case .en: return "Close"
        }
    }

    var generateSBOMTitle: String {
        switch self {
        case .ko: return "SBOM 생성"
        case .en: return "Generate SBOM"
        }
    }

    var runOSVLookupTitle: String {
        switch self {
        case .ko: return "OSV/CVE + KEV/EPSS 조회"
        case .en: return "Run OSV/CVE + KEV/EPSS"
        }
    }

    var runHostScanTitle: String {
        switch self {
        case .ko: return "이 컴퓨터 점검 (호스트 보안)"
        case .en: return "Check this computer (host posture)"
        }
    }

    var runAITriageTitle: String {
        switch self {
        case .ko: return "AI 오탐 검토 (로컬 LLM)"
        case .en: return "AI false-positive triage (local LLM)"
        }
    }

    var runChangedOnlyTitle: String {
        switch self {
        case .ko: return "변경 파일만 점검 (git)"
        case .en: return "Scan changed files only (git)"
        }
    }

    var generateVEXTitle: String {
        switch self {
        case .ko: return "VEX 문서 생성"
        case .en: return "Generate VEX"
        }
    }

    var generateZAPPlanTitle: String {
        switch self {
        case .ko: return "ZAP DAST 계획 생성"
        case .en: return "Create ZAP DAST Plan"
        }
    }

    var runZAPDASTTitle: String {
        switch self {
        case .ko: return "ZAP DAST 실행"
        case .en: return "Run ZAP DAST"
        }
    }

    var evidenceChecklistTitle: String {
        switch self {
        case .ko: return "수동 증적 체크리스트"
        case .en: return "Manual Evidence Checklist"
        }
    }

    var releaseSecurityPackageTitle: String {
        switch self {
        case .ko: return "릴리스 보안 패키지 생성"
        case .en: return "Create Release Security Package"
        }
    }

    var releaseSigningPlanTitle: String {
        switch self {
        case .ko: return "릴리스 서명 계획 생성"
        case .en: return "Create Release Signing Plan"
        }
    }

    var scoreDiffTitle: String {
        switch self {
        case .ko: return "점검 변경 리포트"
        case .en: return "Scan Change Report"
        }
    }

    var createIgnoreFileTitle: String {
        switch self {
        case .ko: return "예외 파일 생성"
        case .en: return "Create Ignore File"
        }
    }

    var repositorySecurityChecklistTitle: String {
        switch self {
        case .ko: return "저장소 보안 설정 체크리스트"
        case .en: return "Repository Security Checklist"
        }
    }

    var ssdfWorkflowPlanTitle: String {
        switch self {
        case .ko: return "NIST SSDF 워크플로 계획"
        case .en: return "NIST SSDF Workflow Plan"
        }
    }

    var secureByDesignPlanTitle: String {
        switch self {
        case .ko: return "Secure by Design 예방 계획"
        case .en: return "Secure by Design Plan"
        }
    }

    var threatModelWizardTitle: String {
        switch self {
        case .ko: return "위협 모델 마법사"
        case .en: return "Threat Model Wizard"
        }
    }

    var threatModelWizardSubtitle: String {
        switch self {
        case .ko: return "프로젝트 특성을 선택하면 필요한 예방 통제와 위협 모델 초안을 만듭니다."
        case .en: return "Select project characteristics to generate recommended controls and a threat-model draft."
        }
    }

    var complianceDashboardTitle: String {
        switch self {
        case .ko: return "기준 준수 현황"
        case .en: return "Compliance Dashboard"
        }
    }

    var complianceDashboardSubtitle: String {
        switch self {
        case .ko: return "보안 기준별 자동 확인, 조치 필요, 증적 보완 상태를 한 화면에서 봅니다."
        case .en: return "Review automatic, needs-action, and evidence-needed status by security standard."
        }
    }

    var secretRotationRunbookTitle: String {
        switch self {
        case .ko: return "비밀값 회전 절차"
        case .en: return "Secret Rotation Runbook"
        }
    }

    var aiLLMSecurityPlanTitle: String {
        switch self {
        case .ko: return "AI/LLM 보안 계획"
        case .en: return "AI/LLM Security Plan"
        }
    }

    var mobileSecurityPlanTitle: String {
        switch self {
        case .ko: return "모바일 보안 계획"
        case .en: return "Mobile Security Plan"
        }
    }

    var nistCSFProfileTitle: String {
        switch self {
        case .ko: return "NIST CSF 2.0 프로파일"
        case .en: return "NIST CSF 2.0 Profile"
        }
    }

    var cisaAttestationChecklistTitle: String {
        switch self {
        case .ko: return "CISA 확인서 체크리스트"
        case .en: return "CISA Attestation Checklist"
        }
    }

    var threatModelAuthTitle: String {
        switch self {
        case .ko: return "로그인/인증 기능"
        case .en: return "Login or authentication"
        }
    }

    var threatModelPIITitle: String {
        switch self {
        case .ko: return "개인정보/민감정보 처리"
        case .en: return "PII or sensitive data"
        }
    }

    var threatModelPaymentTitle: String {
        switch self {
        case .ko: return "결제/금융 데이터"
        case .en: return "Payment or financial data"
        }
    }

    var threatModelAdminTitle: String {
        switch self {
        case .ko: return "관리자 기능"
        case .en: return "Administrative functions"
        }
    }

    var threatModelPublicAPITitle: String {
        switch self {
        case .ko: return "외부 공개 API"
        case .en: return "Public API"
        }
    }

    var threatModelFileUploadTitle: String {
        switch self {
        case .ko: return "파일 업로드/다운로드"
        case .en: return "File upload or download"
        }
    }

    var threatModelAILLMTitle: String {
        switch self {
        case .ko: return "AI/LLM 기능"
        case .en: return "AI/LLM features"
        }
    }

    var threatModelMobileTitle: String {
        switch self {
        case .ko: return "모바일 앱"
        case .en: return "Mobile app"
        }
    }

    var threatModelCloudTitle: String {
        switch self {
        case .ko: return "컨테이너/클라우드 배포"
        case .en: return "Container or cloud deployment"
        }
    }

    var recommendedControlsTitle: String {
        switch self {
        case .ko: return "권장 통제"
        case .en: return "Recommended Controls"
        }
    }

    var saveThreatModelTitle: String {
        switch self {
        case .ko: return "위협 모델 저장"
        case .en: return "Save Threat Model"
        }
    }

    var recommendThreatModelBase: String {
        switch self {
        case .ko: return "신뢰 경계, 주요 자산, 악용 시나리오를 문서화합니다."
        case .en: return "Document trust boundaries, critical assets, and abuse cases."
        }
    }

    var recommendSecurityPolicy: String {
        switch self {
        case .ko: return "SECURITY.md, CODEOWNERS, 예외 만료 기준을 준비합니다."
        case .en: return "Prepare SECURITY.md, CODEOWNERS, and exception expiry rules."
        }
    }

    var recommendSASTDependency: String {
        switch self {
        case .ko: return "SAST, 의존성, 비밀값 점검을 PR/릴리스 게이트로 연결합니다."
        case .en: return "Connect SAST, dependency, and secret checks to PR/release gates."
        }
    }

    var recommendAuthSession: String {
        switch self {
        case .ko: return "인증, 인가, 세션, 쿠키 설정을 ASVS 관점으로 검토합니다."
        case .en: return "Review authentication, authorization, sessions, and cookies against ASVS."
        }
    }

    var recommendSecretRotation: String {
        switch self {
        case .ko: return "비밀값 회전 절차와 민감정보 로깅 마스킹을 준비합니다."
        case .en: return "Prepare secret rotation and sensitive-log masking procedures."
        }
    }

    var recommendDASTASVS: String {
        switch self {
        case .ko: return "파일 처리, 공개 API, 런타임 동작은 DAST/침투테스트 범위에 넣습니다."
        case .en: return "Include file handling, public APIs, and runtime behavior in DAST or penetration testing scope."
        }
    }

    var recommendLLMPlan: String {
        switch self {
        case .ko: return "OWASP LLM Top 10 기준으로 프롬프트, 도구 권한, 민감정보 전달을 점검합니다."
        case .en: return "Use OWASP LLM Top 10 to review prompts, tool authority, and sensitive-data flow."
        }
    }

    var recommendMASVSPlan: String {
        switch self {
        case .ko: return "OWASP MASVS 기준으로 모바일 저장소, 통신, 플랫폼 설정, 릴리스 서명을 검토합니다."
        case .en: return "Use OWASP MASVS for mobile storage, network, platform settings, and release signing."
        }
    }

    var recommendIaCContainer: String {
        switch self {
        case .ko: return "Docker, Compose, Kubernetes, Terraform 권한과 이미지 고정 상태를 확인합니다."
        case .en: return "Check Docker, Compose, Kubernetes, Terraform permissions, and image pinning."
        }
    }

    var scoreHistoryTitle: String {
        switch self {
        case .ko: return "보안 점수 추적"
        case .en: return "Security Score History"
        }
    }

    var saveProjectProfileTitle: String {
        switch self {
        case .ko: return "현재 대상을 프로파일로 저장"
        case .en: return "Save Current Targets as Profile"
        }
    }

    var projectProfilesTitle: String {
        switch self {
        case .ko: return "프로젝트 프로파일"
        case .en: return "Project Profiles"
        }
    }

    var scoreHistorySubtitle: String {
        switch self {
        case .ko: return "최근 스캔의 위험점수와 발견 항목 수를 기록해 개선 추이를 확인합니다."
        case .en: return "Track risk score and finding count from recent scans to see security progress."
        }
    }

    var noScoreHistoryTitle: String {
        switch self {
        case .ko: return "아직 기록된 점수가 없습니다."
        case .en: return "No score history yet."
        }
    }

    var noScoreHistorySubtitle: String {
        switch self {
        case .ko: return "보안 점검을 실행하면 자동으로 점수 기록이 저장됩니다."
        case .en: return "Run a security scan to save the first score snapshot."
        }
    }

    var clearHistoryTitle: String {
        switch self {
        case .ko: return "기록 지우기"
        case .en: return "Clear History"
        }
    }

    var runScanTitle: String {
        switch self {
        case .ko: return "보안 점검 실행"
        case .en: return "Run Security Scan"
        }
    }

    var runningTitle: String {
        switch self {
        case .ko: return "점검 중"
        case .en: return "Scanning"
        }
    }

    var noTargetsTitle: String {
        switch self {
        case .ko: return "선택된 항목 없음"
        case .en: return "No targets selected"
        }
    }

    var removeTargetHelp: String {
        switch self {
        case .ko: return "점검 대상 삭제"
        case .en: return "Remove scan target"
        }
    }

    var resultsTitle: String {
        switch self {
        case .ko: return "점검 결과 조회"
        case .en: return "Scan Results"
        }
    }

    var overallResultsTitle: String {
        switch self {
        case .ko: return "전체 조회"
        case .en: return "Overall Results"
        }
    }

    var overallResultsSubtitle: String {
        switch self {
        case .ko: return "스캔 결과 전체를 한 화면에서 확인합니다."
        case .en: return "View all scan results in one screen."
        }
    }

    var standardsResultsTitle: String {
        switch self {
        case .ko: return "보안기준별 점검결과"
        case .en: return "Results by Security Standard"
        }
    }

    var standardsResultsSubtitle: String {
        switch self {
        case .ko: return "전체 화면에서 기준별 설명, 도움말, KO/EN 토글과 함께 결과를 확인합니다."
        case .en: return "Open a full-screen view with standard details, help, and the KO/EN toggle."
        }
    }

    var resultCardsEnabledTitle: String {
        switch self {
        case .ko: return "점검을 실행하면 결과 조회 카드가 활성화됩니다."
        case .en: return "Run a scan to activate result cards."
        }
    }

    var resultCardsEnabledSubtitle: String {
        switch self {
        case .ko: return "점검 전에는 보안기준 카드를 눌러 기준 설명 화면을 먼저 볼 수 있습니다."
        case .en: return "Before scanning, open a security-standard card to review its criteria."
        }
    }

    var exportTitle: String {
        switch self {
        case .ko: return "다운로드"
        case .en: return "Download"
        }
    }

    var maskReportExportTitle: String {
        switch self {
        case .ko: return "공유용 마스킹"
        case .en: return "Mask for Sharing"
        }
    }

    var maskReportExportHelp: String {
        switch self {
        case .ko: return "다운로드하는 HTML/PDF/Markdown 리포트에서 로컬 경로와 토큰처럼 보이는 값을 가립니다."
        case .en: return "Hide local paths and token-like values in downloaded HTML/PDF/Markdown reports."
        }
    }

    func findingCountText(_ count: Int) -> String {
        switch self {
        case .ko: return "\(count)건"
        case .en: return "\(count) finding\(count == 1 ? "" : "s")"
        }
    }

    func riskScoreText(_ score: Int) -> String {
        switch self {
        case .ko: return "\(score)점"
        case .en: return "\(score) pts"
        }
    }

    func mappedItemsText(mapped: Int, total: Int) -> String {
        switch self {
        case .ko: return "매핑 항목 \(mapped)/\(total)"
        case .en: return "Mapped checks \(mapped)/\(total)"
        }
    }

    func selectedFixCountText(_ selected: Int, total: Int) -> String {
        switch self {
        case .ko: return "선택 \(selected)/\(total)"
        case .en: return "Selected \(selected)/\(total)"
        }
    }
}

struct HelpGuideRoute: Identifiable, Hashable {
    let id: String
    let title: String
    let standard: AppSecurityStandard?

    private init(id: String, title: String, standard: AppSecurityStandard?) {
        self.id = id
        self.title = title
        self.standard = standard
    }

    init(report: ScanReportItem) {
        if let standard = report.standard {
            self.init(standard: standard)
        } else {
            self.init(id: "overall", title: "전체 조회", standard: nil)
        }
    }

    init(standard: AppSecurityStandard) {
        self.init(id: standard.id, title: standard.title, standard: standard)
    }
}

struct LanguageToggle: View {
    @Binding var language: AppLanguage

    var body: some View {
        HStack(spacing: 0) {
            languageButton(.ko)
            languageButton(.en)
        }
        .padding(3)
        .background(Color(red: 0.04, green: 0.07, blue: 0.13))
        .clipShape(RoundedRectangle(cornerRadius: 8))
        .overlay {
            RoundedRectangle(cornerRadius: 8)
                .stroke(Color.white.opacity(0.28), lineWidth: 1)
        }
        .accessibilityLabel("Language")
    }

    private func languageButton(_ value: AppLanguage) -> some View {
        Button {
            language = value
        } label: {
            Text(value.rawValue.uppercased())
                .font(.caption.weight(.bold))
                .foregroundStyle(.white)
                .frame(width: 44, height: 26)
                .background(language == value ? Color.white.opacity(0.26) : Color.clear)
                .clipShape(RoundedRectangle(cornerRadius: 6))
        }
        .buttonStyle(.plain)
        .help(value == .ko ? "한국어" : "English")
    }
}

struct KODAScreenTopBar<LeadingContent: View, ActionContent: View>: View {
    @Binding var language: AppLanguage
    let onBack: () -> Void
    private let leadingContent: LeadingContent
    private let actionContent: ActionContent

    init(
        language: Binding<AppLanguage>,
        onBack: @escaping () -> Void,
        @ViewBuilder leading: () -> LeadingContent,
        @ViewBuilder actions: () -> ActionContent
    ) {
        self._language = language
        self.onBack = onBack
        self.leadingContent = leading()
        self.actionContent = actions()
    }

    var body: some View {
        HStack(spacing: 14) {
            Button {
                onBack()
            } label: {
                Label(language.backTitle, systemImage: "chevron.left")
            }
            .buttonStyle(.borderless)
            .foregroundStyle(.white)

            leadingContent
                .layoutPriority(1)

            Spacer(minLength: 16)

            actionContent

            LanguageToggle(language: $language)
        }
        .padding(.horizontal, 22)
        .padding(.vertical, 14)
        .frame(maxWidth: .infinity, minHeight: 58, alignment: .center)
        .background(Color(red: 0.04, green: 0.07, blue: 0.13))
    }
}

struct AppSecurityStandard: Identifiable, Hashable {
    let id: String
    let title: String
    let subtitle: String
    let scope: String
    let coverage: String
    let badge: String
    let icon: String
    let accent: StandardAccent
    let categories: [AppStandardCategory]
    let references: [AppStandardReference]

    var supportedCategoryCount: Int {
        categories.filter(\.isMapped).count
    }

    func title(language: AppLanguage) -> String {
        guard language == .en else { return title }
        return SecurityStandardLocalization.standardText[id]?.title ?? title
    }

    func subtitle(language: AppLanguage) -> String {
        guard language == .en else { return subtitle }
        return SecurityStandardLocalization.standardText[id]?.subtitle ?? subtitle
    }

    func scope(language: AppLanguage) -> String {
        guard language == .en else { return scope }
        return SecurityStandardLocalization.standardText[id]?.scope ?? scope
    }

    func coverage(language: AppLanguage) -> String {
        guard language == .en else { return coverage }
        return SecurityStandardLocalization.standardText[id]?.coverage ?? coverage
    }

    func badge(language: AppLanguage) -> String {
        guard language == .en else { return badge }
        return SecurityStandardLocalization.badgeText[badge] ?? badge
    }

    func publication(language: AppLanguage) -> String? {
        guard let publication = SecurityStandardLocalization.publicationText[id] else {
            return nil
        }
        return language == .ko ? publication.ko : publication.en
    }
}

struct AppStandardCategory: Identifiable, Hashable {
    let id: String
    let title: String
    let coverage: String
    let isMapped: Bool

    func title(language: AppLanguage) -> String {
        guard language == .en else { return title }
        return SecurityStandardLocalization.categoryTitleText[title] ?? title
    }

    func coverage(language: AppLanguage) -> String {
        guard language == .en else { return coverage }
        if !isMapped {
            return "Evidence review required. This area needs manual review, runtime testing, or external evidence."
        }
        return SecurityStandardLocalization.categoryCoverageText[coverage]
            ?? "Checks this area using locally available source, configuration, secret, and dependency evidence."
    }

    func detailItems(language: AppLanguage) -> [String] {
        let key = "\(id) \(title) \(coverage)".lowercased()
        let koItems: [String]
        let enItems: [String]

        if key.contains("prevention") || key.contains("guardrail") || key.contains("automation") || key.contains("security.md") || key.contains("예방") || key.contains("자동화") {
            koItems = [
                "SECURITY.md, 신고 절차, 지원 버전처럼 보안 운영 기준이 문서화되어 있는지 확인합니다.",
                "Dependabot/Renovate, CI 보안 점검 workflow, OSV/SARIF 연동 준비 상태를 찾습니다.",
                ".env 예시/ignore, .dockerignore, SBOM 산출물처럼 릴리스 전 누락되기 쉬운 예방 장치를 표시합니다.",
            ]
            enItems = [
                "Checks whether SECURITY.md, reporting process, and supported-version expectations are documented.",
                "Finds Dependabot/Renovate, CI security workflows, and OSV/SARIF integration readiness.",
                "Highlights pre-release guardrails such as .env examples/ignore rules, .dockerignore, and SBOM artifacts.",
            ]
        } else if key.contains("xss") || key.contains("script") || key.contains("스크립") {
            koItems = [
                "HTML 출력, 템플릿 렌더링, DOM sink에 사용자 입력이 직접 연결되는지 확인합니다.",
                "innerHTML, dangerouslySetInnerHTML, document.write 등 브라우저 실행 경로를 찾습니다.",
                "이스케이프, 인코딩, 콘텐츠 보안 정책으로 보완이 필요한 지점을 표시합니다.",
            ]
            enItems = [
                "Checks whether user input reaches HTML output, template rendering, or DOM sinks.",
                "Finds browser execution paths such as innerHTML, dangerouslySetInnerHTML, and document.write.",
                "Highlights places that need escaping, encoding, or Content Security Policy controls.",
            ]
        } else if key.contains("sql") || key.contains("injection") || key.contains("인젝션") || key.contains("입력") {
            koItems = [
                "SQL 문자열 조합, 명령 실행, 템플릿 인젝션처럼 입력값이 실행 구문에 섞이는 패턴을 확인합니다.",
                "exec, system, subprocess, child_process, eval 계열 호출과 사용자 입력 흐름을 찾습니다.",
                "쿼리 파라미터화, 허용목록 검증, 명령 인자 분리로 고쳐야 할 지점을 표시합니다.",
            ]
            enItems = [
                "Checks patterns where input is mixed into SQL strings, command execution, or template execution.",
                "Finds exec, system, subprocess, child_process, eval, and similar calls tied to input flow.",
                "Highlights places that should use parameterized queries, allowlists, or separated command arguments.",
            ]
        } else if key.contains("path") || key.contains("file") || key.contains("download") || key.contains("upload") || key.contains("파일") || key.contains("다운로드") {
            koItems = [
                "다운로드/업로드 핸들러, 경로 조합, ../ 사용처럼 파일 접근 범위가 넓어지는 패턴을 확인합니다.",
                "정적 파일 공개, 임시 파일, 오래된 업로드/게시판 디렉터리 흔적을 찾습니다.",
                "기준 디렉터리 제한, 확장자 허용목록, 파일명 정규화가 필요한 위치를 표시합니다.",
            ]
            enItems = [
                "Checks download/upload handlers, path joins, and ../ patterns that can widen file access.",
                "Finds static file exposure, temporary-file use, and legacy upload or board-directory traces.",
                "Highlights where base-directory constraints, extension allowlists, and filename normalization are needed.",
            ]
        } else if key.contains("directory") || key.contains("listing") || key.contains("webdav") || key.contains("cors") || key.contains("debug") || key.contains("설정") || key.contains("배포") || key.contains("server") {
            koItems = [
                "debug 플래그, CORS 전체 허용, directory listing, WebDAV 활성화 설정을 확인합니다.",
                "nginx, Apache, IIS, Docker, compose, framework 설정 파일에서 운영 노출 위험을 찾습니다.",
                "운영 배포 전 끄거나 제한해야 할 서버 옵션과 오류 노출 설정을 표시합니다.",
            ]
            enItems = [
                "Checks debug flags, overly permissive CORS, directory listing, and enabled WebDAV settings.",
                "Finds exposure risks in nginx, Apache, IIS, Docker, compose, and framework configuration files.",
                "Highlights server options and error-disclosure settings that should be disabled or restricted before release.",
            ]
        } else if key.contains("session") || key.contains("cookie") || key.contains("auth") || key.contains("인증") || key.contains("인가") || key.contains("세션") || key.contains("접근") {
            koItems = [
                "쿠키 Secure, HttpOnly, SameSite 누락과 세션 설정 약화를 확인합니다.",
                "인가 우회, 라우트 보호 누락, 파일/관리자 경로 접근 패턴을 찾습니다.",
                "인증 우회 조건, 기본 계정, 테스트용 권한 설정이 남은 위치를 표시합니다.",
            ]
            enItems = [
                "Checks missing cookie Secure, HttpOnly, SameSite flags and weak session settings.",
                "Finds authorization bypass patterns, unprotected routes, and file or admin path access risks.",
                "Highlights leftover auth bypass conditions, default accounts, and test-only authorization settings.",
            ]
        } else if key.contains("secret") || key.contains("credential") || key.contains("crypto") || key.contains("hash") || key.contains("암호") || key.contains("비밀") || key.contains("중요정보") {
            koItems = [
                "API 키, 토큰, 개인키, DB 비밀번호처럼 저장소에 남은 비밀값을 확인합니다.",
                "MD5, SHA1, DES, ECB 등 약한 해시/암호와 평문 전송 흔적을 찾습니다.",
                "환경변수 분리, 키 순환, 강한 KDF/암호화 알고리즘으로 바꿔야 할 위치를 표시합니다.",
            ]
            enItems = [
                "Checks repository remnants such as API keys, tokens, private keys, and database passwords.",
                "Finds weak hashes or crypto such as MD5, SHA1, DES, ECB, plus cleartext transport traces.",
                "Highlights where to move secrets to environment storage, rotate keys, or use stronger KDF and crypto algorithms.",
            ]
        } else if key.contains("dependency") || key.contains("sbom") || key.contains("manifest") || key.contains("version") || key.contains("supply") || key.contains("의존") || key.contains("공급망") || key.contains("매니페스트") {
            koItems = [
                "package.json, requirements, Gemfile, lockfile 등 의존성 매니페스트와 잠금 파일 상태를 확인합니다.",
                "고정되지 않은 버전, wildcard, latest, HTTP 소스, 원격 스크립트 즉시 실행 패턴을 찾습니다.",
                "SBOM 생성 준비성, 무결성 검증, OSV/Dependency-Check 연동 대상 파일을 표시합니다.",
            ]
            enItems = [
                "Checks dependency manifests and lockfiles such as package.json, requirements, Gemfile, and lock files.",
                "Finds unpinned versions, wildcards, latest, HTTP sources, and remote script execution patterns.",
                "Highlights SBOM readiness, integrity checks, and files suitable for OSV or Dependency-Check integration.",
            ]
        } else {
            koItems = [
                "소스코드, 설정 파일, 의존성 파일에서 이 기준과 연결되는 정적 근거를 수집합니다.",
                "런타임 호출 없이 확인 가능한 위험 패턴과 운영 전 제거해야 할 흔적을 찾습니다.",
                "조직 정책이나 운영 증적이 필요한 항목은 증적 확인 필요로 구분해 표시합니다.",
            ]
            enItems = [
                "Collects static evidence from source code, configuration, and dependency files mapped to this standard.",
                "Finds risky patterns and release-time leftovers that can be checked without runtime execution.",
                "Marks items that need organizational policy or operational evidence as evidence required.",
            ]
        }

        return language == .ko ? koItems : enItems
    }

    func evidenceSummary(language: AppLanguage) -> String {
        if isMapped {
            switch language {
            case .ko:
                return "선택한 폴더/파일의 소스 라인, 설정 파일, 의존성 매니페스트, 압축 해제 파일에서 발견된 로컬 증거를 사용합니다."
            case .en:
                return "Uses local evidence from source lines, configuration files, dependency manifests, and extracted archives in the selected targets."
            }
        }

        switch language {
        case .ko:
            return "로컬 파일에서 확인 가능한 단서를 사용하며, 실제 취약 여부는 런타임 테스트, 운영 설정, 정책 증적으로 추가 검토해야 합니다."
        case .en:
            return "Uses local files for signals; runtime testing, deployed configuration, and policy evidence are still needed for final validation."
        }
    }
}

struct AppStandardReference: Identifiable, Hashable {
    let title: String
    let url: String

    var id: String { url }
}

enum StandardAccent: String, Hashable {
    case blue
    case cyan
    case green
    case indigo
    case orange
    case red
    case slate
    case teal

    var color: Color {
        switch self {
        case .blue: return .blue
        case .cyan: return .cyan
        case .green: return .green
        case .indigo: return .indigo
        case .orange: return .orange
        case .red: return .red
        case .slate: return .secondary
        case .teal: return .teal
        }
    }
}

enum KODATheme {
    static var cardBackground: Color {
        Color(nsColor: .controlBackgroundColor)
    }

    static var insetBackground: Color {
        Color(nsColor: .windowBackgroundColor)
    }
}

private enum SecurityStandardLocalization {
    struct StandardText {
        let title: String
        let subtitle: String
        let scope: String
        let coverage: String
    }

    struct PublicationText {
        let ko: String
        let en: String
    }

    static let badgeText: [String: String] = [
        "기본": "Default",
        "국제 기준": "International",
        "국내 기준": "Korean Standard",
        "국내 인증": "Korean Certification",
        "국제 검증표준": "International Verification",
        "국제 테스트가이드": "International Testing Guide",
        "국제 프레임워크": "International Framework",
        "국제 성숙도모델": "International Maturity Model",
        "국제 원칙": "International Principles",
        "공급망": "Supply Chain",
    ]

    static let publicationText: [String: PublicationText] = [
        "owasp-top-10-2025": PublicationText(ko: "OWASP 재단 · 2025년판", en: "OWASP Foundation · 2025 edition"),
        "owasp-proactive-controls": PublicationText(ko: "OWASP 재단 · 2024년판", en: "OWASP Foundation · 2024 edition"),
        "owasp-api-security-2023": PublicationText(ko: "OWASP 재단 · 2023년판", en: "OWASP Foundation · 2023 edition"),
        "owasp-mobile-top-10-2024": PublicationText(ko: "OWASP 재단 · 2024년판", en: "OWASP Foundation · 2024 edition"),
        "owasp-masvs": PublicationText(ko: "OWASP 재단 · v2.1.0 · 2024-01-18", en: "OWASP Foundation · v2.1.0 · 2024-01-18"),
        "owasp-llm-top-10-2025": PublicationText(ko: "OWASP 재단 · 2025년판", en: "OWASP Foundation · 2025 edition"),
        "owasp-asvs-5": PublicationText(ko: "OWASP 재단 · v5.0.0 · 2025-05-30", en: "OWASP Foundation · v5.0.0 · 2025-05-30"),
        "owasp-wstg": PublicationText(ko: "OWASP 재단 · v4.2 · 2020-12-03", en: "OWASP Foundation · v4.2 · 2020-12-03"),
        "owasp-samm-2": PublicationText(ko: "OWASP 재단 · v2.0 · 2020년", en: "OWASP Foundation · v2.0 · 2020"),
        "owasp-scvs": PublicationText(ko: "OWASP 재단 · v1.0 · 2020-06-25", en: "OWASP Foundation · v1.0 · 2020-06-25"),
        "cwe-top-25-2025": PublicationText(ko: "MITRE CWE · 2025년판", en: "MITRE CWE · 2025 edition"),
        "sw-dev-security-49": PublicationText(ko: "행정안전부 / KISA · 2021-11-30", en: "MOIS / KISA · 2021-11-30"),
        "sw-dev-security-7-types": PublicationText(ko: "행정안전부 / KISA · 2021-11-30", en: "MOIS / KISA · 2021-11-30"),
        "kisa-secure-coding-guide": PublicationText(ko: "한국인터넷진흥원 · 2021-11-30", en: "KISA · 2021-11-30"),
    ]

    static let standardText: [String: StandardText] = [
        "local": StandardText(
            title: "Local Security Scan",
            subtitle: "Default profile for quickly checking secrets, dependencies, configuration, risky code patterns, screen quality, and prevention guardrails.",
            scope: "File-based static checks",
            coverage: "Fully automated local checks"
        ),
        "cis-macos-benchmark": StandardText(
            title: "CIS Apple macOS Benchmark",
            subtitle: "Maps this computer's endpoint posture to CIS macOS Benchmark Level 1 controls. Run it with the Check this computer button.",
            scope: "macOS host security posture",
            coverage: "Host scan required · External integration"
        ),
        "owasp-top-10-2025": StandardText(
            title: "OWASP Top 10:2025",
            subtitle: "Maps major web application risk categories to local rules.",
            scope: "Web application code and configuration",
            coverage: "Automatic file-based checks"
        ),
        "cwe-top-25-2025": StandardText(
            title: "CWE Top 25:2025",
            subtitle: "Checks the most dangerous CWE weaknesses with file-based static analysis.",
            scope: "Code weaknesses and dependency hygiene",
            coverage: "Automatic file-based checks"
        ),
        "owasp-api-security-2023": StandardText(
            title: "OWASP API Security Top 10:2023",
            subtitle: "Checks API route, authorization, resource, SSRF, and configuration risks.",
            scope: "API code and configuration",
            coverage: "Automatic file-based checks"
        ),
        "owasp-mobile-top-10-2024": StandardText(
            title: "OWASP Mobile Top 10:2024",
            subtitle: "Checks security risks visible in mobile app source and configuration.",
            scope: "Mobile source and configuration files",
            coverage: "External integration required"
        ),
        "owasp-masvs": StandardText(
            title: "OWASP MASVS",
            subtitle: "Maps the eight official MASVS control groups to related local mobile evidence.",
            scope: "Mobile source, manifests, plists, and release evidence",
            coverage: "External integration required"
        ),
        "owasp-llm-top-10-2025": StandardText(
            title: "OWASP LLM Top 10:2025",
            subtitle: "Checks LLM prompts, sensitive data flow, tool permissions, supply chain, and AI security-plan evidence.",
            scope: "AI/LLM application code and prevention evidence",
            coverage: "Automatic file-based checks"
        ),
        "sw-dev-security-49": StandardText(
            title: "Korean Software Development Security 49",
            subtitle: "Tracks all 49 MOIS/KISA implementation-stage weaknesses individually. Automatable items run as local rules; the rest are marked partial, manual-review, or unsupported.",
            scope: "Korean secure-coding criteria",
            coverage: "Automated and partial local checks; design, permission, and data-flow criteria need manual review or external SAST"
        ),
        "sw-dev-security-7-types": StandardText(
            title: "Korean Software Development Security 7 Types",
            subtitle: "Groups development-security weaknesses into seven broad Korean guide types.",
            scope: "Korean secure-coding types",
            coverage: "Automatic file-based checks"
        ),
        "kisa-secure-coding-guide": StandardText(
            title: "KISA Software Security Weakness Diagnostic Guide 2021",
            subtitle: "Checks the seven types and 49 implementation-stage security weaknesses in KISA's official 2021 diagnostic guide.",
            scope: "Korean secure-coding criteria",
            coverage: "Automated and partial local checks; design, permission, and data-flow criteria need manual review or external SAST"
        ),
        "electronic-financial-8": StandardText(
            title: "Electronic Financial Supervision 8 Vulnerabilities",
            subtitle: "Maps Korean electronic-finance public web-server review items to local rules.",
            scope: "Financial web-service code and configuration",
            coverage: "External integration required"
        ),
        "isms-p-28": StandardText(
            title: "ISMS-P 2.8 Development Security",
            subtitle: "Maps development-security controls to items that can be checked with local evidence.",
            scope: "Development, testing, and production handoff security",
            coverage: "Evidence review required"
        ),
        "owasp-asvs-5": StandardText(
            title: "OWASP ASVS 5.0",
            subtitle: "Shows all 17 official ASVS 5.0.0 chapters and attaches only directly related KODA heuristics.",
            scope: "Application security verification",
            coverage: "Partial evidence only · no requirement-level compliance claim"
        ),
        "owasp-wstg": StandardText(
            title: "OWASP WSTG v4.2",
            subtitle: "Shows all 12 official web-application testing areas and attaches static hints only where related file evidence exists.",
            scope: "Web security testing methodology",
            coverage: "Live-target testing required"
        ),
        "nist-ssdf": StandardText(
            title: "NIST SSDF SP 800-218",
            subtitle: "Checks secure software development practices and prevention-control readiness with local evidence.",
            scope: "Secure development process",
            coverage: "Evidence review required"
        ),
        "owasp-samm-2": StandardText(
            title: "OWASP SAMM 2",
            subtitle: "Maps the five official business functions to related repository evidence; KODA does not score the 15 practices or maturity levels.",
            scope: "Software assurance maturity",
            coverage: "Evidence review required"
        ),
        "cisa-secure-by-design": StandardText(
            title: "CISA Secure by Design",
            subtitle: "Maps Secure by Design principles to local prevention evidence, secure defaults, transparency artifacts, and ownership signals.",
            scope: "Product security prevention program",
            coverage: "Evidence review required"
        ),
        "nist-csf-2": StandardText(
            title: "NIST Cybersecurity Framework 2.0",
            subtitle: "Maps Govern, Identify, Protect, Detect, Respond, and Recover functions to local checks and organizational evidence.",
            scope: "Organizational cybersecurity risk management profile",
            coverage: "Evidence review required"
        ),
        "cisa-secure-software-attestation": StandardText(
            title: "CISA Secure Software Development Attestation",
            subtitle: "Organizes secure development environment, third-party component, verification, and vulnerability response evidence for attestation readiness.",
            scope: "SSDF-based secure development attestation evidence",
            coverage: "Evidence review required"
        ),
        "owasp-scvs": StandardText(
            title: "OWASP Software Component Verification Standard",
            subtitle: "Checks component inventory, SBOM, build environment, package management, component analysis, and provenance evidence.",
            scope: "Software supply-chain component assurance",
            coverage: "Evidence review required"
        ),
        "owasp-dependency-check": StandardText(
            title: "OWASP Dependency-Check Baseline",
            subtitle: "Dependency hygiene baseline for identifying known vulnerable components.",
            scope: "Dependency manifests and lockfiles",
            coverage: "External integration required"
        ),
        "owasp-dependency-track": StandardText(
            title: "OWASP Dependency-Track / SBOM Baseline",
            subtitle: "Checks local evidence for SBOM readiness, dependency tracking, and automation readiness.",
            scope: "SBOM and supply-chain management",
            coverage: "External integration required"
        ),
        "openssf-scorecard-baseline": StandardText(
            title: "OpenSSF Scorecard Baseline",
            subtitle: "Checks repository-file evidence for supply-chain posture from the Scorecard perspective.",
            scope: "Open source supply-chain posture",
            coverage: "External integration required"
        ),
        "cisa-kev-epss-priority": StandardText(
            title: "CISA KEV / FIRST EPSS Priority",
            subtitle: "Reprioritizes OSV results using known exploitation and exploit-probability intelligence.",
            scope: "Vulnerable dependency prioritization",
            coverage: "External integration required"
        ),
        "slsa-sigstore-baseline": StandardText(
            title: "SLSA / Sigstore Baseline",
            subtitle: "Checks release signing, provenance, and CI least-privilege readiness.",
            scope: "Build and release supply chain",
            coverage: "External integration required"
        ),
    ]

    static let categoryTitleText: [String: String] = [
        "비밀값": "Secrets",
        "의존성": "Dependencies",
        "설정": "Configuration",
        "코드 패턴": "Code Patterns",
        "예방 가드레일": "Prevention Guardrails",
        "인가 취약점": "Authorization Weaknesses",
        "리소스 제한": "Resource Limits",
        "API 설정": "API Configuration",
        "자격증명 저장": "Credential Storage",
        "통신 보안": "Communication Security",
        "앱 설정": "App Configuration",
        "모바일 의존성": "Mobile Dependencies",
        "안전한 개발 환경": "Secure Development Environment",
        "안전한 개발 실천": "Secure Development Practices",
        "제3자 구성요소": "Third-Party Components",
        "검증 및 대응": "Verification and Response",
        "입력 데이터 검증 및 표현": "Input Validation and Representation",
        "보안 기능": "Security Functions",
        "입력데이터 검증 및 표현": "Input Data Validation and Representation",
        "보안기능": "Security Features",
        "시간 및 상태": "Time and State",
        "에러 처리 및 코드 품질": "Error Handling and Code Quality",
        "캡슐화 및 API 오용": "Encapsulation and API Misuse",
        "에러 처리": "Error Handling",
        "에러처리": "Error Handling",
        "코드 오류": "Code Errors",
        "코드오류": "Code Error",
        "인젝션": "Injection",
        "크로스사이트 스크립팅": "Cross-Site Scripting",
        "파일 처리": "File Handling",
        "중요정보 보호": "Sensitive Information Protection",
        "파일 다운로드": "File Download",
        "디렉터리 리스팅": "Directory Listing",
        "레거시 게시판": "Legacy Bulletin Board",
        "서버 설정": "Server Configuration",
        "세션 관리": "Session Management",
        "보안 요구사항": "Security Requirements",
        "시큐어코딩": "Secure Coding",
        "시험 데이터 보호": "Test Data Protection",
        "소스 프로그램 관리": "Source Program Management",
        "운영 이관": "Production Handoff",
        "고객 보안 결과 책임": "Own Customer Security Outcomes",
        "안전한 기본값": "Secure Defaults",
        "투명성 및 책임성": "Transparency and Accountability",
        "경영진 주도": "Lead From the Top",
        "입력 검증": "Input Validation",
        "인증 및 세션": "Authentication and Session",
        "접근통제": "Access Control",
        "데이터 보호 및 암호": "Data Protection and Cryptography",
        "공급망": "Supply Chain",
        "설정 및 배포": "Configuration and Deployment",
        "인증": "Authentication",
        "인가": "Authorization",
        "입력값 검증": "Input Validation",
        "약한 암호": "Weak Cryptography",
        "Protect the Software": "Protect the Software",
        "Produce Well-Secured Software": "Produce Well-Secured Software",
        "Verify Security": "Verify Security",
        "Respond to Vulnerabilities": "Respond to Vulnerabilities",
        "Design": "Design",
        "Implementation": "Implementation",
        "Verification": "Verification",
        "Operations": "Operations",
        "매니페스트 위생": "Manifest Hygiene",
        "버전 고정": "Version Pinning",
        "의존성 소스": "Dependency Sources",
        "자동화 준비성": "Automation Readiness",
        "보안 정책": "Security Policy",
        "의존성 업데이트 자동화": "Dependency Update Automation",
        "정적 분석": "Static Analysis",
        "토큰 권한": "Token Permissions",
        "고정된 Actions": "Pinned Actions",
        "서명된 릴리스": "Signed Releases",
        "실제 악용 취약점": "Known Exploited Vulnerabilities",
        "악용 가능성": "Exploit Probability",
        "VEX 대응 추적": "VEX Response Tracking",
        "SBOM 추적": "SBOM Tracking",
        "빌드 출처 증명": "Build Provenance",
        "서명된 산출물": "Signed Artifacts",
        "Respond / Recover": "Respond / Recover",
        "SBOM 준비성": "SBOM Readiness",
        "버전 위생": "Version Hygiene",
        "CWE-79 XSS": "CWE-79 XSS",
        "CWE-89 SQL Injection": "CWE-89 SQL Injection",
        "CWE-78 OS Command Injection": "CWE-78 OS Command Injection",
        "CWE-22 Path Traversal": "CWE-22 Path Traversal",
        "CWE-352 CSRF": "CWE-352 CSRF",
        "CWE-798 Hard-coded Credentials": "CWE-798 Hard-coded Credentials",
        "인증 및 접근통제": "Authentication and Access Control",
        "암호 및 비밀정보": "Cryptography and Secrets",
        "보안 설정": "Security Configuration",
    ]

    static let categoryCoverageText: [String: String] = [
        "API 키, 토큰, 개인키로 보이는 값을 탐지합니다.": "Detects possible API keys, tokens, and private keys.",
        "고정되지 않은 버전, 락파일 누락, 안전하지 않은 소스를 확인합니다.": "Checks unpinned versions, missing lockfiles, and unsafe dependency sources.",
        ".env, debug, 권한 상승 컨테이너 설정을 확인합니다.": "Checks .env files, debug flags, and privileged container settings.",
        "XSS, SQL injection, command injection, path traversal 등을 확인합니다.": "Checks XSS, SQL injection, command injection, path traversal, and related patterns.",
        "SECURITY.md, 의존성 자동 업데이트, CI 보안 점검, SBOM 준비성을 확인합니다.": "Checks SECURITY.md, dependency update automation, CI security scans, and SBOM readiness.",
        "인가 우회, 파일 다운로드, 경로 접근 패턴을 확인합니다.": "Checks authorization bypass, file download, and path access patterns.",
        "비밀값, 약한 해시, 평문 전송 흔적을 확인합니다.": "Checks secrets, weak hashes, and cleartext transport traces.",
        "SQL, command, template, path traversal 입력 흐름을 확인합니다.": "Checks SQL, command, template, and path traversal input flows.",
        "debug, CORS, directory listing, WebDAV 설정을 확인합니다.": "Checks debug, CORS, directory listing, and WebDAV settings.",
        "의존성 위생과 OSV 확장 대상 매니페스트를 확인합니다.": "Checks dependency hygiene and manifests suitable for OSV extension.",
        "동적 SQL 조합과 입력 흐름을 확인합니다.": "Checks dynamic SQL construction and input flow.",
        "shell 명령 조합과 실행 패턴을 확인합니다.": "Checks shell command construction and execution patterns.",
        "경로 조작 및 파일 다운로드 위험을 확인합니다.": "Checks path manipulation and file download risks.",
        "하드코딩된 비밀값과 토큰을 확인합니다.": "Checks hard-coded secrets and tokens.",
        "키, 토큰, 비밀값 노출을 확인합니다.": "Checks exposed keys, tokens, and secrets.",
        "SQL, XSS, command, path traversal 패턴을 확인합니다.": "Checks SQL, XSS, command, and path traversal patterns.",
        "인증, 세션, 암호, 권한 흐름을 확인합니다.": "Checks authentication, session, cryptography, and authorization flows.",
        "임시 파일, 경쟁 상태 가능 패턴을 확인합니다.": "Checks temporary-file and possible race-condition patterns.",
        "오류 노출, 위험 API 사용 흔적을 확인합니다.": "Checks error disclosure and risky API usage traces.",
        "파일·명령·직렬화 API 오용을 확인합니다.": "Checks file, command, and serialization API misuse.",
        "입력값 기반 공격 패턴을 확인합니다.": "Checks attack patterns driven by user input.",
        "인증, 세션, 암호 사용 위험을 확인합니다.": "Checks authentication, session, and cryptography risks.",
        "임시 파일 및 상태 처리 위험을 확인합니다.": "Checks temporary-file and state-handling risks.",
        "디버그와 오류 노출 설정을 확인합니다.": "Checks debug and error-disclosure settings.",
        "위험 API와 오용 패턴을 확인합니다.": "Checks risky APIs and misuse patterns.",
        "SQL, command, template injection 패턴을 확인합니다.": "Checks SQL, command, and template injection patterns.",
        "DOM sink와 HTML 렌더링 위험을 확인합니다.": "Checks DOM sinks and HTML rendering risks.",
        "다운로드, 경로 조작, directory listing 위험을 확인합니다.": "Checks download, path manipulation, and directory listing risks.",
        "비밀값과 약한 암호 사용을 확인합니다.": "Checks secrets and weak cryptography use.",
        "동적 SQL 조합과 쿼리 입력 흐름을 확인합니다.": "Checks dynamic SQL construction and query input flow.",
        "DOM XSS와 HTML 출력 위험을 확인합니다.": "Checks DOM XSS and HTML output risks.",
        "경로 조작과 다운로드 핸들러 위험을 확인합니다.": "Checks path manipulation and download-handler risks.",
        "index 옵션과 listing 설정을 확인합니다.": "Checks index options and listing settings.",
        "WebDAV 활성화 설정을 확인합니다.": "Checks WebDAV enablement settings.",
        "오래된 게시판·업로드 흔적을 확인합니다.": "Checks traces of legacy bulletin-board and upload components.",
        "SQL과 명령 실행 위험을 확인합니다.": "Checks SQL and command-execution risks.",
        "브라우저 실행 스크립트 주입 위험을 확인합니다.": "Checks browser-side script injection risks.",
        "다운로드, 업로드, 경로 조작 위험을 확인합니다.": "Checks download, upload, and path manipulation risks.",
        "디렉터리 리스팅, WebDAV, debug 설정을 확인합니다.": "Checks directory listing, WebDAV, and debug settings.",
        "쿠키와 세션 설정 위험을 확인합니다.": "Checks cookie and session setting risks.",
        "비밀값, 설정, 의존성 관리 근거를 확인합니다.": "Checks evidence for secrets, configuration, and dependency management.",
        "코드 약점과 위험 API 사용을 확인합니다.": "Checks code weaknesses and risky API usage.",
        ".env, 샘플 비밀값, 테스트 credential을 확인합니다.": "Checks .env files, sample secrets, and test credentials.",
        "락파일, 의존성, 설정 위생을 확인합니다.": "Checks lockfile, dependency, and configuration hygiene.",
        "debug와 위험 설정 잔존 여부를 확인합니다.": "Checks whether debug and risky settings remain.",
        "입력값 검증과 인코딩 위험을 확인합니다.": "Checks input validation and encoding risks.",
        "쿠키, 세션, 인증 처리 위험을 확인합니다.": "Checks cookie, session, and authentication handling risks.",
        "파일·라우트 접근통제 위험을 확인합니다.": "Checks file and route access-control risks.",
        "의존성 및 무결성 설정을 확인합니다.": "Checks dependency and integrity settings.",
        "CORS, debug, directory listing, WebDAV를 확인합니다.": "Checks CORS, debug, directory listing, and WebDAV.",
        "인증·세션 관련 코드 패턴을 확인합니다.": "Checks authentication and session code patterns.",
        "파일 접근과 라우트 접근 위험을 확인합니다.": "Checks file and route access risks.",
        "XSS, SQL, command, traversal 패턴을 확인합니다.": "Checks XSS, SQL, command, and traversal patterns.",
        "약한 해시와 비밀값 노출을 확인합니다.": "Checks weak hashes and exposed secrets.",
        "비밀값, 의존성 위생, 보안 정책 문서화 상태를 확인합니다.": "Checks secrets, dependency hygiene, and security-policy documentation.",
        "보안 설정, 코드 약점, CI 보안 점검 준비성을 확인합니다.": "Checks security configuration, code weaknesses, and CI security-scan readiness.",
        "로컬 룰 기반 검증 증거와 자동화 가드레일을 수집합니다.": "Collects local-rule verification evidence and automation guardrails.",
        "취약 의존성 대응을 위한 매니페스트, SBOM, 업데이트 자동화를 확인합니다.": "Checks manifests, SBOM, and update automation for vulnerable-dependency response.",
        "보안 요구와 예방 정책 문서화 근거를 확인합니다.": "Checks evidence for security requirements and preventive policy documentation.",
        "시큐어코딩, 의존성 위생, CI 보안 점검 준비성을 확인합니다.": "Checks secure-coding, dependency hygiene, and CI security-scan readiness.",
        "정적 점검 근거와 자동화 가드레일을 수집합니다.": "Collects local static-check evidence and automation guardrails.",
        "운영 이관 전 debug, 비밀값 잔존, SBOM 준비성을 확인합니다.": "Checks debug remnants, secret remnants, and SBOM readiness before production handoff.",
        "package.json, requirements, lockfile 상태를 확인합니다.": "Checks package.json, requirements, and lockfile status.",
        "고정되지 않은 버전과 wildcard를 확인합니다.": "Checks unpinned versions and wildcards.",
        "평문 또는 원격 실행 의존성 소스를 확인합니다.": "Checks cleartext or remote-execution dependency sources.",
        "매니페스트, 락파일, SBOM 산출물 존재 여부를 확인합니다.": "Checks manifests, lockfiles, and whether an SBOM artifact exists.",
        "고정되지 않은 의존성과 wildcard를 확인합니다.": "Checks unpinned dependencies and wildcards.",
        "안전하지 않은 다운로드와 원격 실행 패턴을 확인합니다.": "Checks unsafe download and remote-execution patterns.",
        "Dependabot/Renovate와 CI 보안 점검 workflow를 확인합니다.": "Checks Dependabot/Renovate and CI security-scan workflows.",
    ]
}

struct SecurityStandardsGridView: View {
    let standards: [AppSecurityStandard]
    let minimumCardWidth: CGFloat
    let language: AppLanguage
    let onSelect: (AppSecurityStandard) -> Void

    var body: some View {
        ScrollView {
            LazyVGrid(
                columns: [GridItem(.adaptive(minimum: minimumCardWidth, maximum: 420), spacing: 14)],
                alignment: .leading,
                spacing: 14
            ) {
                ForEach(standards) { standard in
                    Button {
                        onSelect(standard)
                    } label: {
                        SecurityStandardCard(standard: standard, language: language)
                    }
                    .buttonStyle(.plain)
                }
            }
            .padding(22)
        }
        .background(Color(nsColor: .windowBackgroundColor))
    }
}

struct ScanResultsGroupedView: View {
    let reports: [ScanReportItem]
    let standards: [AppSecurityStandard]
    let minimumCardWidth: CGFloat
    let language: AppLanguage
    let onSelectReport: (ScanReportItem) -> Void
    let onSelectStandard: (AppSecurityStandard) -> Void

    private var overallReport: ScanReportItem? {
        reports.first(where: \.isOverall)
    }

    private var standardReports: [ScanReportItem] {
        reports.filter { !$0.isOverall }
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 22) {
                if reports.isEmpty {
                    emptyState
                }

                groupedSection(title: language.overallResultsTitle, subtitle: language.overallResultsSubtitle) {
                    if let overallReport {
                        Button {
                            onSelectReport(overallReport)
                        } label: {
                            ScanReportNavigationCard(report: overallReport, language: language)
                        }
                        .buttonStyle(.plain)
                    } else {
                        DisabledResultCard(
                            title: language.overallResultsTitle,
                            subtitle: language == .ko
                                ? "점검 실행 후 전체 결과 화면으로 이동할 수 있습니다."
                                : "Run a scan to open the overall results screen.",
                            icon: "rectangle.stack"
                        )
                    }
                }

                groupedSection(title: language.standardsResultsTitle, subtitle: language.standardsResultsSubtitle) {
                    if standardReports.isEmpty {
                        LazyVGrid(columns: gridColumns, alignment: .leading, spacing: 14) {
                            ForEach(standards) { standard in
                                Button {
                                    onSelectStandard(standard)
                                } label: {
                                    SecurityStandardCard(standard: standard, language: language)
                                }
                                .buttonStyle(.plain)
                            }
                        }
                    } else {
                        LazyVGrid(columns: gridColumns, alignment: .leading, spacing: 14) {
                            ForEach(standardReports) { report in
                                Button {
                                    onSelectReport(report)
                                } label: {
                                    ScanReportNavigationCard(report: report, language: language)
                                }
                                .buttonStyle(.plain)
                            }
                        }
                    }
                }
            }
            .padding(22)
        }
        .background(Color(nsColor: .windowBackgroundColor))
    }

    private var gridColumns: [GridItem] {
        [GridItem(.adaptive(minimum: minimumCardWidth, maximum: 420), spacing: 14)]
    }

    private var emptyState: some View {
        HStack(spacing: 12) {
            Image(systemName: "play.circle")
                .font(.title2.weight(.semibold))
                .foregroundStyle(.secondary)

            VStack(alignment: .leading, spacing: 4) {
                Text(language.resultCardsEnabledTitle)
                    .font(.headline)
                Text(language.resultCardsEnabledSubtitle)
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(KODATheme.cardBackground)
        .clipShape(RoundedRectangle(cornerRadius: 8))
        .overlay {
            RoundedRectangle(cornerRadius: 8)
                .stroke(Color(nsColor: .separatorColor), lineWidth: 1)
        }
    }

    private func groupedSection<Content: View>(
        title: String,
        subtitle: String,
        @ViewBuilder content: () -> Content
    ) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            VStack(alignment: .leading, spacing: 4) {
                Text(title)
                    .font(.title3.weight(.bold))
                Text(subtitle)
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
            content()
        }
    }
}

private struct ScanReportNavigationCard: View {
    let report: ScanReportItem
    let language: AppLanguage

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: report.icon)
                    .font(.system(size: 24, weight: .semibold))
                    .foregroundStyle(report.accent.color)
                    .frame(width: 34, height: 34)

                VStack(alignment: .leading, spacing: 5) {
                    Text(report.title(language: language))
                        .font(.headline)
                        .foregroundStyle(.primary)
                        .lineLimit(2)
                        .fixedSize(horizontal: false, vertical: true)

                    Text(report.badge(language: language))
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(report.accent.color)
                }

                Spacer(minLength: 8)

                Image(systemName: "arrow.up.right.square")
                    .foregroundStyle(.secondary)
            }

            Text(report.subtitle(language: language))
                .font(.callout)
                .foregroundStyle(.secondary)
                .lineLimit(2)
                .fixedSize(horizontal: false, vertical: true)

            HStack(spacing: 12) {
                Label(language.findingCountText(report.findingCount), systemImage: "list.bullet.rectangle")
                Label(language.riskScoreText(report.riskScore), systemImage: "gauge.with.dots.needle.50percent")
            }
            .font(.caption)
            .foregroundStyle(.secondary)
        }
        .padding(16)
        .frame(maxWidth: .infinity, minHeight: 156, alignment: .topLeading)
        .background(KODATheme.cardBackground)
        .overlay(alignment: .leading) {
            Rectangle()
                .fill(report.accent.color)
                .frame(width: 4)
        }
        .clipShape(RoundedRectangle(cornerRadius: 8))
        .overlay {
            RoundedRectangle(cornerRadius: 8)
                .stroke(Color(nsColor: .separatorColor), lineWidth: 1)
        }
    }
}

private struct DisabledResultCard: View {
    let title: String
    let subtitle: String
    let icon: String

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: icon)
                .font(.title2.weight(.semibold))
                .foregroundStyle(.secondary)
                .frame(width: 34, height: 34)

            VStack(alignment: .leading, spacing: 5) {
                Text(title)
                    .font(.headline)
                Text(subtitle)
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }

            Spacer()
        }
        .padding(16)
        .frame(maxWidth: .infinity, minHeight: 96, alignment: .leading)
        .background(KODATheme.cardBackground.opacity(0.65))
        .clipShape(RoundedRectangle(cornerRadius: 8))
        .overlay {
            RoundedRectangle(cornerRadius: 8)
                .stroke(Color(nsColor: .separatorColor), lineWidth: 1)
        }
    }
}

private struct SecurityStandardCard: View {
    let standard: AppSecurityStandard
    let language: AppLanguage

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: standard.icon)
                    .font(.system(size: 24, weight: .semibold))
                    .foregroundStyle(standard.accent.color)
                    .frame(width: 34, height: 34)

                VStack(alignment: .leading, spacing: 5) {
                    Text(standard.title(language: language))
                        .font(.headline)
                        .foregroundStyle(.primary)
                        .lineLimit(2)
                        .fixedSize(horizontal: false, vertical: true)

                    Text(standard.badge(language: language))
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(standard.accent.color)
                }

                Spacer(minLength: 8)

                Image(systemName: "chevron.right")
                    .foregroundStyle(.secondary)
            }

            Text(standard.subtitle(language: language))
                .font(.callout)
                .foregroundStyle(.secondary)
                .lineLimit(3)
                .fixedSize(horizontal: false, vertical: true)

            if let publication = standard.publication(language: language) {
                Label(publication, systemImage: "calendar")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            HStack(spacing: 8) {
                Label("\(standard.supportedCategoryCount)/\(standard.categories.count)", systemImage: "checklist")
                Text(standard.coverage(language: language))
            }
            .font(.caption)
            .foregroundStyle(.secondary)
        }
        .padding(16)
        .frame(maxWidth: .infinity, minHeight: 168, alignment: .topLeading)
        .background(KODATheme.cardBackground)
        .overlay(alignment: .leading) {
            Rectangle()
                .fill(standard.accent.color)
                .frame(width: 4)
        }
        .clipShape(RoundedRectangle(cornerRadius: 8))
        .overlay {
            RoundedRectangle(cornerRadius: 8)
                .stroke(Color(nsColor: .separatorColor), lineWidth: 1)
        }
    }
}

struct SecurityStandardDetailScreen: View {
    let standard: AppSecurityStandard
    @Binding var language: AppLanguage
    let onBack: () -> Void
    let onHelp: () -> Void
    @State private var expandedCategoryIDs: Set<String> = []

    var body: some View {
        GeometryReader { proxy in
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    header(width: proxy.size.width)
                    content(width: proxy.size.width)
                }
            }
            .background(Color(nsColor: .windowBackgroundColor))
        }
    }

    private func header(width: CGFloat) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            KODAScreenTopBar(language: $language, onBack: onBack) {
                EmptyView()
            } actions: {
                Button {
                    onHelp()
                } label: {
                    Label(language.helpTitle, systemImage: "questionmark.circle")
                }
                .buttonStyle(.borderless)
                .foregroundStyle(.white)
            }

            VStack(alignment: .leading, spacing: 18) {
                HStack(alignment: .top, spacing: 16) {
                    Image(systemName: standard.icon)
                        .font(.system(size: scaledIconSize(width), weight: .bold))
                        .foregroundStyle(standard.accent.color)
                        .frame(width: scaledIconSize(width) + 12, height: scaledIconSize(width) + 12)

                    VStack(alignment: .leading, spacing: 8) {
                        Text(standard.title(language: language))
                            .font(.system(size: scaledTitleSize(width), weight: .bold))
                            .foregroundStyle(.white)
                            .lineLimit(2)
                            .fixedSize(horizontal: false, vertical: true)

                        Text(standard.subtitle(language: language))
                            .font(.title3)
                            .foregroundStyle(.white.opacity(0.75))
                            .fixedSize(horizontal: false, vertical: true)
                    }

                    Spacer()
                }

                Text("\(standard.badge(language: language)) | \(language.mappedItemsText(mapped: standard.supportedCategoryCount, total: standard.categories.count))")
                    .font(.callout.weight(.semibold))
                    .foregroundStyle(.white.opacity(0.8))
            }
            .padding(.horizontal, horizontalPadding(width))
            .padding(.top, 12)
            .padding(.bottom, max(28, width * 0.035))
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color(red: 0.04, green: 0.07, blue: 0.13))
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func content(width: CGFloat) -> some View {
        VStack(alignment: .leading, spacing: 20) {
            LazyVGrid(columns: detailColumns(width), spacing: 14) {
                DetailSummaryTile(title: language.scopeTitle, value: standard.scope(language: language))
                DetailSummaryTile(title: language.automationTitle, value: standard.coverage(language: language))
                if let publication = standard.publication(language: language) {
                    DetailSummaryTile(title: language.publicationTitle, value: publication)
                }
            }

            section(title: language.criteriaTitle) {
                LazyVStack(alignment: .leading, spacing: 10) {
                    ForEach(standard.categories) { category in
                        StandardCategoryAccordion(
                            category: category,
                            language: language,
                            isExpanded: categoryExpansionBinding(for: category.id)
                        )
                    }
                }
            }

            section(title: language.referenceTitle) {
                VStack(alignment: .leading, spacing: 10) {
                    ForEach(standard.references) { reference in
                        Link(destination: URL(string: reference.url)!) {
                            HStack {
                                Image(systemName: "link")
                                Text(reference.title)
                                Spacer()
                                Text(reference.url)
                                    .foregroundStyle(.secondary)
                                    .lineLimit(1)
                                    .truncationMode(.middle)
                            }
                            .padding(.horizontal, 14)
                            .padding(.vertical, 11)
                            .background(KODATheme.cardBackground)
                            .clipShape(RoundedRectangle(cornerRadius: 8))
                            .overlay {
                                RoundedRectangle(cornerRadius: 8)
                                    .stroke(Color(nsColor: .separatorColor), lineWidth: 1)
                            }
                        }
                        .buttonStyle(.plain)
                    }
                }
            }
        }
        .padding(.horizontal, horizontalPadding(width))
        .padding(.vertical, 24)
    }

    private func section<Content: View>(title: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(title)
                .font(.title2.weight(.bold))
            content()
        }
    }

    private func categoryExpansionBinding(for id: String) -> Binding<Bool> {
        Binding(
            get: { expandedCategoryIDs.contains(id) },
            set: { isExpanded in
                if isExpanded {
                    expandedCategoryIDs.insert(id)
                } else {
                    expandedCategoryIDs.remove(id)
                }
            }
        )
    }

    private func detailColumns(_ width: CGFloat) -> [GridItem] {
        let minimum = width > 1120 ? CGFloat(330) : CGFloat(280)
        return [GridItem(.adaptive(minimum: minimum), spacing: 12)]
    }

    private func horizontalPadding(_ width: CGFloat) -> CGFloat {
        min(46, max(20, width * 0.04))
    }

    private func scaledTitleSize(_ width: CGFloat) -> CGFloat {
        min(42, max(28, width * 0.038))
    }

    private func scaledIconSize(_ width: CGFloat) -> CGFloat {
        min(48, max(34, width * 0.04))
    }
}

private struct DetailSummaryTile: View {
    let title: String
    let value: String

    var body: some View {
        VStack(alignment: .leading, spacing: 9) {
            Text(title)
                .font(.caption.weight(.bold))
                .foregroundStyle(.secondary)
            Text(value)
                .font(.body)
                .foregroundStyle(.primary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(16)
        .frame(maxWidth: .infinity, minHeight: 112, alignment: .topLeading)
        .background(KODATheme.cardBackground)
        .clipShape(RoundedRectangle(cornerRadius: 8))
        .overlay {
            RoundedRectangle(cornerRadius: 8)
                .stroke(Color(nsColor: .separatorColor), lineWidth: 1)
        }
    }
}

struct HelpGuideScreen: View {
    let route: HelpGuideRoute
    @Binding var language: AppLanguage
    let onBack: () -> Void

    private var guideStandard: AppSecurityStandard? {
        route.standard ?? SecurityStandardCatalog.all.first { $0.id == "local" }
    }

    var body: some View {
        GeometryReader { proxy in
            VStack(spacing: 0) {
                header(width: proxy.size.width)

                ScrollView {
                    VStack(alignment: .leading, spacing: 22) {
                        LazyVGrid(columns: detailColumns(proxy.size.width), spacing: 14) {
                            DetailSummaryTile(title: language.scopeTitle, value: route.standard?.scope(language: language) ?? overallScope)
                            DetailSummaryTile(title: language.automationTitle, value: route.standard?.coverage(language: language) ?? overallCoverage)
                            if let publication = route.standard?.publication(language: language) {
                                DetailSummaryTile(title: language.publicationTitle, value: publication)
                            }
                            DetailSummaryTile(title: language.riskFormulaTitle, value: language.riskFormulaDescription)
                        }

                        section(title: language.guideSummaryTitle) {
                            Text(message)
                                .font(.callout)
                                .foregroundStyle(.secondary)
                                .fixedSize(horizontal: false, vertical: true)
                                .padding(16)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .background(KODATheme.cardBackground)
                                .clipShape(RoundedRectangle(cornerRadius: 8))
                                .overlay {
                                    RoundedRectangle(cornerRadius: 8)
                                        .stroke(Color(nsColor: .separatorColor), lineWidth: 1)
                                }
                        }

                        section(title: language.checkedItemsTitle) {
                            if checkedCategories.isEmpty {
                                Text(language.noCheckedItemsTitle)
                                    .font(.callout)
                                    .foregroundStyle(.secondary)
                            } else {
                                LazyVGrid(columns: detailColumns(proxy.size.width), spacing: 12) {
                                    ForEach(checkedCategories) { category in
                                        HelpCriteriaCard(category: category, language: language)
                                    }
                                }
                            }
                        }

                        section(title: language.guideUsageTitle) {
                            Text(language.guideUsageDescription)
                                .font(.callout)
                                .foregroundStyle(.secondary)
                                .fixedSize(horizontal: false, vertical: true)
                                .padding(16)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .background(KODATheme.cardBackground)
                                .clipShape(RoundedRectangle(cornerRadius: 8))
                                .overlay {
                                    RoundedRectangle(cornerRadius: 8)
                                        .stroke(Color(nsColor: .separatorColor), lineWidth: 1)
                                }
                        }

                        if let standard = guideStandard {
                            section(title: language.referenceTitle) {
                                VStack(alignment: .leading, spacing: 10) {
                                    ForEach(standard.references) { reference in
                                        Link(destination: URL(string: reference.url)!) {
                                            HStack {
                                                Image(systemName: "link")
                                                Text(reference.title)
                                                Spacer()
                                                Text(reference.url)
                                                    .foregroundStyle(.secondary)
                                                    .lineLimit(1)
                                                    .truncationMode(.middle)
                                            }
                                            .padding(.horizontal, 14)
                                            .padding(.vertical, 11)
                                            .background(KODATheme.cardBackground)
                                            .clipShape(RoundedRectangle(cornerRadius: 8))
                                            .overlay {
                                                RoundedRectangle(cornerRadius: 8)
                                                    .stroke(Color(nsColor: .separatorColor), lineWidth: 1)
                                            }
                                        }
                                        .buttonStyle(.plain)
                                    }
                                }
                            }
                        }
                    }
                    .padding(.horizontal, horizontalPadding(proxy.size.width))
                    .padding(.vertical, 24)
                }
            }
            .background(Color(nsColor: .windowBackgroundColor))
        }
    }

    private func header(width: CGFloat) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            KODAScreenTopBar(language: $language, onBack: onBack) {
                EmptyView()
            } actions: {
                EmptyView()
            }

            HStack(alignment: .top, spacing: 16) {
                Image(systemName: guideStandard?.icon ?? "questionmark.circle")
                    .font(.system(size: min(48, max(34, width * 0.04)), weight: .bold))
                    .foregroundStyle(guideStandard?.accent.color ?? .blue)
                    .frame(width: 60, height: 60)

                VStack(alignment: .leading, spacing: 8) {
                    Text(language.helpGuideTitle)
                        .font(.system(size: min(42, max(28, width * 0.038)), weight: .bold))
                        .foregroundStyle(.white)

                    Text(displayTitle)
                        .font(.title3)
                        .foregroundStyle(.white.opacity(0.78))
                        .fixedSize(horizontal: false, vertical: true)
                }

                Spacer()
            }
            .padding(.horizontal, horizontalPadding(width))
            .padding(.top, 12)
            .padding(.bottom, max(28, width * 0.035))
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color(red: 0.04, green: 0.07, blue: 0.13))
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var message: String {
        let standardName = displayTitle

        switch language {
        case .ko:
            return "\(standardName) 기준의 점검 가이드입니다. 아래 항목은 KODA가 로컬 파일과 설정에서 확인하는 범위이며, 자동 점검 항목과 별도 검토가 필요한 항목을 함께 보여줍니다."
        case .en:
            return "This guide explains what KODA checks for \(standardName). The items below show what can be inspected from local files and configuration, including locally automated and separately reviewed areas."
        }
    }

    private var checkedCategories: [AppStandardCategory] {
        guideStandard?.categories ?? []
    }

    private var displayTitle: String {
        if let standard = route.standard {
            return standard.title(language: language)
        }
        switch language {
        case .ko: return "전체 조회"
        case .en: return "Overall Results"
        }
    }

    private var overallScope: String {
        switch language {
        case .ko: return "전체 로컬 보안 점검 결과"
        case .en: return "All local security scan results"
        }
    }

    private var overallCoverage: String {
        switch language {
        case .ko: return "기준 제한 없이 전체 자동 점검"
        case .en: return "All automated checks without standard filtering"
        }
    }

    private func section<Content: View>(title: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(title)
                .font(.title2.weight(.bold))
            content()
        }
    }

    private func detailColumns(_ width: CGFloat) -> [GridItem] {
        let minimum = width > 1120 ? CGFloat(330) : CGFloat(280)
        return [GridItem(.adaptive(minimum: minimum), spacing: 12)]
    }

    private func horizontalPadding(_ width: CGFloat) -> CGFloat {
        min(46, max(20, width * 0.04))
    }
}

private struct HelpCriteriaCard: View {
    let category: AppStandardCategory
    let language: AppLanguage

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Text(category.title(language: language))
                    .font(.callout.weight(.semibold))
                    .lineLimit(2)
                    .fixedSize(horizontal: false, vertical: true)

                Spacer(minLength: 8)

                Text(category.isMapped ? language.localCheckBadge : language.evidenceRequiredBadge)
                    .font(.caption.weight(.bold))
                    .foregroundStyle(category.isMapped ? .green : .orange)
            }

            HelpInfoBlock(title: language.checkMethodTitle, text: category.coverage(language: language))

            VStack(alignment: .leading, spacing: 6) {
                Text(language.detailedChecksTitle)
                    .font(.caption.weight(.bold))
                    .foregroundStyle(.secondary)

                ForEach(category.detailItems(language: language), id: \.self) { item in
                    HStack(alignment: .top, spacing: 7) {
                        Image(systemName: "checkmark.circle.fill")
                            .font(.caption2.weight(.bold))
                            .foregroundStyle(category.isMapped ? .green : .orange)
                            .padding(.top, 2)
                        Text(item)
                            .font(.caption)
                            .foregroundStyle(.primary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }

            HelpInfoBlock(title: language.evidenceSourceTitle, text: category.evidenceSummary(language: language))
        }
        .padding(14)
        .frame(maxWidth: .infinity, minHeight: 220, alignment: .topLeading)
        .background(KODATheme.cardBackground)
        .clipShape(RoundedRectangle(cornerRadius: 8))
        .overlay {
            RoundedRectangle(cornerRadius: 8)
                .stroke(Color(nsColor: .separatorColor), lineWidth: 1)
        }
    }
}

private struct HelpInfoBlock: View {
    let title: String
    let text: String

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title)
                .font(.caption.weight(.bold))
                .foregroundStyle(.secondary)
            Text(text)
                .font(.caption)
                .foregroundStyle(.primary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}

private struct StandardCategoryAccordion: View {
    let category: AppStandardCategory
    let language: AppLanguage
    @Binding var isExpanded: Bool

    var body: some View {
        DisclosureGroup(isExpanded: $isExpanded) {
            VStack(alignment: .leading, spacing: 12) {
                Text(category.coverage(language: language))
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)

                VStack(alignment: .leading, spacing: 6) {
                    Text(language.detailedChecksTitle)
                        .font(.caption.weight(.bold))
                        .foregroundStyle(.secondary)

                    ForEach(category.detailItems(language: language), id: \.self) { item in
                        HStack(alignment: .top, spacing: 7) {
                            Image(systemName: "checkmark.circle.fill")
                                .font(.caption2.weight(.bold))
                                .foregroundStyle(category.isMapped ? .green : .orange)
                                .padding(.top, 2)
                            Text(item)
                                .font(.caption)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                }

                HelpInfoBlock(
                    title: language.evidenceSourceTitle,
                    text: category.evidenceSummary(language: language)
                )
            }
            .padding(.top, 8)
        } label: {
            HStack(spacing: 8) {
                Text(category.title(language: language))
                    .font(.headline)
                Spacer()
                Text(category.isMapped ? language.localCheckBadge : language.evidenceRequiredBadge)
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(category.isMapped ? .green : .orange)
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .background(KODATheme.cardBackground)
        .clipShape(RoundedRectangle(cornerRadius: 8))
        .overlay {
            RoundedRectangle(cornerRadius: 8)
                .stroke(Color(nsColor: .separatorColor), lineWidth: 1)
        }
    }
}

enum SecurityStandardCatalog {
    static let all: [AppSecurityStandard] = [
        AppSecurityStandard(
            id: "local",
            title: "로컬 보안 점검",
            subtitle: "비밀값, 의존성, 설정, 코드 패턴, 화면 품질, 예방 가드레일을 빠르게 확인하는 기본 프로파일입니다.",
            scope: "파일 기반 정적 점검",
            coverage: "전체 자동 점검",
            badge: "기본",
            icon: "magnifyingglass",
            accent: .blue,
            categories: [
                category("secrets", "비밀값", "API 키, 토큰, 개인키로 보이는 값을 탐지합니다."),
                category("dependencies", "의존성", "고정되지 않은 버전, 락파일 누락, 안전하지 않은 소스를 확인합니다."),
                category("configuration", "설정", ".env, debug, 권한 상승 컨테이너 설정을 확인합니다."),
                category("code", "코드 패턴", "XSS, SQL injection, command injection, path traversal 등을 확인합니다."),
                category("screen_quality", "화면 품질", "HTML/JSP/CLX/JS/Vue/React 화면 소스의 접근성, 반응형, 링크, 노출 위험을 확인합니다."),
                category("prevention", "예방 가드레일", "SECURITY.md, 의존성 자동 업데이트, CI 보안 점검, SBOM 준비성을 확인합니다."),
                category("api-security", "API 보안", "API 인증, 객체/기능 권한, mass assignment, rate limit, 외부 API timeout을 확인합니다."),
                category("auth-session", "인증 및 세션", "JWT 검증, none 알고리즘, 긴 세션 만료, 쿠키/CSRF 설정을 확인합니다."),
                category("cloud-iac", "Cloud/IaC", "Docker/Compose, Kubernetes, Terraform 노출, 암호화, runtime 하드닝을 확인합니다."),
                category("privacy", "개인정보 및 PII", "개인정보 로그, 민감 데이터 프롬프트, 백업/파일 공유, 데이터 맵 준비성을 확인합니다."),
                category("component-verification", "구성요소 검증", "OWASP SCVS 관점의 의존성, SBOM, VEX, 출처 증명 준비성을 확인합니다."),
                category("exception-governance", "예외 거버넌스", "koda-ignore 예외의 사유, 담당자, 만료일과 만료 상태를 확인합니다."),
                category("roadmap-evidence", "로드맵 및 증적", "보안 로드맵과 릴리스·점검·승인 증적 보관 대장을 확인합니다."),
                category("headers-container-hardening", "헤더 및 컨테이너 하드닝", "보안 헤더 기준, directory listing/WebDAV, 컨테이너 capability와 runtime 기준을 확인합니다.")
            ],
            references: [
                reference("KODA GitLab", "https://gitlab.aigov.go.kr/y2kthr/koda")
            ]
        ),
        AppSecurityStandard(
            id: "cis-macos-benchmark",
            title: "CIS Apple macOS 벤치마크",
            subtitle: "이 컴퓨터(엔드포인트)의 보안 상태를 CIS macOS 벤치마크 Level 1 통제에 매핑합니다. '이 컴퓨터 점검' 버튼으로 실행합니다.",
            scope: "macOS 호스트 보안 상태",
            coverage: "호스트 점검 필요 · 외부 연동 필요",
            badge: "국제 기준",
            icon: "lock.laptopcomputer",
            accent: .teal,
            categories: [
                category("disk-encryption", "디스크 암호화", "FileVault 디스크 암호화가 켜져 있는지 확인합니다."),
                category("system-integrity", "시스템 무결성", "SIP와 Gatekeeper가 켜져 있는지 확인합니다."),
                category("network", "네트워크", "응용프로그램 방화벽과 스텔스 모드를 확인합니다."),
                category("software-updates", "소프트웨어 업데이트", "보안 응답 및 시스템 파일 자동 설치 여부를 확인합니다."),
                category("account-lock", "계정 및 잠금", "자동 로그인, 게스트 계정, 화면 잠금 비밀번호 설정을 확인합니다.")
            ],
            references: [
                reference("CIS Apple macOS Benchmarks", "https://www.cisecurity.org/benchmark/apple_os")
            ]
        ),
        AppSecurityStandard(
            id: "owasp-top-10-2025",
            title: "OWASP Top 10:2025",
            subtitle: "웹 애플리케이션 주요 위험 범주를 로컬 룰에 매핑한 프로파일입니다.",
            scope: "웹 애플리케이션 코드 및 설정",
            coverage: "자동 점검",
            badge: "국제 기준",
            icon: "shield.lefthalf.filled",
            accent: .cyan,
            categories: [
                category("broken-access-control", "Broken Access Control", "인가 우회, 파일 다운로드, 경로 접근 패턴을 확인합니다."),
                category("cryptographic-failures", "Cryptographic Failures", "비밀값, 약한 해시, 평문 전송 흔적을 확인합니다."),
                category("injection", "Injection", "SQL, command, template, path traversal 입력 흐름을 확인합니다."),
                category("security-misconfiguration", "Security Misconfiguration", "debug, CORS, directory listing, WebDAV 설정을 확인합니다."),
                category("vulnerable-components", "Vulnerable Components", "의존성 위생과 OSV 확장 대상 매니페스트를 확인합니다.")
            ],
            references: [
                reference("OWASP Top Ten Project", "https://owasp.org/www-project-top-ten/")
            ]
        ),
        AppSecurityStandard(
            id: "cwe-top-25-2025",
            title: "CWE Top 25:2025",
            subtitle: "가장 위험한 CWE 약점을 파일 기반 정적 점검으로 확인합니다.",
            scope: "코드 약점 및 의존성 위생",
            coverage: "자동 점검",
            badge: "국제 기준",
            icon: "list.number",
            accent: .orange,
            categories: cweCategories(),
            references: [
                reference("MITRE CWE Top 25:2025", "https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html")
            ]
        ),
        AppSecurityStandard(
            id: "owasp-api-security-2023",
            title: "OWASP API Security Top 10:2023",
            subtitle: "API 라우트, 인가, 리소스, SSRF, 설정 위험을 확인합니다.",
            scope: "API 코드 및 설정",
            coverage: "자동 점검",
            badge: "국제 기준",
            icon: "point.3.connected.trianglepath.dotted",
            accent: .teal,
            categories: [
                category("authorization", "인가 취약점", "객체·기능 수준 접근통제 누락 위험을 확인합니다."),
                category("resource", "리소스 제한", "요청 크기, 반복 처리, 외부 요청 위험을 확인합니다."),
                category("ssrf", "SSRF", "사용자 입력 URL 요청 패턴을 확인합니다."),
                category("misconfiguration", "API 설정", "CORS, debug, 오류 노출 설정을 확인합니다.")
            ],
            references: [
                reference("OWASP API Security Project", "https://owasp.org/API-Security/")
            ]
        ),
        AppSecurityStandard(
            id: "owasp-mobile-top-10-2024",
            title: "OWASP Mobile Top 10:2024",
            subtitle: "모바일 앱 소스와 설정에서 확인 가능한 보안 위험을 점검합니다.",
            scope: "모바일 소스 및 설정 파일",
            coverage: "외부 연동 필요",
            badge: "국제 기준",
            icon: "iphone.gen3",
            accent: .green,
            categories: [
                category("credentials", "자격증명 저장", "키, 토큰, 비밀값 노출을 확인합니다."),
                category("communication", "통신 보안", "평문 URL, 약한 TLS 설정 흔적을 확인합니다."),
                category("configuration", "앱 설정", "debug, backup, 권한 관련 설정을 확인합니다."),
                category("dependencies", "모바일 의존성", "매니페스트와 의존성 위생을 확인합니다.")
            ],
            references: [
                reference("OWASP Mobile Top 10", "https://owasp.org/www-project-mobile-top-10/")
            ]
        ),
        AppSecurityStandard(
            id: "owasp-masvs",
            title: "OWASP MASVS",
            subtitle: "모바일 앱 보안 검증 표준의 공식 8개 통제 그룹에 관련 로컬 모바일 증거를 매핑합니다.",
            scope: "모바일 앱 소스, Manifest, plist, 릴리스 증적",
            coverage: "외부 연동 필요",
            badge: "국제 검증표준",
            icon: "iphone.and.arrow.forward",
            accent: .green,
            categories: [
                category("storage", "MASVS-STORAGE", "민감정보 저장, 백업, iOS 파일 공유, Android 백업 설정을 확인합니다."),
                category("crypto", "MASVS-CRYPTO", "약한 해시, 키 길이, 난수, 솔트 사용과 같은 암호 기능 단서를 확인합니다."),
                category("auth", "MASVS-AUTH", "인증, 인가, 세션 관련 코드 단서를 확인합니다."),
                category("network", "MASVS-NETWORK", "ATS 예외, Android cleartext traffic, 평문 의존성 소스를 확인합니다."),
                category("platform", "MASVS-PLATFORM", "Android exported component, iOS document sharing, 파일 처리 위험을 확인합니다."),
                category("code", "MASVS-CODE", "알려진 취약 구성요소와 위험 코드 사용 단서를 확인합니다."),
                category("resilience", "MASVS-RESILIENCE", "Android debug build 잔존 여부를 확인합니다."),
                category("privacy", "MASVS-PRIVACY", "민감정보 저장·로깅·공유와 개인정보 보호 계획 증거를 확인합니다.")
            ],
            references: [
                reference("OWASP MASVS", "https://mas.owasp.org/MASVS/"),
                reference("OWASP MASTG", "https://mas.owasp.org/MASTG/")
            ]
        ),
        AppSecurityStandard(
            id: "owasp-llm-top-10-2025",
            title: "OWASP LLM Top 10:2025",
            subtitle: "LLM 프롬프트, 민감정보 전달, 도구 권한, 공급망, AI 보안 계획을 로컬 증거로 확인합니다.",
            scope: "AI/LLM 애플리케이션 코드 및 예방 증적",
            coverage: "자동 점검",
            badge: "국제 기준",
            icon: "sparkles",
            accent: .indigo,
            categories: [
                category("llm01", "LLM01 Prompt Injection", "사용자 입력이 privileged prompt에 직접 결합되는 패턴을 확인합니다."),
                category("llm02", "LLM02 Sensitive Information Disclosure", "비밀값이 LLM 요청이나 로그로 전달될 수 있는 패턴을 확인합니다."),
                category("llm03", "LLM03 Supply Chain", "LLM SDK, 의존성, SBOM, VEX 준비성을 확인합니다."),
                category("llm05", "LLM05 Improper Output Handling", "모델 출력이 HTML, shell, SQL, 파일 처리로 바로 연결될 수 있는지 확인합니다."),
                category("llm06", "LLM06 Excessive Agency", "도구 호출이 광범위하거나 자동으로 열려 있는 패턴을 확인합니다.")
            ],
            references: [
                reference("OWASP Top 10 for LLM Applications", "https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/")
            ]
        ),
        AppSecurityStandard(
            id: "sw-dev-security-49",
            title: "소프트웨어 개발보안 49",
            subtitle: "행정안전부·KISA 구현단계 보안약점 49개를 기준별로 표시합니다. 자동 확인 가능한 항목은 로컬 룰로 점검하고, 나머지는 부분 지원·수동 검토·미지원으로 구분합니다.",
            scope: "국내 시큐어코딩 기준",
            coverage: "자동·부분 로컬 점검 (설계·권한·데이터 흐름 항목은 수동 검토 또는 외부 SAST 필요)",
            badge: "국내 기준",
            icon: "doc.text.magnifyingglass",
            accent: .blue,
            categories: [
                category("input-data", "입력데이터 검증 및 표현", "SQL, XSS, command, path traversal 패턴을 확인합니다."),
                category("security-function", "보안기능", "인증, 세션, 암호, 권한 흐름을 확인합니다."),
                category("time-state", "시간 및 상태", "임시 파일, 경쟁 상태 가능 패턴을 확인합니다."),
                category("error", "에러처리", "오류 메시지 노출과 예외 처리 부재 단서를 확인합니다."),
                category("code-error", "코드오류", "위험한 역직렬화 등 직접 확인 가능한 코드 오류를 확인합니다."),
                category("encapsulation", "캡슐화", "디버그 코드 등 로컬에서 확인 가능한 캡슐화 단서를 확인합니다."),
                category("api-misuse", "API 오용", "위험한 C/C++ API 사용 단서를 확인합니다.")
            ],
            references: [
                reference("행정안전부 소프트웨어 개발보안 가이드(2021)", "https://www.mois.go.kr/frt/bbs/type001/commonSelectBoardArticle.do?bbsId=BBSMSTR_000000000015&nttId=88956"),
                reference("KISA 소프트웨어 보안약점 진단가이드(2021)", "https://www.kisa.or.kr/2060204/form?page=1&postSeq=9")
            ]
        ),
        AppSecurityStandard(
            id: "sw-dev-security-7-types",
            title: "소프트웨어 개발보안 7대 유형",
            subtitle: "개발보안 약점을 7가지 큰 유형으로 묶어 점검합니다.",
            scope: "국내 시큐어코딩 유형",
            coverage: "자동 점검",
            badge: "국내 기준",
            icon: "7.circle",
            accent: .blue,
            categories: [
                category("input", "입력 데이터 검증 및 표현", "입력값 기반 공격 패턴을 확인합니다."),
                category("security", "보안 기능", "인증, 세션, 암호 사용 위험을 확인합니다."),
                category("time-state", "시간 및 상태", "임시 파일 및 상태 처리 위험을 확인합니다."),
                category("error", "에러 처리", "디버그와 오류 노출 설정을 확인합니다."),
                category("code-error", "코드 오류", "역직렬화와 코드 오류 단서를 확인합니다."),
                category("encapsulation", "캡슐화", "디버그 코드 등 캡슐화 관련 단서를 확인합니다."),
                category("api-misuse", "API 오용", "위험 API 사용 단서를 확인합니다.")
            ],
            references: [
                reference("행정안전부 소프트웨어 개발보안 가이드(2021)", "https://www.mois.go.kr/frt/bbs/type001/commonSelectBoardArticle.do?bbsId=BBSMSTR_000000000015&nttId=88956"),
                reference("KISA 소프트웨어 보안약점 진단가이드(2021)", "https://www.kisa.or.kr/2060204/form?page=1&postSeq=9")
            ]
        ),
        AppSecurityStandard(
            id: "kisa-secure-coding-guide",
            title: "KISA 소프트웨어 보안약점 진단가이드 2021",
            subtitle: "KISA가 2021년에 발행한 공식 진단가이드의 7개 유형·구현단계 보안약점 49개를 점검합니다.",
            scope: "국내 시큐어코딩 기준",
            coverage: "자동·부분 로컬 점검 (설계·권한·데이터 흐름 항목은 수동 검토 또는 외부 SAST 필요)",
            badge: "국내 기준",
            icon: "checkmark.shield",
            accent: .green,
            categories: [
                category("input", "입력 데이터 검증 및 표현", "입력값 기반 공격 패턴을 확인합니다."),
                category("security", "보안 기능", "인증, 세션, 암호 사용 위험을 확인합니다."),
                category("time-state", "시간 및 상태", "임시 파일 및 상태 처리 위험을 확인합니다."),
                category("error", "에러 처리", "오류 노출과 예외 처리 단서를 확인합니다."),
                category("code-error", "코드 오류", "역직렬화와 코드 오류 단서를 확인합니다."),
                category("encapsulation", "캡슐화", "디버그 코드 등 캡슐화 관련 단서를 확인합니다."),
                category("api-misuse", "API 오용", "위험 API 사용 단서를 확인합니다.")
            ],
            references: [
                reference("KISA 소프트웨어 보안약점 진단가이드(2021)", "https://www.kisa.or.kr/2060204/form?page=1&postSeq=9"),
                reference("행정안전부 소프트웨어 개발보안 가이드(2021)", "https://www.mois.go.kr/frt/bbs/type001/commonSelectBoardArticle.do?bbsId=BBSMSTR_000000000015&nttId=88956")
            ]
        ),
        AppSecurityStandard(
            id: "electronic-financial-8",
            title: "전자금융감독규정 8대 취약점",
            subtitle: "전자금융 공개 웹서버 점검 항목을 로컬 룰에 매핑합니다.",
            scope: "금융권 웹서비스 코드 및 설정",
            coverage: "외부 연동 필요",
            badge: "국내 기준",
            icon: "banknote",
            accent: .red,
            categories: [
                category("injection", "인젝션", "SQL과 명령 실행 위험을 확인합니다."),
                category("xss", "XSS", "브라우저 실행 스크립트 주입 위험을 확인합니다."),
                category("file", "파일 처리", "다운로드, 업로드, 경로 조작 위험을 확인합니다."),
                category("config", "서버 설정", "디렉터리 리스팅, WebDAV, debug 설정을 확인합니다."),
                category("session", "세션 관리", "쿠키와 세션 설정 위험을 확인합니다.")
            ],
            references: [
                reference("금융감독원", "https://www.fss.or.kr/")
            ]
        ),
        AppSecurityStandard(
            id: "isms-p-28",
            title: "ISMS-P 2.8 개발보안",
            subtitle: "개발보안 통제 영역을 로컬 증거로 확인 가능한 항목에 매핑합니다.",
            scope: "개발·시험·운영 이관 보안",
            coverage: "증적 확인 필요",
            badge: "국내 인증",
            icon: "checkmark.seal",
            accent: .green,
            categories: [
                category("requirements", "보안 요구사항", "비밀값, 설정, 의존성 관리 근거를 확인합니다."),
                category("secure-coding", "시큐어코딩", "코드 약점과 위험 API 사용을 확인합니다."),
                category("test-data", "시험 데이터 보호", ".env, 샘플 비밀값, 테스트 credential을 확인합니다."),
                category("source-management", "소스 프로그램 관리", "락파일, 의존성, 설정 위생을 확인합니다."),
                category("migration", "운영 이관", "debug와 위험 설정 잔존 여부를 확인합니다.")
            ],
            references: [
                reference("KISA ISMS-P", "https://isms.kisa.or.kr/")
            ]
        ),
        AppSecurityStandard(
            id: "owasp-asvs-5",
            title: "OWASP ASVS 5.0",
            subtitle: "ASVS 5.0.0의 공식 17개 장을 표시하고 직접 관련된 KODA 휴리스틱만 연결합니다.",
            scope: "애플리케이션 보안 검증",
            coverage: "부분 증거만 제공 · 요구사항 단위 준수 판정 아님",
            badge: "국제 검증표준",
            icon: "doc.badge.gearshape",
            accent: .indigo,
            categories: [
                category("v1", "V1 인코딩 및 정제", "인젝션, 역직렬화, 메모리 API 관련 정적 단서를 확인합니다."),
                category("v2", "V2 검증 및 비즈니스 로직", "입력 검증과 리소스 제한 관련 단서를 확인합니다."),
                category("v3", "V3 웹 프런트엔드 보안", "XSS, CORS, 쿠키, CSRF, 리디렉션 단서를 확인합니다."),
                category("v4", "V4 API 및 웹 서비스", "API 라우트, 인가, SSRF, 리소스 제한 단서를 확인합니다."),
                category("v5", "V5 파일 처리", "파일 업로드와 경로 처리 단서를 확인합니다."),
                category("v6", "V6 인증", "인증 우회와 토큰 검증 단서를 확인합니다."),
                category("v7", "V7 세션 관리", "쿠키, CSRF, JWT, 세션 만료 단서를 확인합니다."),
                category("v8", "V8 인가", "인가 누락과 mass assignment 단서를 확인합니다."),
                category("v9", "V9 자체 포함 토큰", "JWT 검증, none 알고리즘, 만료 단서를 확인합니다."),
                category("v10", "V10 OAuth 및 OIDC", "직접 자동 점검은 지원하지 않습니다.", isMapped: false),
                category("v11", "V11 암호기술", "약한 해시, 키 길이, 난수, 솔트 사용 단서를 확인합니다."),
                category("v12", "V12 안전한 통신", "평문 전송과 인증서 검증 비활성화 단서를 확인합니다."),
                category("v13", "V13 설정", "보안 설정 오류 단서를 확인합니다."),
                category("v14", "V14 데이터 보호", "비밀값과 민감정보 노출 단서를 확인합니다."),
                category("v15", "V15 안전한 코딩 및 아키텍처", "위험 API, 역직렬화, 위협 모델 증거를 확인합니다."),
                category("v16", "V16 보안 로깅 및 오류 처리", "오류 노출과 민감정보 로깅 단서를 확인합니다."),
                category("v17", "V17 WebRTC", "직접 자동 점검은 지원하지 않습니다.", isMapped: false)
            ],
            references: [
                reference("OWASP ASVS", "https://owasp.org/www-project-application-security-verification-standard/"),
                reference("OWASP ASVS 5.0.0 CSV", "https://github.com/OWASP/ASVS/raw/v5.0.0/5.0/docs_en/OWASP_Application_Security_Verification_Standard_5.0.0_en.csv")
            ]
        ),
        AppSecurityStandard(
            id: "owasp-wstg",
            title: "OWASP WSTG v4.2",
            subtitle: "공식 웹 애플리케이션 테스트 12개 영역을 표시하고 관련 파일 증거가 있는 곳에만 정적 단서를 연결합니다.",
            scope: "웹 보안 테스트 방법론",
            coverage: "실제 대상 웹 테스트 필요",
            badge: "국제 테스트가이드",
            icon: "network",
            accent: .indigo,
            categories: [
                category("information", "정보 수집", "정적 스캔만으로 WSTG 시나리오를 완료할 수 없습니다.", isMapped: false),
                category("configuration", "설정 및 배포 관리 테스트", "CORS, debug, directory listing, WebDAV 단서를 확인합니다."),
                category("identity", "식별 관리 테스트", "정적 스캔만으로 완료할 수 없습니다.", isMapped: false),
                category("authentication", "인증 테스트", "인증 관련 코드 단서를 확인합니다."),
                category("authorization", "인가 테스트", "접근통제 관련 코드 단서를 확인합니다."),
                category("session", "세션 관리 테스트", "쿠키와 세션 관련 코드 단서를 확인합니다."),
                category("input", "입력 검증 테스트", "XSS, SQL, command, traversal 단서를 확인합니다."),
                category("error", "오류 처리 테스트", "디버그와 오류 노출 단서를 확인합니다."),
                category("crypto", "약한 암호 테스트", "약한 암호와 민감정보 처리 단서를 확인합니다."),
                category("business", "비즈니스 로직 테스트", "정적 스캔만으로 완료할 수 없습니다.", isMapped: false),
                category("client", "클라이언트 측 테스트", "XSS, 리디렉션, CORS 단서를 확인합니다."),
                category("api", "API 테스트", "API 인벤토리, SSRF, 요청 제한 단서를 확인합니다.")
            ],
            references: [
                reference("OWASP WSTG", "https://owasp.org/www-project-web-security-testing-guide/"),
                reference("OWASP WSTG v4.2", "https://owasp.org/www-project-web-security-testing-guide/v42/")
            ]
        ),
        AppSecurityStandard(
            id: "nist-ssdf",
            title: "NIST SSDF SP 800-218",
            subtitle: "보안 소프트웨어 개발 프레임워크의 실천 항목과 예방 통제 준비성을 로컬 증거로 확인합니다.",
            scope: "보안 개발 프로세스",
            coverage: "증적 확인 필요",
            badge: "국제 프레임워크",
            icon: "gearshape.2",
            accent: .slate,
            categories: [
                category("protect", "Protect the Software", "비밀값, 의존성 위생, 보안 정책 문서화 상태를 확인합니다."),
                category("produce", "Produce Well-Secured Software", "보안 설정, 코드 약점, CI 보안 점검 준비성을 확인합니다."),
                category("verify", "Verify Security", "로컬 룰 기반 검증 증거와 자동화 가드레일을 수집합니다."),
                category("respond", "Respond to Vulnerabilities", "취약 의존성 대응을 위한 매니페스트, SBOM, 업데이트 자동화를 확인합니다.")
            ],
            references: [
                reference("NIST SSDF SP 800-218", "https://csrc.nist.gov/publications/detail/sp/800-218/final")
            ]
        ),
        AppSecurityStandard(
            id: "owasp-samm-2",
            title: "OWASP SAMM 2",
            subtitle: "공식 5개 비즈니스 기능에 저장소 증거를 매핑하며 15개 실천항목이나 성숙도 수준은 채점하지 않습니다.",
            scope: "소프트웨어 보증 성숙도",
            coverage: "증적 확인 필요",
            badge: "국제 성숙도모델",
            icon: "chart.line.uptrend.xyaxis",
            accent: .teal,
            categories: [
                category("governance", "Governance", "정책, 책임자, 로드맵, 증적 등록부 단서를 확인합니다."),
                category("design", "Design", "보안 요구와 예방 정책 문서화 근거를 확인합니다."),
                category("implementation", "Implementation", "시큐어코딩, 의존성 위생, CI 보안 점검 준비성을 확인합니다."),
                category("verification", "Verification", "정적 점검 근거와 자동화 가드레일을 수집합니다."),
                category("operations", "Operations", "운영 이관 전 debug, 비밀값 잔존, SBOM 준비성을 확인합니다.")
            ],
            references: [
                reference("OWASP SAMM", "https://owasp.org/www-project-samm/"),
                reference("OWASP SAMM Model", "https://owaspsamm.org/model/")
            ]
        ),
        AppSecurityStandard(
            id: "cisa-secure-by-design",
            title: "CISA Secure by Design",
            subtitle: "제품 보안 결과 책임, 안전한 기본값, 투명성, 경영진 책임을 예방 통제와 증적 기준으로 확인합니다.",
            scope: "제품 보안 예방 프로그램",
            coverage: "증적 확인 필요",
            badge: "국제 원칙",
            icon: "shield.righthalf.filled",
            accent: .red,
            categories: [
                category("ownership", "고객 보안 결과 책임", "보안 정책, 취약점 대응, 의존성 위험 대응 책임이 드러나는지 확인합니다."),
                category("secure-defaults", "안전한 기본값", "쿠키, CORS, debug, 컨테이너, CI token처럼 기본 설정이 안전한지 확인합니다."),
                category("transparency", "투명성 및 책임성", "SECURITY.md, SBOM, VEX, 예외 만료, 점수 추적 같은 공개·추적 산출물을 확인합니다."),
                category("leadership", "경영진 주도", "CODEOWNERS, SSDF workflow, Secure by Design 계획처럼 책임 구조와 정기 검토 증적을 확인합니다.")
            ],
            references: [
                reference("CISA Secure by Design", "https://www.cisa.gov/resources-tools/resources/secure-by-design"),
                reference("CISA Secure by Design Pledge", "https://www.cisa.gov/securebydesign")
            ]
        ),
        AppSecurityStandard(
            id: "nist-csf-2",
            title: "NIST CSF 2.0",
            subtitle: "Govern, Identify, Protect, Detect, Respond, Recover 기능을 로컬 점검과 조직 증적에 매핑합니다.",
            scope: "조직 사이버보안 위험관리 프로파일",
            coverage: "증적 확인 필요",
            badge: "국제 프레임워크",
            icon: "hexagon.lefthalf.filled",
            accent: .slate,
            categories: [
                category("govern", "Govern", "정책, owner, 예외, Secure by Design, CSF 프로파일 증적을 확인합니다."),
                category("identify", "Identify", "자산, 의존성, SBOM, 저장소 보안 설정 준비성을 확인합니다."),
                category("protect", "Protect", "비밀값, 인증, 세션, 컨테이너, 모바일, AI, CI 보안 기본값을 확인합니다."),
                category("detect", "Detect", "KODA/SAST/의존성 점검과 보안 로깅 준비성을 확인합니다."),
                category("respond-recover", "Respond / Recover", "VEX, 취약점 대응, secret rotation, 릴리스 보안 패키지를 확인합니다.")
            ],
            references: [
                reference("NIST Cybersecurity Framework", "https://www.nist.gov/cyberframework")
            ]
        ),
        AppSecurityStandard(
            id: "cisa-secure-software-attestation",
            title: "CISA 보안 소프트웨어 개발 확인서",
            subtitle: "보안 개발 환경, 제3자 구성요소, 검증, 취약점 대응 증적을 확인서 관점으로 정리합니다.",
            scope: "SSDF 기반 보안 개발 확인 증적",
            coverage: "증적 확인 필요",
            badge: "국제 프레임워크",
            icon: "doc.text.badge.checkmark",
            accent: .red,
            categories: [
                category("environment", "안전한 개발 환경", "브랜치 보호, CODEOWNERS, CI 게이트, 비밀값 회전 절차를 확인합니다."),
                category("development", "안전한 개발 실천", "위협 모델, 시큐어코딩, 예외 만료, SSDF 워크플로를 확인합니다."),
                category("components", "제3자 구성요소", "SBOM, 버전 고정, 의존성 업데이트, VEX 대응을 확인합니다."),
                category("response", "검증 및 대응", "SAST, OSV/CVE, 취약점 신고와 조치 증적을 확인합니다.")
            ],
            references: [
                reference("CISA Secure Software Development Attestation", "https://www.cisa.gov/secure-software-attestation-form"),
                reference("NIST SSDF SP 800-218", "https://csrc.nist.gov/publications/detail/sp/800-218/final")
            ]
        ),
        AppSecurityStandard(
            id: "owasp-scvs",
            title: "OWASP SCVS",
            subtitle: "소프트웨어 구성요소 인벤토리, SBOM, 빌드 환경, 패키지 관리, 구성요소 분석, 출처 증명을 공급망 관점으로 확인합니다.",
            scope: "소프트웨어 공급망 구성요소 보증",
            coverage: "증적 확인 필요",
            badge: "공급망",
            icon: "shippingbox.and.arrow.backward",
            accent: .orange,
            categories: [
                category("v1-inventory", "V1 Inventory", "의존성 매니페스트와 구성요소 인벤토리 준비성을 확인합니다."),
                category("v2-sbom", "V2 SBOM", "SBOM 산출물과 SBOM 분석 backend 연동 준비성을 확인합니다."),
                category("v3-build", "V3 Build Environment", "CI token 권한, 고정된 Actions, 릴리스 provenance 준비성을 확인합니다."),
                category("v4-package", "V4 Package Management", "lockfile, 버전 고정, 안전한 패키지 소스를 확인합니다."),
                category("v5-analysis", "V5 Component Analysis", "OSV/CVE, VEX, Dependency-Track 인수인계 준비성을 확인합니다."),
                category("v6-provenance", "V6 Pedigree and Provenance", "SLSA/Sigstore, 체크섬, 서명, binary artifact 관리 상태를 확인합니다.")
            ],
            references: [
                reference("OWASP SCVS", "https://owasp.org/www-project-software-component-verification-standard/"),
                reference("SCVS Control Families", "https://scvs.owasp.org/scvs/using-scvs/")
            ]
        ),
        AppSecurityStandard(
            id: "owasp-dependency-check",
            title: "OWASP Dependency-Check 기준",
            subtitle: "알려진 취약 컴포넌트 식별을 위한 의존성 위생 기준입니다.",
            scope: "의존성 매니페스트 및 락파일",
            coverage: "외부 연동 필요",
            badge: "공급망",
            icon: "shippingbox",
            accent: .orange,
            categories: [
                category("manifest", "매니페스트 위생", "package.json, requirements, lockfile 상태를 확인합니다."),
                category("version", "버전 고정", "고정되지 않은 버전과 wildcard를 확인합니다."),
                category("sources", "의존성 소스", "평문 또는 원격 실행 의존성 소스를 확인합니다.")
            ],
            references: [
                reference("OWASP Dependency-Check", "https://owasp.org/www-project-dependency-check/")
            ]
        ),
        AppSecurityStandard(
            id: "owasp-dependency-track",
            title: "OWASP Dependency-Track / SBOM 기준",
            subtitle: "SBOM 준비성과 의존성 추적을 위한 로컬 증거를 확인합니다.",
            scope: "SBOM 및 공급망 관리",
            coverage: "외부 연동 필요",
            badge: "공급망",
            icon: "doc.zipper",
            accent: .orange,
            categories: [
                category("sbom-readiness", "SBOM 준비성", "매니페스트, 락파일, SBOM 산출물 존재 여부를 확인합니다."),
                category("version-hygiene", "버전 위생", "고정되지 않은 의존성과 wildcard를 확인합니다."),
                category("dependency-source", "의존성 소스", "안전하지 않은 다운로드와 원격 실행 패턴을 확인합니다."),
                category("automation", "자동화 준비성", "Dependabot/Renovate와 CI 보안 점검 workflow를 확인합니다.")
            ],
            references: [
                reference("OWASP Dependency-Track", "https://owasp.org/www-project-dependency-track/")
            ]
        ),
        AppSecurityStandard(
            id: "openssf-scorecard-baseline",
            title: "OpenSSF Scorecard 기준",
            subtitle: "저장소 파일에서 추론 가능한 공급망 보안 상태를 Scorecard 관점으로 확인합니다.",
            scope: "오픈소스 공급망 보안 상태",
            coverage: "외부 연동 필요",
            badge: "공급망",
            icon: "checklist.checked",
            accent: .teal,
            categories: [
                category("security-policy", "보안 정책", "SECURITY.md와 취약점 신고 기준을 확인합니다."),
                category("dependency-update-tool", "의존성 업데이트 자동화", "Dependabot/Renovate 준비성을 확인합니다."),
                category("sast", "정적 분석", "CodeQL/Semgrep 등 SAST workflow를 확인합니다."),
                category("token-permissions", "토큰 권한", "GitHub Actions token permissions 최소 권한 설정을 확인합니다."),
                category("pinned-actions", "고정된 Actions", "main/master/latest 또는 major 버전만 참조하는 액션을 확인합니다."),
                category("signed-releases", "서명된 릴리스", "SLSA/Sigstore/cosign 출처 증명 준비성을 확인합니다.")
            ],
            references: [
                reference("OpenSSF Scorecard", "https://scorecard.dev/"),
                reference("OpenSSF Scorecard GitHub", "https://github.com/ossf/scorecard")
            ]
        ),
        AppSecurityStandard(
            id: "cisa-kev-epss-priority",
            title: "CISA KEV / FIRST EPSS 우선순위",
            subtitle: "OSV 조회 결과를 실제 악용 여부와 악용 확률로 재우선순위화합니다.",
            scope: "취약 의존성 우선순위",
            coverage: "외부 연동 필요",
            badge: "공급망",
            icon: "flame",
            accent: .red,
            categories: [
                category("known-exploited", "실제 악용 취약점", "CISA KEV에 등록된 CVE를 최우선으로 표시합니다."),
                category("exploit-probability", "악용 가능성", "FIRST EPSS 확률과 percentile을 근거로 우선순위를 높입니다."),
                category("vex-response", "VEX 대응 추적", "검토된 CVE의 VEX 문서화 준비성을 확인합니다."),
                category("sbom-tracking", "SBOM 추적", "SBOM과 Dependency-Track 연동 준비성을 확인합니다.")
            ],
            references: [
                reference("CISA KEV Catalog", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"),
                reference("FIRST EPSS", "https://www.first.org/epss/")
            ]
        ),
        AppSecurityStandard(
            id: "slsa-sigstore-baseline",
            title: "SLSA / Sigstore 기준",
            subtitle: "릴리스 산출물 서명, 출처 증명, CI 최소 권한 준비성을 확인합니다.",
            scope: "빌드·릴리스 공급망",
            coverage: "외부 연동 필요",
            badge: "공급망",
            icon: "signature",
            accent: .indigo,
            categories: [
                category("provenance", "빌드 출처 증명", "SLSA provenance 또는 attestation workflow를 확인합니다."),
                category("signed-artifacts", "서명된 산출물", "Sigstore/cosign 또는 서명 정책 준비성을 확인합니다."),
                category("pinned-actions", "고정된 Actions", "외부 GitHub Actions 참조와 token 권한을 확인합니다.")
            ],
            references: [
                reference("SLSA", "https://slsa.dev/"),
                reference("Sigstore Cosign", "https://docs.sigstore.dev/cosign/")
            ]
        )
    ]

    private static func cweCategories() -> [AppStandardCategory] {
        [
            category("cwe-79", "CWE-79 Improper Neutralization of Input During Web Page Generation", "XSS 관련 정적 단서를 확인합니다."),
            category("cwe-89", "CWE-89 Improper Neutralization of Special Elements used in an SQL Command", "SQL 삽입 관련 정적 단서를 확인합니다."),
            category("cwe-352", "CWE-352 Cross-Site Request Forgery", "CSRF 보호 비활성화 단서를 확인합니다."),
            category("cwe-862", "CWE-862 Missing Authorization", "인가 누락 단서를 확인합니다."),
            category("cwe-787", "CWE-787 Out-of-bounds Write", "정밀 메모리 분석을 지원하지 않습니다.", isMapped: false),
            category("cwe-22", "CWE-22 Improper Limitation of a Pathname to a Restricted Directory", "경로 조작 단서를 확인합니다."),
            category("cwe-416", "CWE-416 Use After Free", "메모리 수명 분석을 지원하지 않습니다.", isMapped: false),
            category("cwe-125", "CWE-125 Out-of-bounds Read", "정밀 메모리 분석을 지원하지 않습니다.", isMapped: false),
            category("cwe-78", "CWE-78 Improper Neutralization of Special Elements used in an OS Command", "OS 명령 삽입 단서를 확인합니다."),
            category("cwe-94", "CWE-94 Improper Control of Generation of Code", "코드 삽입 단서를 확인합니다."),
            category("cwe-120", "CWE-120 Buffer Copy without Checking Size of Input", "위험 C/C++ 버퍼 API 사용 단서만 확인합니다."),
            category("cwe-434", "CWE-434 Unrestricted Upload of File with Dangerous Type", "위험 파일 업로드 단서를 확인합니다."),
            category("cwe-476", "CWE-476 NULL Pointer Dereference", "Java/Kotlin 동일 파일의 명시적 null 대입과 nullable 조회 역참조 후보를 부분 점검합니다. 함수 간 흐름은 외부 SAST 검토가 필요합니다."),
            category("cwe-121", "CWE-121 Stack-based Buffer Overflow", "정밀 메모리 분석을 지원하지 않습니다.", isMapped: false),
            category("cwe-502", "CWE-502 Deserialization of Untrusted Data", "위험한 역직렬화 단서를 확인합니다."),
            category("cwe-122", "CWE-122 Heap-based Buffer Overflow", "정밀 메모리 분석을 지원하지 않습니다.", isMapped: false),
            category("cwe-863", "CWE-863 Incorrect Authorization", "정확한 인가 결정 분석을 지원하지 않습니다.", isMapped: false),
            category("cwe-20", "CWE-20 Improper Input Validation", "입력 검증 관련 정적 단서를 확인합니다."),
            category("cwe-284", "CWE-284 Improper Access Control", "접근통제 관련 정적 단서를 확인합니다."),
            category("cwe-200", "CWE-200 Exposure of Sensitive Information to an Unauthorized Actor", "민감정보 노출 단서를 확인합니다."),
            category("cwe-306", "CWE-306 Missing Authentication for Critical Function", "중요 기능 인증 누락 단서를 확인합니다."),
            category("cwe-918", "CWE-918 Server-Side Request Forgery", "SSRF 단서를 확인합니다."),
            category("cwe-77", "CWE-77 Improper Neutralization of Special Elements used in a Command", "명령 삽입 단서를 확인합니다."),
            category("cwe-639", "CWE-639 Authorization Bypass Through User-Controlled Key", "객체 단위 인가 흐름 분석을 지원하지 않습니다.", isMapped: false),
            category("cwe-770", "CWE-770 Allocation of Resources Without Limits or Throttling", "요청 크기와 rate limit 부재 단서를 확인합니다.")
        ]
    }

    private static func category(
        _ id: String,
        _ title: String,
        _ coverage: String,
        isMapped: Bool = true
    ) -> AppStandardCategory {
        AppStandardCategory(id: id, title: title, coverage: coverage, isMapped: isMapped)
    }

    private static func reference(_ title: String, _ url: String) -> AppStandardReference {
        AppStandardReference(title: title, url: url)
    }
}
