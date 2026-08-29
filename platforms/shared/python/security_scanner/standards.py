from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
from typing import Any, Mapping

from .models import DEFAULT_CATEGORIES, Finding


DEFAULT_STANDARD = "local"
DEFAULT_STANDARD_CATEGORY = "all"


SECRET_RULE_IDS = (
    "secret.private-key",
    "secret.aws-access-key",
    "secret.github-token",
    "secret.openai-key",
    "secret.slack-token",
    "secret.generic-assignment",
)

# Comment-scanning secret rule. Kept out of SECRET_RULE_IDS so profiles that map
# "hard-coded secrets" (e.g. SW49 S-06) are not polluted by the comment rule,
# which belongs to S-13 (sensitive information in comments).
SENSITIVE_COMMENT_RULE_IDS = ("secret.sensitive-comment",)

DEPENDENCY_RULE_IDS = (
    "dependency.package-json-invalid",
    "dependency.node-missing-lockfile",
    "dependency.node-unbounded-version",
    "dependency.node-insecure-url",
    "dependency.remote-shell-script",
    "dependency.python-insecure-url",
    "dependency.python-unpinned-requirement",
    "dependency.python-wildcard-version",
    "dependency.docker-unpinned-base",
    "dependency.docker-remote-shell",
    "dependency.osv-known-vulnerability",
)

CONFIGURATION_RULE_IDS = (
    "config.env-file-present",
    "config.private-key-like-file",
    "config.debug-enabled",
    "config.development-environment",
    "config.docker-root-user",
    "config.docker-add-http",
    "config.docker-no-user",
    "config.compose-privileged",
    "config.compose-host-network",
    "config.compose-docker-sock",
    "config.compose-dangerous-capability",
    "config.compose-host-pid",
    "config.compose-secret-in-environment",
    "config.k8s-privileged-container",
    "config.k8s-allow-privilege-escalation",
    "config.k8s-host-network",
    "config.k8s-hostpath-volume",
    "config.k8s-run-as-root",
    "config.k8s-service-account-token",
    "config.k8s-unpinned-image",
    "config.k8s-seccomp-unconfined",
    "config.k8s-dangerous-capability",
    "config.terraform-public-storage",
    "config.terraform-public-access-block-disabled",
    "config.terraform-open-admin-port",
    "config.terraform-wildcard-iam-action",
    "config.terraform-wildcard-principal",
    "config.terraform-public-ingress",
    "config.terraform-unencrypted-storage",
    "config.terraform-sensitive-output",
    "config.github-pull-request-target",
    "config.github-untrusted-event-in-run",
    "config.android-debuggable",
    "config.android-allow-backup",
    "config.android-cleartext-traffic",
    "config.android-exported-component",
    "config.ios-ats-arbitrary-loads",
    "config.ios-file-sharing-enabled",
    "config.ios-open-documents-in-place",
)

CODE_PATTERN_RULE_IDS = (
    "code.xss-dom-sink",
    "code.sql-dynamic-query",
    "code.command-injection",
    "code.path-traversal",
    "code.csrf-disabled",
    "code.auth-disabled-endpoint",
    "code.eval-user-input",
    "code.unsafe-deserialization",
    "code.ssrf-user-url",
    "code.unrestricted-file-upload",
    "code.dangerous-c-buffer-api",
    "code.unbounded-request-body",
    "code.logging-sensitive-data",
    "code.empty-exception-handler",
    "code.broad-exception-handler",
    "code.stack-trace-exposure",
    "code.unversioned-api-route",
    "code.insecure-temp-file",
    "code.wildcard-cors",
    "code.public-bind-all-interfaces",
    "code.insecure-cookie-settings",
    "code.persistent-sensitive-cookie",
    "code.jwt-verification-disabled",
    "code.jwt-none-algorithm",
    "code.session-long-expiry",
    "code.api-route-missing-auth",
    "code.api-mass-assignment",
    "code.api-missing-rate-limit",
    "code.auth-attempt-protection-missing",
    "code.external-api-no-timeout",
    "code.pii-logging",
    "code.directory-listing-enabled",
    "code.webdav-enabled",
    "code.legacy-board-software",
    "code.weak-hash",
    "code.xml-external-entity",
    "code.llm-prompt-user-concat",
    "code.llm-tool-unrestricted",
    "code.llm-sensitive-data-in-prompt",
    "code.open-redirect-user-input",
    "code.xml-injection",
    "code.ldap-injection",
    "code.http-response-splitting",
    "code.format-string-user-input",
    "code.insufficient-key-length",
    "code.insecure-random-security-use",
    "code.tls-certificate-verification-disabled",
    "code.password-hash-without-salt",
    "code.null-pointer-dereference",
    "code.improper-resource-release",
    "code.use-after-free",
    "code.uninitialized-variable",
    "code.dns-security-decision",
    "code.integer-overflow-user-input",
    "code.security-decision-user-input",
    "code.authorization-check-missing",
    "code.insecure-resource-permissions",
    "code.weak-password-policy",
    "code.uncontrolled-loop",
    "code.session-shared-state",
    "code.private-array-return",
    "code.private-array-assignment",
    "code.dangerous-managed-api",
)

PREVENTION_RULE_IDS = (
    "prevention.security-policy-missing",
    "prevention.dependency-update-automation-missing",
    "prevention.ci-security-scan-missing",
    "prevention.pre-commit-hook-missing",
    "prevention.codeowners-missing",
    "prevention.repository-security-settings-missing",
    "prevention.release-provenance-automation-missing",
    "prevention.ssdf-workflow-missing",
    "prevention.secure-by-design-program-missing",
    "prevention.env-not-gitignored",
    "prevention.env-example-missing",
    "prevention.dockerignore-missing",
    "prevention.sbom-missing",
    "prevention.sast-workflow-missing",
    "prevention.openssf-scorecard-missing",
    "prevention.github-token-permissions-not-readonly",
    "prevention.github-actions-unpinned",
    "prevention.slsa-sigstore-missing",
    "prevention.zap-baseline-missing",
    "prevention.dependency-track-integration-missing",
    "prevention.vex-missing",
    "prevention.binary-artifact-committed",
    "prevention.threat-model-missing",
    "prevention.secret-rotation-runbook-missing",
    "prevention.ai-llm-security-plan-missing",
    "prevention.mobile-security-plan-missing",
    "prevention.nist-csf-profile-missing",
    "prevention.cisa-attestation-missing",
    "prevention.api-security-plan-missing",
    "prevention.scvs-plan-missing",
    "prevention.privacy-data-map-missing",
    "prevention.security-roadmap-missing",
    "prevention.evidence-register-missing",
    "prevention.exception-reason-missing",
    "prevention.exception-owner-missing",
    "prevention.exception-expiry-missing",
    "prevention.exception-expired",
    "prevention.k8s-network-policy-missing",
    "prevention.security-headers-guide-missing",
    "prevention.container-hardening-guide-missing",
    "prevention.cloud-iac-security-plan-missing",
)

SCREEN_QUALITY_RULE_IDS = (
    "screen.html-lang-missing",
    "screen.viewport-missing",
    "screen.image-alt-missing",
    "screen.input-label-missing",
    "screen.button-type-missing",
    "screen.link-target-empty",
    "screen.sensitive-text-exposed",
    "screen.system-path-exposed",
)

ACCESS_CONTROL_RULE_IDS = (
    "code.auth-disabled-endpoint",
    "code.api-route-missing-auth",
    "code.api-mass-assignment",
)

AUTHENTICATION_RULE_IDS = (
    "code.auth-disabled-endpoint",
    "code.jwt-verification-disabled",
    "code.jwt-none-algorithm",
    "code.session-long-expiry",
    "code.auth-attempt-protection-missing",
)

INJECTION_RULE_IDS = (
    "code.xss-dom-sink",
    "code.sql-dynamic-query",
    "code.command-injection",
    "code.eval-user-input",
    "code.xml-injection",
    "code.ldap-injection",
    "code.http-response-splitting",
    "code.format-string-user-input",
)

INPUT_VALIDATION_RULE_IDS = (
    "code.xss-dom-sink",
    "code.sql-dynamic-query",
    "code.command-injection",
    "code.path-traversal",
    "code.eval-user-input",
    "code.ssrf-user-url",
    "code.unrestricted-file-upload",
    "code.xml-external-entity",
)

INSECURE_DESIGN_RULE_IDS = (
    "code.csrf-disabled",
    "code.auth-disabled-endpoint",
    "code.unbounded-request-body",
    "code.api-missing-rate-limit",
    "prevention.threat-model-missing",
    "prevention.api-security-plan-missing",
)

MEMORY_SAFETY_RULE_IDS = (
    "code.dangerous-c-buffer-api",
)

SENSITIVE_DATA_RULE_IDS = SECRET_RULE_IDS + (
    "config.env-file-present",
    "config.private-key-like-file",
    "code.logging-sensitive-data",
    "code.pii-logging",
)

INSECURE_TRANSPORT_RULE_IDS = (
    "dependency.node-insecure-url",
    "dependency.python-insecure-url",
    "config.docker-add-http",
)

REMOTE_EXECUTION_RULE_IDS = (
    "dependency.remote-shell-script",
    "dependency.docker-remote-shell",
    "config.docker-add-http",
)

SUPPLY_CHAIN_RULE_IDS = DEPENDENCY_RULE_IDS

INTEGRITY_RULE_IDS = (
    "dependency.node-missing-lockfile",
    "dependency.node-insecure-url",
    "dependency.remote-shell-script",
    "dependency.python-insecure-url",
    "dependency.docker-remote-shell",
    "config.docker-add-http",
)

ERROR_HANDLING_RULE_IDS = (
    "config.debug-enabled",
    "config.development-environment",
    "code.empty-exception-handler",
    "code.broad-exception-handler",
    "code.stack-trace-exposure",
)

LOGGING_MONITORING_RULE_IDS = (
    "code.logging-sensitive-data",
    "code.empty-exception-handler",
    "code.stack-trace-exposure",
)

API_INVENTORY_RULE_IDS = (
    "code.unversioned-api-route",
    "prevention.api-security-plan-missing",
)

MISCONFIGURATION_RULE_IDS = CONFIGURATION_RULE_IDS + (
    "code.wildcard-cors",
    "code.public-bind-all-interfaces",
    "code.directory-listing-enabled",
    "code.webdav-enabled",
)

SESSION_MANAGEMENT_RULE_IDS = (
    "code.insecure-cookie-settings",
    "code.persistent-sensitive-cookie",
    "code.csrf-disabled",
    "code.jwt-verification-disabled",
    "code.jwt-none-algorithm",
    "code.session-long-expiry",
)

CRYPTOGRAPHY_RULE_IDS = SENSITIVE_DATA_RULE_IDS + INSECURE_TRANSPORT_RULE_IDS + (
    "code.weak-hash",
    "code.insufficient-key-length",
    "code.insecure-random-security-use",
    "code.tls-certificate-verification-disabled",
    "code.password-hash-without-salt",
)

WEB_FILE_HANDLING_RULE_IDS = (
    "code.path-traversal",
    "code.unrestricted-file-upload",
)

API_SECURITY_RULE_IDS = ACCESS_CONTROL_RULE_IDS + AUTHENTICATION_RULE_IDS + (
    "code.unbounded-request-body",
    "code.api-missing-rate-limit",
    "code.ssrf-user-url",
    "code.wildcard-cors",
    "code.external-api-no-timeout",
    "code.unversioned-api-route",
    "prevention.api-security-plan-missing",
)

CLOUD_IAC_RULE_IDS = (
    "config.compose-privileged",
    "config.compose-host-network",
    "config.compose-docker-sock",
    "config.compose-dangerous-capability",
    "config.compose-host-pid",
    "config.compose-secret-in-environment",
    "config.k8s-privileged-container",
    "config.k8s-allow-privilege-escalation",
    "config.k8s-host-network",
    "config.k8s-hostpath-volume",
    "config.k8s-run-as-root",
    "config.k8s-service-account-token",
    "config.k8s-unpinned-image",
    "config.k8s-seccomp-unconfined",
    "config.k8s-dangerous-capability",
    "config.terraform-public-storage",
    "config.terraform-public-access-block-disabled",
    "config.terraform-open-admin-port",
    "config.terraform-wildcard-iam-action",
    "config.terraform-wildcard-principal",
    "config.terraform-public-ingress",
    "config.terraform-unencrypted-storage",
    "config.terraform-sensitive-output",
    "prevention.k8s-network-policy-missing",
    "prevention.container-hardening-guide-missing",
    "prevention.cloud-iac-security-plan-missing",
)

PRIVACY_RULE_IDS = SENSITIVE_DATA_RULE_IDS + (
    "code.pii-logging",
    "code.llm-sensitive-data-in-prompt",
    "config.android-allow-backup",
    "config.ios-file-sharing-enabled",
    "prevention.privacy-data-map-missing",
)

EXCEPTION_GOVERNANCE_RULE_IDS = (
    "prevention.exception-reason-missing",
    "prevention.exception-owner-missing",
    "prevention.exception-expiry-missing",
    "prevention.exception-expired",
)

SECURITY_GOVERNANCE_RULE_IDS = (
    "prevention.security-roadmap-missing",
    "prevention.evidence-register-missing",
) + EXCEPTION_GOVERNANCE_RULE_IDS

SCVS_RULE_IDS = DEPENDENCY_RULE_IDS + (
    "prevention.scvs-plan-missing",
    "prevention.sbom-missing",
    "prevention.vex-missing",
    "prevention.dependency-update-automation-missing",
    "prevention.dependency-track-integration-missing",
    "prevention.slsa-sigstore-missing",
    "prevention.release-provenance-automation-missing",
    "prevention.github-actions-unpinned",
    "prevention.github-token-permissions-not-readonly",
)

MOBILE_CONFIGURATION_RULE_IDS = (
    "config.android-debuggable",
    "config.android-allow-backup",
    "config.android-cleartext-traffic",
    "config.android-exported-component",
    "config.ios-ats-arbitrary-loads",
    "config.ios-file-sharing-enabled",
    "config.ios-open-documents-in-place",
)

MOBILE_SECURITY_RULE_IDS = SENSITIVE_DATA_RULE_IDS + INSECURE_TRANSPORT_RULE_IDS + MOBILE_CONFIGURATION_RULE_IDS + (
    "prevention.mobile-security-plan-missing",
)

LLM_SECURITY_RULE_IDS = (
    "code.llm-prompt-user-concat",
    "code.llm-tool-unrestricted",
    "code.llm-sensitive-data-in-prompt",
    "code.logging-sensitive-data",
    "code.unbounded-request-body",
    "code.eval-user-input",
    "dependency.osv-known-vulnerability",
    "prevention.ai-llm-security-plan-missing",
    "prevention.threat-model-missing",
    "prevention.sbom-missing",
    "prevention.vex-missing",
)

@dataclass(frozen=True)
class StandardReference:
    labels: dict[str, str]
    url: str


@dataclass(frozen=True)
class StandardCategory:
    id: str
    labels: dict[str, str]
    scanner_categories: tuple[str, ...] = ()
    rule_ids: tuple[str, ...] = ()
    description: dict[str, str] = field(default_factory=dict)

    @property
    def supported(self) -> bool:
        return bool(self.scanner_categories)


@dataclass(frozen=True)
class SecurityStandard:
    id: str
    labels: dict[str, str]
    categories: tuple[StandardCategory, ...]
    description: dict[str, str] = field(default_factory=dict)
    coverage: dict[str, str] = field(default_factory=dict)
    references: tuple[StandardReference, ...] = ()
    coverage_level: str = "evidence"
    issuer: dict[str, str] = field(default_factory=dict)
    published_on: str = ""
    version: str = ""


@dataclass(frozen=True)
class StandardSelection:
    standard: str
    category: str
    scanner_categories: tuple[str, ...]
    rule_ids: frozenset[str] | None = None


def _all_category(categories: tuple[StandardCategory, ...], labels: dict[str, str]) -> StandardCategory:
    scanner_categories: list[str] = []
    rule_ids: list[str] = []
    for category in categories:
        for scanner_category in category.scanner_categories:
            if scanner_category not in scanner_categories:
                scanner_categories.append(scanner_category)
        for rule_id in category.rule_ids:
            if rule_id not in rule_ids:
                rule_ids.append(rule_id)
    return StandardCategory(
        DEFAULT_STANDARD_CATEGORY,
        labels,
        scanner_categories=tuple(scanner_categories),
        rule_ids=tuple(rule_ids),
    )


def _reference(en: str, ko: str, url: str) -> StandardReference:
    return StandardReference({"en": en, "ko": ko}, url)


def _text(en: str, ko: str) -> dict[str, str]:
    return {"en": en, "ko": ko}


LOCAL_STANDARD = SecurityStandard(
    DEFAULT_STANDARD,
    {"en": "All", "ko": "전체"},
    (
        StandardCategory(
            DEFAULT_STANDARD_CATEGORY,
            {"en": "All", "ko": "전체"},
            scanner_categories=DEFAULT_CATEGORIES,
        ),
        StandardCategory(
            "secrets",
            {"en": "Secrets", "ko": "비밀값"},
            scanner_categories=("secrets",),
        ),
        StandardCategory(
            "dependencies",
            {"en": "Dependencies", "ko": "의존성"},
            scanner_categories=("dependencies",),
        ),
        StandardCategory(
            "configuration",
            {"en": "Configuration", "ko": "설정"},
            scanner_categories=("configuration",),
        ),
        StandardCategory(
            "code",
            {"en": "Code Patterns", "ko": "코드 패턴"},
            scanner_categories=("code",),
        ),
        StandardCategory(
            "screen_quality",
            {"en": "Screen Quality", "ko": "화면 품질"},
            scanner_categories=("screen_quality",),
        ),
        StandardCategory(
            "prevention",
            {"en": "Prevention Guardrails", "ko": "예방 가드레일"},
            scanner_categories=("prevention",),
            rule_ids=PREVENTION_RULE_IDS,
        ),
        StandardCategory(
            "api-security",
            {"en": "API Security", "ko": "API 보안"},
            scanner_categories=("code", "prevention"),
            rule_ids=API_SECURITY_RULE_IDS,
        ),
        StandardCategory(
            "auth-session",
            {"en": "Authentication and Session", "ko": "인증 및 세션"},
            scanner_categories=("code",),
            rule_ids=AUTHENTICATION_RULE_IDS + SESSION_MANAGEMENT_RULE_IDS,
        ),
        StandardCategory(
            "cloud-iac",
            {"en": "Cloud and IaC", "ko": "Cloud/IaC"},
            scanner_categories=("configuration", "prevention"),
            rule_ids=CLOUD_IAC_RULE_IDS,
        ),
        StandardCategory(
            "privacy",
            {"en": "Privacy and PII", "ko": "개인정보 및 PII"},
            scanner_categories=("secrets", "configuration", "code", "prevention"),
            rule_ids=PRIVACY_RULE_IDS,
        ),
        StandardCategory(
            "component-verification",
            {"en": "Component Verification", "ko": "구성요소 검증"},
            scanner_categories=("dependencies", "prevention"),
            rule_ids=SCVS_RULE_IDS,
        ),
        StandardCategory(
            "exception-governance",
            {"en": "Exception Governance", "ko": "예외 거버넌스"},
            scanner_categories=("prevention",),
            rule_ids=EXCEPTION_GOVERNANCE_RULE_IDS,
        ),
        StandardCategory(
            "roadmap-evidence",
            {"en": "Roadmap and Evidence", "ko": "로드맵 및 증적"},
            scanner_categories=("prevention",),
            rule_ids=SECURITY_GOVERNANCE_RULE_IDS,
        ),
        StandardCategory(
            "headers-container-hardening",
            {"en": "Headers and Container Hardening", "ko": "헤더 및 컨테이너 하드닝"},
            scanner_categories=("configuration", "code", "prevention"),
            rule_ids=(
                "code.directory-listing-enabled",
                "code.webdav-enabled",
                "config.compose-privileged",
                "config.compose-host-network",
                "config.compose-dangerous-capability",
                "config.k8s-seccomp-unconfined",
                "config.k8s-dangerous-capability",
                "prevention.security-headers-guide-missing",
                "prevention.container-hardening-guide-missing",
            ),
        ),
    ),
    description=_text(
        "KODA native rule categories for local file, dependency, configuration, code-pattern, screen-quality, and prevention guardrail checks.",
        "로컬 파일, 의존성, 설정, 코드 패턴, 화면 품질, 예방 가드레일을 점검하는 KODA 기본 룰 묶음입니다.",
    ),
    coverage=_text(
        "Runs the local heuristic rules directly. It is not a replacement for full SAST, DAST, or CVE intelligence.",
        "로컬 휴리스틱 룰을 직접 실행합니다. 전체 SAST, DAST, CVE 인텔리전스를 대체하지는 않습니다.",
    ),
    references=(
        _reference("KODA GitLab", "KODA GitLab", "https://gitlab.aigov.go.kr/y2kthr/koda"),
    ),
    coverage_level="local",
)


# OWASP Top 10 Proactive Controls (2024).  These are developer-facing secure
# coding controls rather than a vulnerability taxonomy; each category below is
# deliberately limited to local rules that can produce static evidence.
_OWASP_PROACTIVE_CONTROLS_CATEGORIES = (
    StandardCategory("c1-access-control", {"en": "C1 Implement Access Control", "ko": "C1 접근통제 구현"}, scanner_categories=("code",), rule_ids=ACCESS_CONTROL_RULE_IDS),
    StandardCategory("c2-cryptography", {"en": "C2 Use Cryptography to Protect Data", "ko": "C2 데이터 보호를 위한 암호기술 사용"}, scanner_categories=("secrets", "configuration", "dependencies", "code"), rule_ids=CRYPTOGRAPHY_RULE_IDS),
    StandardCategory("c3-input-exceptions", {"en": "C3 Validate all Input & Handle Exceptions", "ko": "C3 모든 입력 검증 및 예외 처리"}, scanner_categories=("code", "configuration"), rule_ids=INPUT_VALIDATION_RULE_IDS + ERROR_HANDLING_RULE_IDS),
    StandardCategory("c4-security-start", {"en": "C4 Address Security from the Start", "ko": "C4 초기 단계부터 보안 반영"}, scanner_categories=("code", "prevention"), rule_ids=INSECURE_DESIGN_RULE_IDS + PREVENTION_RULE_IDS),
    StandardCategory("c5-secure-defaults", {"en": "C5 Secure By Default Configurations", "ko": "C5 안전한 기본 설정"}, scanner_categories=("configuration", "code"), rule_ids=MISCONFIGURATION_RULE_IDS),
    StandardCategory("c6-components", {"en": "C6 Keep your Components Secure", "ko": "C6 구성요소 안전성 유지"}, scanner_categories=("dependencies", "prevention"), rule_ids=DEPENDENCY_RULE_IDS + INTEGRITY_RULE_IDS),
    StandardCategory("c7-digital-identity", {"en": "C7 Secure Digital Identities", "ko": "C7 디지털 신원 보호"}, scanner_categories=("code",), rule_ids=AUTHENTICATION_RULE_IDS),
    StandardCategory("c8-browser-security", {"en": "C8 Leverage Browser Security Features", "ko": "C8 브라우저 보안 기능 활용"}, scanner_categories=("code", "configuration"), rule_ids=INSECURE_TRANSPORT_RULE_IDS + ("code.wildcard-cors", "code.insecure-cookie-settings")),
    StandardCategory("c9-logging-monitoring", {"en": "C9 Implement Security Logging and Monitoring", "ko": "C9 보안 로깅 및 모니터링"}, scanner_categories=("code",), rule_ids=LOGGING_MONITORING_RULE_IDS),
    StandardCategory("c10-ssrf", {"en": "C10 Stop Server Side Request Forgery", "ko": "C10 서버사이드 요청 위조 차단"}, scanner_categories=("code",), rule_ids=("code.ssrf-user-url",)),
)

OWASP_PROACTIVE_CONTROLS = SecurityStandard(
    "owasp-proactive-controls",
    {"en": "OWASP Top 10 Proactive Controls:2024", "ko": "OWASP Top 10 Proactive Controls:2024"},
    (
        _all_category(_OWASP_PROACTIVE_CONTROLS_CATEGORIES, {"en": "All mapped OWASP proactive controls", "ko": "매핑된 OWASP 선제적 통제 전체"}),
        *_OWASP_PROACTIVE_CONTROLS_CATEGORIES,
    ),
    description=_text(
        "OWASP's 2024 developer-focused secure coding controls mapped to local static evidence.",
        "OWASP 2024 개발자 중심 시큐어코딩 통제를 로컬 정적 증거에 매핑한 프로파일입니다.",
    ),
    coverage=_text(
        "Automatic local checks cover only the mapped patterns; design, runtime, and business-logic review remain required.",
        "자동 점검은 매핑된 패턴만 다루며 설계, 런타임, 비즈니스 로직 검토가 추가로 필요합니다.",
    ),
    references=(
        _reference("OWASP Top 10 Proactive Controls", "OWASP Top 10 Proactive Controls", "https://top10proactive.owasp.org/the-top-10/"),
        _reference("OWASP Developer Guide", "OWASP Developer Guide", "https://devguide.owasp.org/en/05-implementation/01-documentation/01-proactive-controls/"),
    ),
    issuer=_text("OWASP Foundation", "OWASP 재단"),
    published_on="2024",
    version="2024",
)


# --- Korea SW Development Security 49 official implementation-stage controls -----
#
# Each of the 49 MOIS/KISA implementation-stage weaknesses is registered as an
# independent SecurityControl. A control may map to several KODA rules; a rule
# is only attached to the control it actually evidences. Controls that KODA
# cannot judge from static patterns are marked manual-review or unsupported and
# are never auto-passed.

SW49_SUPPORT_LEVELS = ("automated", "partial", "manual-review", "unsupported")
SW49_STATUSES = ("PASS", "VULNERABLE", "NEEDS_REVIEW", "UNSUPPORTED", "NOT_APPLICABLE", "NOT_SCANNED")

SW49_CATEGORY_EXPECTED_COUNTS = {
    "input-validation-expression": 17,
    "security-features": 16,
    "time-state": 2,
    "error-handling": 3,
    "code-error": 5,
    "encapsulation": 4,
    "api-misuse": 2,
}

SW49_CATEGORY_LABELS = {
    "input-validation-expression": {"en": "Input Data Validation and Representation", "ko": "입력데이터 검증 및 표현"},
    "security-features": {"en": "Security Features", "ko": "보안기능"},
    "time-state": {"en": "Time and State", "ko": "시간 및 상태"},
    "error-handling": {"en": "Error Handling", "ko": "에러처리"},
    "code-error": {"en": "Code Error", "ko": "코드오류"},
    "encapsulation": {"en": "Encapsulation", "ko": "캡슐화"},
    "api-misuse": {"en": "API Misuse", "ko": "API 오용"},
}

SW49_GUIDE_SECTION_BY_PREFIX = {
    "I": "1",
    "S": "2",
    "T": "3",
    "E": "4",
    "C": "5",
    "P": "6",
    "A": "7",
}

# Active web-probe rules that can add verified evidence to a control when a web
# scan has been run. They are not part of the local file-scan rule catalog.
WEB_VERIFIED_RULE_IDS = (
    "web.sql-injection-error-verified",
    "web.reflected-xss-verified",
    "web.open-redirect-verified",
)


@dataclass(frozen=True)
class SecurityControl:
    control_id: str
    official_id: str
    guide_id: str
    category_id: str
    title: dict[str, str]
    cwe_ids: tuple[str, ...] = ()
    rule_ids: tuple[str, ...] = ()
    support_level: str = "unsupported"
    supported_languages: tuple[str, ...] = ()
    notes: dict[str, str] = field(default_factory=dict)


def _control(
    official_id: str,
    category_id: str,
    ko: str,
    en: str,
    cwe_ids: tuple[str, ...],
    rule_ids: tuple[str, ...] = (),
    support_level: str = "unsupported",
    supported_languages: tuple[str, ...] = (),
    note_ko: str = "",
    note_en: str = "",
) -> SecurityControl:
    prefix, number = official_id.split("-", 1)
    guide_id = f"{SW49_GUIDE_SECTION_BY_PREFIX[prefix]}.{int(number)}"
    return SecurityControl(
        control_id=f"sw49.{prefix.lower()}{number}",
        official_id=official_id,
        guide_id=guide_id,
        category_id=category_id,
        title={"en": en, "ko": ko},
        cwe_ids=cwe_ids,
        rule_ids=rule_ids,
        support_level=support_level,
        supported_languages=supported_languages,
        notes=_text(note_en, note_ko) if (note_ko or note_en) else {},
    )


_WEB_LANGS = ("Java", "JSP", "JavaScript", "TypeScript", "Python", "PHP", "Ruby", "Kotlin", "C#", "Go", "Rust")
_C_LANGS = ("C", "C++")

SW49_CONTROLS: tuple[SecurityControl, ...] = (
    # 입력데이터 검증 및 표현 (17)
    _control(
        "I-01", "input-validation-expression", "SQL 삽입", "SQL Injection", ("CWE-89",),
        ("code.sql-dynamic-query", "web.sql-injection-error-verified"), "partial", _WEB_LANGS,
        note_ko="동적 SQL 문자열 조립 패턴을 탐지합니다. ORM 내부 우회나 저장 프로시저는 수동 확인이 필요합니다.",
        note_en="Detects dynamic SQL string assembly. ORM bypasses and stored procedures need manual review.",
    ),
    _control(
        "I-02", "input-validation-expression", "코드 삽입", "Code Injection", ("CWE-94", "CWE-95"),
        ("code.eval-user-input",), "partial",
        ("JavaScript", "TypeScript", "Python", "PHP", "Ruby", "HTML"),
    ),
    _control(
        "I-03", "input-validation-expression", "경로 조작 및 자원 삽입", "Path Manipulation and Resource Injection", ("CWE-22", "CWE-99"),
        ("code.path-traversal",), "partial", _WEB_LANGS,
    ),
    _control(
        "I-04", "input-validation-expression", "크로스사이트 스크립트", "Cross-site Scripting", ("CWE-79", "CWE-80"),
        ("code.xss-dom-sink", "web.reflected-xss-verified"), "partial",
        ("HTML", "JSP", "JavaScript", "TypeScript"),
        note_ko="DOM 싱크 패턴과 웹 능동 점검(실행 시)으로 확인합니다. 서버측 템플릿 XSS는 부분적으로만 탐지됩니다.",
        note_en="Covers DOM sinks and (when run) active web probes. Server-side template XSS is only partially detected.",
    ),
    _control(
        "I-05", "input-validation-expression", "운영체제 명령어 삽입", "OS Command Injection", ("CWE-78",),
        ("code.command-injection",), "partial", _WEB_LANGS,
    ),
    _control(
        "I-06", "input-validation-expression", "위험한 형식 파일 업로드", "Unrestricted Dangerous File Upload", ("CWE-434",),
        ("code.unrestricted-file-upload",), "partial",
        ("JavaScript", "TypeScript", "PHP", "Python"),
        note_ko="업로드 저장 패턴만 탐지합니다. 확장자·콘텐츠 검증 로직의 완전성은 수동 확인이 필요합니다.",
        note_en="Detects upload-save patterns only; completeness of extension/content validation needs manual review.",
    ),
    _control(
        "I-07", "input-validation-expression", "신뢰되지 않는 URL 주소로 자동접속 연결", "Open Redirect", ("CWE-601",),
        ("code.open-redirect-user-input", "web.open-redirect-verified"), "partial", _WEB_LANGS,
    ),
    _control(
        "I-08", "input-validation-expression", "부적절한 XML 외부 개체 참조", "Improper XML External Entity Reference", ("CWE-611",),
        ("code.xml-external-entity",), "partial", ("Java", "Kotlin", "C#", "Python"),
    ),
    _control(
        "I-09", "input-validation-expression", "XML 삽입", "XML Injection", ("CWE-91",),
        ("code.xml-injection",), "partial", ("Java", "Kotlin", "JavaScript", "TypeScript", "Python", "PHP"),
        note_ko="문자열 연결로 XML 본문을 조립하는 패턴만 탐지합니다. XXE(I-08)와는 별도 기준입니다.",
        note_en="Detects string-assembled XML bodies only. Separate from XXE (I-08).",
    ),
    _control(
        "I-10", "input-validation-expression", "LDAP 삽입", "LDAP Injection", ("CWE-90",),
        ("code.ldap-injection",), "partial", ("Java", "Kotlin", "Python"),
    ),
    _control(
        "I-11", "input-validation-expression", "크로스사이트 요청 위조", "Cross-Site Request Forgery", ("CWE-352",),
        ("code.csrf-disabled",), "partial", _WEB_LANGS,
        note_ko="CSRF 보호를 명시적으로 끄는 코드만 탐지합니다. 토큰 미구현 자체는 수동 확인이 필요합니다.",
        note_en="Detects explicit CSRF-protection opt-outs only; missing token implementations need manual review.",
    ),
    _control(
        "I-12", "input-validation-expression", "서버사이드 요청 위조", "Server-Side Request Forgery", ("CWE-918",),
        ("code.ssrf-user-url",), "partial", _WEB_LANGS,
    ),
    _control(
        "I-13", "input-validation-expression", "HTTP 응답분할", "HTTP Response Splitting", ("CWE-113",),
        ("code.http-response-splitting",), "partial", _WEB_LANGS,
    ),
    _control(
        "I-14", "input-validation-expression", "정수형 오버플로우", "Integer Overflow", ("CWE-190",),
        ("code.integer-overflow-user-input",), "partial", _C_LANGS + ("Java", "Kotlin", "C#"),
        note_ko="외부 입력에서 파싱한 정수가 동일 함수에서 범위 확인 없이 인덱스·할당 크기에 사용되는 경우를 후보로 표시합니다.",
        note_en="Flags integers parsed from external input and used in same-function indexing or allocation without a visible bounds check.",
    ),
    _control(
        "I-15", "input-validation-expression", "보안기능 결정에 사용되는 부적절한 입력값", "Improper Input in Security Decisions", ("CWE-807", "CWE-20"),
        ("code.security-decision-user-input",), "partial",
        ("Java", "Kotlin", "C#", "Python", "JavaScript", "TypeScript", "PHP", "Ruby"),
        note_ko="요청에서 받은 역할·권한·가격 등 결정값이 서버측 기준 조회 없이 사용되는 동일 함수 흐름을 후보로 표시합니다.",
        note_en="Flags same-function uses of request-controlled role, permission, price, and similar decision values without a visible server-side lookup.",
    ),
    _control(
        "I-16", "input-validation-expression", "메모리 버퍼 오버플로우", "Memory Buffer Overflow", ("CWE-119", "CWE-120", "CWE-121", "CWE-122"),
        ("code.dangerous-c-buffer-api",), "partial", _C_LANGS,
        note_ko="위험한 C 버퍼 API 사용만 탐지합니다. 경계 검증 여부는 수동 확인이 필요합니다.",
        note_en="Detects dangerous C buffer APIs only; bounds-check adequacy needs manual review.",
    ),
    _control(
        "I-17", "input-validation-expression", "포맷 스트링 삽입", "Format String Injection", ("CWE-134",),
        ("code.format-string-user-input",), "partial", _C_LANGS + ("Java", "Kotlin"),
    ),
    # 보안기능 (16)
    _control(
        "S-01", "security-features", "적절한 인증 없는 중요기능 허용", "Missing Authentication for Critical Function", ("CWE-306",),
        ("code.auth-disabled-endpoint", "code.api-route-missing-auth"), "partial", _WEB_LANGS,
        note_ko="인증을 끄거나 빠뜨린 것으로 보이는 라우트 패턴만 탐지합니다. 기능의 중요도 판단은 수동 확인이 필요합니다.",
        note_en="Detects routes that appear to disable or omit auth; criticality of the function needs manual review.",
    ),
    _control(
        "S-02", "security-features", "부적절한 인가", "Improper Authorization", ("CWE-862", "CWE-863"),
        ("code.authorization-check-missing",), "partial",
        ("Java", "Kotlin", "C#", "Python", "JavaScript", "TypeScript", "PHP", "Ruby"),
        note_ko="중요 기능의 라우트·메소드 주변에서 역할·소유권·권한 검사가 보이지 않는 경우를 후보로 표시합니다.",
        note_en="Flags sensitive routes or methods without a nearby role, ownership, or permission check.",
    ),
    _control(
        "S-03", "security-features", "중요한 자원에 대한 잘못된 권한 설정", "Incorrect Permission for Critical Resource", ("CWE-732",),
        ("code.insecure-resource-permissions",), "partial",
        ("Java", "Kotlin", "C#", "Python", "JavaScript", "TypeScript", "C", "C++"),
        note_ko="모든 사용자 쓰기·전체 제어처럼 명시적으로 과도한 파일·자원 권한을 설정하는 API 호출을 탐지합니다.",
        note_en="Detects API calls that explicitly grant world-writable or full-control resource permissions.",
    ),
    _control(
        "S-04", "security-features", "취약한 암호화 알고리즘 사용", "Use of Weak Cryptographic Algorithm", ("CWE-327",),
        ("code.weak-hash",), "partial", _WEB_LANGS,
        note_ko="MD5/SHA-1 호출 패턴만 탐지합니다. DES 등 대칭키 알고리즘 설정은 수동 확인이 필요합니다.",
        note_en="Detects MD5/SHA-1 call patterns; symmetric-cipher configuration (e.g. DES) needs manual review.",
    ),
    _control(
        "S-05", "security-features", "암호화되지 않은 중요정보", "Unencrypted Sensitive Data", ("CWE-311", "CWE-319"),
        (
            "config.env-file-present",
            "config.private-key-like-file",
            "dependency.node-insecure-url",
            "dependency.python-insecure-url",
            "config.docker-add-http",
        ),
        "partial",
        note_ko="평문 전송 URL과 저장소 내 민감 파일만 탐지합니다. 저장 데이터 암호화 여부는 수동 확인이 필요합니다.",
        note_en="Detects plaintext transport URLs and sensitive files in the repo; at-rest encryption needs manual review.",
    ),
    _control(
        "S-06", "security-features", "하드코드된 중요정보", "Hard-coded Sensitive Information", ("CWE-259", "CWE-321", "CWE-798"),
        SECRET_RULE_IDS, "partial",
    ),
    _control(
        "S-07", "security-features", "충분하지 않은 키 길이 사용", "Insufficient Key Length", ("CWE-326",),
        ("code.insufficient-key-length",), "partial", ("Java", "Kotlin", "Python", "Go", "C#", "JavaScript", "TypeScript"),
        note_ko="RSA/DSA/DH 1024비트 이하 등 명시적 짧은 키 설정만 탐지합니다.",
        note_en="Detects explicit short key sizes (RSA/DSA/DH <= 1024 bits) only.",
    ),
    _control(
        "S-08", "security-features", "적절하지 않은 난수 값 사용", "Use of Insufficiently Random Values", ("CWE-330", "CWE-338"),
        ("code.insecure-random-security-use",), "partial", ("Java", "Kotlin", "Python", "JavaScript", "TypeScript", "PHP", "Ruby", "C#"),
        note_ko="보안 목적 변수에 비암호학적 난수를 대입하는 패턴만 탐지합니다.",
        note_en="Detects non-cryptographic randomness assigned to security-purpose variables only.",
    ),
    _control(
        "S-09", "security-features", "취약한 비밀번호 허용", "Weak Password Requirements", ("CWE-521",),
        ("code.weak-password-policy",), "partial",
        ("Java", "Kotlin", "C#", "Python", "JavaScript", "TypeScript", "PHP", "Ruby"),
        note_ko="명시된 비밀번호 최소 길이가 8자 미만인 정책을 탐지합니다. 조합·유출 비밀번호 검증의 완전성은 수동 확인이 필요합니다.",
        note_en="Detects explicit minimum password lengths below eight; composition and breached-password controls still need review.",
    ),
    _control(
        "S-10", "security-features", "부적절한 전자서명 확인", "Improper Verification of Digital Signature", ("CWE-347",),
        ("code.jwt-verification-disabled", "code.jwt-none-algorithm"), "partial", _WEB_LANGS,
        note_ko="JWT 서명 검증 비활성화만 탐지합니다. JWT 외 전자서명 검증은 수동 확인이 필요합니다.",
        note_en="Covers disabled JWT verification only; non-JWT signature verification needs manual review.",
    ),
    _control(
        "S-11", "security-features", "부적절한 인증서 유효성 검증", "Improper Certificate Validation", ("CWE-295",),
        ("code.tls-certificate-verification-disabled",), "partial",
        ("Java", "Kotlin", "Python", "Go", "JavaScript", "TypeScript", "C#", "PHP", "Ruby"),
    ),
    _control(
        "S-12", "security-features", "사용자 하드디스크에 저장되는 쿠키를 통한 정보 노출", "Information Exposure Through Persistent Cookies", ("CWE-539",),
        ("code.persistent-sensitive-cookie",), "partial", _WEB_LANGS,
        note_ko="민감한 이름의 값과 쿠키 영속성 속성이 같은 저장 지점에 있을 때만 후보로 표시합니다. 실제 값의 민감도는 검토가 필요합니다.",
        note_en="Flags only cookie sinks that combine a sensitive-looking value with persistence; actual data sensitivity still needs review.",
    ),
    _control(
        "S-13", "security-features", "주석문 안에 포함된 시스템 주요정보", "Sensitive Information in Comments", ("CWE-615",),
        ("secret.sensitive-comment",), "partial",
        note_ko="주석 내 자격증명 대입 패턴을 탐지하며 발견 증거는 마스킹됩니다.",
        note_en="Detects credential assignments inside comments; evidence is redacted.",
    ),
    _control(
        "S-14", "security-features", "솔트 없이 일방향 해쉬 함수 사용", "One-way Hash Without Salt", ("CWE-759",),
        ("code.password-hash-without-salt",), "partial", ("Python", "Java", "Kotlin", "JavaScript", "TypeScript", "PHP", "Ruby", "C#"),
        note_ko="비밀번호 문맥에서 해시를 직접 호출하는 패턴만 탐지합니다.",
        note_en="Detects direct hash calls in password contexts only.",
    ),
    _control(
        "S-15", "security-features", "무결성 검사 없는 코드 다운로드", "Download of Code Without Integrity Check", ("CWE-494",),
        (
            "dependency.remote-shell-script",
            "dependency.docker-remote-shell",
            "config.docker-add-http",
            "prevention.github-actions-unpinned",
        ),
        "partial",
        note_ko="원격 스크립트 즉시 실행과 SHA 미고정 액션을 탐지합니다. 자체 업데이트 로직은 수동 확인이 필요합니다.",
        note_en="Detects remote-script piping and unpinned actions; custom self-update logic needs manual review.",
    ),
    _control(
        "S-16", "security-features", "반복된 인증시도 제한 기능 부재", "Missing Brute-force Protection", ("CWE-307",),
        ("code.auth-attempt-protection-missing",), "partial", ("Java", "Kotlin", "Python", "JavaScript", "TypeScript", "C#"),
        note_ko="인증 흐름이 확인되면서 속도 제한·잠금·추가 인증 통제가 보이지 않을 때만 후보로 표시합니다.",
        note_en="Flags authentication flows only when throttling, lockout, or step-up controls are not visible.",
    ),
    # 시간 및 상태 (2)
    _control(
        "T-01", "time-state", "경쟁조건: 검사 시점과 사용 시점(TOCTOU)", "Race Condition: TOCTOU", ("CWE-367",),
        ("code.insecure-temp-file",), "partial",
        note_ko="예측 가능한 임시파일 사용만 탐지합니다. 일반 TOCTOU는 수동 검토가 필요합니다.",
        note_en="Detects predictable temp-file use only; general TOCTOU needs manual review.",
    ),
    _control(
        "T-02", "time-state", "종료되지 않는 반복문 또는 재귀 함수", "Uncontrolled Loop or Recursion", ("CWE-835", "CWE-674"),
        ("code.uncontrolled-loop",), "partial",
        ("Java", "Kotlin", "C#", "Python", "JavaScript", "TypeScript", "PHP", "Ruby", "Go", "C", "C++"),
        note_ko="상수 조건 반복문에 종료 경로가 없거나 직접 재귀에 기저 조건이 보이지 않는 동일 함수 후보를 표시합니다.",
        note_en="Flags literal infinite loops without an exit and direct recursion without a visible base case in the same function.",
    ),
    # 에러처리 (3)
    _control(
        "E-01", "error-handling", "오류 메시지 정보노출", "Error Message Information Exposure", ("CWE-209",),
        ("config.debug-enabled", "code.stack-trace-exposure"), "partial",
    ),
    _control(
        "E-02", "error-handling", "오류 상황 대응 부재", "Missing Error Handling", ("CWE-390", "CWE-755"),
        ("code.empty-exception-handler",), "partial",
    ),
    _control(
        "E-03", "error-handling", "부적절한 예외 처리", "Improper Exception Handling", ("CWE-754", "CWE-755", "CWE-396", "CWE-397"),
        ("code.broad-exception-handler",), "partial", ("Java", "Kotlin", "Python", "Ruby", "C#"),
        note_ko="최상위 예외 형식을 포괄적으로 처리하는 지점만 후보로 표시하며, 빈 처리와 스택 노출은 각각 E-02와 E-01로 분리합니다.",
        note_en="Flags broad exception types for review; empty handlers and stack exposure remain E-02 and E-01 respectively.",
    ),
    # 코드오류 (5)
    _control(
        "C-01", "code-error", "Null Pointer 역참조", "Null Pointer Dereference", ("CWE-476",),
        ("code.null-pointer-dereference",), "partial", ("Java", "Kotlin"),
        note_ko="Java/Kotlin의 명시적 null 대입과 알려진 nullable 조회 API의 동일 파일 역참조만 점검합니다. 함수 간 흐름은 외부 SAST 검토가 필요합니다.",
        note_en="Checks explicit null assignments and known nullable lookup dereferences in the same Java/Kotlin file. Interprocedural flows still require external SAST.",
    ),
    _control(
        "C-02", "code-error", "부적절한 자원 해제", "Improper Resource Release", ("CWE-404", "CWE-772"),
        ("code.improper-resource-release",), "partial", ("Java", "Kotlin"),
        note_ko="동일 파일에서 자원 취득 후 명시적 해제나 try-with-resources가 보이지 않는 경우를 후보로 표시합니다.",
        note_en="Flags same-file acquisitions without an obvious close/release or try-with-resources construct.",
    ),
    _control(
        "C-03", "code-error", "해제된 자원 사용", "Use After Free", ("CWE-416",),
        ("code.use-after-free",), "partial", _C_LANGS,
    ),
    _control(
        "C-04", "code-error", "초기화되지 않은 변수 사용", "Use of Uninitialized Variable", ("CWE-457",),
        ("code.uninitialized-variable",), "partial", _C_LANGS,
    ),
    _control(
        "C-05", "code-error", "신뢰할 수 없는 데이터의 역직렬화", "Deserialization of Untrusted Data", ("CWE-502",),
        ("code.unsafe-deserialization",), "partial", ("Python", "Java", "PHP", "Ruby", "C#"),
    ),
    # 캡슐화 (4)
    _control(
        "P-01", "encapsulation", "잘못된 세션에 의한 데이터 정보 노출", "Data Exposure Between Sessions", ("CWE-488",),
        ("code.session-shared-state",), "partial", ("Java", "Kotlin", "C#", "Python"),
        note_ko="요청·세션별 사용자 데이터를 모듈 전역 또는 서블릿·컨트롤러 인스턴스 필드에 저장하는 패턴을 탐지합니다.",
        note_en="Detects request or session user data stored in module globals or servlet/controller instance fields.",
    ),
    _control(
        "P-02", "encapsulation", "제거되지 않고 남은 디버그 코드", "Leftover Debug Code", ("CWE-489",),
        ("config.debug-enabled", "config.development-environment"), "partial",
        note_ko="디버그 설정 활성화만 탐지합니다. 코드 내 디버그 출력 잔재는 수동 확인이 필요합니다.",
        note_en="Detects enabled debug configuration only; leftover debug prints need manual review.",
    ),
    _control(
        "P-03", "encapsulation", "Public 메소드부터 반환된 Private 배열", "Private Array Returned From Public Method", ("CWE-495",),
        ("code.private-array-return",), "partial", ("Java", "Kotlin", "C#"),
        note_ko="public 메소드가 private 배열·가변 컬렉션 참조를 clone 또는 복사 없이 직접 반환하는 경우를 탐지합니다.",
        note_en="Detects public methods that directly return private array or mutable collection references without cloning or copying.",
    ),
    _control(
        "P-04", "encapsulation", "Private 배열에 Public 데이터 할당", "Public Data Assigned to Private Array", ("CWE-496",),
        ("code.private-array-assignment",), "partial", ("Java", "Kotlin", "C#"),
        note_ko="public 메소드 인자의 배열·가변 컬렉션 참조를 private 필드에 clone 또는 복사 없이 직접 저장하는 경우를 탐지합니다.",
        note_en="Detects public method parameters assigned directly to private array or mutable collection fields without defensive copying.",
    ),
    # API 오용 (2)
    _control(
        "A-01", "api-misuse", "DNS lookup에 의존한 보안결정", "Security Decision Based on DNS Lookup", ("CWE-350", "CWE-247"),
        ("code.dns-security-decision",), "partial", ("Java", "Kotlin", "Python", "JavaScript", "TypeScript", "Go", "C#", "Ruby", "PHP", "C", "C++"),
        note_ko="동일 파일에서 DNS 조회 결과가 인증·인가·신뢰 비교에 직접 사용되는 경우를 후보로 표시합니다.",
        note_en="Flags same-file DNS results used directly in authentication, authorization, or trust comparisons.",
    ),
    _control(
        "A-02", "api-misuse", "취약한 API 사용", "Use of Dangerous API", ("CWE-676",),
        ("code.dangerous-c-buffer-api", "code.dangerous-managed-api"), "partial",
        _C_LANGS + ("Java", "Kotlin", "C#"),
        note_ko="가이드의 C/C++ 금지 API와 J2EE 직접 Socket·System.exit, C# Application.Exit 사용을 탐지합니다.",
        note_en="Covers the guide's C/C++ banned APIs, direct J2EE Socket/System.exit calls, and C# Application.Exit.",
    ),
)

SW49_CONTROLS_BY_OFFICIAL_ID = {control.official_id: control for control in SW49_CONTROLS}

_RULE_PREFIX_SCANNER_CATEGORY = {
    "code": "code",
    "secret": "secrets",
    "config": "configuration",
    "dependency": "dependencies",
    "prevention": "prevention",
}


def _rule_scanner_category(rule_id: str) -> str | None:
    return _RULE_PREFIX_SCANNER_CATEGORY.get(rule_id.split(".", 1)[0])


def _sw49_category(category_id: str) -> StandardCategory:
    rule_ids: list[str] = []
    scanner_categories: list[str] = []
    for control in SW49_CONTROLS:
        if control.category_id != category_id:
            continue
        for rule_id in control.rule_ids:
            scanner_category = _rule_scanner_category(rule_id)
            if scanner_category is None:
                continue  # web.* probe rules are not part of the local file scan
            if rule_id not in rule_ids:
                rule_ids.append(rule_id)
            if scanner_category not in scanner_categories:
                scanner_categories.append(scanner_category)
    return StandardCategory(
        category_id,
        SW49_CATEGORY_LABELS[category_id],
        scanner_categories=tuple(scanner_categories),
        rule_ids=tuple(rule_ids),
    )


# The seven official type categories are derived from the 49 controls so the
# profile filter and the per-control mapping can never drift apart.
_SW_DEV_SECURITY_CATEGORIES = tuple(_sw49_category(category_id) for category_id in SW49_CATEGORY_EXPECTED_COUNTS)


SW49_PREDICATE_FIELDS = {
    "evidence_kind": ("direct", "dataflow", "control_flow", "lifetime", "candidate"),
    "verification_state": ("confirmed", "needs_review"),
    "trace_complete": bool, "trace_step_count": int,
    "has_source": bool, "has_sink": bool, "has_guard": bool, "has_sanitizer": bool,
    "analyzer_rule_id": str,
}
SW49_PREDICATE_OPERATORS = {"eq", "in", "gte"}


def validate_sw49_predicate(predicate: Mapping[str, Any], *, depth: int = 0) -> None:
    if not isinstance(predicate, Mapping) or depth > 8:
        raise ValueError("invalid SW49 predicate")
    keys = set(predicate)
    if keys & {"all", "any", "not"}:
        if len(keys) != 1:
            raise ValueError("predicate has mixed operators")
        op = next(iter(keys)); value = predicate[op]
        if op in {"all", "any"}:
            if not isinstance(value, list) or not value:
                raise ValueError(f"{op} must be non-empty")
            for child in value: validate_sw49_predicate(child, depth=depth + 1)
        else: validate_sw49_predicate(value, depth=depth + 1)
        return
    if keys != {"field", "op", "value"}:
        raise ValueError("predicate fields are not allowed")
    name, op, value = predicate["field"], predicate["op"], predicate["value"]
    if name not in SW49_PREDICATE_FIELDS or op not in SW49_PREDICATE_OPERATORS:
        raise ValueError("unknown predicate field/operator")
    if name in {"trace_complete", "has_source", "has_sink", "has_guard", "has_sanitizer"}:
        if op != "eq" or type(value) is not bool: raise ValueError("invalid boolean predicate")
    elif name == "trace_step_count":
        values = value if op == "in" else [value]
        if op not in {"eq", "in", "gte"} or (op == "in" and (not isinstance(value, list) or not value)):
            raise ValueError("invalid integer predicate")
        if any(type(item) is not int or item < 0 for item in values): raise ValueError("invalid integer")
        if op == "in" and (len(value) > 128 or len(set(value)) != len(value)): raise ValueError("invalid in-list")
    else:
        values = value if op == "in" else [value]
        if op == "gte" or (op == "in" and (not isinstance(value, list) or not value)): raise ValueError("invalid scalar predicate")
        if name == "analyzer_rule_id" and any(not isinstance(item, str) or not item or len(item) > 256 for item in values): raise ValueError("invalid rule id")
        domain = SW49_PREDICATE_FIELDS[name]
        if isinstance(domain, tuple) and any(item not in domain for item in values): raise ValueError("invalid enum")
        if op == "in" and (len(value) > 128 or len(set(value)) != len(value)): raise ValueError("invalid in-list")


def evaluate_sw49_predicate(predicate: Mapping[str, Any], evidence: Mapping[str, Any]) -> bool:
    try:
        validate_sw49_predicate(predicate)
        if "all" in predicate: return all(evaluate_sw49_predicate(p, evidence) for p in predicate["all"])
        if "any" in predicate: return any(evaluate_sw49_predicate(p, evidence) for p in predicate["any"])
        if "not" in predicate: return not evaluate_sw49_predicate(predicate["not"], evidence)
        name, op, expected = predicate["field"], predicate["op"], predicate["value"]
        actual = evidence.get(name)
        if actual is None or (name == "trace_step_count" and type(actual) is not int): return False
        if op == "eq": return type(actual) is type(expected) and actual == expected
        if op == "in": return any(type(actual) is type(item) and actual == item for item in expected)
        return type(actual) is int and actual >= expected
    except (TypeError, ValueError, KeyError):
        return False


def sw49_contracts_payload() -> dict[str, Any]:
    path = Path(__file__).with_name("resources") / "sw49" / "contracts.json"
    raw = json.loads(path.read_text(encoding="utf-8"))
    validate_sw49_contracts(raw)
    return raw


def validate_sw49_contracts(document: Mapping[str, Any]) -> None:
    """Validate an untrusted contract document against canonical SW49 metadata."""
    if set(document) != {"schema", "mapping_version", "controls"} or document.get("schema") != "koda.sw49-contracts.v1":
        raise ValueError("invalid SW49 contract root")
    rows = document["controls"]
    if not isinstance(rows, list) or len(rows) != 49:
        raise ValueError("SW49 contracts must contain exactly 49 rows")
    seen = set()
    required_keys = {
        "official_id", "guide_id", "title_ko", "category_id", "cwe_ids", "applicability",
        "local_rule_ids", "external_mappings", "sources", "sinks", "propagators", "sanitizers",
        "evidence_requirements", "confirmation_predicate", "review_predicate", "required_strategies",
        "negative_coverage_strategy", "pass_certified_profiles",
    }
    for row in rows:
        if not isinstance(row, Mapping) or set(row) != required_keys or row.get("official_id") in seen:
            raise ValueError("duplicate or malformed SW49 contract")
        official_id = row["official_id"]; seen.add(official_id)
        control = SW49_CONTROLS_BY_OFFICIAL_ID.get(official_id)
        if control is None or row.get("guide_id") != control.guide_id or row.get("category_id") != control.category_id or tuple(row.get("cwe_ids", ())) != control.cwe_ids or row.get("title_ko") != control.title["ko"]:
            raise ValueError(f"non-canonical SW49 metadata: {official_id}")
        for key in ("confirmation_predicate", "review_predicate"):
            validate_sw49_predicate(row.get(key, {}))
        if not isinstance(row.get("required_strategies"), list) or not row["required_strategies"]:
            raise ValueError(f"missing strategies: {official_id}")
        if any(not isinstance(row.get(key), list) for key in ("local_rule_ids", "external_mappings", "sources", "sinks", "propagators", "sanitizers", "pass_certified_profiles")):
            raise ValueError(f"invalid SW49 contract list: {official_id}")
        expected_local = sorted(rule_id for rule_id in control.rule_ids if not rule_id.startswith("web."))
        if row["local_rule_ids"] != expected_local:
            raise ValueError(f"non-canonical local rules: {official_id}")
        applicability = row.get("applicability")
        if not isinstance(applicability, Mapping) or applicability.get("languages") != sorted(control.supported_languages) or applicability.get("extensions") != []:
            raise ValueError(f"non-canonical applicability: {official_id}")
        evidence = row.get("evidence_requirements")
        negative = row.get("negative_coverage_strategy")
        if not isinstance(evidence, Mapping) or not isinstance(evidence.get("required_fields"), list) or type(evidence.get("trace_required")) is not bool:
            raise ValueError(f"invalid evidence requirements: {official_id}")
        if not isinstance(negative, Mapping) or type(negative.get("clean_result_supports_pass")) is not bool:
            raise ValueError(f"invalid negative coverage strategy: {official_id}")
        external_strategy_ids = set()
        for external in row["external_mappings"]:
            if not isinstance(external, Mapping) or set(external) != {"analyzer", "rule_ids", "profile_id", "strategy_id"}:
                raise ValueError(f"invalid external mapping: {official_id}")
            if not external["analyzer"] or not external["profile_id"] or not external["rule_ids"]:
                raise ValueError(f"incomplete external mapping: {official_id}")
            external_strategy_ids.add(external["strategy_id"])
        if not external_strategy_ids.issubset(set(row["required_strategies"])):
            raise ValueError(f"unrequired external strategy: {official_id}")
        local_strategy = f"sw49.{official_id.lower().replace('-', '')}.local"
        expected_strategies = [local_strategy] + (["sw49.c01.codeql"] if official_id == "C-01" else [])
        if row["required_strategies"] != expected_strategies:
            raise ValueError(f"non-canonical strategies: {official_id}")
        if official_id == "C-01":
            expected_external_rules = {
                "java/dereferenced-value-is-always-null",
                "java/dereferenced-value-may-be-null",
                "java/dereferenced-expr-may-be-null",
                "java/null-dereference",
            }
            if len(row["external_mappings"]) != 1 or set(row["external_mappings"][0]["rule_ids"]) != expected_external_rules:
                raise ValueError("non-canonical C-01 external rules")
        elif row["external_mappings"]:
            raise ValueError(f"unexpected external mapping: {official_id}")
        if row["pass_certified_profiles"]:
            raise ValueError(f"uncertified PASS profile: {official_id}")
    if seen != set(SW49_CONTROLS_BY_OFFICIAL_ID):
        raise ValueError("missing or extra SW49 controls")


SW49_CONTRACTS = sw49_contracts_payload()["controls"]
SW49_STRATEGY_REGISTRY = {}
for _row in SW49_CONTRACTS:
    _control = SW49_CONTROLS_BY_OFFICIAL_ID[_row["official_id"]]
    for _strategy_id in _row["required_strategies"]:
        _external = next(
            (item for item in _row["external_mappings"] if item["strategy_id"] == _strategy_id),
            None,
        )
        SW49_STRATEGY_REGISTRY[_strategy_id] = {
            "kind": "external_rule" if _external else ("local_rule" if _row["local_rule_ids"] else ("manual_context" if _control.support_level == "manual-review" else "source_unsupported")),
            "profile_id": _external["profile_id"] if _external else None,
            "required_rule_ids": tuple(_external["rule_ids"] if _external else _row["local_rule_ids"]),
            "evidence_shape": ("evidence_kind", "verification_state"),
        }


def sw49_sarif_allowlist() -> dict[tuple[str, str], dict[str, object]]:
    """Return the curated analyzer/rule mapping used by the SARIF trust boundary."""
    mapping: dict[tuple[str, str], dict[str, object]] = {}
    for row in SW49_CONTRACTS:
        control = SW49_CONTROLS_BY_OFFICIAL_ID[row["official_id"]]
        for external in row["external_mappings"]:
            for rule_id in external["rule_ids"]:
                mapping[(str(external["analyzer"]).lower(), str(rule_id))] = {
                    "rule_id": control.rule_ids[0],
                    "category": "code",
                    "title": control.title["ko"],
                    "description": control.notes["ko"],
                    "cwe_ids": control.cwe_ids,
                    "verification_status": "confirmed",
                    "evidence_kind": "dataflow",
                    "trace_required": bool(row["evidence_requirements"]["trace_required"]),
                    "analyzer_versions": ("2.26.1",),
                    "official_id": control.official_id,
                }
    return mapping


def build_sw49_strategy_executions(
    manifest: object | None,
    scanned_categories: tuple[str, ...],
    analyzer_runs: tuple[object, ...] = (),
    sarif_warnings: tuple[str, ...] = (),
) -> tuple[object, ...]:
    """Build the fail-closed coverage ledger for all 49 controls.

    Local regex/context rules remain PARTIAL in this release. Imported SARIF is
    positive-only, so even a successful import cannot certify clean coverage.
    """
    from .source_analysis import StrategyExecution, source_languages

    files = tuple(entry[0] for entry in getattr(manifest, "files", ()))
    selected_categories = set(scanned_categories)
    analyzer_by_name = {str(getattr(run, "analyzer", "")).lower(): run for run in analyzer_runs}
    strategies = []
    for row in SW49_CONTRACTS:
        official_id = row["official_id"]
        control = SW49_CONTROLS_BY_OFFICIAL_ID[official_id]
        applicable_files = tuple(
            path for path in files
            if not control.supported_languages
            or any(language in control.supported_languages for language in source_languages(Path(path)))
        )
        for strategy_id in row["required_strategies"]:
            definition = SW49_STRATEGY_REGISTRY[strategy_id]
            kind = definition["kind"]
            required_rules = tuple(definition["required_rule_ids"])
            if kind == "external_rule":
                run = analyzer_by_name.get("codeql") or analyzer_by_name.get("sarif")
                if control.supported_languages and not applicable_files:
                    status = "NOT_APPLICABLE"
                    reason = "no_applicable_source_files"
                elif run is None or getattr(run, "status", "") != "SUCCESS":
                    status = "NOT_RUN"
                    reason = getattr(run, "failure_reason", "analyzer_not_run") if run else "analyzer_not_run"
                else:
                    status = "PARTIAL"
                    reason = "pre_generated_sarif_positive_only" if getattr(run, "output_origin", "") == "pre_generated" else "negative_rule_coverage_not_certified"
                    if sarif_warnings:
                        reason = "sarif_rule_coverage_incomplete"
                strategies.append(StrategyExecution(official_id, language="Java", profile_id=str(definition["profile_id"] or ""), strategy=strategy_id, status=status, analyzer_run_id=str(getattr(run, "run_id", "")) if run else "", required_rule_ids=required_rules, expected_files=applicable_files, analyzed_files=applicable_files if status == "PARTIAL" else (), reason=reason, manifest_digest=str(getattr(manifest, "digest", ""))))
                continue
            if not required_rules:
                status = "NOT_APPLICABLE" if control.supported_languages and not applicable_files else "NOT_RUN"
                reason = "no_applicable_source_files" if status == "NOT_APPLICABLE" else ("manual_context_required" if kind == "manual_context" else "no_source_static_strategy")
                strategies.append(StrategyExecution(official_id, strategy=strategy_id, status=status, expected_files=applicable_files, reason=reason, manifest_digest=str(getattr(manifest, "digest", ""))))
                continue
            rules_selected = all(_rule_scanner_category(rule_id) in selected_categories for rule_id in required_rules)
            status = "PARTIAL" if rules_selected and applicable_files else ("NOT_RUN" if not rules_selected else "NOT_APPLICABLE")
            reason = "local_source_rules_are_partial" if status == "PARTIAL" else ("no_applicable_source_files" if status == "NOT_APPLICABLE" else "required_scanner_category_not_selected")
            strategies.append(StrategyExecution(official_id, strategy=strategy_id, status=status, required_rule_ids=required_rules, present_rule_ids=required_rules if status == "PARTIAL" else (), requested_rule_ids=required_rules if status == "PARTIAL" else (), executed_rule_ids=required_rules if status == "PARTIAL" else (), expected_files=applicable_files, analyzed_files=applicable_files if status == "PARTIAL" else (), reason=reason, manifest_digest=str(getattr(manifest, "digest", ""))))
    return tuple(strategies)


def evaluate_sw49_controls(
    findings: list[Finding],
    scanned_categories: tuple[str, ...] = (),
    executed_rule_ids: frozenset[str] | None = None,
    selected_category_id: str | None = None,
    source_analysis: object | None = None,
) -> list[dict[str, object]]:
    """Judge each of the 49 controls against scan results.

    A control is never marked PASS just because nothing was found: PASS is only
    given to fully automated controls whose rules actually ran. Partial
    controls without findings stay NEEDS_REVIEW, and controls whose rules did
    not run are NOT_SCANNED.
    """
    findings_by_rule: dict[str, list[Finding]] = {}
    for finding in findings:
        findings_by_rule.setdefault(finding.rule_id, []).append(finding)

    scanned = set(scanned_categories)
    strategy_by_control: dict[str, list[object]] = {}
    if source_analysis is not None:
        for strategy in getattr(source_analysis, "strategies", ()):
            strategy_by_control.setdefault(str(getattr(strategy, "official_control", "")), []).append(strategy)
    results: list[dict[str, object]] = []
    for control in SW49_CONTROLS:
        selected = selected_category_id is None or control.category_id == selected_category_id
        eligible_rule_ids = (
            control.rule_ids
            if executed_rule_ids is None
            else tuple(rule_id for rule_id in control.rule_ids if rule_id in executed_rule_ids)
        )
        matched = [f for rule_id in eligible_rule_ids for f in findings_by_rule.get(rule_id, [])] if selected else []
        confirmed = [f for f in matched if f.verification_status == "confirmed"]
        review_candidates = [f for f in matched if f.verification_status == "needs_review"]
        executed = False
        if selected:
            for rule_id in eligible_rule_ids:
                scanner_category = _rule_scanner_category(rule_id)
                if scanner_category is None or scanner_category not in scanned:
                    continue
                if executed_rule_ids is not None and rule_id not in executed_rule_ids:
                    continue
                executed = True
                break

        contract = next(row for row in SW49_CONTRACTS if row["official_id"] == control.official_id)
        required_strategy_ids = tuple(contract["required_strategies"])
        control_strategies = strategy_by_control.get(control.official_id, [])
        all_not_applicable = bool(control_strategies) and all(getattr(item, "status", "") == "NOT_APPLICABLE" for item in control_strategies)
        successful_strategies = tuple(sorted(str(getattr(item, "strategy", "")) for item in control_strategies if getattr(item, "status", "") == "COMPLETE" and bool(getattr(item, "negative_coverage_certified", False))))
        missing_strategies = tuple(sorted(strategy_id for strategy_id in required_strategy_ids if strategy_id not in successful_strategies))
        coverage_complete = bool(required_strategy_ids) and not missing_strategies

        if not selected:
            status = "NOT_SCANNED"
        elif confirmed:
            status = "VULNERABLE"
            executed = True
        elif source_analysis is not None and review_candidates:
            status = "NEEDS_REVIEW"
            executed = True
        elif source_analysis is not None and all_not_applicable:
            status = "NOT_APPLICABLE"
            executed = False
        elif source_analysis is not None and not coverage_complete:
            executed = any(getattr(item, "status", "") not in {"NOT_RUN", "NOT_APPLICABLE"} for item in control_strategies)
            if control.support_level == "unsupported":
                status = "UNSUPPORTED"
            elif control.support_level == "manual-review" or executed:
                status = "NEEDS_REVIEW"
            else:
                status = "NOT_SCANNED"
        elif source_analysis is not None:
            # No profile is benchmark-certified for PASS in this release.
            status = "PASS" if contract["pass_certified_profiles"] else "NOT_SCANNED"
        elif control.support_level == "unsupported":
            status = "UNSUPPORTED"
        elif control.support_level == "manual-review":
            status = "NEEDS_REVIEW"
        elif not executed:
            status = "NOT_SCANNED"
        elif control.support_level == "automated":
            status = "PASS"
        else:  # partial: automation only covers part of the criterion
            status = "NEEDS_REVIEW"

        evidence = []
        for finding in matched[:5]:
            location = str(finding.path)
            if finding.line:
                location = f"{location}:{finding.line}"
            evidence.append(location)

        results.append(
            {
                "control_id": control.control_id,
                "official_id": control.official_id,
                "guide_id": control.guide_id,
                "category_id": control.category_id,
                "category_labels": SW49_CATEGORY_LABELS[control.category_id],
                "title": dict(control.title),
                "cwe_ids": list(control.cwe_ids),
                "rule_ids": list(control.rule_ids),
                "support_level": control.support_level,
                "supported_languages": list(control.supported_languages),
                "required_strategies": list(required_strategy_ids),
                "successful_strategies": list(successful_strategies),
                "missing_strategies": list(missing_strategies),
                "coverage_complete": coverage_complete,
                "executed": executed,
                "status": status,
                "finding_count": len(matched),
                "confirmed_finding_count": len(confirmed),
                "review_finding_count": len(review_candidates),
                "evidence": evidence,
                "notes": dict(control.notes),
            }
        )
    return results


def sw49_payload(
    findings: list[Finding],
    scanned_categories: tuple[str, ...] = (),
    standard_category: str = DEFAULT_STANDARD_CATEGORY,
    source_analysis: object | None = None,
) -> dict[str, object]:
    """Dashboard/report payload: all 49 control judgements plus a status summary."""
    executed_rule_ids: frozenset[str] | None = None
    selected_category_id: str | None = None
    if standard_category not in ("", DEFAULT_STANDARD_CATEGORY):
        category = _find_category(SW_DEV_SECURITY_49, standard_category)
        executed_rule_ids = frozenset(category.rule_ids)
        selected_category_id = category.id
    evaluation_findings = list(getattr(source_analysis, "all_findings", findings)) if source_analysis is not None else findings
    controls = evaluate_sw49_controls(
        evaluation_findings,
        scanned_categories,
        executed_rule_ids,
        selected_category_id,
        source_analysis,
    )
    if source_analysis is not None:
        visible_controls = evaluate_sw49_controls(
            list(getattr(source_analysis, "report_findings", findings)),
            scanned_categories,
            executed_rule_ids,
            selected_category_id,
            None,
        )
        for control, visible in zip(controls, visible_controls):
            control["analysis_finding_count"] = control["finding_count"]
            for key in ("finding_count", "confirmed_finding_count", "review_finding_count", "evidence"):
                control[key] = visible[key]
    status_counts = {status: 0 for status in SW49_STATUSES}
    support_counts = {level: 0 for level in SW49_SUPPORT_LEVELS}
    for entry in controls:
        status_counts[str(entry["status"])] += 1
        support_counts[str(entry["support_level"])] += 1
    return {
        "total": len(controls),
        "status_counts": status_counts,
        "support_counts": support_counts,
        "controls": controls,
    }

SW_DEV_SECURITY_49 = SecurityStandard(
    "sw-dev-security-49",
    {"en": "Korea SW Development Security 49", "ko": "소프트웨어 개발보안 49"},
    (
        _all_category(
            _SW_DEV_SECURITY_CATEGORIES,
            {"en": "All mapped SW security checks", "ko": "매핑된 SW 개발보안 항목 전체"},
        ),
        *_SW_DEV_SECURITY_CATEGORIES,
    ),
    description=_text(
        "Registers all 49 MOIS/KISA implementation-stage security weaknesses as individual controls with executable local strategies. Partial evidence never becomes an automatic PASS.",
        "행정안전부·KISA 구현단계 보안약점 49개를 기준별 실행 가능한 로컬 전략으로 표시하며, 부분 증거는 자동으로 PASS가 되지 않습니다.",
    ),
    coverage=_text(
        "Lists all 49 controls, but not every control is auto-diagnosed. Automated/partial controls are checked via source, configuration, secret, dependency, and optional web probes; design, permission, session, and complex data-flow controls need manual review or external SAST.",
        "49개 전체 기준 목록을 제공하지만 모든 항목이 자동 진단되는 것은 아닙니다. 자동·부분 지원 항목은 소스, 설정, 비밀값, 의존성 및 선택적 웹 점검으로 확인하고, 설계·권한·세션·복잡한 데이터 흐름 관련 항목은 수동 검토나 외부 SAST가 필요합니다.",
    ),
    references=(
        _reference(
            "MOIS Software Development Security Guide (2021)",
            "행정안전부 소프트웨어 개발보안 가이드(2021)",
            "https://www.mois.go.kr/frt/bbs/type001/commonSelectBoardArticle.do?bbsId=BBSMSTR_000000000015&nttId=88956",
        ),
        _reference("KISA Software Development Security", "KISA 소프트웨어 개발보안", "https://www.kisa.or.kr/1051202"),
    ),
    issuer=_text(
        "Ministry of the Interior and Safety / KISA",
        "행정안전부 / 한국인터넷진흥원",
    ),
    published_on="2021-11-30",
    version="2021",
)


_OWASP_TOP_10_2025_CATEGORIES = (
    StandardCategory(
        "a01-broken-access-control",
        {"en": "A01 Broken Access Control", "ko": "A01 접근권한 취약"},
        scanner_categories=("code",),
        rule_ids=ACCESS_CONTROL_RULE_IDS,
    ),
    StandardCategory(
        "a02-security-misconfiguration",
        {"en": "A02 Security Misconfiguration", "ko": "A02 보안 설정 오류"},
        scanner_categories=("configuration", "code"),
        rule_ids=MISCONFIGURATION_RULE_IDS,
    ),
    StandardCategory(
        "a03-software-supply-chain-failures",
        {"en": "A03 Software Supply Chain Failures", "ko": "A03 소프트웨어 공급망 실패"},
        scanner_categories=("dependencies",),
        rule_ids=SUPPLY_CHAIN_RULE_IDS,
    ),
    StandardCategory(
        "a04-cryptographic-failures",
        {"en": "A04 Cryptographic Failures", "ko": "A04 암호화 오류"},
        scanner_categories=("secrets", "configuration", "dependencies", "code"),
        rule_ids=CRYPTOGRAPHY_RULE_IDS,
    ),
    StandardCategory(
        "a05-injection",
        {"en": "A05 Injection", "ko": "A05 인젝션"},
        scanner_categories=("code",),
        rule_ids=INJECTION_RULE_IDS,
    ),
    StandardCategory(
        "a06-insecure-design",
        {"en": "A06 Insecure Design", "ko": "A06 안전하지 않은 설계"},
        scanner_categories=("code",),
        rule_ids=INSECURE_DESIGN_RULE_IDS,
    ),
    StandardCategory(
        "a07-authentication-failures",
        {"en": "A07 Authentication Failures", "ko": "A07 인증 실패"},
        scanner_categories=("code",),
        rule_ids=AUTHENTICATION_RULE_IDS,
    ),
    StandardCategory(
        "a08-software-data-integrity-failures",
        {"en": "A08 Software or Data Integrity Failures", "ko": "A08 소프트웨어 또는 데이터 무결성 실패"},
        scanner_categories=("dependencies", "configuration", "code"),
        rule_ids=INTEGRITY_RULE_IDS + ("code.unsafe-deserialization",),
    ),
    StandardCategory(
        "a09-security-logging-alerting-failures",
        {"en": "A09 Security Logging and Alerting Failures", "ko": "A09 보안 로깅 및 알림 실패"},
        scanner_categories=("code",),
        rule_ids=LOGGING_MONITORING_RULE_IDS,
    ),
    StandardCategory(
        "a10-mishandling-exceptional-conditions",
        {"en": "A10 Mishandling of Exceptional Conditions", "ko": "A10 예외 상황 처리 부적절"},
        scanner_categories=("configuration", "code"),
        rule_ids=ERROR_HANDLING_RULE_IDS,
    ),
)

OWASP_TOP_10_2025 = SecurityStandard(
    "owasp-top-10-2025",
    {"en": "OWASP Top 10:2025", "ko": "OWASP Top 10:2025"},
    (
        _all_category(
            _OWASP_TOP_10_2025_CATEGORIES,
            {"en": "All mapped OWASP 2025 checks", "ko": "매핑된 OWASP 2025 항목 전체"},
        ),
        *_OWASP_TOP_10_2025_CATEGORIES,
    ),
    description=_text(
        "A local profile for the project's OWASP Top 10:2025 category set.",
        "프로젝트에 포함된 OWASP Top 10:2025 카테고리 집합을 로컬 룰에 매핑한 프로파일입니다.",
    ),
    coverage=_text(
        "Automatic file-based checks. Validate against the official OWASP project before using it as formal evidence.",
        "자동 점검을 실행합니다. 공식 증적으로 쓰기 전 OWASP 공식 프로젝트 기준과 대조하세요.",
    ),
    references=(
        _reference("OWASP Top Ten Project", "OWASP Top Ten 프로젝트", "https://owasp.org/www-project-top-ten/"),
    ),
    issuer=_text("OWASP Foundation", "OWASP 재단"),
    published_on="2025",
    version="2025",
)


_OWASP_API_2023_CATEGORIES = (
    StandardCategory(
        "api1-broken-object-level-authorization",
        {"en": "API1 Broken Object Level Authorization", "ko": "API1 객체 수준 권한 부여 취약"},
        scanner_categories=("code",),
        rule_ids=ACCESS_CONTROL_RULE_IDS,
    ),
    StandardCategory(
        "api2-broken-authentication",
        {"en": "API2 Broken Authentication", "ko": "API2 인증 취약"},
        scanner_categories=("code",),
        rule_ids=AUTHENTICATION_RULE_IDS,
    ),
    StandardCategory(
        "api3-broken-object-property-level-authorization",
        {"en": "API3 Broken Object Property Level Authorization", "ko": "API3 객체 속성 수준 권한 부여 취약"},
        scanner_categories=("code",),
        rule_ids=ACCESS_CONTROL_RULE_IDS,
    ),
    StandardCategory(
        "api4-unrestricted-resource-consumption",
        {"en": "API4 Unrestricted Resource Consumption", "ko": "API4 제한 없는 리소스 사용"},
        scanner_categories=("code",),
        rule_ids=("code.unbounded-request-body", "code.api-missing-rate-limit"),
    ),
    StandardCategory(
        "api5-broken-function-level-authorization",
        {"en": "API5 Broken Function Level Authorization", "ko": "API5 기능 수준 권한 부여 취약"},
        scanner_categories=("code",),
        rule_ids=ACCESS_CONTROL_RULE_IDS,
    ),
    StandardCategory(
        "api6-unrestricted-access-sensitive-business-flows",
        {"en": "API6 Unrestricted Access to Sensitive Business Flows", "ko": "API6 민감 비즈니스 흐름 접근 제한 미흡"},
        scanner_categories=("code", "prevention"),
        rule_ids=ACCESS_CONTROL_RULE_IDS + ("code.unbounded-request-body", "code.api-missing-rate-limit", "prevention.api-security-plan-missing"),
    ),
    StandardCategory(
        "api7-server-side-request-forgery",
        {"en": "API7 Server Side Request Forgery", "ko": "API7 서버사이드 요청 위조"},
        scanner_categories=("code",),
        rule_ids=("code.ssrf-user-url",),
    ),
    StandardCategory(
        "api8-security-misconfiguration",
        {"en": "API8 Security Misconfiguration", "ko": "API8 보안 설정 오류"},
        scanner_categories=("configuration", "code"),
        rule_ids=MISCONFIGURATION_RULE_IDS,
    ),
    StandardCategory(
        "api9-improper-inventory-management",
        {"en": "API9 Improper Inventory Management", "ko": "API9 부적절한 인벤토리 관리"},
        scanner_categories=("code",),
        rule_ids=API_INVENTORY_RULE_IDS,
    ),
    StandardCategory(
        "api10-unsafe-consumption-of-apis",
        {"en": "API10 Unsafe Consumption of APIs", "ko": "API10 안전하지 않은 API 사용"},
        scanner_categories=("dependencies", "configuration", "code"),
        rule_ids=INSECURE_TRANSPORT_RULE_IDS + REMOTE_EXECUTION_RULE_IDS + ("code.ssrf-user-url", "code.external-api-no-timeout"),
    ),
)

OWASP_API_SECURITY_2023 = SecurityStandard(
    "owasp-api-security-2023",
    {"en": "OWASP API Security Top 10:2023", "ko": "OWASP API Security Top 10:2023"},
    (
        _all_category(
            _OWASP_API_2023_CATEGORIES,
            {"en": "All mapped API Security checks", "ko": "매핑된 API Security 항목 전체"},
        ),
        *_OWASP_API_2023_CATEGORIES,
    ),
    description=_text(
        "OWASP API Security Top 10:2023 risks mapped to local API route, authorization, SSRF, resource, and configuration checks.",
        "OWASP API Security Top 10:2023 위험을 API 라우트, 인가, SSRF, 리소스, 설정 로컬 점검에 매핑한 프로파일입니다.",
    ),
    coverage=_text(
        "Automatic file-based checks. Object-level authorization and business-flow abuse require design and runtime testing for final validation.",
        "자동 점검을 실행합니다. 객체 수준 인가와 비즈니스 흐름 남용은 설계 검토와 실행 점검으로 최종 확인해야 합니다.",
    ),
    references=(
        _reference("OWASP API Security Project", "OWASP API Security 프로젝트", "https://owasp.org/API-Security/"),
    ),
    issuer=_text("OWASP Foundation", "OWASP 재단"),
    published_on="2023",
    version="2023",
)


_OWASP_MOBILE_2024_CATEGORIES = (
    StandardCategory(
        "m1-improper-credential-usage",
        {"en": "M1 Improper Credential Usage", "ko": "M1 부적절한 자격증명 사용"},
        scanner_categories=("secrets", "configuration"),
        rule_ids=SENSITIVE_DATA_RULE_IDS,
    ),
    StandardCategory(
        "m2-inadequate-supply-chain-security",
        {"en": "M2 Inadequate Supply Chain Security", "ko": "M2 부적절한 공급망 보안"},
        scanner_categories=("dependencies",),
        rule_ids=SUPPLY_CHAIN_RULE_IDS,
    ),
    StandardCategory(
        "m3-insecure-authentication-authorization",
        {"en": "M3 Insecure Authentication/Authorization", "ko": "M3 안전하지 않은 인증/인가"},
        scanner_categories=("code",),
        rule_ids=AUTHENTICATION_RULE_IDS,
    ),
    StandardCategory(
        "m4-insufficient-input-output-validation",
        {"en": "M4 Insufficient Input/Output Validation", "ko": "M4 입출력 검증 부족"},
        scanner_categories=("code",),
        rule_ids=INPUT_VALIDATION_RULE_IDS,
    ),
    StandardCategory(
        "m5-insecure-communication",
        {"en": "M5 Insecure Communication", "ko": "M5 안전하지 않은 통신"},
        scanner_categories=("dependencies", "configuration"),
        rule_ids=INSECURE_TRANSPORT_RULE_IDS,
    ),
    StandardCategory(
        "m6-inadequate-privacy-controls",
        {"en": "M6 Inadequate Privacy Controls", "ko": "M6 부적절한 개인정보 보호 통제"},
        scanner_categories=("secrets", "configuration"),
        rule_ids=SENSITIVE_DATA_RULE_IDS,
    ),
    StandardCategory("m7-insufficient-binary-protections", {"en": "M7 Insufficient Binary Protections", "ko": "M7 바이너리 보호 부족"}),
    StandardCategory(
        "m8-security-misconfiguration",
        {"en": "M8 Security Misconfiguration", "ko": "M8 보안 설정 오류"},
        scanner_categories=("configuration", "code"),
        rule_ids=MISCONFIGURATION_RULE_IDS,
    ),
    StandardCategory(
        "m9-insecure-data-storage",
        {"en": "M9 Insecure Data Storage", "ko": "M9 안전하지 않은 데이터 저장"},
        scanner_categories=("secrets", "configuration"),
        rule_ids=SENSITIVE_DATA_RULE_IDS,
    ),
    StandardCategory(
        "m10-insufficient-cryptography",
        {"en": "M10 Insufficient Cryptography", "ko": "M10 암호화 부족"},
        scanner_categories=("secrets", "configuration", "dependencies"),
        rule_ids=SENSITIVE_DATA_RULE_IDS + INSECURE_TRANSPORT_RULE_IDS,
    ),
)

OWASP_MOBILE_TOP_10_2024 = SecurityStandard(
    "owasp-mobile-top-10-2024",
    {"en": "OWASP Mobile Top 10:2024", "ko": "OWASP Mobile Top 10:2024"},
    (
        _all_category(
            _OWASP_MOBILE_2024_CATEGORIES,
            {"en": "All mapped Mobile Top 10 checks", "ko": "매핑된 Mobile Top 10 항목 전체"},
        ),
        *_OWASP_MOBILE_2024_CATEGORIES,
    ),
    description=_text(
        "OWASP mobile application risk categories mapped where source and configuration evidence is available.",
        "모바일 앱 위험 범주 중 소스와 설정 근거가 있는 항목을 로컬 룰에 매핑한 프로파일입니다.",
    ),
    coverage=_text(
        "External integration required for complete mobile validation. Local source and configuration checks still run automatically.",
        "완전한 모바일 검증에는 외부 연동이 필요합니다. 로컬 소스와 설정 점검은 자동으로 실행합니다.",
    ),
    references=(
        _reference("OWASP Mobile Application Security", "OWASP Mobile Application Security", "https://owasp.org/www-project-mobile-top-10/"),
    ),
    issuer=_text("OWASP Foundation", "OWASP 재단"),
    published_on="2024",
    version="2024",
)


_CWE_TOP_25_2025_CATEGORIES = (
    StandardCategory(
        "cwe-79-cross-site-scripting",
        {"en": "CWE-79 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')", "ko": "CWE-79 웹 페이지 생성 중 입력값 무해화 미흡(크로스사이트 스크립팅)"},
        scanner_categories=("code",),
        rule_ids=("code.xss-dom-sink",),
    ),
    StandardCategory(
        "cwe-89-sql-injection",
        {"en": "CWE-89 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')", "ko": "CWE-89 SQL 명령 특수요소 무해화 미흡(SQL 삽입)"},
        scanner_categories=("code",),
        rule_ids=("code.sql-dynamic-query",),
    ),
    StandardCategory(
        "cwe-352-cross-site-request-forgery",
        {"en": "CWE-352 Cross-Site Request Forgery (CSRF)", "ko": "CWE-352 크로스사이트 요청 위조(CSRF)"},
        scanner_categories=("code",),
        rule_ids=("code.csrf-disabled",),
    ),
    StandardCategory(
        "cwe-862-missing-authorization",
        {"en": "CWE-862 Missing Authorization", "ko": "CWE-862 인가 누락"},
        scanner_categories=("code",),
        rule_ids=("code.auth-disabled-endpoint", "code.api-route-missing-auth"),
    ),
    StandardCategory(
        "cwe-787-out-of-bounds-write",
        {"en": "CWE-787 Out-of-bounds Write", "ko": "CWE-787 범위 밖 쓰기"},
    ),
    StandardCategory(
        "cwe-22-path-traversal",
        {"en": "CWE-22 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')", "ko": "CWE-22 제한 디렉터리 경로명 제한 미흡(경로 조작)"},
        scanner_categories=("code",),
        rule_ids=("code.path-traversal",),
    ),
    StandardCategory(
        "cwe-416-use-after-free",
        {"en": "CWE-416 Use After Free", "ko": "CWE-416 해제 후 사용"},
    ),
    StandardCategory(
        "cwe-125-out-of-bounds-read",
        {"en": "CWE-125 Out-of-bounds Read", "ko": "CWE-125 범위 밖 읽기"},
    ),
    StandardCategory(
        "cwe-78-os-command-injection",
        {"en": "CWE-78 Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')", "ko": "CWE-78 운영체제 명령 특수요소 무해화 미흡(OS 명령 삽입)"},
        scanner_categories=("code",),
        rule_ids=("code.command-injection",),
    ),
    StandardCategory(
        "cwe-94-code-injection",
        {"en": "CWE-94 Improper Control of Generation of Code ('Code Injection')", "ko": "CWE-94 코드 생성 제어 미흡(코드 삽입)"},
        scanner_categories=("code",),
        rule_ids=("code.eval-user-input",),
    ),
    StandardCategory(
        "cwe-120-classic-buffer-overflow",
        {"en": "CWE-120 Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')", "ko": "CWE-120 입력 크기 확인 없는 버퍼 복사(전통적 버퍼 오버플로우)"},
        scanner_categories=("code",),
        rule_ids=MEMORY_SAFETY_RULE_IDS,
    ),
    StandardCategory(
        "cwe-434-dangerous-file-upload",
        {"en": "CWE-434 Unrestricted Upload of File with Dangerous Type", "ko": "CWE-434 위험한 형식의 파일 업로드 제한 미흡"},
        scanner_categories=("code",),
        rule_ids=("code.unrestricted-file-upload",),
    ),
    StandardCategory(
        "cwe-476-null-pointer-dereference",
        {"en": "CWE-476 NULL Pointer Dereference", "ko": "CWE-476 NULL 포인터 역참조"},
        scanner_categories=("code",),
        rule_ids=("code.null-pointer-dereference",),
    ),
    StandardCategory(
        "cwe-121-stack-buffer-overflow",
        {"en": "CWE-121 Stack-based Buffer Overflow", "ko": "CWE-121 스택 기반 버퍼 오버플로우"},
    ),
    StandardCategory(
        "cwe-502-unsafe-deserialization",
        {"en": "CWE-502 Deserialization of Untrusted Data", "ko": "CWE-502 신뢰할 수 없는 데이터 역직렬화"},
        scanner_categories=("code",),
        rule_ids=("code.unsafe-deserialization",),
    ),
    StandardCategory(
        "cwe-122-heap-buffer-overflow",
        {"en": "CWE-122 Heap-based Buffer Overflow", "ko": "CWE-122 힙 기반 버퍼 오버플로우"},
    ),
    StandardCategory(
        "cwe-863-incorrect-authorization",
        {"en": "CWE-863 Incorrect Authorization", "ko": "CWE-863 잘못된 인가"},
    ),
    StandardCategory(
        "cwe-20-improper-input-validation",
        {"en": "CWE-20 Improper Input Validation", "ko": "CWE-20 부적절한 입력값 검증"},
        scanner_categories=("code",),
        rule_ids=INPUT_VALIDATION_RULE_IDS,
    ),
    StandardCategory(
        "cwe-284-improper-access-control",
        {"en": "CWE-284 Improper Access Control", "ko": "CWE-284 부적절한 접근통제"},
        scanner_categories=("code",),
        rule_ids=ACCESS_CONTROL_RULE_IDS,
    ),
    StandardCategory(
        "cwe-200-sensitive-information-exposure",
        {"en": "CWE-200 Exposure of Sensitive Information to an Unauthorized Actor", "ko": "CWE-200 비인가자에 대한 민감정보 노출"},
        scanner_categories=("secrets", "configuration"),
        rule_ids=SENSITIVE_DATA_RULE_IDS,
    ),
    StandardCategory(
        "cwe-306-missing-authentication-critical-function",
        {"en": "CWE-306 Missing Authentication for Critical Function", "ko": "CWE-306 중요 기능 인증 누락"},
        scanner_categories=("code",),
        rule_ids=("code.auth-disabled-endpoint", "code.api-route-missing-auth"),
    ),
    StandardCategory(
        "cwe-918-server-side-request-forgery",
        {"en": "CWE-918 Server-Side Request Forgery (SSRF)", "ko": "CWE-918 서버사이드 요청 위조(SSRF)"},
        scanner_categories=("code",),
        rule_ids=("code.ssrf-user-url",),
    ),
    StandardCategory(
        "cwe-77-command-injection",
        {"en": "CWE-77 Improper Neutralization of Special Elements used in a Command ('Command Injection')", "ko": "CWE-77 명령 특수요소 무해화 미흡(명령 삽입)"},
        scanner_categories=("code",),
        rule_ids=("code.command-injection",),
    ),
    StandardCategory(
        "cwe-639-authorization-bypass-user-controlled-key",
        {"en": "CWE-639 Authorization Bypass Through User-Controlled Key", "ko": "CWE-639 사용자 제어 키를 통한 인가 우회"},
    ),
    StandardCategory(
        "cwe-770-resource-allocation-without-limits",
        {"en": "CWE-770 Allocation of Resources Without Limits or Throttling", "ko": "CWE-770 제한 또는 조절 없는 자원 할당"},
        scanner_categories=("code",),
        rule_ids=("code.unbounded-request-body", "code.api-missing-rate-limit"),
    ),
)

CWE_TOP_25_2025 = SecurityStandard(
    "cwe-top-25-2025",
    {"en": "CWE Top 25:2025", "ko": "CWE Top 25:2025"},
    (
        _all_category(
            _CWE_TOP_25_2025_CATEGORIES,
            {"en": "All mapped CWE Top 25 checks", "ko": "매핑된 CWE Top 25 항목 전체"},
        ),
        *_CWE_TOP_25_2025_CATEGORIES,
    ),
    description=_text(
        "MITRE CWE Top 25:2025 weaknesses mapped to the local rules where lightweight evidence is possible.",
        "MITRE CWE Top 25:2025 약점 중 경량 로컬 근거를 만들 수 있는 항목을 매핑한 프로파일입니다.",
    ),
    coverage=_text(
        "Automatic file-based checks. Deep memory-lifetime and interprocedural null-dereference analysis remains unsupported.",
        "자동 파일 점검을 실행합니다. 메모리 수명과 함수 간 NULL 역참조의 깊은 분석은 아직 지원하지 않습니다.",
    ),
    references=(
        _reference("MITRE CWE Top 25:2025", "MITRE CWE Top 25:2025", "https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html"),
    ),
    issuer=_text("MITRE CWE", "MITRE CWE"),
    published_on="2025",
    version="2025",
)


_ISMS_P_28_CATEGORIES = (
    StandardCategory(
        "2.8.1-security-requirements-definition",
        {"en": "2.8.1 Security Requirements Definition", "ko": "2.8.1 보안 요구사항 정의"},
        scanner_categories=DEFAULT_CATEGORIES,
        rule_ids=SECRET_RULE_IDS + DEPENDENCY_RULE_IDS + CONFIGURATION_RULE_IDS + CODE_PATTERN_RULE_IDS,
    ),
    StandardCategory(
        "2.8.2-security-requirements-review-testing",
        {"en": "2.8.2 Security Requirements Review and Testing", "ko": "2.8.2 보안 요구사항 검토 및 시험"},
        scanner_categories=DEFAULT_CATEGORIES,
        rule_ids=SECRET_RULE_IDS + DEPENDENCY_RULE_IDS + CONFIGURATION_RULE_IDS + CODE_PATTERN_RULE_IDS,
    ),
    StandardCategory(
        "2.8.3-test-production-separation",
        {"en": "2.8.3 Test and Production Environment Separation", "ko": "2.8.3 시험과 운영 환경 분리"},
        scanner_categories=("configuration", "code"),
        rule_ids=ERROR_HANDLING_RULE_IDS,
    ),
    StandardCategory(
        "2.8.4-test-data-security",
        {"en": "2.8.4 Test Data Security", "ko": "2.8.4 시험 데이터 보안"},
        scanner_categories=("secrets", "configuration"),
        rule_ids=SENSITIVE_DATA_RULE_IDS,
    ),
    StandardCategory(
        "2.8.5-source-program-management",
        {"en": "2.8.5 Source Program Management", "ko": "2.8.5 소스 프로그램 관리"},
        scanner_categories=("secrets", "dependencies", "configuration", "code"),
        rule_ids=SECRET_RULE_IDS
        + (
            "config.env-file-present",
            "config.private-key-like-file",
            "dependency.node-missing-lockfile",
        )
        + CODE_PATTERN_RULE_IDS,
    ),
    StandardCategory(
        "2.8.6-production-migration",
        {"en": "2.8.6 Production Migration", "ko": "2.8.6 운영환경 이관"},
        scanner_categories=("configuration",),
        rule_ids=CONFIGURATION_RULE_IDS,
    ),
)

ISMS_P_DEVELOPMENT_SECURITY = SecurityStandard(
    "isms-p-development-security",
    {"en": "ISMS-P 2.8 Development Security", "ko": "ISMS-P 2.8 개발보안"},
    (
        _all_category(
            _ISMS_P_28_CATEGORIES,
            {"en": "All mapped ISMS-P 2.8 checks", "ko": "매핑된 ISMS-P 2.8 항목 전체"},
        ),
        *_ISMS_P_28_CATEGORIES,
    ),
    description=_text(
        "ISMS-P development-security control area mapped to local evidence for secure requirements, testing, test data, source management, and migration hygiene.",
        "ISMS-P 개발보안 통제 영역을 보안 요구사항, 시험, 시험 데이터, 소스 관리, 운영 이관 위생의 로컬 근거에 매핑한 프로파일입니다.",
    ),
    coverage=_text(
        "Evidence review required. Certification evidence also requires process documents, approvals, and operating records.",
        "증적 확인이 필요합니다. 인증 증적에는 프로세스 문서, 승인, 운영 기록도 필요합니다.",
    ),
    references=(
        _reference("KISA ISMS-P", "KISA ISMS-P", "https://isms.kisa.or.kr/"),
    ),
)


KISA_SECURE_CODING_GUIDE = SecurityStandard(
    "kisa-secure-coding-guide",
    {
        "en": "KISA Software Security Weakness Diagnostic Guide 2021",
        "ko": "KISA 소프트웨어 보안약점 진단가이드 2021",
    },
    (
        _all_category(
            _SW_DEV_SECURITY_CATEGORIES,
            {"en": "All mapped secure-coding guide checks", "ko": "매핑된 시큐어코딩 가이드 항목 전체"},
        ),
        *_SW_DEV_SECURITY_CATEGORIES,
    ),
    description=_text(
        "KISA's official 2021 diagnostic guide, using the same seven types and 49 implementation-stage security weaknesses published with the Korean software development security criteria.",
        "KISA가 2021년에 발행한 공식 진단가이드의 7개 유형·구현단계 보안약점 49개를 사용하는 프로파일입니다.",
    ),
    coverage=SW_DEV_SECURITY_49.coverage,
    references=(
        _reference(
            "KISA Software Security Weakness Diagnostic Guide (2021)",
            "KISA 소프트웨어 보안약점 진단가이드(2021)",
            "https://www.kisa.or.kr/2060204/form?page=1&postSeq=9",
        ),
        _reference(
            "MOIS Software Development Security Guide (2021)",
            "행정안전부 소프트웨어 개발보안 가이드(2021)",
            "https://www.mois.go.kr/frt/bbs/type001/commonSelectBoardArticle.do?bbsId=BBSMSTR_000000000015&nttId=88956",
        ),
    ),
    issuer=_text("Korea Internet & Security Agency", "한국인터넷진흥원"),
    published_on="2021-11-30",
    version="2021",
)

SW_DEV_SECURITY_7_TYPES = SecurityStandard(
    "sw-dev-security-7-types",
    {"en": "Korea SW Development Security 7 Types", "ko": "소프트웨어 개발보안 7가지 유형"},
    (
        _all_category(
            _SW_DEV_SECURITY_CATEGORIES,
            {"en": "All mapped SW development security type checks", "ko": "매핑된 SW 개발보안 유형 전체"},
        ),
        *_SW_DEV_SECURITY_CATEGORIES,
    ),
    description=_text(
        "The seven secure-coding type taxonomy: input validation, security features, time/state, error handling, code error, encapsulation, and API misuse.",
        "입력데이터 검증, 보안기능, 시간 및 상태, 에러처리, 코드오류, 캡슐화, API 오용의 7가지 유형 프로파일입니다.",
    ),
    coverage=SW_DEV_SECURITY_49.coverage,
    references=SW_DEV_SECURITY_49.references,
    issuer=SW_DEV_SECURITY_49.issuer,
    published_on=SW_DEV_SECURITY_49.published_on,
    version=SW_DEV_SECURITY_49.version,
)


_E_FINANCE_WEB_8_CATEGORIES = (
    StandardCategory(
        "sql-injection",
        {"en": "SQL Injection", "ko": "SQL 삽입"},
        scanner_categories=("code",),
        rule_ids=("code.sql-dynamic-query",),
    ),
    StandardCategory(
        "upload",
        {"en": "Upload Vulnerability", "ko": "업로드 취약점"},
        scanner_categories=("code",),
        rule_ids=("code.unrestricted-file-upload",),
    ),
    StandardCategory(
        "cookie-session",
        {"en": "Cookie and Session Management", "ko": "쿠키 및 세션 관리"},
        scanner_categories=("code",),
        rule_ids=SESSION_MANAGEMENT_RULE_IDS,
    ),
    StandardCategory(
        "xss",
        {"en": "Cross-site Scripting", "ko": "크로스사이트 스크립팅"},
        scanner_categories=("code",),
        rule_ids=("code.xss-dom-sink",),
    ),
    StandardCategory(
        "buffer-overflow",
        {"en": "Buffer Overflow", "ko": "버퍼 오버플로우"},
        scanner_categories=("code",),
        rule_ids=MEMORY_SAFETY_RULE_IDS,
    ),
    StandardCategory(
        "parameter",
        {"en": "Improper Parameters", "ko": "부적절한 파라미터"},
        scanner_categories=("code",),
        rule_ids=INPUT_VALIDATION_RULE_IDS,
    ),
    StandardCategory(
        "access-control",
        {"en": "Access Control", "ko": "접근통제"},
        scanner_categories=("code",),
        rule_ids=ACCESS_CONTROL_RULE_IDS,
    ),
    StandardCategory(
        "server-configuration",
        {"en": "Server Configuration", "ko": "서버 환경설정"},
        scanner_categories=("configuration", "code"),
        rule_ids=MISCONFIGURATION_RULE_IDS,
    ),
)

ELECTRONIC_FINANCIAL_SUPERVISION_8 = SecurityStandard(
    "electronic-financial-supervision-8",
    {"en": "Electronic Financial Supervision 8 Web Vulnerabilities", "ko": "전자금융감독규정 8대 취약점"},
    (
        _all_category(
            _E_FINANCE_WEB_8_CATEGORIES,
            {"en": "All mapped electronic-finance web checks", "ko": "매핑된 전자금융 8대 항목 전체"},
        ),
        *_E_FINANCE_WEB_8_CATEGORIES,
    ),
    description=_text(
        "Public web-server vulnerability categories referenced by Korean electronic financial supervision rules and related guidance.",
        "전자금융감독규정 및 관련 세칙에서 언급되는 공개용 웹서버 해킹 대응 항목을 매핑한 프로파일입니다.",
    ),
    coverage=_text(
        "External integration and evidence review required. Formal compliance requires infrastructure, web runtime, and operational evidence beyond source files.",
        "외부 연동과 증적 확인이 필요합니다. 공식 준수에는 소스 파일 외 인프라, 웹 런타임, 운영 증적이 필요합니다.",
    ),
    references=(
        _reference("Korean Law Information Center", "국가법령정보센터", "https://www.law.go.kr/LSW/admRulInfoP.do?admRulSeq=2100000274812&chrClsCd=010201"),
    ),
)


_OWASP_ASVS_5_CATEGORIES = (
    StandardCategory(
        "v1-encoding-sanitization",
        {"en": "V1 Encoding and Sanitization", "ko": "V1 인코딩 및 정제"},
        scanner_categories=("code",),
        rule_ids=INJECTION_RULE_IDS
        + (
            "code.xml-external-entity",
            "code.unsafe-deserialization",
            "code.ldap-injection",
            "code.format-string-user-input",
            "code.dangerous-c-buffer-api",
        ),
    ),
    StandardCategory(
        "v2-validation-business-logic",
        {"en": "V2 Validation and Business Logic", "ko": "V2 검증 및 비즈니스 로직"},
        scanner_categories=("code",),
        rule_ids=INPUT_VALIDATION_RULE_IDS + ("code.unbounded-request-body", "code.api-missing-rate-limit"),
    ),
    StandardCategory(
        "v3-web-frontend-security",
        {"en": "V3 Web Frontend Security", "ko": "V3 웹 프런트엔드 보안"},
        scanner_categories=("code",),
        rule_ids=(
            "code.xss-dom-sink",
            "code.wildcard-cors",
            "code.insecure-cookie-settings",
            "code.csrf-disabled",
            "code.open-redirect-user-input",
        ),
    ),
    StandardCategory(
        "v4-api-web-service",
        {"en": "V4 API and Web Service", "ko": "V4 API 및 웹 서비스"},
        scanner_categories=("code", "prevention"),
        rule_ids=API_SECURITY_RULE_IDS,
    ),
    StandardCategory(
        "v5-file-handling",
        {"en": "V5 File Handling", "ko": "V5 파일 처리"},
        scanner_categories=("code",),
        rule_ids=WEB_FILE_HANDLING_RULE_IDS,
    ),
    StandardCategory(
        "v6-authentication",
        {"en": "V6 Authentication", "ko": "V6 인증"},
        scanner_categories=("code",),
        rule_ids=AUTHENTICATION_RULE_IDS,
    ),
    StandardCategory(
        "v7-session-management",
        {"en": "V7 Session Management", "ko": "V7 세션 관리"},
        scanner_categories=("code",),
        rule_ids=SESSION_MANAGEMENT_RULE_IDS,
    ),
    StandardCategory(
        "v8-authorization",
        {"en": "V8 Authorization", "ko": "V8 인가"},
        scanner_categories=("code",),
        rule_ids=ACCESS_CONTROL_RULE_IDS,
    ),
    StandardCategory(
        "v9-self-contained-tokens",
        {"en": "V9 Self-contained Tokens", "ko": "V9 자체 포함 토큰"},
        scanner_categories=("code",),
        rule_ids=("code.jwt-verification-disabled", "code.jwt-none-algorithm", "code.session-long-expiry"),
    ),
    StandardCategory("v10-oauth-oidc", {"en": "V10 OAuth and OIDC", "ko": "V10 OAuth 및 OIDC"}),
    StandardCategory(
        "v11-cryptography",
        {"en": "V11 Cryptography", "ko": "V11 암호기술"},
        scanner_categories=("code",),
        rule_ids=(
            "code.weak-hash",
            "code.insufficient-key-length",
            "code.insecure-random-security-use",
            "code.password-hash-without-salt",
        ),
    ),
    StandardCategory(
        "v12-secure-communication",
        {"en": "V12 Secure Communication", "ko": "V12 안전한 통신"},
        scanner_categories=("dependencies", "configuration", "code"),
        rule_ids=INSECURE_TRANSPORT_RULE_IDS + ("code.tls-certificate-verification-disabled",),
    ),
    StandardCategory(
        "v13-configuration",
        {"en": "V13 Configuration", "ko": "V13 설정"},
        scanner_categories=("configuration", "code"),
        rule_ids=MISCONFIGURATION_RULE_IDS,
    ),
    StandardCategory(
        "v14-data-protection",
        {"en": "V14 Data Protection", "ko": "V14 데이터 보호"},
        scanner_categories=("secrets", "configuration", "code"),
        rule_ids=SENSITIVE_DATA_RULE_IDS,
    ),
    StandardCategory(
        "v15-secure-coding-architecture",
        {"en": "V15 Secure Coding and Architecture", "ko": "V15 안전한 코딩 및 아키텍처"},
        scanner_categories=("code", "prevention"),
        rule_ids=(
            "code.dangerous-c-buffer-api",
            "code.unsafe-deserialization",
            "prevention.threat-model-missing",
        ),
    ),
    StandardCategory(
        "v16-security-logging-error-handling",
        {"en": "V16 Security Logging and Error Handling", "ko": "V16 보안 로깅 및 오류 처리"},
        scanner_categories=("configuration", "code"),
        rule_ids=ERROR_HANDLING_RULE_IDS + LOGGING_MONITORING_RULE_IDS,
    ),
    StandardCategory("v17-webrtc", {"en": "V17 WebRTC", "ko": "V17 WebRTC"}),
)

OWASP_ASVS_5 = SecurityStandard(
    "owasp-asvs-5",
    {"en": "OWASP ASVS 5.0", "ko": "OWASP ASVS 5.0"},
    (
        _all_category(_OWASP_ASVS_5_CATEGORIES, {"en": "All mapped ASVS checks", "ko": "매핑된 ASVS 항목 전체"}),
        *_OWASP_ASVS_5_CATEGORIES,
    ),
    description=_text(
        "The 17 official OWASP ASVS 5.0.0 chapters, with only directly related KODA heuristics attached to each chapter.",
        "OWASP ASVS 5.0.0의 공식 17개 장을 그대로 표시하고, 각 장에 직접 관련된 KODA 휴리스틱만 연결합니다.",
    ),
    coverage=_text(
        "Partial evidence only. KODA does not claim ASVS requirement-level compliance; unsupported chapters and requirements require design review, tests, and runtime evidence.",
        "부분 증거만 제공합니다. KODA는 ASVS 요구사항 단위 준수를 주장하지 않으며, 미지원 장과 요구사항은 설계 검토·테스트·런타임 증거가 필요합니다.",
    ),
    references=(
        _reference("OWASP ASVS", "OWASP ASVS", "https://owasp.org/www-project-application-security-verification-standard/"),
        _reference(
            "OWASP ASVS 5.0.0 CSV",
            "OWASP ASVS 5.0.0 CSV",
            "https://github.com/OWASP/ASVS/raw/v5.0.0/5.0/docs_en/OWASP_Application_Security_Verification_Standard_5.0.0_en.csv",
        ),
    ),
    issuer=_text("OWASP Foundation", "OWASP 재단"),
    published_on="2025-05-30",
    version="5.0.0",
)


_OWASP_WSTG_CATEGORIES = (
    StandardCategory("information-gathering", {"en": "Information Gathering", "ko": "정보 수집"}),
    StandardCategory("configuration-deployment-management", {"en": "Configuration and Deployment Management Testing", "ko": "설정 및 배포 관리 테스트"}, scanner_categories=("configuration", "code"), rule_ids=MISCONFIGURATION_RULE_IDS),
    StandardCategory("identity-management", {"en": "Identity Management Testing", "ko": "식별 관리 테스트"}),
    StandardCategory("authentication", {"en": "Authentication", "ko": "인증"}, scanner_categories=("code",), rule_ids=AUTHENTICATION_RULE_IDS),
    StandardCategory("authorization", {"en": "Authorization", "ko": "인가"}, scanner_categories=("code",), rule_ids=ACCESS_CONTROL_RULE_IDS),
    StandardCategory("session-management", {"en": "Session Management", "ko": "세션 관리"}, scanner_categories=("code",), rule_ids=SESSION_MANAGEMENT_RULE_IDS),
    StandardCategory("input-validation", {"en": "Input Validation", "ko": "입력값 검증"}, scanner_categories=("code",), rule_ids=INPUT_VALIDATION_RULE_IDS + ("code.xml-external-entity",)),
    StandardCategory("error-handling", {"en": "Error Handling", "ko": "에러 처리"}, scanner_categories=("configuration", "code"), rule_ids=ERROR_HANDLING_RULE_IDS),
    StandardCategory("weak-cryptography", {"en": "Weak Cryptography", "ko": "약한 암호"}, scanner_categories=("secrets", "configuration", "dependencies", "code"), rule_ids=CRYPTOGRAPHY_RULE_IDS),
    StandardCategory("business-logic", {"en": "Business Logic Testing", "ko": "비즈니스 로직 테스트"}),
    StandardCategory(
        "client-side",
        {"en": "Client-side Testing", "ko": "클라이언트 측 테스트"},
        scanner_categories=("code",),
        rule_ids=("code.xss-dom-sink", "code.open-redirect-user-input", "code.wildcard-cors"),
    ),
    StandardCategory("api-testing", {"en": "API Testing", "ko": "API 테스트"}, scanner_categories=("code",), rule_ids=API_INVENTORY_RULE_IDS + ("code.ssrf-user-url", "code.unbounded-request-body")),
)

OWASP_WSTG = SecurityStandard(
    "owasp-wstg",
    {"en": "OWASP WSTG", "ko": "OWASP WSTG"},
    (
        _all_category(_OWASP_WSTG_CATEGORIES, {"en": "All mapped WSTG checks", "ko": "매핑된 WSTG 항목 전체"}),
        *_OWASP_WSTG_CATEGORIES,
    ),
    description=_text(
        "The 12 official OWASP WSTG v4.2 web-application testing areas, with static hints attached only where KODA can collect related file evidence.",
        "OWASP WSTG v4.2의 공식 웹 애플리케이션 테스트 12개 영역을 표시하고, KODA가 관련 파일 증거를 수집할 수 있는 영역에만 정적 단서를 연결합니다.",
    ),
    coverage=_text(
        "External testing required. A static finding is not a completed WSTG scenario; live-target testing is required and WSTG is not selectable as a source-only CLI standard.",
        "외부 테스트가 필요합니다. 정적 발견은 WSTG 시나리오 완료 판정이 아니며 실제 대상 테스트가 필요하므로 소스 전용 CLI 기준으로 선택할 수 없습니다.",
    ),
    references=(
        _reference("OWASP WSTG", "OWASP WSTG", "https://owasp.org/www-project-web-security-testing-guide/"),
        _reference("OWASP WSTG v4.2", "OWASP WSTG v4.2", "https://owasp.org/www-project-web-security-testing-guide/v42/"),
    ),
    issuer=_text("OWASP Foundation", "OWASP 재단"),
    published_on="2020-12-03",
    version="4.2",
)


_NIST_SSDF_CATEGORIES = (
    StandardCategory("protect-software", {"en": "Protect the Software", "ko": "소프트웨어 보호"}, scanner_categories=("secrets", "dependencies", "configuration", "prevention"), rule_ids=SENSITIVE_DATA_RULE_IDS + INTEGRITY_RULE_IDS + PREVENTION_RULE_IDS),
    StandardCategory("produce-well-secured-software", {"en": "Produce Well-Secured Software", "ko": "안전한 소프트웨어 생산"}, scanner_categories=("configuration", "code", "prevention"), rule_ids=CONFIGURATION_RULE_IDS + CODE_PATTERN_RULE_IDS + PREVENTION_RULE_IDS),
    StandardCategory("verify-security", {"en": "Verify Security", "ko": "보안 검증"}, scanner_categories=DEFAULT_CATEGORIES, rule_ids=SECRET_RULE_IDS + DEPENDENCY_RULE_IDS + CONFIGURATION_RULE_IDS + CODE_PATTERN_RULE_IDS + PREVENTION_RULE_IDS),
    StandardCategory("respond-vulnerabilities", {"en": "Respond to Vulnerabilities", "ko": "취약점 대응"}, scanner_categories=("dependencies", "prevention"), rule_ids=DEPENDENCY_RULE_IDS + ("prevention.security-policy-missing", "prevention.dependency-update-automation-missing", "prevention.sbom-missing")),
)

NIST_SSDF = SecurityStandard(
    "nist-ssdf-sp800-218",
    {"en": "NIST SSDF SP 800-218", "ko": "NIST SSDF SP 800-218"},
    (
        _all_category(_NIST_SSDF_CATEGORIES, {"en": "All mapped SSDF checks", "ko": "매핑된 SSDF 항목 전체"}),
        *_NIST_SSDF_CATEGORIES,
    ),
    description=_text(
        "NIST Secure Software Development Framework practices mapped to local evidence for secure development and vulnerability response.",
        "NIST Secure Software Development Framework 실천항목을 안전한 개발과 취약점 대응의 로컬 근거에 매핑한 프로파일입니다.",
    ),
    coverage=_text(
        "Evidence review required. SSDF also needs organizational process evidence, attestations, and supplier management records.",
        "증적 확인이 필요합니다. SSDF는 조직 프로세스 증적, 증명, 공급자 관리 기록도 필요합니다.",
    ),
    references=(
        _reference("NIST SP 800-218", "NIST SP 800-218", "https://csrc.nist.gov/pubs/sp/800/218/final"),
    ),
)


_OWASP_SAMM_CATEGORIES = (
    StandardCategory(
        "governance",
        {"en": "Governance", "ko": "거버넌스"},
        scanner_categories=("prevention",),
        rule_ids=(
            "prevention.security-policy-missing",
            "prevention.secure-by-design-program-missing",
            "prevention.security-roadmap-missing",
            "prevention.evidence-register-missing",
            "prevention.codeowners-missing",
        ),
    ),
    StandardCategory(
        "design",
        {"en": "Design", "ko": "설계"},
        scanner_categories=("prevention",),
        rule_ids=(
            "prevention.threat-model-missing",
            "prevention.api-security-plan-missing",
            "prevention.mobile-security-plan-missing",
            "prevention.ai-llm-security-plan-missing",
        ),
    ),
    StandardCategory(
        "implementation",
        {"en": "Implementation", "ko": "구현"},
        scanner_categories=("dependencies", "configuration", "code", "prevention"),
        rule_ids=SUPPLY_CHAIN_RULE_IDS
        + INTEGRITY_RULE_IDS
        + MISCONFIGURATION_RULE_IDS
        + CODE_PATTERN_RULE_IDS
        + (
            "prevention.ci-security-scan-missing",
            "prevention.sast-workflow-missing",
            "prevention.pre-commit-hook-missing",
        ),
    ),
    StandardCategory(
        "verification",
        {"en": "Verification", "ko": "검증"},
        scanner_categories=DEFAULT_CATEGORIES,
        rule_ids=SECRET_RULE_IDS
        + DEPENDENCY_RULE_IDS
        + CONFIGURATION_RULE_IDS
        + CODE_PATTERN_RULE_IDS
        + (
            "prevention.ci-security-scan-missing",
            "prevention.sast-workflow-missing",
            "prevention.zap-baseline-missing",
        ),
    ),
    StandardCategory(
        "operations",
        {"en": "Operations", "ko": "운영"},
        scanner_categories=("configuration", "dependencies", "code", "prevention"),
        rule_ids=MISCONFIGURATION_RULE_IDS + INTEGRITY_RULE_IDS + ERROR_HANDLING_RULE_IDS + ("prevention.ci-security-scan-missing", "prevention.dockerignore-missing", "prevention.sbom-missing"),
    ),
)

OWASP_SAMM_2 = SecurityStandard(
    "owasp-samm-2",
    {"en": "OWASP SAMM 2", "ko": "OWASP SAMM 2"},
    (
        _all_category(_OWASP_SAMM_CATEGORIES, {"en": "All mapped SAMM checks", "ko": "매핑된 SAMM 항목 전체"}),
        *_OWASP_SAMM_CATEGORIES,
    ),
    description=_text(
        "The five official OWASP SAMM 2 business functions mapped to related local repository evidence.",
        "OWASP SAMM 2의 공식 5개 비즈니스 기능을 관련 로컬 저장소 증거에 매핑한 프로파일입니다.",
    ),
    coverage=_text(
        "Evidence review required. KODA does not score the 15 practices or three maturity levels; a formal SAMM assessment requires process, people, governance, and program evidence.",
        "증적 확인이 필요합니다. KODA는 15개 보안 실천항목이나 3개 성숙도 수준을 채점하지 않으며, 공식 SAMM 평가는 프로세스·인력·거버넌스·프로그램 증거가 필요합니다.",
    ),
    references=(
        _reference("OWASP SAMM", "OWASP SAMM", "https://owasp.org/www-project-samm/"),
        _reference("OWASP SAMM Model", "OWASP SAMM 모델", "https://owaspsamm.org/model/"),
    ),
    issuer=_text("OWASP Foundation", "OWASP 재단"),
    published_on="2020",
    version="2.0",
)


_OWASP_DEPENDENCY_CHECK_CATEGORIES = (
    StandardCategory("manifest-health", {"en": "Manifest and Lockfile Health", "ko": "매니페스트 및 락파일 위생"}, scanner_categories=("dependencies",), rule_ids=("dependency.package-json-invalid", "dependency.node-missing-lockfile")),
    StandardCategory("version-hygiene", {"en": "Version Pinning Hygiene", "ko": "버전 고정 위생"}, scanner_categories=("dependencies",), rule_ids=("dependency.node-unbounded-version", "dependency.python-unpinned-requirement", "dependency.python-wildcard-version", "dependency.docker-unpinned-base")),
    StandardCategory("insecure-sources", {"en": "Insecure Dependency Sources", "ko": "안전하지 않은 의존성 소스"}, scanner_categories=("dependencies", "configuration"), rule_ids=INSECURE_TRANSPORT_RULE_IDS + REMOTE_EXECUTION_RULE_IDS),
    StandardCategory("automation-readiness", {"en": "Automation and SBOM Readiness", "ko": "자동화 및 SBOM 준비성"}, scanner_categories=("prevention",), rule_ids=("prevention.dependency-update-automation-missing", "prevention.ci-security-scan-missing", "prevention.sbom-missing")),
)

OWASP_DEPENDENCY_CHECK_BASELINE = SecurityStandard(
    "owasp-dependency-check-baseline",
    {"en": "OWASP Dependency-Check Baseline", "ko": "OWASP Dependency-Check 기준"},
    (
        _all_category(_OWASP_DEPENDENCY_CHECK_CATEGORIES, {"en": "All mapped Dependency-Check baseline checks", "ko": "매핑된 Dependency-Check 기준 전체"}),
        *_OWASP_DEPENDENCY_CHECK_CATEGORIES,
    ),
    description=_text(
        "A local dependency hygiene profile aligned with OWASP Dependency-Check's known-vulnerable-component purpose.",
        "알려진 취약 컴포넌트 식별이라는 OWASP Dependency-Check 목적에 맞춘 로컬 의존성 위생 프로파일입니다.",
    ),
    coverage=_text(
        "External integration required. Actual CVE matching requires Dependency-Check, OSV, NVD, or another vulnerability feed.",
        "외부 연동이 필요합니다. 실제 CVE 대조에는 Dependency-Check, OSV, NVD 같은 취약점 피드 연동이 필요합니다.",
    ),
    references=(
        _reference("OWASP Dependency-Check", "OWASP Dependency-Check", "https://owasp.org/www-project-dependency-check/"),
    ),
)


OWASP_DEPENDENCY_TRACK_BASELINE = SecurityStandard(
    "owasp-dependency-track-baseline",
    {"en": "OWASP Dependency-Track / SBOM Baseline", "ko": "OWASP Dependency-Track / SBOM 기준"},
    (
        _all_category(_OWASP_DEPENDENCY_CHECK_CATEGORIES, {"en": "All mapped SBOM readiness checks", "ko": "매핑된 SBOM 준비성 항목 전체"}),
        *_OWASP_DEPENDENCY_CHECK_CATEGORIES,
    ),
    description=_text(
        "A local supply-chain readiness profile for projects that may later publish SBOMs to Dependency-Track.",
        "향후 Dependency-Track에 SBOM을 연동할 프로젝트를 위한 로컬 공급망 준비성 프로파일입니다.",
    ),
    coverage=_text(
        "External integration required. Portfolio tracking, SBOM ingestion, VEX, EPSS, and policy workflows require Dependency-Track integration.",
        "외부 연동이 필요합니다. 포트폴리오 추적, SBOM 수집, VEX, EPSS, 정책 워크플로는 Dependency-Track 연동이 필요합니다.",
    ),
    references=(
        _reference("OWASP Dependency-Track", "OWASP Dependency-Track", "https://owasp.org/www-project-dependency-track/"),
        _reference("CycloneDX", "CycloneDX", "https://cyclonedx.org/"),
    ),
)


_OPENSSF_SCORECARD_CATEGORIES = (
    StandardCategory("security-policy", {"en": "Security Policy", "ko": "보안 정책"}, scanner_categories=("prevention",), rule_ids=("prevention.security-policy-missing",)),
    StandardCategory("maintained-owners", {"en": "Maintained Owners", "ko": "관리 책임자"}, scanner_categories=("prevention",), rule_ids=("prevention.codeowners-missing", "prevention.repository-security-settings-missing")),
    StandardCategory("dependency-update-tool", {"en": "Dependency Update Tool", "ko": "의존성 업데이트 자동화"}, scanner_categories=("prevention",), rule_ids=("prevention.dependency-update-automation-missing",)),
    StandardCategory("sast", {"en": "SAST", "ko": "정적 분석"}, scanner_categories=("prevention",), rule_ids=("prevention.sast-workflow-missing", "prevention.ci-security-scan-missing")),
    StandardCategory("token-permissions", {"en": "Token Permissions", "ko": "토큰 권한"}, scanner_categories=("prevention",), rule_ids=("prevention.github-token-permissions-not-readonly",)),
    StandardCategory("pinned-dependencies", {"en": "Pinned Dependencies and Actions", "ko": "고정된 의존성 및 액션"}, scanner_categories=("dependencies", "prevention"), rule_ids=("dependency.node-unbounded-version", "dependency.python-unpinned-requirement", "dependency.python-wildcard-version", "dependency.docker-unpinned-base", "prevention.github-actions-unpinned")),
    StandardCategory("signed-releases", {"en": "Signed Releases", "ko": "서명된 릴리스"}, scanner_categories=("prevention",), rule_ids=("prevention.slsa-sigstore-missing",)),
    StandardCategory("binary-artifacts", {"en": "Binary Artifacts", "ko": "바이너리 아티팩트"}, scanner_categories=("prevention",), rule_ids=("prevention.binary-artifact-committed",)),
    StandardCategory("vulnerabilities", {"en": "Known Vulnerabilities", "ko": "알려진 취약점"}, scanner_categories=("dependencies",), rule_ids=("dependency.osv-known-vulnerability",)),
)

OPENSSF_SCORECARD_BASELINE = SecurityStandard(
    "openssf-scorecard-baseline",
    {"en": "OpenSSF Scorecard Baseline", "ko": "OpenSSF Scorecard 기준"},
    (
        _all_category(_OPENSSF_SCORECARD_CATEGORIES, {"en": "All mapped Scorecard checks", "ko": "매핑된 Scorecard 항목 전체"}),
        *_OPENSSF_SCORECARD_CATEGORIES,
    ),
    description=_text(
        "A local approximation of OpenSSF Scorecard supply-chain posture checks that can be inferred from repository files.",
        "저장소 파일에서 추론 가능한 OpenSSF Scorecard 공급망 보안 상태를 로컬 기준으로 점검하는 프로파일입니다.",
    ),
    coverage=_text(
        "External integration required. Branch protection, maintainer 2FA, repository metadata, and live vulnerability status still require GitHub or Scorecard service access.",
        "외부 연동이 필요합니다. 브랜치 보호, 유지관리자 2FA, 저장소 메타데이터, 실시간 취약점 상태는 GitHub 또는 Scorecard 서비스 접근이 필요합니다.",
    ),
    references=(
        _reference("OpenSSF Scorecard", "OpenSSF Scorecard", "https://scorecard.dev/"),
        _reference("OpenSSF Scorecard GitHub", "OpenSSF Scorecard GitHub", "https://github.com/ossf/scorecard"),
    ),
)


_CISA_KEV_EPSS_CATEGORIES = (
    StandardCategory("known-exploited", {"en": "Known Exploited Vulnerabilities", "ko": "실제 악용 취약점"}, scanner_categories=("dependencies",), rule_ids=("dependency.osv-known-vulnerability",)),
    StandardCategory("exploit-probability", {"en": "Exploit Probability", "ko": "악용 가능성"}, scanner_categories=("dependencies",), rule_ids=("dependency.osv-known-vulnerability",)),
    StandardCategory("vex-response", {"en": "VEX Response Tracking", "ko": "VEX 대응 추적"}, scanner_categories=("prevention",), rule_ids=("prevention.vex-missing",)),
    StandardCategory("sbom-tracking", {"en": "SBOM Tracking", "ko": "SBOM 추적"}, scanner_categories=("prevention",), rule_ids=("prevention.sbom-missing", "prevention.dependency-track-integration-missing")),
)

CISA_KEV_EPSS_PRIORITY = SecurityStandard(
    "cisa-kev-epss-priority",
    {"en": "CISA KEV / FIRST EPSS Priority", "ko": "CISA KEV / FIRST EPSS 우선순위"},
    (
        _all_category(_CISA_KEV_EPSS_CATEGORIES, {"en": "All mapped exploit-priority checks", "ko": "매핑된 악용 우선순위 항목 전체"}),
        *_CISA_KEV_EPSS_CATEGORIES,
    ),
    description=_text(
        "Prioritizes known vulnerable dependencies using CISA Known Exploited Vulnerabilities and FIRST EPSS exploit probability when OSV lookup is enabled.",
        "OSV 조회를 켰을 때 CISA Known Exploited Vulnerabilities와 FIRST EPSS 악용 확률을 사용해 취약 의존성 우선순위를 높이는 프로파일입니다.",
    ),
    coverage=_text(
        "External integration required. It depends on exact dependency versions and live external intelligence feeds.",
        "외부 연동이 필요합니다. 정확한 의존성 버전과 외부 인텔리전스 피드 조회에 의존합니다.",
    ),
    references=(
        _reference("CISA Known Exploited Vulnerabilities Catalog", "CISA 알려진 악용 취약점 카탈로그", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"),
        _reference("FIRST EPSS", "FIRST EPSS", "https://www.first.org/epss/"),
    ),
)


_SLSA_SIGSTORE_CATEGORIES = (
    StandardCategory("provenance", {"en": "Build Provenance", "ko": "빌드 출처 증명"}, scanner_categories=("prevention",), rule_ids=("prevention.slsa-sigstore-missing", "prevention.release-provenance-automation-missing")),
    StandardCategory("signed-artifacts", {"en": "Signed Artifacts", "ko": "서명된 산출물"}, scanner_categories=("prevention",), rule_ids=("prevention.slsa-sigstore-missing", "prevention.release-provenance-automation-missing", "prevention.binary-artifact-committed")),
    StandardCategory("pinned-actions", {"en": "Pinned Actions", "ko": "고정된 액션"}, scanner_categories=("prevention",), rule_ids=("prevention.github-actions-unpinned", "prevention.github-token-permissions-not-readonly")),
)

SLSA_SIGSTORE_BASELINE = SecurityStandard(
    "slsa-sigstore-baseline",
    {"en": "SLSA / Sigstore Baseline", "ko": "SLSA / Sigstore 기준"},
    (
        _all_category(_SLSA_SIGSTORE_CATEGORIES, {"en": "All mapped signing and provenance checks", "ko": "매핑된 서명 및 출처 증명 항목 전체"}),
        *_SLSA_SIGSTORE_CATEGORIES,
    ),
    description=_text(
        "Checks whether release workflows are prepared for signed artifacts, provenance, and tighter GitHub Actions supply-chain controls.",
        "릴리스 workflow가 산출물 서명, 출처 증명, GitHub Actions 공급망 통제에 준비되어 있는지 확인하는 프로파일입니다.",
    ),
    coverage=_text(
        "External integration required. Real signing verification requires release artifacts, identities, certificate transparency logs, and CI metadata.",
        "외부 연동이 필요합니다. 실제 서명 검증에는 릴리스 산출물, 신원, 인증서 투명성 로그, CI 메타데이터가 필요합니다.",
    ),
    references=(
        _reference("SLSA", "SLSA", "https://slsa.dev/"),
        _reference("Sigstore Cosign", "Sigstore Cosign", "https://docs.sigstore.dev/cosign/"),
    ),
)


_CISA_SECURE_BY_DESIGN_CATEGORIES = (
    StandardCategory("ownership", {"en": "Own Customer Security Outcomes", "ko": "고객 보안 결과 책임"}, scanner_categories=("prevention", "dependencies", "configuration", "code"), rule_ids=("prevention.secure-by-design-program-missing", "prevention.security-policy-missing", "prevention.ssdf-workflow-missing") + DEPENDENCY_RULE_IDS + MISCONFIGURATION_RULE_IDS + CODE_PATTERN_RULE_IDS),
    StandardCategory("secure-defaults", {"en": "Secure Defaults", "ko": "안전한 기본값"}, scanner_categories=("configuration", "code", "prevention"), rule_ids=MISCONFIGURATION_RULE_IDS + SESSION_MANAGEMENT_RULE_IDS + ("prevention.pre-commit-hook-missing", "prevention.ci-security-scan-missing")),
    StandardCategory("transparency", {"en": "Transparency and Accountability", "ko": "투명성 및 책임성"}, scanner_categories=("prevention", "dependencies"), rule_ids=("prevention.security-policy-missing", "prevention.vex-missing", "prevention.sbom-missing", "prevention.repository-security-settings-missing", "prevention.dependency-update-automation-missing") + DEPENDENCY_RULE_IDS),
    StandardCategory("leadership", {"en": "Lead From the Top", "ko": "경영진 주도"}, scanner_categories=("prevention",), rule_ids=("prevention.secure-by-design-program-missing", "prevention.ssdf-workflow-missing", "prevention.codeowners-missing")),
)

CISA_SECURE_BY_DESIGN = SecurityStandard(
    "cisa-secure-by-design",
    {"en": "CISA Secure by Design", "ko": "CISA Secure by Design"},
    (
        _all_category(_CISA_SECURE_BY_DESIGN_CATEGORIES, {"en": "All mapped Secure by Design checks", "ko": "매핑된 Secure by Design 항목 전체"}),
        *_CISA_SECURE_BY_DESIGN_CATEGORIES,
    ),
    description=_text(
        "Maps CISA Secure by Design principles to local prevention evidence, secure defaults, transparency artifacts, and ownership signals.",
        "CISA Secure by Design 원칙을 로컬 예방 증거, 안전한 기본값, 투명성 산출물, 책임 주체 신호에 매핑한 프로파일입니다.",
    ),
    coverage=_text(
        "Evidence review required. Product security outcomes, executive ownership, and customer-impact metrics need organizational evidence beyond source files.",
        "증적 확인이 필요합니다. 제품 보안 결과, 경영진 책임, 고객 영향 지표는 소스 파일 외 조직 증적이 필요합니다.",
    ),
    references=(
        _reference("CISA Secure by Design", "CISA Secure by Design", "https://www.cisa.gov/resources-tools/resources/secure-by-design"),
        _reference("CISA Secure by Design Pledge", "CISA Secure by Design Pledge", "https://www.cisa.gov/securebydesign"),
    ),
)


_OWASP_MASVS_CATEGORIES = (
    StandardCategory("masvs-storage", {"en": "MASVS-STORAGE Secure Storage", "ko": "MASVS-STORAGE 안전한 저장"}, scanner_categories=("secrets", "configuration"), rule_ids=SENSITIVE_DATA_RULE_IDS + ("config.android-allow-backup", "config.ios-file-sharing-enabled", "config.ios-open-documents-in-place")),
    StandardCategory(
        "masvs-crypto",
        {"en": "MASVS-CRYPTO Cryptographic Functionality", "ko": "MASVS-CRYPTO 암호 기능"},
        scanner_categories=("code",),
        rule_ids=(
            "code.weak-hash",
            "code.insufficient-key-length",
            "code.insecure-random-security-use",
            "code.password-hash-without-salt",
        ),
    ),
    StandardCategory(
        "masvs-auth",
        {"en": "MASVS-AUTH Authentication and Authorization", "ko": "MASVS-AUTH 인증 및 인가"},
        scanner_categories=("code",),
        rule_ids=AUTHENTICATION_RULE_IDS + SESSION_MANAGEMENT_RULE_IDS + ACCESS_CONTROL_RULE_IDS,
    ),
    StandardCategory(
        "masvs-network",
        {"en": "MASVS-NETWORK Network Communication", "ko": "MASVS-NETWORK 네트워크 통신"},
        scanner_categories=("dependencies", "configuration", "code"),
        rule_ids=INSECURE_TRANSPORT_RULE_IDS
        + (
            "config.android-cleartext-traffic",
            "config.ios-ats-arbitrary-loads",
            "code.tls-certificate-verification-disabled",
        ),
    ),
    StandardCategory(
        "masvs-platform",
        {"en": "MASVS-PLATFORM Platform Interaction", "ko": "MASVS-PLATFORM 플랫폼 상호작용"},
        scanner_categories=("configuration", "code"),
        rule_ids=(
            "config.android-exported-component",
            "config.ios-file-sharing-enabled",
            "config.ios-open-documents-in-place",
            "code.path-traversal",
            "code.unrestricted-file-upload",
        ),
    ),
    StandardCategory(
        "masvs-code",
        {"en": "MASVS-CODE Code Security and Updates", "ko": "MASVS-CODE 코드 보안 및 업데이트"},
        scanner_categories=("code", "dependencies"),
        rule_ids=DEPENDENCY_RULE_IDS + ("code.dangerous-c-buffer-api", "code.unsafe-deserialization"),
    ),
    StandardCategory(
        "masvs-resilience",
        {"en": "MASVS-RESILIENCE Reverse Engineering and Tampering Resilience", "ko": "MASVS-RESILIENCE 역공학 및 변조 대응"},
        scanner_categories=("configuration",),
        rule_ids=("config.android-debuggable",),
    ),
    StandardCategory(
        "masvs-privacy",
        {"en": "MASVS-PRIVACY Privacy Controls", "ko": "MASVS-PRIVACY 개인정보 보호 통제"},
        scanner_categories=("secrets", "configuration", "code", "prevention"),
        rule_ids=SENSITIVE_DATA_RULE_IDS
        + (
            "config.android-allow-backup",
            "config.ios-file-sharing-enabled",
            "code.logging-sensitive-data",
            "prevention.mobile-security-plan-missing",
        ),
    ),
)

OWASP_MASVS = SecurityStandard(
    "owasp-masvs",
    {"en": "OWASP MASVS", "ko": "OWASP MASVS"},
    (
        _all_category(_OWASP_MASVS_CATEGORIES, {"en": "All mapped MASVS checks", "ko": "매핑된 MASVS 항목 전체"}),
        *_OWASP_MASVS_CATEGORIES,
    ),
    description=_text(
        "OWASP Mobile Application Security Verification Standard control groups mapped to mobile source, manifest, plist, dependency, and prevention evidence.",
        "OWASP 모바일 애플리케이션 보안 검증 표준의 통제 그룹을 모바일 소스, Manifest, plist, 의존성, 예방 증거에 매핑한 프로파일입니다.",
    ),
    coverage=_text(
        "Local mobile source and configuration checks run automatically. Complete MASVS validation still needs device/runtime testing and manual evidence.",
        "모바일 소스와 설정 점검은 자동으로 실행합니다. 완전한 MASVS 검증에는 기기/런타임 테스트와 수동 증적이 필요합니다.",
    ),
    references=(
        _reference("OWASP MASVS", "OWASP MASVS", "https://mas.owasp.org/MASVS/"),
        _reference("OWASP MASTG", "OWASP MASTG", "https://mas.owasp.org/MASTG/"),
    ),
    coverage_level="external",
    issuer=_text("OWASP Foundation", "OWASP 재단"),
    published_on="2024-01-18",
    version="2.1.0",
)


_OWASP_LLM_TOP_10_2025_CATEGORIES = (
    StandardCategory("llm01-prompt-injection", {"en": "LLM01 Prompt Injection", "ko": "LLM01 프롬프트 인젝션"}, scanner_categories=("code", "prevention"), rule_ids=("code.llm-prompt-user-concat", "prevention.threat-model-missing", "prevention.ai-llm-security-plan-missing")),
    StandardCategory("llm02-sensitive-information-disclosure", {"en": "LLM02 Sensitive Information Disclosure", "ko": "LLM02 민감정보 노출"}, scanner_categories=("secrets", "code", "prevention"), rule_ids=SECRET_RULE_IDS + ("code.llm-sensitive-data-in-prompt", "code.logging-sensitive-data", "prevention.secret-rotation-runbook-missing")),
    StandardCategory("llm03-supply-chain", {"en": "LLM03 Supply Chain", "ko": "LLM03 공급망"}, scanner_categories=("dependencies", "prevention"), rule_ids=DEPENDENCY_RULE_IDS + ("prevention.sbom-missing", "prevention.vex-missing", "prevention.dependency-track-integration-missing")),
    StandardCategory("llm04-data-model-poisoning", {"en": "LLM04 Data and Model Poisoning", "ko": "LLM04 데이터 및 모델 오염"}, scanner_categories=("prevention",), rule_ids=("prevention.ai-llm-security-plan-missing", "prevention.threat-model-missing")),
    StandardCategory("llm05-improper-output-handling", {"en": "LLM05 Improper Output Handling", "ko": "LLM05 부적절한 출력 처리"}, scanner_categories=("code",), rule_ids=("code.eval-user-input", "code.command-injection", "code.unsafe-deserialization", "code.xss-dom-sink")),
    StandardCategory("llm06-excessive-agency", {"en": "LLM06 Excessive Agency", "ko": "LLM06 과도한 자율 권한"}, scanner_categories=("code", "prevention"), rule_ids=("code.llm-tool-unrestricted", "prevention.threat-model-missing")),
    StandardCategory("llm07-system-prompt-leakage", {"en": "LLM07 System Prompt Leakage", "ko": "LLM07 시스템 프롬프트 누출"}, scanner_categories=("code", "secrets"), rule_ids=("code.llm-sensitive-data-in-prompt", "code.logging-sensitive-data") + SECRET_RULE_IDS),
    StandardCategory("llm08-vector-embedding-weakness", {"en": "LLM08 Vector and Embedding Weaknesses", "ko": "LLM08 벡터 및 임베딩 약점"}, scanner_categories=("prevention",), rule_ids=("prevention.ai-llm-security-plan-missing", "prevention.threat-model-missing")),
    StandardCategory("llm09-misinformation", {"en": "LLM09 Misinformation", "ko": "LLM09 잘못된 정보"}, scanner_categories=("prevention",), rule_ids=("prevention.ai-llm-security-plan-missing", "prevention.threat-model-missing")),
    StandardCategory("llm10-unbounded-consumption", {"en": "LLM10 Unbounded Consumption", "ko": "LLM10 무제한 소비"}, scanner_categories=("code", "prevention"), rule_ids=("code.unbounded-request-body", "prevention.ai-llm-security-plan-missing")),
)

OWASP_LLM_TOP_10_2025 = SecurityStandard(
    "owasp-llm-top-10-2025",
    {"en": "OWASP Top 10 for LLM Applications:2025", "ko": "OWASP LLM Top 10:2025"},
    (
        _all_category(_OWASP_LLM_TOP_10_2025_CATEGORIES, {"en": "All mapped LLM Top 10 checks", "ko": "매핑된 LLM Top 10 항목 전체"}),
        *_OWASP_LLM_TOP_10_2025_CATEGORIES,
    ),
    description=_text(
        "OWASP LLM application risks mapped to prompt construction, broad tool access, sensitive prompt data, dependency, and AI security-plan evidence.",
        "OWASP LLM 애플리케이션 위험을 프롬프트 구성, 광범위한 도구 권한, 민감정보 프롬프트 전달, 의존성, AI 보안 계획 증거에 매핑한 프로파일입니다.",
    ),
    coverage=_text(
        "Automatic local heuristics for code and prevention evidence. Adversarial prompt tests, model behavior validation, and runtime guardrails still need live testing.",
        "코드와 예방 증거에 대한 로컬 휴리스틱을 자동 실행합니다. 적대적 프롬프트 테스트, 모델 동작 검증, 런타임 가드레일은 별도 실행 검증이 필요합니다.",
    ),
    references=(
        _reference("OWASP Top 10 for LLM Applications", "OWASP LLM Top 10", "https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/"),
    ),
    issuer=_text("OWASP Foundation", "OWASP 재단"),
    published_on="2025",
    version="2025",
)


_NIST_CSF_2_CATEGORIES = (
    StandardCategory("govern", {"en": "Govern", "ko": "거버넌스"}, scanner_categories=("prevention",), rule_ids=("prevention.nist-csf-profile-missing", "prevention.security-policy-missing", "prevention.codeowners-missing", "prevention.secure-by-design-program-missing")),
    StandardCategory("identify", {"en": "Identify", "ko": "식별"}, scanner_categories=("dependencies", "prevention"), rule_ids=DEPENDENCY_RULE_IDS + ("prevention.sbom-missing", "prevention.repository-security-settings-missing")),
    StandardCategory("protect", {"en": "Protect", "ko": "보호"}, scanner_categories=("secrets", "configuration", "code", "prevention"), rule_ids=SECRET_RULE_IDS + MISCONFIGURATION_RULE_IDS + SESSION_MANAGEMENT_RULE_IDS + ("prevention.pre-commit-hook-missing", "prevention.secret-rotation-runbook-missing")),
    StandardCategory("detect", {"en": "Detect", "ko": "탐지"}, scanner_categories=("code", "prevention"), rule_ids=LOGGING_MONITORING_RULE_IDS + ("prevention.ci-security-scan-missing", "prevention.sast-workflow-missing", "prevention.openssf-scorecard-missing")),
    StandardCategory("respond", {"en": "Respond", "ko": "대응"}, scanner_categories=("dependencies", "prevention"), rule_ids=("dependency.osv-known-vulnerability", "prevention.vex-missing", "prevention.security-policy-missing", "prevention.secret-rotation-runbook-missing")),
    StandardCategory("recover", {"en": "Recover", "ko": "복구"}, scanner_categories=("prevention",), rule_ids=("prevention.release-provenance-automation-missing", "prevention.slsa-sigstore-missing", "prevention.cisa-attestation-missing")),
)

NIST_CSF_2 = SecurityStandard(
    "nist-csf-2",
    {"en": "NIST Cybersecurity Framework 2.0", "ko": "NIST CSF 2.0"},
    (
        _all_category(_NIST_CSF_2_CATEGORIES, {"en": "All mapped NIST CSF checks", "ko": "매핑된 NIST CSF 항목 전체"}),
        *_NIST_CSF_2_CATEGORIES,
    ),
    description=_text(
        "NIST CSF 2.0 Govern, Identify, Protect, Detect, Respond, and Recover functions mapped to local prevention and technical evidence.",
        "NIST CSF 2.0의 Govern, Identify, Protect, Detect, Respond, Recover 기능을 로컬 예방 및 기술 증거에 매핑한 프로파일입니다.",
    ),
    coverage=_text(
        "Evidence review required. KODA can collect file-level signals, but organization-level risk management evidence must be confirmed by the team.",
        "증적 확인이 필요합니다. KODA는 파일 수준 단서를 수집하지만 조직 차원의 위험관리 증거는 팀이 확인해야 합니다.",
    ),
    references=(
        _reference("NIST Cybersecurity Framework", "NIST Cybersecurity Framework", "https://www.nist.gov/cyberframework"),
    ),
    coverage_level="evidence",
)


_CISA_ATTESTATION_CATEGORIES = (
    StandardCategory("development-environment", {"en": "Secure Development Environment", "ko": "안전한 개발 환경"}, scanner_categories=("prevention", "configuration"), rule_ids=("prevention.cisa-attestation-missing", "prevention.repository-security-settings-missing", "prevention.codeowners-missing", "prevention.pre-commit-hook-missing") + MISCONFIGURATION_RULE_IDS),
    StandardCategory("secure-development", {"en": "Secure Development Practices", "ko": "안전한 개발 실천"}, scanner_categories=("code", "prevention"), rule_ids=CODE_PATTERN_RULE_IDS + ("prevention.ssdf-workflow-missing", "prevention.secure-by-design-program-missing", "prevention.threat-model-missing")),
    StandardCategory("third-party-components", {"en": "Third-Party Components", "ko": "제3자 구성요소"}, scanner_categories=("dependencies", "prevention"), rule_ids=DEPENDENCY_RULE_IDS + ("prevention.sbom-missing", "prevention.dependency-update-automation-missing", "prevention.vex-missing")),
    StandardCategory("vulnerability-response", {"en": "Vulnerability Response", "ko": "취약점 대응"}, scanner_categories=("dependencies", "prevention"), rule_ids=("dependency.osv-known-vulnerability", "prevention.security-policy-missing", "prevention.vex-missing", "prevention.secret-rotation-runbook-missing")),
    StandardCategory("attestation-evidence", {"en": "Attestation Evidence", "ko": "확인서 증적"}, scanner_categories=("prevention",), rule_ids=("prevention.cisa-attestation-missing", "prevention.nist-csf-profile-missing", "prevention.release-provenance-automation-missing")),
)

CISA_SECURE_SOFTWARE_ATTESTATION = SecurityStandard(
    "cisa-secure-software-attestation",
    {"en": "CISA Secure Software Development Attestation", "ko": "CISA 보안 소프트웨어 개발 확인서"},
    (
        _all_category(_CISA_ATTESTATION_CATEGORIES, {"en": "All mapped attestation checks", "ko": "매핑된 확인서 항목 전체"}),
        *_CISA_ATTESTATION_CATEGORIES,
    ),
    description=_text(
        "CISA/OMB secure software development attestation readiness mapped to SSDF-style local evidence, supply-chain artifacts, and response records.",
        "CISA/OMB 보안 소프트웨어 개발 확인서 준비성을 SSDF 기반 로컬 증거, 공급망 산출물, 대응 기록에 매핑한 프로파일입니다.",
    ),
    coverage=_text(
        "Evidence review required. KODA can prepare evidence files and local findings; the producer must confirm organizational practices before attestation.",
        "증적 확인이 필요합니다. KODA는 증거 파일과 로컬 발견 항목을 준비하지만, 확인서 제출 전 조직 실천 여부는 제작자가 확인해야 합니다.",
    ),
    references=(
        _reference("CISA Secure Software Development Attestation Form", "CISA 보안 소프트웨어 개발 확인서", "https://www.cisa.gov/secure-software-attestation-form"),
        _reference("NIST SSDF SP 800-218", "NIST SSDF SP 800-218", "https://csrc.nist.gov/publications/detail/sp/800-218/final"),
    ),
    coverage_level="evidence",
)

_OWASP_SCVS_CATEGORIES = (
    StandardCategory("v1-inventory", {"en": "V1 Inventory", "ko": "V1 인벤토리"}, scanner_categories=("dependencies", "prevention"), rule_ids=DEPENDENCY_RULE_IDS + ("prevention.scvs-plan-missing",)),
    StandardCategory("v2-sbom", {"en": "V2 SBOM", "ko": "V2 SBOM"}, scanner_categories=("prevention",), rule_ids=("prevention.sbom-missing", "prevention.dependency-track-integration-missing")),
    StandardCategory("v3-build-environment", {"en": "V3 Build Environment", "ko": "V3 빌드 환경"}, scanner_categories=("configuration", "prevention"), rule_ids=("prevention.github-token-permissions-not-readonly", "prevention.github-actions-unpinned", "prevention.ci-security-scan-missing", "prevention.release-provenance-automation-missing")),
    StandardCategory("v4-package-management", {"en": "V4 Package Management", "ko": "V4 패키지 관리"}, scanner_categories=("dependencies", "prevention"), rule_ids=DEPENDENCY_RULE_IDS + ("prevention.dependency-update-automation-missing",)),
    StandardCategory("v5-component-analysis", {"en": "V5 Component Analysis", "ko": "V5 구성요소 분석"}, scanner_categories=("dependencies", "prevention"), rule_ids=("dependency.osv-known-vulnerability", "prevention.vex-missing", "prevention.dependency-track-integration-missing")),
    StandardCategory("v6-pedigree-provenance", {"en": "V6 Pedigree and Provenance", "ko": "V6 출처 및 계보"}, scanner_categories=("prevention",), rule_ids=("prevention.slsa-sigstore-missing", "prevention.release-provenance-automation-missing", "prevention.binary-artifact-committed")),
)

OWASP_SCVS = SecurityStandard(
    "owasp-scvs",
    {"en": "OWASP SCVS", "ko": "OWASP SCVS"},
    (
        _all_category(_OWASP_SCVS_CATEGORIES, {"en": "All mapped SCVS checks", "ko": "매핑된 SCVS 항목 전체"}),
        *_OWASP_SCVS_CATEGORIES,
    ),
    description=_text(
        "OWASP Software Component Verification Standard controls mapped to dependency inventory, SBOM, build environment, package management, component analysis, and provenance evidence.",
        "OWASP Software Component Verification Standard 통제를 의존성 인벤토리, SBOM, 빌드 환경, 패키지 관리, 구성요소 분석, 출처 증거에 매핑한 프로파일입니다.",
    ),
    coverage=_text(
        "Automatic local and evidence checks. Procurement and organizational risk-acceptance evidence still require human confirmation.",
        "자동 로컬 점검과 증적 확인을 함께 수행합니다. 조달 및 조직 위험 수용 증거는 사람이 최종 확인해야 합니다.",
    ),
    references=(
        _reference("OWASP Software Component Verification Standard", "OWASP SCVS", "https://owasp.org/www-project-software-component-verification-standard/"),
        _reference("SCVS control families", "SCVS control families", "https://scvs.owasp.org/scvs/using-scvs/"),
    ),
    coverage_level="evidence",
    issuer=_text("OWASP Foundation", "OWASP 재단"),
    published_on="2020-06-25",
    version="1.0",
)


_CIS_MACOS_CATEGORIES = (
    StandardCategory(
        "disk-encryption",
        {"en": "Disk Encryption", "ko": "디스크 암호화"},
        scanner_categories=("host",),
        rule_ids=("host.macos.filevault-on", "host.macos.filevault-off", "host.macos.filevault-unverified"),
    ),
    StandardCategory(
        "system-integrity",
        {"en": "System Integrity", "ko": "시스템 무결성"},
        scanner_categories=("host",),
        rule_ids=(
            "host.macos.sip-enabled",
            "host.macos.sip-disabled",
            "host.macos.sip-unverified",
            "host.macos.gatekeeper-enabled",
            "host.macos.gatekeeper-disabled",
            "host.macos.gatekeeper-unverified",
        ),
    ),
    StandardCategory(
        "network",
        {"en": "Network", "ko": "네트워크"},
        scanner_categories=("host",),
        rule_ids=(
            "host.macos.firewall-enabled",
            "host.macos.firewall-disabled",
            "host.macos.firewall-unverified",
            "host.macos.firewall-stealth-enabled",
            "host.macos.firewall-stealth-disabled",
            "host.macos.firewall-stealth-unverified",
        ),
    ),
    StandardCategory(
        "software-updates",
        {"en": "Software Updates", "ko": "소프트웨어 업데이트"},
        scanner_categories=("host",),
        rule_ids=(
            "host.macos.auto-security-updates-enabled",
            "host.macos.auto-security-updates-disabled",
            "host.macos.auto-security-updates-unverified",
        ),
    ),
    StandardCategory(
        "account-lock",
        {"en": "Account and Lock", "ko": "계정 및 잠금"},
        scanner_categories=("host",),
        rule_ids=(
            "host.macos.auto-login-enabled",
            "host.macos.auto-login-disabled",
            "host.macos.auto-login-unverified",
            "host.macos.guest-account-enabled",
            "host.macos.guest-account-disabled",
            "host.macos.guest-account-unverified",
            "host.macos.screen-lock-enabled",
            "host.macos.screen-lock-disabled",
            "host.macos.screen-lock-unverified",
            "host.drift.regressed",
            "host.drift.improved",
        ),
    ),
)

CIS_MACOS_BENCHMARK = SecurityStandard(
    "cis-macos-benchmark",
    {"en": "CIS Apple macOS Benchmark", "ko": "CIS Apple macOS 벤치마크"},
    (
        _all_category(_CIS_MACOS_CATEGORIES, {"en": "All mapped macOS host checks", "ko": "매핑된 macOS 호스트 항목 전체"}),
        *_CIS_MACOS_CATEGORIES,
    ),
    description=_text(
        "Maps CIS Apple macOS Benchmark Level 1 endpoint controls (disk encryption, system integrity, network, software updates) to live host posture checks. Requires running 'host-scan' on the macOS endpoint.",
        "CIS Apple macOS 벤치마크 Level 1 단말 통제(디스크 암호화, 시스템 무결성, 네트워크, 소프트웨어 업데이트)를 실시간 호스트 점검에 매핑합니다. macOS 단말에서 'host-scan' 실행이 필요합니다.",
    ),
    coverage=_text(
        "Host posture checks run live on the macOS machine. Full benchmark conformance still requires items KODA does not yet probe (e.g. account, audit, and privacy controls).",
        "호스트 점검은 macOS 기기에서 실시간으로 실행됩니다. KODA가 아직 점검하지 않는 항목(계정, 감사, 프라이버시 통제 등)은 벤치마크 전체 준수를 위해 별도 확인이 필요합니다.",
    ),
    references=(
        _reference("CIS Apple macOS Benchmarks", "CIS Apple macOS 벤치마크", "https://www.cisecurity.org/benchmark/apple_os"),
    ),
    coverage_level="external",
)

_CIS_WINDOWS_CATEGORIES = (
    StandardCategory(
        "disk-encryption",
        {"en": "Disk Encryption", "ko": "디스크 암호화"},
        scanner_categories=("host",),
        rule_ids=("host.windows.bitlocker-on", "host.windows.bitlocker-off", "host.windows.bitlocker-unverified"),
    ),
    StandardCategory(
        "boot-integrity",
        {"en": "Boot Integrity", "ko": "부팅 무결성"},
        scanner_categories=("host",),
        rule_ids=(
            "host.windows.secure-boot-on",
            "host.windows.secure-boot-off",
            "host.windows.secure-boot-unsupported",
            "host.windows.secure-boot-unverified",
        ),
    ),
    StandardCategory(
        "network",
        {"en": "Network", "ko": "네트워크"},
        scanner_categories=("host",),
        rule_ids=(
            "host.windows.firewall-all-profiles-enabled",
            "host.windows.firewall-profile-disabled",
            "host.windows.firewall-unverified",
        ),
    ),
    StandardCategory(
        "malware-defense",
        {"en": "Malware Defense", "ko": "악성코드 방어"},
        scanner_categories=("host",),
        rule_ids=(
            "host.windows.defender-realtime-on",
            "host.windows.defender-realtime-off",
            "host.windows.defender-unverified",
        ),
    ),
    StandardCategory(
        "account-lock",
        {"en": "Account and Lock", "ko": "계정 및 잠금"},
        scanner_categories=("host",),
        rule_ids=(
            "host.windows.auto-login-enabled",
            "host.windows.auto-login-disabled",
            "host.windows.auto-login-unverified",
            "host.windows.guest-account-enabled",
            "host.windows.guest-account-disabled",
            "host.windows.guest-account-unverified",
            "host.windows.screen-lock-enabled",
            "host.windows.screen-lock-disabled",
            "host.windows.screen-lock-unverified",
            "host.drift.regressed",
            "host.drift.improved",
        ),
    ),
)

CIS_WINDOWS_BENCHMARK = SecurityStandard(
    "cis-windows-benchmark",
    {"en": "CIS Microsoft Windows Benchmark", "ko": "CIS Microsoft Windows 벤치마크"},
    (
        _all_category(_CIS_WINDOWS_CATEGORIES, {"en": "All mapped Windows host checks", "ko": "매핑된 Windows 호스트 항목 전체"}),
        *_CIS_WINDOWS_CATEGORIES,
    ),
    description=_text(
        "Maps CIS Microsoft Windows Benchmark Level 1 endpoint controls (disk encryption, boot integrity, network, malware defense) to live host posture checks. Requires running 'host-scan' on the Windows endpoint.",
        "CIS Microsoft Windows 벤치마크 Level 1 단말 통제(디스크 암호화, 부팅 무결성, 네트워크, 악성코드 방어)를 실시간 호스트 점검에 매핑합니다. Windows 단말에서 'host-scan' 실행이 필요합니다.",
    ),
    coverage=_text(
        "Host posture checks run live on the Windows machine via read-only PowerShell. Coverage is partial; account, audit, and policy controls require separate confirmation.",
        "호스트 점검은 Windows 기기에서 읽기 전용 PowerShell로 실시간 실행됩니다. 적용 범위는 일부이며 계정, 감사, 정책 통제는 별도 확인이 필요합니다.",
    ),
    references=(
        _reference("CIS Microsoft Windows Benchmarks", "CIS Microsoft Windows 벤치마크", "https://www.cisecurity.org/benchmark/microsoft_windows_desktop"),
    ),
    coverage_level="external",
)


SECURITY_STANDARDS = (
    LOCAL_STANDARD,
    OWASP_TOP_10_2025,
    OWASP_PROACTIVE_CONTROLS,
    CWE_TOP_25_2025,
    OWASP_API_SECURITY_2023,
    OWASP_MOBILE_TOP_10_2024,
    OWASP_MASVS,
    OWASP_LLM_TOP_10_2025,
    SW_DEV_SECURITY_49,
    SW_DEV_SECURITY_7_TYPES,
    KISA_SECURE_CODING_GUIDE,
    ELECTRONIC_FINANCIAL_SUPERVISION_8,
    ISMS_P_DEVELOPMENT_SECURITY,
    OWASP_ASVS_5,
    OWASP_WSTG,
    NIST_SSDF,
    OWASP_SAMM_2,
    OWASP_DEPENDENCY_CHECK_BASELINE,
    OWASP_DEPENDENCY_TRACK_BASELINE,
    OPENSSF_SCORECARD_BASELINE,
    CISA_SECURE_BY_DESIGN,
    NIST_CSF_2,
    CISA_SECURE_SOFTWARE_ATTESTATION,
    OWASP_SCVS,
    CISA_KEV_EPSS_PRIORITY,
    SLSA_SIGSTORE_BASELINE,
    CIS_MACOS_BENCHMARK,
    CIS_WINDOWS_BENCHMARK,
)
SECURITY_STANDARD_IDS = tuple(standard.id for standard in SECURITY_STANDARDS)

# Profiles intended for source-code/static analysis.  Host, web-runtime,
# certification, and supply-chain-only profiles remain available to the
# dashboard/server APIs but are not valid ``koda scan --standard`` choices.
SOURCE_STANDARD_IDS = (
    DEFAULT_STANDARD,
    "owasp-top-10-2025",
    "owasp-proactive-controls",
    "owasp-asvs-5",
    "cwe-top-25-2025",
    "sw-dev-security-49",
    "sw-dev-security-7-types",
    "kisa-secure-coding-guide",
)

AUTOMATIC_COVERAGE_STANDARD_IDS = {
    DEFAULT_STANDARD,
    "owasp-top-10-2025",
    "owasp-proactive-controls",
    "cwe-top-25-2025",
    "owasp-api-security-2023",
    "owasp-llm-top-10-2025",
    "sw-dev-security-49",
    "sw-dev-security-7-types",
    "kisa-secure-coding-guide",
}
EXTERNAL_COVERAGE_STANDARD_IDS = {
    "owasp-mobile-top-10-2024",
    "owasp-masvs",
    "electronic-financial-supervision-8",
    "owasp-wstg",
    "owasp-dependency-check-baseline",
    "owasp-dependency-track-baseline",
    "openssf-scorecard-baseline",
    "cisa-kev-epss-priority",
    "slsa-sigstore-baseline",
    "cis-macos-benchmark",
    "cis-windows-benchmark",
}


def _effective_coverage_level(standard: SecurityStandard) -> str:
    if standard.id in AUTOMATIC_COVERAGE_STANDARD_IDS:
        return "local"
    if standard.id in EXTERNAL_COVERAGE_STANDARD_IDS:
        return "external"
    return standard.coverage_level


def standards_payload() -> list[dict[str, object]]:
    return [
        {
            "id": standard.id,
            "labels": standard.labels,
            "description": standard.description,
            "coverage": standard.coverage,
            "coverage_level": _effective_coverage_level(standard),
            "issuer": standard.issuer,
            "published_on": standard.published_on,
            "version": standard.version,
            "references": [
                {
                    "labels": reference.labels,
                    "url": reference.url,
                }
                for reference in standard.references
            ],
            "categories": [
                {
                    "id": category.id,
                    "labels": category.labels,
                    "description": category.description,
                    "scanner_categories": list(category.scanner_categories),
                    "supported": category.supported,
                }
                for category in standard.categories
            ],
        }
        for standard in SECURITY_STANDARDS
    ]


def source_standard_help(language: str = "en") -> str:
    lines = ["Current source-analysis standards:"]
    for standard_id in SOURCE_STANDARD_IDS:
        standard = _find_standard(standard_id)
        label = standard.labels.get(language) or standard.labels.get("en") or standard.id
        if standard.issuer:
            issuer = standard.issuer.get(language) or standard.issuer.get("en") or ""
            edition = f"v{standard.version}" if standard.version and not standard.version.isdigit() else standard.version
            details = " · ".join(
                item
                for item in (
                    issuer,
                    f"edition {edition}" if edition else "",
                    f"published {standard.published_on}" if standard.published_on else "",
                )
                if item
            )
        else:
            details = "KODA built-in profile; not an external standard"
        lines.append(f"  {standard.id}: {label} — {details}")
    return "\n".join(lines)


def rule_standard_mappings_payload() -> dict[str, list[dict[str, object]]]:
    mappings: dict[str, list[dict[str, object]]] = {}
    for standard in SECURITY_STANDARDS:
        if standard.id == "sw-dev-security-49":
            for control in SW49_CONTROLS:
                for rule_id in control.rule_ids:
                    mappings.setdefault(rule_id, []).append(
                        {
                            "standard_id": standard.id,
                            "standard_labels": standard.labels,
                            "category_id": control.category_id,
                            "category_labels": SW49_CATEGORY_LABELS[control.category_id],
                            "control_id": control.control_id,
                            "official_id": control.official_id,
                            "guide_id": control.guide_id,
                            "control_title": dict(control.title),
                            "cwe_ids": list(control.cwe_ids),
                            "support_level": control.support_level,
                        }
                    )
            continue
        for category in standard.categories:
            if category.id == DEFAULT_STANDARD_CATEGORY:
                continue
            for rule_id in category.rule_ids:
                mappings.setdefault(rule_id, []).append(
                    {
                        "standard_id": standard.id,
                        "standard_labels": standard.labels,
                        "category_id": category.id,
                        "category_labels": category.labels,
                        # Keep one metadata shape for the portal.  Standards
                        # without a separate control registry use their
                        # canonical category id and local support status.
                        "control_id": category.id,
                        "official_id": "",
                        "guide_id": "",
                        "cwe_ids": ["-".join(category.id.split("-", 2)[:2]).upper()]
                        if category.id.lower().startswith("cwe-") and len(category.id.split("-", 2)) > 1 else [],
                        "support_level": "automated" if category.supported else "unsupported",
                    }
                )
    return mappings


def resolve_standard_selection(
    standard_id: str = DEFAULT_STANDARD,
    category_id: str = DEFAULT_STANDARD_CATEGORY,
    explicit_categories: tuple[str, ...] | None = None,
) -> StandardSelection:
    if explicit_categories is not None and standard_id == DEFAULT_STANDARD and category_id == DEFAULT_STANDARD_CATEGORY:
        return StandardSelection(
            standard=standard_id,
            category=category_id,
            scanner_categories=explicit_categories,
            rule_ids=None,
        )

    standard = _find_standard(standard_id)
    category = _find_category(standard, category_id)
    if not category.supported:
        raise ValueError(f"Selected standard category has no local checks yet: {standard_id}/{category_id}")
    rule_ids = frozenset(category.rule_ids) if category.rule_ids else None
    return StandardSelection(
        standard=standard.id,
        category=category.id,
        scanner_categories=category.scanner_categories,
        rule_ids=rule_ids,
    )


def filter_findings_by_standard(findings: list[Finding], selection: StandardSelection) -> list[Finding]:
    if selection.rule_ids is None:
        return findings
    return [finding for finding in findings if finding.rule_id in selection.rule_ids]


def _find_standard(standard_id: str) -> SecurityStandard:
    for standard in SECURITY_STANDARDS:
        if standard.id == standard_id:
            return standard
    raise ValueError(f"Unsupported standard: {standard_id}")


def _find_category(standard: SecurityStandard, category_id: str) -> StandardCategory:
    for category in standard.categories:
        if category.id == category_id:
            return category
    raise ValueError(f"Unsupported standard category: {standard.id}/{category_id}")
