from __future__ import annotations

from pathlib import Path
from typing import Iterable

from ..models import Finding, TargetConfig
from .common import normalized_relpath, read_text_lines


DEPENDENCY_MANIFEST_NAMES = {
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "requirements.txt",
    "requirements.in",
    "pyproject.toml",
    "poetry.lock",
    "Pipfile",
    "Pipfile.lock",
    "Gemfile",
    "Gemfile.lock",
    "go.mod",
    "go.sum",
    "Cargo.toml",
    "Cargo.lock",
    "composer.json",
    "composer.lock",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
}

SECURITY_POLICY_PATHS = {
    "SECURITY.md",
    ".github/SECURITY.md",
    "docs/SECURITY.md",
}

DEPENDENCY_AUTOMATION_PATHS = {
    ".github/dependabot.yml",
    ".github/dependabot.yaml",
    "dependabot.yml",
    "dependabot.yaml",
    "renovate.json",
    ".renovaterc",
    ".renovaterc.json",
    ".github/renovate.json",
}

SECURITY_WORKFLOW_KEYWORDS = (
    "sec-chk",
    "koda",
    "osv",
    "dependency-check",
    "trivy",
    "grype",
    "snyk",
    "semgrep",
    "codeql",
    "gitleaks",
    "trufflehog",
    "zap",
    "bandit",
    "safety",
    "pip-audit",
    "npm audit",
)

SAST_WORKFLOW_KEYWORDS = ("codeql", "semgrep", "sonar", "bandit", "brakeman", "gosec")
SCORECARD_WORKFLOW_KEYWORDS = ("scorecard-action", "openssf/scorecard", "scorecard")
DAST_WORKFLOW_KEYWORDS = ("zap-baseline", "zaproxy", "owasp/zap", "ghcr.io/zaproxy")
SLSA_SIGSTORE_KEYWORDS = ("slsa", "sigstore", "cosign", "provenance", "attestation", "attest")
AI_LLM_KEYWORDS = ("openai", "anthropic", "langchain", "llamaindex", "chat.completions", "responses.create", "generatecontent", "tool_choice", "function_call")
API_KEYWORDS = ("app.get(", "app.post(", "router.get(", "router.post(", "fastapi(", "@getmapping", "@postmapping", "/api/")
VEX_NAMES = {"vex.json", "vex.cdx.json", "cyclonedx-vex.json", "openvex.json"}
VEX_SUFFIXES = {".json"}
PRE_COMMIT_GUIDE_PATHS = {"docs/security/pre_commit.md", "docs/security/pre-commit.md"}
REPOSITORY_SECURITY_GUIDE_PATHS = {"docs/security/github_repository_security.md", "docs/security/repository_security.md"}
CODEOWNERS_PATHS = {".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"}
SSDF_WORKFLOW_PATHS = {"docs/security/nist_ssdf_workflow.md", "docs/security/ssdf_workflow.md"}
SECURE_BY_DESIGN_PATHS = {"docs/security/secure_by_design.md"}
THREAT_MODEL_PATHS = {"docs/security/threat_model.md", "docs/security/threat-model.md"}
SECRET_ROTATION_PATHS = {"docs/security/secret_rotation.md", "docs/security/secrets_rotation.md", "docs/security/secret-rotation.md"}
AI_LLM_SECURITY_PATHS = {"docs/security/ai_llm_security.md", "docs/security/llm_security.md", "docs/security/ai-security.md"}
MOBILE_SECURITY_PATHS = {"docs/security/mobile_security.md", "docs/security/mobile-security.md"}
NIST_CSF_PROFILE_PATHS = {"docs/security/nist_csf_2_profile.md", "docs/security/nist-csf-2-profile.md"}
CISA_ATTESTATION_PATHS = {"docs/security/cisa_secure_software_attestation.md", "docs/security/cisa-attestation.md"}
API_SECURITY_PATHS = {"docs/security/api_security.md", "docs/security/api-security.md"}
SCVS_PLAN_PATHS = {"docs/security/scvs_plan.md", "docs/security/owasp_scvs.md", "docs/security/software_component_verification.md"}
PRIVACY_DATA_MAP_PATHS = {"docs/security/privacy_data_map.md", "docs/security/privacy-data-map.md", "docs/security/data_inventory.md"}
SECURITY_ROADMAP_PATHS = {"docs/security/security_roadmap.md", "docs/security/security-roadmap.md"}
EVIDENCE_REGISTER_PATHS = {"docs/security/evidence_register.md", "docs/security/security_evidence.md"}
SECURITY_HEADERS_PATHS = {"docs/security/security_headers.md", "docs/security/security-headers.md"}
CONTAINER_HARDENING_PATHS = {"docs/security/container_hardening.md", "docs/security/container-hardening.md"}
CLOUD_IAC_SECURITY_PATHS = {"docs/security/cloud_iac_security.md", "docs/security/cloud-iac-security.md"}
RELEASE_PROVENANCE_WORKFLOW_PATHS = {".github/workflows/koda-release-provenance.yml", ".github/workflows/koda-release-provenance.yaml"}
RELEASE_PROVENANCE_KEYWORDS = (
    "slsa-framework",
    "slsa-github-generator",
    "sigstore",
    "cosign",
    "sign-blob",
    "attestation",
    "provenance",
)
BINARY_ARTIFACT_SUFFIXES = {
    ".app",
    ".apk",
    ".dmg",
    ".dll",
    ".dylib",
    ".ear",
    ".exe",
    ".msi",
    ".pkg",
    ".so",
    ".war",
}

ENV_EXAMPLE_NAMES = {
    ".env.example",
    ".env.sample",
    ".env.template",
    ".env.local.example",
    ".env.development.example",
    ".env.production.example",
}

SBOM_SUFFIXES = {".json", ".xml"}


def check_file(path: Path, target: TargetConfig) -> list[Finding]:
    del path, target
    return []


def check_project(root: Path, files: Iterable[Path], target: TargetConfig) -> list[Finding]:
    file_list = tuple(files)
    rel_paths = {normalized_relpath(path, root) for path in file_list}
    basenames = {path.name for path in file_list}
    lower_rel_paths = {rel.lower() for rel in rel_paths}
    lower_basenames = {name.lower() for name in basenames}

    findings: list[Finding] = []
    has_dependency_manifest = bool(DEPENDENCY_MANIFEST_NAMES & basenames)
    has_source_code = any(path.suffix.lower() in {".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".go", ".rb", ".php", ".cs", ".swift", ".rs"} for path in file_list)
    has_ai_llm_code = _project_text_contains(file_list, target, AI_LLM_KEYWORDS)
    has_api_code = _project_text_contains(file_list, target, API_KEYWORDS)
    has_mobile_project = _looks_like_mobile_project(file_list, basenames, lower_rel_paths, target)
    has_cloud_iac = _looks_like_cloud_iac(file_list, basenames, lower_rel_paths)
    dockerfiles = [path for path in file_list if path.name.lower() == "dockerfile" or path.name.lower().startswith("dockerfile.")]
    k8s_files = [path for path in file_list if _looks_like_kubernetes_manifest(path)]
    env_files = [
        path
        for path in file_list
        if path.name == ".env" or (path.name.startswith(".env.") and not path.name.endswith((".example", ".sample", ".template")))
    ]
    workflow_files = [path for path in file_list if normalized_relpath(path, root).startswith(".github/workflows/")]
    workflow_texts = _workflow_texts(workflow_files, target)
    combined_workflow_text = "\n".join(workflow_texts)
    findings.extend(_ignore_file_findings(root, file_list, target))

    if (has_source_code or has_dependency_manifest) and not (SECURITY_POLICY_PATHS & rel_paths):
        findings.append(
            _finding(
                "prevention.security-policy-missing",
                "info",
                root,
                "Security policy is not documented",
                "SECURITY.md",
                "No SECURITY.md found",
                "Add SECURITY.md with supported versions, vulnerability reporting contact, and disclosure expectations.",
            )
        )

    if (has_source_code or has_dependency_manifest) and _is_git_repo(root) and not _has_pre_commit_hook(root, target) and not (PRE_COMMIT_GUIDE_PATHS & lower_rel_paths):
        findings.append(
            _finding(
                "prevention.pre-commit-hook-missing",
                "low",
                root,
                "Pre-commit security gate is not installed",
                ".git/hooks/pre-commit",
                "No KODA pre-commit hook or pre-commit guide found",
                "Install the KODA pre-commit hook so high-risk findings block commits before they enter the repository.",
            )
        )

    if has_dependency_manifest and not (DEPENDENCY_AUTOMATION_PATHS & rel_paths):
        findings.append(
            _finding(
                "prevention.dependency-update-automation-missing",
                "low",
                root,
                "Dependency update automation is not configured",
                "dependency automation",
                "No Dependabot or Renovate configuration found",
                "Add Dependabot or Renovate so vulnerable and outdated dependencies are surfaced continuously.",
            )
        )

    if (workflow_files or ".github" in {path.split("/", 1)[0] for path in lower_rel_paths}) and not (CODEOWNERS_PATHS & rel_paths):
        findings.append(
            _finding(
                "prevention.codeowners-missing",
                "info",
                root,
                "CODEOWNERS is not configured",
                "CODEOWNERS",
                "No CODEOWNERS file found",
                "Add CODEOWNERS so security-sensitive paths require review from accountable owners.",
            )
        )

    if (workflow_files or ".github" in {path.split("/", 1)[0] for path in lower_rel_paths}) and not (REPOSITORY_SECURITY_GUIDE_PATHS & lower_rel_paths):
        findings.append(
            _finding(
                "prevention.repository-security-settings-missing",
                "info",
                root,
                "GitHub repository security settings are not documented",
                "GitHub repository settings",
                "No branch protection, secret scanning, and Actions-hardening checklist found",
                "Document and enable branch protection, required reviews, secret scanning, Dependabot alerts, and least-privilege Actions settings.",
            )
        )

    if (has_dependency_manifest or has_source_code) and not _has_security_workflow(workflow_files, target):
        findings.append(
            _finding(
                "prevention.ci-security-scan-missing",
                "info",
                root,
                "CI security scan is not configured",
                ".github/workflows",
                "No recognized security scan workflow found",
                "Add a CI job for KODA, CodeQL, Semgrep, OSV, Trivy, Gitleaks, ZAP baseline, or a similar security scanner.",
            )
        )

    if (
        (has_dependency_manifest or has_source_code)
        and not (RELEASE_PROVENANCE_WORKFLOW_PATHS & lower_rel_paths)
        and not _contains_any(combined_workflow_text, RELEASE_PROVENANCE_KEYWORDS)
        and "docs/security/slsa_sigstore.md" not in lower_rel_paths
    ):
        findings.append(
            _finding(
                "prevention.release-provenance-automation-missing",
                "info",
                root,
                "Release signing automation is not prepared",
                "release provenance workflow",
                "No release provenance/signing workflow found",
                "Add a release workflow that builds artifacts in CI, generates provenance, signs artifacts, and publishes checksums.",
            )
        )

    if (has_source_code or has_dependency_manifest) and not _contains_any(combined_workflow_text, SAST_WORKFLOW_KEYWORDS):
        findings.append(
            _finding(
                "prevention.sast-workflow-missing",
                "info",
                root,
                "SAST workflow is not configured",
                ".github/workflows",
                "No CodeQL, Semgrep, or similar static analysis workflow found",
                "Add a SAST workflow such as CodeQL or Semgrep so code-level security checks run on pull requests.",
            )
        )

    if (has_source_code or has_dependency_manifest) and not (SSDF_WORKFLOW_PATHS & lower_rel_paths):
        findings.append(
            _finding(
                "prevention.ssdf-workflow-missing",
                "info",
                root,
                "NIST SSDF workflow is not documented",
                "docs/security/NIST_SSDF_WORKFLOW.md",
                "No SSDF workflow checklist found",
                "Map design, implementation, verification, release, and vulnerability response activities to NIST SSDF evidence.",
            )
        )

    if (has_source_code or has_dependency_manifest) and not (SECURE_BY_DESIGN_PATHS & lower_rel_paths):
        findings.append(
            _finding(
                "prevention.secure-by-design-program-missing",
                "info",
                root,
                "Secure by Design prevention plan is not documented",
                "docs/security/SECURE_BY_DESIGN.md",
                "No Secure by Design checklist found",
                "Track secure defaults, customer-impact ownership, radical transparency, and product-security metrics as a product-level prevention program.",
            )
        )

    if (has_source_code or has_dependency_manifest) and not (THREAT_MODEL_PATHS & lower_rel_paths):
        findings.append(
            _finding(
                "prevention.threat-model-missing",
                "info",
                root,
                "Threat model is not documented",
                "docs/security/THREAT_MODEL.md",
                "No threat model found",
                "Document trust boundaries, assets, abuse cases, and security assumptions before release.",
            )
        )

    if (has_source_code or env_files) and not (SECRET_ROTATION_PATHS & lower_rel_paths):
        findings.append(
            _finding(
                "prevention.secret-rotation-runbook-missing",
                "info",
                root,
                "Secret rotation runbook is not documented",
                "docs/security/SECRET_ROTATION.md",
                "No secret rotation runbook found",
                "Document how to revoke, rotate, audit, and re-scan after any exposed credential.",
            )
        )

    if has_ai_llm_code and not (AI_LLM_SECURITY_PATHS & lower_rel_paths):
        findings.append(
            _finding(
                "prevention.ai-llm-security-plan-missing",
                "info",
                root,
                "AI/LLM security plan is not documented",
                "docs/security/AI_LLM_SECURITY.md",
                "AI or LLM usage detected without a security plan",
                "Document prompt-injection controls, tool boundaries, sensitive data handling, model/provider inventory, and adversarial tests.",
            )
        )

    if has_api_code and not (API_SECURITY_PATHS & lower_rel_paths):
        findings.append(
            _finding(
                "prevention.api-security-plan-missing",
                "info",
                root,
                "API security plan is not documented",
                "docs/security/API_SECURITY.md",
                "API routes or handlers detected without an API security checklist",
                "Document API inventory, authn/authz, rate limits, object authorization, schema validation, and unsafe external API consumption controls.",
            )
        )

    if has_mobile_project and not (MOBILE_SECURITY_PATHS & lower_rel_paths):
        findings.append(
            _finding(
                "prevention.mobile-security-plan-missing",
                "info",
                root,
                "Mobile security plan is not documented",
                "docs/security/MOBILE_SECURITY.md",
                "Mobile project files detected without a mobile security plan",
                "Document MASVS coverage, platform configuration, storage, network, release signing, and device-test requirements.",
            )
        )

    if has_cloud_iac and not (CLOUD_IAC_SECURITY_PATHS & lower_rel_paths):
        findings.append(
            _finding(
                "prevention.cloud-iac-security-plan-missing",
                "info",
                root,
                "Cloud/IaC security baseline is not documented",
                "docs/security/CLOUD_IAC_SECURITY.md",
                "Cloud, Terraform, Kubernetes, or Compose files detected without an IaC security plan",
                "Document network exposure, IAM boundaries, encryption, container runtime hardening, and deployment review requirements.",
            )
        )

    if k8s_files and not _has_kubernetes_network_policy(file_list):
        findings.append(
            _finding(
                "prevention.k8s-network-policy-missing",
                "info",
                root,
                "Kubernetes NetworkPolicy is not present",
                "Kubernetes NetworkPolicy",
                "Kubernetes workload manifests exist but no NetworkPolicy was found",
                "Add NetworkPolicies or document why the namespace relies on another network isolation layer.",
            )
        )

    if (has_source_code or has_dependency_manifest) and not (NIST_CSF_PROFILE_PATHS & lower_rel_paths):
        findings.append(
            _finding(
                "prevention.nist-csf-profile-missing",
                "info",
                root,
                "NIST CSF 2.0 profile is not documented",
                "docs/security/NIST_CSF_2_PROFILE.md",
                "No NIST CSF profile found",
                "Map Govern, Identify, Protect, Detect, Respond, and Recover activities to project evidence and owners.",
            )
        )

    if has_dependency_manifest and not (SCVS_PLAN_PATHS & lower_rel_paths):
        findings.append(
            _finding(
                "prevention.scvs-plan-missing",
                "info",
                root,
                "OWASP SCVS component verification plan is not documented",
                "docs/security/SCVS_PLAN.md",
                "Dependency manifests exist without a software component verification plan",
                "Document component inventory, SBOM, build environment, package management, component analysis, and provenance controls.",
            )
        )

    if (has_source_code or env_files) and not (PRIVACY_DATA_MAP_PATHS & lower_rel_paths):
        findings.append(
            _finding(
                "prevention.privacy-data-map-missing",
                "info",
                root,
                "Privacy data map is not documented",
                "docs/security/PRIVACY_DATA_MAP.md",
                "No data inventory or privacy map found",
                "Record personal data fields, purposes, storage locations, retention, sharing, and logging restrictions.",
            )
        )

    if (has_source_code or has_dependency_manifest) and not (SECURITY_ROADMAP_PATHS & lower_rel_paths):
        findings.append(
            _finding(
                "prevention.security-roadmap-missing",
                "info",
                root,
                "Security roadmap is not documented",
                "docs/security/SECURITY_ROADMAP.md",
                "No security roadmap found",
                "Track security backlog, owners, due dates, accepted risks, and target control maturity in one project roadmap.",
            )
        )

    if (has_source_code or has_dependency_manifest) and not (EVIDENCE_REGISTER_PATHS & lower_rel_paths):
        findings.append(
            _finding(
                "prevention.evidence-register-missing",
                "info",
                root,
                "Security evidence register is not documented",
                "docs/security/EVIDENCE_REGISTER.md",
                "No security evidence register found",
                "Keep links to scan reports, SBOM, VEX, DAST, review decisions, attestations, and approvals for audit/release review.",
            )
        )

    if _looks_like_web_project(file_list, basenames) and not (SECURITY_HEADERS_PATHS & lower_rel_paths):
        findings.append(
            _finding(
                "prevention.security-headers-guide-missing",
                "info",
                root,
                "Security headers baseline is not documented",
                "docs/security/SECURITY_HEADERS.md",
                "Web project detected without a security headers guide",
                "Document expected CSP, HSTS, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy settings.",
            )
        )

    if (dockerfiles or k8s_files or any(path.name in {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"} for path in file_list)) and not (CONTAINER_HARDENING_PATHS & lower_rel_paths):
        findings.append(
            _finding(
                "prevention.container-hardening-guide-missing",
                "info",
                root,
                "Container hardening guide is not documented",
                "docs/security/CONTAINER_HARDENING.md",
                "Container deployment files exist without a hardening baseline",
                "Document non-root users, read-only filesystems, dropped capabilities, image pinning, resource limits, and runtime profiles.",
            )
        )

    if (has_source_code or has_dependency_manifest) and not (CISA_ATTESTATION_PATHS & lower_rel_paths):
        findings.append(
            _finding(
                "prevention.cisa-attestation-missing",
                "info",
                root,
                "CISA secure software attestation evidence is not documented",
                "docs/security/CISA_SECURE_SOFTWARE_ATTESTATION.md",
                "No secure software attestation evidence checklist found",
                "Record SSDF-aligned development, dependency, verification, and vulnerability-response evidence before attesting.",
            )
        )

    if (has_source_code or has_dependency_manifest) and not _contains_any(combined_workflow_text, SCORECARD_WORKFLOW_KEYWORDS):
        findings.append(
            _finding(
                "prevention.openssf-scorecard-missing",
                "info",
                root,
                "OpenSSF Scorecard workflow is not configured",
                ".github/workflows",
                "No OpenSSF Scorecard workflow found",
                "Run OpenSSF Scorecard in CI to monitor supply-chain posture such as token permissions, pinned actions, SAST, and dependency-update automation.",
            )
        )

    if workflow_files and not _has_readonly_token_permissions(combined_workflow_text):
        findings.append(
            _finding(
                "prevention.github-token-permissions-not-readonly",
                "low",
                root,
                "GitHub Actions token permissions are not locked down",
                ".github/workflows permissions",
                "No read-only workflow token baseline found",
                "Set top-level workflow permissions to contents: read and grant write permissions only to jobs that need them.",
            )
        )

    floating_actions = _floating_github_actions(workflow_texts)
    if floating_actions:
        findings.append(
            _finding(
                "prevention.github-actions-unpinned",
                "medium",
                root,
                "GitHub Actions references are not pinned tightly",
                ".github/workflows uses",
                ", ".join(floating_actions[:5]),
                "Pin third-party GitHub Actions to immutable commit SHAs or reviewed version tags, and avoid main/master/latest references.",
            )
        )

    if (
        (has_dependency_manifest or has_source_code)
        and not _contains_any(combined_workflow_text, SLSA_SIGSTORE_KEYWORDS)
        and "docs/security/slsa_sigstore.md" not in lower_rel_paths
    ):
        findings.append(
            _finding(
                "prevention.slsa-sigstore-missing",
                "info",
                root,
                "Release signing or provenance is not configured",
                "SLSA/Sigstore",
                "No SLSA provenance, Sigstore, cosign, or attestation workflow found",
                "Add artifact signing and provenance generation for releases using Sigstore/cosign or SLSA generators.",
            )
        )

    if (
        _looks_like_web_project(file_list, basenames)
        and not _contains_any(combined_workflow_text, DAST_WORKFLOW_KEYWORDS)
        and "docs/security/zap_baseline.md" not in lower_rel_paths
    ):
        findings.append(
            _finding(
                "prevention.zap-baseline-missing",
                "info",
                root,
                "DAST baseline is not configured",
                "OWASP ZAP",
                "No OWASP ZAP baseline workflow or guide found",
                "For authorized staging URLs, add an OWASP ZAP baseline check or document the DAST handoff process.",
            )
        )

    if has_dependency_manifest and not _has_vex(lower_rel_paths, lower_basenames):
        findings.append(
            _finding(
                "prevention.vex-missing",
                "info",
                root,
                "VEX document is not present",
                "VEX",
                "Dependency manifests exist but no local VEX artifact was found",
                "Generate a VEX document for reviewed dependency vulnerabilities so exploitable, fixed, and not-affected decisions are traceable.",
            )
        )

    binary_artifacts = _binary_artifacts(file_list, root)
    if binary_artifacts:
        findings.append(
            _finding(
                "prevention.binary-artifact-committed",
                "low",
                root,
                "Binary release artifact is committed",
                "binary artifacts",
                ", ".join(binary_artifacts[:5]),
                "Keep build artifacts out of source control unless they are intentionally vendored and covered by provenance, checksums, or signatures.",
            )
        )

    if env_files and not _gitignore_ignores_env(root, target):
        findings.append(
            _finding(
                "prevention.env-not-gitignored",
                "low",
                root,
                ".env files are not ignored",
                ".gitignore",
                "Environment files exist but .gitignore does not exclude them",
                "Add .env, .env.*, or an equivalent pattern to .gitignore before committing real environment files.",
            )
        )

    if env_files and not (ENV_EXAMPLE_NAMES & basenames):
        findings.append(
            _finding(
                "prevention.env-example-missing",
                "low",
                root,
                "Sanitized environment example is missing",
                ".env.example",
                "Environment files exist without a sanitized example",
                "Commit a sanitized .env.example or .env.sample and keep real values outside the repository.",
            )
        )

    if dockerfiles and ".dockerignore" not in basenames:
        findings.append(
            _finding(
                "prevention.dockerignore-missing",
                "low",
                root,
                ".dockerignore is missing",
                ".dockerignore",
                "Dockerfile exists without .dockerignore",
                "Add .dockerignore to keep secrets, VCS metadata, build output, and local files out of Docker build contexts.",
            )
        )

    if has_dependency_manifest and not _has_sbom(lower_rel_paths, lower_basenames):
        findings.append(
            _finding(
                "prevention.sbom-missing",
                "info",
                root,
                "SBOM artifact is not present",
                "sbom",
                "Dependency manifests exist but no local SBOM artifact was found",
                "Generate and retain a CycloneDX or SPDX SBOM for release builds or CI artifacts.",
            )
        )

    return findings


def _finding(
    rule_id: str,
    severity: str,
    root: Path,
    title: str,
    evidence: str,
    description: str,
    recommendation: str,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        category="prevention",
        severity=severity,
        title=title,
        path=root,
        evidence=evidence,
        description=description,
        recommendation=recommendation,
    )


def _has_security_workflow(workflow_files: Iterable[Path], target: TargetConfig) -> bool:
    for workflow in workflow_files:
        lines = read_text_lines(workflow, target.max_file_size_bytes)
        if not lines:
            continue
        text = "\n".join(lines).lower()
        if any(keyword in text for keyword in SECURITY_WORKFLOW_KEYWORDS):
            return True
    return False


def _project_text_contains(files: Iterable[Path], target: TargetConfig, keywords: tuple[str, ...]) -> bool:
    source_suffixes = {".js", ".jsx", ".md", ".py", ".ts", ".tsx", ".txt"}
    for path in files:
        if path.suffix.lower() not in source_suffixes:
            continue
        lines = read_text_lines(path, target.max_file_size_bytes)
        if not lines:
            continue
        text = "\n".join(lines).lower()
        if any(keyword in text for keyword in keywords):
            return True
    return False


def _looks_like_mobile_project(files: Iterable[Path], basenames: set[str], lower_rel_paths: set[str], target: TargetConfig) -> bool:
    if "AndroidManifest.xml" in basenames:
        return True
    if "Info.plist" in basenames and any(part in rel_path for rel_path in lower_rel_paths for part in ("/ios/", "/app/", "/mobile/")):
        return True
    if any(rel_path.endswith(".xcodeproj/project.pbxproj") or rel_path.endswith(".xcworkspace/contents.xcworkspacedata") for rel_path in lower_rel_paths):
        return True
    for path in files:
        if path.name not in {"build.gradle", "build.gradle.kts"}:
            continue
        lines = read_text_lines(path, target.max_file_size_bytes)
        text = "\n".join(lines or []).lower()
        if "com.android.application" in text or "com.android.library" in text:
            return True
    return False


def _looks_like_cloud_iac(files: Iterable[Path], basenames: set[str], lower_rel_paths: set[str]) -> bool:
    if {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"} & basenames:
        return True
    if any(path.name.lower() == "dockerfile" or path.name.lower().startswith("dockerfile.") or path.suffix.lower() in {".tf", ".tfvars"} for path in files):
        return True
    return any(any(part in rel_path for part in ("/k8s/", "/kubernetes/", "/helm/", "/terraform/", "/infra/")) for rel_path in lower_rel_paths)


def _looks_like_kubernetes_manifest(path: Path) -> bool:
    lower_name = path.name.lower()
    if lower_name in {"deployment.yml", "deployment.yaml", "pod.yml", "pod.yaml", "daemonset.yml", "daemonset.yaml", "statefulset.yml", "statefulset.yaml", "networkpolicy.yml", "networkpolicy.yaml"}:
        return True
    if path.suffix.lower() not in {".yaml", ".yml"}:
        return False
    lowered_parts = {part.lower() for part in path.parts}
    return bool({"k8s", "kubernetes", "manifests", "helm"} & lowered_parts)


def _has_kubernetes_network_policy(files: Iterable[Path]) -> bool:
    for path in files:
        if path.suffix.lower() not in {".yaml", ".yml"}:
            continue
        if "networkpolicy" in path.name.lower():
            return True
        lines = read_text_lines(path, 524288)
        if not lines:
            continue
        if "kind: networkpolicy" in "\n".join(lines).lower():
            return True
    return False


def _ignore_file_findings(root: Path, files: Iterable[Path], target: TargetConfig) -> list[Finding]:
    findings: list[Finding] = []
    for path in files:
        if path.name not in {"koda-ignore.yml", ".koda-ignore.yml"}:
            continue
        lines = read_text_lines(path, target.max_file_size_bytes)
        if not lines:
            continue
        findings.extend(_inspect_ignore_file(root, path, lines))
    return findings


def _inspect_ignore_file(root: Path, path: Path, lines: list[str]) -> list[Finding]:
    from datetime import date

    findings: list[Finding] = []
    current: dict[str, tuple[str, int]] = {}

    def flush() -> None:
        if not current:
            return
        line = min((line_number for _, line_number in current.values()), default=None)
        rule = current.get("rule", ("*", line or 1))[0]
        evidence = f"rule={rule}, path={current.get('path', ('*', 0))[0]}"
        if not current.get("reason", ("", 0))[0]:
            findings.append(
                Finding(
                    rule_id="prevention.exception-reason-missing",
                    category="prevention",
                    severity="low",
                    title="KODA exception lacks a reason",
                    path=path,
                    line=line,
                    evidence=evidence,
                    description="Finding exceptions without a clear reason are hard to review and can hide real risk.",
                    recommendation="Add a specific reason describing why the finding is accepted or considered false positive.",
                )
            )
        if not current.get("owner", ("", 0))[0]:
            findings.append(
                Finding(
                    rule_id="prevention.exception-owner-missing",
                    category="prevention",
                    severity="low",
                    title="KODA exception lacks an owner",
                    path=path,
                    line=line,
                    evidence=evidence,
                    description="Finding exceptions need an accountable owner for review and renewal decisions.",
                    recommendation="Add owner with the accountable person, team, or ticket queue.",
                )
            )
        until = current.get("until", ("", 0))[0]
        if not until:
            findings.append(
                Finding(
                    rule_id="prevention.exception-expiry-missing",
                    category="prevention",
                    severity="medium",
                    title="KODA exception lacks an expiry date",
                    path=path,
                    line=line,
                    evidence=evidence,
                    description="Open-ended exceptions tend to become permanent risk acceptance.",
                    recommendation="Add until in YYYY-MM-DD format and review the exception before extending it.",
                )
            )
        else:
            try:
                if date.fromisoformat(until) < date.today():
                    findings.append(
                        Finding(
                            rule_id="prevention.exception-expired",
                            category="prevention",
                            severity="medium",
                            title="KODA exception is expired",
                            path=path,
                            line=current.get("until", ("", line or 1))[1],
                            evidence=f"{evidence}, until={until}",
                            description="Expired exceptions no longer suppress findings and should be reviewed or removed.",
                            recommendation="Remove the exception, fix the underlying issue, or renew it with a fresh approval and reason.",
                        )
                    )
            except ValueError:
                findings.append(
                    Finding(
                        rule_id="prevention.exception-expiry-missing",
                        category="prevention",
                        severity="medium",
                        title="KODA exception expiry is invalid",
                        path=path,
                        line=current.get("until", ("", line or 1))[1],
                        evidence=f"{evidence}, until={until}",
                        description="Exception expiry could not be parsed as YYYY-MM-DD.",
                        recommendation="Use an ISO date such as 2099-12-31 for the until field.",
                    )
                )

    for line_number, raw_line in enumerate(lines, start=1):
        stripped = raw_line.split("#", 1)[0].strip()
        if not stripped or stripped == "ignore:":
            continue
        if stripped.startswith("- "):
            flush()
            current = {}
            stripped = stripped[2:].strip()
        if ":" not in stripped:
            continue
        key, value = stripped.split(":", 1)
        current[key.strip()] = (value.strip().strip("'\""), line_number)
    flush()
    del root
    return findings


def _is_git_repo(root: Path) -> bool:
    return (root / ".git").exists()


def _has_pre_commit_hook(root: Path, target: TargetConfig) -> bool:
    hook = root / ".git" / "hooks" / "pre-commit"
    lines = read_text_lines(hook, target.max_file_size_bytes)
    if not lines:
        return False
    text = "\n".join(lines).lower()
    return "koda" in text or "security_scanner" in text or "local-security-scan" in text


def _workflow_texts(workflow_files: Iterable[Path], target: TargetConfig) -> list[str]:
    texts: list[str] = []
    for workflow in workflow_files:
        lines = read_text_lines(workflow, target.max_file_size_bytes)
        if lines:
            texts.append("\n".join(lines).lower())
    return texts


def _contains_any(text: str, keywords: tuple[str, ...]) -> bool:
    return any(keyword in text for keyword in keywords)


def _has_readonly_token_permissions(workflow_text: str) -> bool:
    if "permissions: read-all" in workflow_text:
        return True
    if "permissions:" not in workflow_text:
        return False
    return "contents: read" in workflow_text and "write-all" not in workflow_text


def _floating_github_actions(workflow_texts: Iterable[str]) -> list[str]:
    floating: list[str] = []
    for text in workflow_texts:
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("- uses:"):
                reference = stripped.split("- uses:", 1)[1].strip().strip("'\"")
            elif stripped.startswith("uses:"):
                reference = stripped.split("uses:", 1)[1].strip().strip("'\"")
            else:
                continue
            if _is_floating_action_reference(reference):
                floating.append(reference)
    return sorted(set(floating))


def _is_floating_action_reference(reference: str) -> bool:
    if reference.startswith("./"):
        return False
    if "@" not in reference:
        return True
    ref = reference.rsplit("@", 1)[1].strip().lower()
    if ref in {"main", "master", "latest", "head"}:
        return True
    return False


def _gitignore_ignores_env(root: Path, target: TargetConfig) -> bool:
    lines = read_text_lines(root / ".gitignore", target.max_file_size_bytes)
    if not lines:
        return False
    patterns = {line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#")}
    env_patterns = {".env", ".env*", ".env.*", "*.env", "**/.env", "**/.env.*"}
    return bool(patterns & env_patterns)


def _has_sbom(lower_rel_paths: set[str], lower_basenames: set[str]) -> bool:
    known_names = {"sbom.cdx.json", "bom.json", "bom.xml", "cyclonedx.json", "cyclonedx.xml", "spdx.json", "spdx.xml"}
    if known_names & lower_basenames:
        return True
    return any("sbom" in rel and Path(rel).suffix.lower() in SBOM_SUFFIXES for rel in lower_rel_paths)


def _has_vex(lower_rel_paths: set[str], lower_basenames: set[str]) -> bool:
    if VEX_NAMES & lower_basenames:
        return True
    return any("vex" in rel and Path(rel).suffix.lower() in VEX_SUFFIXES for rel in lower_rel_paths)


def _looks_like_web_project(file_list: tuple[Path, ...], basenames: set[str]) -> bool:
    if {"package.json", "vite.config.js", "next.config.js", "next.config.mjs"} & basenames:
        return True
    web_suffixes = {".html", ".jsx", ".tsx", ".php", ".vue", ".svelte"}
    web_config_names = {"nginx.conf", "httpd.conf", "apache2.conf", "web.config"}
    return any(path.suffix.lower() in web_suffixes or path.name.lower() in web_config_names for path in file_list)


def _binary_artifacts(file_list: tuple[Path, ...], root: Path) -> list[str]:
    artifacts: list[str] = []
    for path in file_list:
        if path.suffix.lower() in BINARY_ARTIFACT_SUFFIXES:
            artifacts.append(normalized_relpath(path, root))
    return sorted(artifacts)
