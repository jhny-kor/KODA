from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class TemplateWriteResult:
    path: Path
    status: str


def security_template_files(project_name: str = "KODA Project") -> dict[str, str]:
    clean_name = project_name.strip() or "KODA Project"
    return {
        "SECURITY.md": _security_policy(clean_name),
        ".github/dependabot.yml": _dependabot_config(),
        ".github/workflows/koda-security.yml": _github_security_workflow(),
        ".github/workflows/koda-release-provenance.yml": _github_release_provenance_workflow(),
        ".github/CODEOWNERS": _codeowners(),
        ".dockerignore": _dockerignore(),
        ".env.example": _env_example(),
        "docs/security/PRE_COMMIT.md": render_pre_commit_guide(),
        "docs/security/GITHUB_REPOSITORY_SECURITY.md": render_repository_security_checklist(clean_name),
        "docs/security/ZAP_BASELINE.md": _zap_baseline_guide(),
        "docs/security/DEPENDENCY_TRACK.md": _dependency_track_guide(clean_name),
        "docs/security/VEX.md": _vex_guide(),
        "docs/security/SLSA_SIGSTORE.md": _slsa_sigstore_guide(),
        "docs/security/NIST_SSDF_WORKFLOW.md": render_ssdf_workflow_plan(clean_name),
        "docs/security/SECURE_BY_DESIGN.md": render_secure_by_design_plan(clean_name),
        "docs/security/THREAT_MODEL.md": render_threat_model_template(clean_name),
        "docs/security/SECRET_ROTATION.md": render_secret_rotation_runbook(clean_name),
        "docs/security/AI_LLM_SECURITY.md": render_ai_llm_security_plan(clean_name),
        "docs/security/MOBILE_SECURITY.md": render_mobile_security_plan(clean_name),
        "docs/security/NIST_CSF_2_PROFILE.md": render_nist_csf_profile(clean_name),
        "docs/security/CISA_SECURE_SOFTWARE_ATTESTATION.md": render_cisa_attestation_checklist(clean_name),
        "docs/security/API_SECURITY.md": render_api_security_plan(clean_name),
        "docs/security/SCVS_PLAN.md": render_scvs_plan(clean_name),
        "docs/security/PRIVACY_DATA_MAP.md": render_privacy_data_map(clean_name),
        "docs/security/SECURITY_ROADMAP.md": render_security_roadmap(clean_name),
        "docs/security/EVIDENCE_REGISTER.md": render_evidence_register(clean_name),
        "docs/security/SECURITY_HEADERS.md": render_security_headers_baseline(clean_name),
        "docs/security/CONTAINER_HARDENING.md": render_container_hardening_baseline(clean_name),
        "docs/security/CLOUD_IAC_SECURITY.md": render_cloud_iac_security_plan(clean_name),
    }


def write_security_template_files(root: Path, *, project_name: str = "", force: bool = False) -> list[TemplateWriteResult]:
    root = root.expanduser().resolve()
    if not root.exists() or not root.is_dir():
        raise ValueError(f"Target directory does not exist: {root}")

    results: list[TemplateWriteResult] = []
    for relative_path, content in security_template_files(project_name or root.name).items():
        destination = root / relative_path
        if destination.exists() and not force:
            results.append(TemplateWriteResult(destination, "skipped"))
            continue
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(content, encoding="utf-8")
        results.append(TemplateWriteResult(destination, "written"))
    return results


def install_pre_commit_hook(root: Path, *, fail_on: str = "high", force: bool = False) -> TemplateWriteResult:
    root = root.expanduser().resolve()
    git_dir = root / ".git"
    if not git_dir.exists():
        raise ValueError(f"Target is not a Git repository: {root}")
    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)
    hook = hooks_dir / "pre-commit"
    if hook.exists() and not force:
        return TemplateWriteResult(hook, "skipped")
    hook.write_text(render_pre_commit_hook(fail_on=fail_on), encoding="utf-8")
    hook.chmod(0o755)
    return TemplateWriteResult(hook, "written")


def write_ignore_template(root: Path, *, force: bool = False) -> TemplateWriteResult:
    root = root.expanduser().resolve()
    if not root.exists() or not root.is_dir():
        raise ValueError(f"Target directory does not exist: {root}")
    destination = root / "koda-ignore.yml"
    if destination.exists() and not force:
        return TemplateWriteResult(destination, "skipped")
    destination.write_text(_ignore_template(), encoding="utf-8")
    return TemplateWriteResult(destination, "written")


def _ignore_template() -> str:
    return """# KODA finding exceptions. Existing scans ignore matching entries until the date expires.
# Keep reasons specific and review every exception before extending it.
ignore:
  - rule: secret.generic-assignment
    path: "tests/**"
    reason: "example test fixture only"
    until: "2099-12-31"
"""


def render_pre_commit_hook(*, fail_on: str = "high") -> str:
    threshold = fail_on if fail_on in {"critical", "high", "medium", "low", "info"} else "high"
    return f"""#!/bin/sh
# KODA pre-commit security gate.
# Blocks commits when findings meet or exceed KODA_PRE_COMMIT_FAIL_ON.
set -eu

if command -v python3 >/dev/null 2>&1; then
  PYTHON=python3
else
  PYTHON=python
fi

FAIL_ON="${{KODA_PRE_COMMIT_FAIL_ON:-{threshold}}}"
TARGET="${{KODA_PRE_COMMIT_TARGET:-.}}"
REPORT="${{TMPDIR:-/tmp}}/koda-pre-commit-report.md"

"$PYTHON" -m security_scanner scan \\
  --target "$TARGET" \\
  --format markdown \\
  --output "$REPORT" \\
  --fail-on "$FAIL_ON"

echo "KODA pre-commit scan passed. Report: $REPORT"
"""


def render_pre_commit_guide() -> str:
    return """# KODA Pre-Commit Security Gate

Install the KODA pre-commit hook to stop high-risk issues before they enter Git history.

```bash
python -m security_scanner install-hook --target . --fail-on high
```

The hook runs `python -m security_scanner scan` against the repository and blocks the commit when findings meet or exceed `KODA_PRE_COMMIT_FAIL_ON`.

Useful environment variables:

- `KODA_PRE_COMMIT_FAIL_ON`: critical, high, medium, low, or info
- `KODA_PRE_COMMIT_TARGET`: target path, default `.`

Keep the hook focused on prevention. Use full CI for deeper external integrations such as DAST, SBOM upload, and release signing.
"""


def render_security_toolkit_markdown(project_name: str = "KODA Project") -> str:
    files = security_template_files(project_name)
    sections = [
        "# KODA Security Prevention Kit",
        "",
        "이 문서는 KODA가 생성한 보안 예방 가드레일 템플릿입니다.",
        "프로젝트에 맞게 담당자, 브랜치, 패키지 생태계, 운영 URL을 수정한 뒤 저장소에 반영하세요.",
        "",
    ]
    for path, content in files.items():
        fence = "yaml" if path.endswith((".yml", ".yaml")) else "markdown"
        if path == ".dockerignore" or path == ".env.example":
            fence = "text"
        sections.extend([f"## {path}", "", f"```{fence}", content.rstrip(), "```", ""])
    return "\n".join(sections)


def render_repository_security_checklist(project_name: str = "KODA Project") -> str:
    return f"""# GitHub Repository Security Checklist

Project: {project_name}

KODA cannot enforce every repository-hosted setting from local files, so this checklist records what should be enabled in GitHub or an equivalent forge.

## Branch And Review Protection

- [ ] Protect the default branch.
- [ ] Require pull requests before merge.
- [ ] Require at least one approving review.
- [ ] Require status checks for KODA/SAST tests before merge.
- [ ] Require review from CODEOWNERS for security-sensitive paths.
- [ ] Dismiss stale approvals when new commits are pushed.

## Secret And Dependency Protection

- [ ] Enable secret scanning and push protection.
- [ ] Enable Dependabot alerts.
- [ ] Enable Dependabot security updates.
- [ ] Upload SARIF results from KODA, CodeQL, Semgrep, or equivalent tools.
- [ ] Keep Actions token permissions read-only by default.

## Accountability

- [ ] Add `.github/CODEOWNERS`.
- [ ] Define a vulnerability reporting contact in `SECURITY.md`.
- [ ] Review exceptions in `koda-ignore.yml` on a schedule.
- [ ] Track SBOM and VEX artifacts for releases.
"""


def render_ssdf_workflow_plan(project_name: str = "KODA Project") -> str:
    return f"""# NIST SSDF Workflow

Project: {project_name}

This plan maps KODA prevention controls to NIST SP 800-218 SSDF practice groups.

## Prepare The Organization

- [ ] Define secure-development roles and owners.
- [ ] Keep `SECURITY.md`, CODEOWNERS, and exception policy current.
- [ ] Train contributors on secrets, dependency hygiene, and secure defaults.

## Protect The Software

- [ ] Keep source access least-privilege.
- [ ] Block secrets and high-risk findings before commit.
- [ ] Generate SBOMs for release builds.
- [ ] Sign release artifacts and preserve provenance.

## Produce Well-Secured Software

- [ ] Run KODA, SAST, and dependency checks on pull requests.
- [ ] Use secure defaults for configuration, cookies, CORS, containers, and CI tokens.
- [ ] Keep dependency update automation enabled.
- [ ] Review design changes for auth, data protection, and trust boundaries.

## Respond To Vulnerabilities

- [ ] Triage OSV/CVE findings with KEV/EPSS context.
- [ ] Record reviewed dependency findings in VEX.
- [ ] Track remediation owner, due date, and release note/advisory.
- [ ] Re-run KODA and compare score history after remediation.
"""


def render_secure_by_design_plan(project_name: str = "KODA Project") -> str:
    return f"""# CISA Secure by Design Plan

Project: {project_name}

This checklist turns CISA Secure by Design principles into project-level prevention work that KODA can help track.

## Take Ownership Of Customer Security Outcomes

- [ ] Treat exposed secrets, unsafe defaults, and known exploited vulnerabilities as customer-impacting defects.
- [ ] Provide secure defaults for auth, sessions, logging, CORS, and deployment configuration.
- [ ] Ship updates or compensating guidance quickly for exploitable dependency findings.
- [ ] Keep a security contact and vulnerability handling process visible.

## Embrace Radical Transparency And Accountability

- [ ] Publish security policy, supported versions, and remediation expectations.
- [ ] Keep SBOM and VEX artifacts for releases.
- [ ] Record known limitations, accepted risks, and exception expiry dates.
- [ ] Track score history and severity deltas after each release.

## Lead From The Top

- [ ] Assign owners for product security outcomes.
- [ ] Review Secure by Design metrics regularly: high findings, time to remediate, secrets blocked, and vulnerable dependencies.
- [ ] Require security gates before merge and release.
- [ ] Invest in prevention automation instead of relying only on post-release fixes.
"""


def render_threat_model_template(project_name: str = "KODA Project") -> str:
    return f"""# Threat Model

Project: {project_name}

## Scope

- [ ] Product or service boundary:
- [ ] In-scope repositories, apps, APIs, workers, and admin tools:
- [ ] Out-of-scope systems:

## Assets

| Asset | Sensitivity | Owner | Storage/Transit |
| --- | --- | --- | --- |
| Customer data | high | TBD | TBD |
| Secrets and tokens | critical | TBD | secret manager / environment |
| Build and release artifacts | high | TBD | CI/release storage |

## Trust Boundaries

- [ ] Browser/mobile client to backend API
- [ ] Backend to database/cache/object storage
- [ ] CI runner to package registries and release storage
- [ ] Admin/operator access to production systems
- [ ] AI/LLM provider, tool, or retrieval boundary when used

## Abuse Cases

- [ ] Unauthorized access to user/admin function
- [ ] Secret leak through repository, logs, prompt, or artifact
- [ ] Dependency or CI supply-chain compromise
- [ ] File upload/download path manipulation
- [ ] Prompt injection or over-privileged agent action when AI is used

## Required Controls

- [ ] Authentication and authorization checked for sensitive operations
- [ ] Secrets are stored outside source and have rotation owners
- [ ] Dependency versions are pinned and checked in CI
- [ ] Logs mask sensitive values
- [ ] Runtime and external tests are scheduled for risks KODA cannot prove locally
"""


def render_secret_rotation_runbook(project_name: str = "KODA Project") -> str:
    return f"""# Secret Rotation Runbook

Project: {project_name}

Use this runbook whenever KODA finds a real token, key, password, certificate, or private key.

## Immediate Response

- [ ] Identify the secret owner and affected service.
- [ ] Revoke or disable the exposed value.
- [ ] Issue a replacement secret through the approved secret manager.
- [ ] Deploy the replacement without writing it to source control.
- [ ] Re-run KODA and secret scanning on the repository.

## Audit

- [ ] Review provider logs from the first possible exposure time.
- [ ] Check CI logs, issue attachments, release artifacts, and chat copies.
- [ ] Determine whether data access, privilege escalation, or lateral movement occurred.
- [ ] Record incident ticket, owner, timeline, and final disposition.

## Prevention

- [ ] Add or update `.gitignore`, `.env.example`, and pre-commit scanning.
- [ ] Add provider-side secret scanning or push protection when available.
- [ ] Store emergency rotation contacts and provider console links outside this repository.
"""


def render_ai_llm_security_plan(project_name: str = "KODA Project") -> str:
    return f"""# AI / LLM Security Plan

Project: {project_name}

## Inventory

| Use case | Model/provider | Data sent | Tools/actions | Owner |
| --- | --- | --- | --- | --- |
| TBD | TBD | TBD | TBD | TBD |

## OWASP LLM Top 10 Controls

- [ ] LLM01 Prompt Injection: user and retrieved content are separated from system/developer instructions.
- [ ] LLM02 Sensitive Information Disclosure: prompts and logs redact credentials, tokens, PII, and customer secrets.
- [ ] LLM03 Supply Chain: model, SDK, plugin, and retrieval dependencies are inventoried and reviewed.
- [ ] LLM05 Improper Output Handling: model output is validated before HTML, shell, SQL, file, or API use.
- [ ] LLM06 Excessive Agency: tools are allowlisted, scoped, logged, and require confirmation for side effects.
- [ ] LLM07 System Prompt Leakage: prompts do not contain credentials or non-disclosable policy text.
- [ ] LLM08 Vector and Embedding Weaknesses: retrieval sources are trusted, access-controlled, and poison-resistant.
- [ ] LLM10 Unbounded Consumption: request size, loop count, tool calls, and cost limits are enforced.

## Tests

- [ ] Prompt injection fixtures cover direct and indirect input.
- [ ] Tool calls reject path traversal, network abuse, and unauthorized destructive actions.
- [ ] Sensitive data canary values are not returned by the model or stored in logs.
"""


def render_mobile_security_plan(project_name: str = "KODA Project") -> str:
    return f"""# Mobile Security Plan

Project: {project_name}

## OWASP MASVS Coverage

- [ ] MASVS-STORAGE: local storage, backups, keychain/keystore, and cached files reviewed.
- [ ] MASVS-CRYPTO: approved crypto and key handling used.
- [ ] MASVS-AUTH: authentication, session, biometric, and authorization flows tested.
- [ ] MASVS-NETWORK: TLS/ATS/network security config reviewed; cleartext traffic disabled.
- [ ] MASVS-PLATFORM: exported Android components and iOS document sharing reviewed.
- [ ] MASVS-CODE: debug flags, logging, injection, file handling, and dependency hygiene checked.
- [ ] MASVS-RESILIENCE: release signing, debug builds, and tamper/reverse-engineering expectations documented.
- [ ] MASVS-PRIVACY: personal data collection, retention, prompts, analytics, and logs reviewed.

## Release Checks

- [ ] Android release build is not debuggable and backup behavior is intentional.
- [ ] iOS ATS exceptions are domain-scoped and justified.
- [ ] Mobile dependency and SDK inventory is exported for release review.
- [ ] Device/runtime tests are performed for storage, network, and platform interaction risks.
"""


def render_nist_csf_profile(project_name: str = "KODA Project") -> str:
    return f"""# NIST CSF 2.0 Profile

Project: {project_name}

## Govern

- [ ] Cybersecurity risk owners are assigned.
- [ ] Security policy, exception handling, and review cadence are documented.

## Identify

- [ ] Repositories, services, dependency manifests, SBOM, data stores, and critical assets are inventoried.
- [ ] Third-party and open source dependency risk is reviewed.

## Protect

- [ ] Secrets, authentication, session, container, mobile, AI, and CI settings have secure defaults.
- [ ] Pre-commit and CI security gates are active.

## Detect

- [ ] KODA/SAST/dependency scans run on pull requests or release branches.
- [ ] Logs and alerts avoid sensitive data while preserving useful security events.

## Respond

- [ ] Vulnerability reports, OSV/CVE findings, secret leaks, and DAST findings have owners and due dates.
- [ ] VEX records explain reviewed dependency vulnerability decisions.

## Recover

- [ ] Release packages include checksums, SBOM, VEX, scan reports, and signing/provenance evidence.
- [ ] Post-incident fixes are re-scanned and score history is reviewed.
"""


def render_cisa_attestation_checklist(project_name: str = "KODA Project") -> str:
    return f"""# CISA Secure Software Development Attestation Checklist

Project: {project_name}

This checklist helps collect evidence before a responsible producer signs or submits a secure software development attestation.

## Secure Development Environment

- [ ] Source access is least-privilege and reviewed.
- [ ] Branch protection, required review, CODEOWNERS, and CI gates are configured.
- [ ] Secrets are not stored in source and have rotation procedures.

## Secure Development Practices

- [ ] Threat modeling is performed for significant features.
- [ ] Secure coding checks run locally or in CI.
- [ ] Security-relevant exceptions have owner, reason, and expiry.

## Third-Party Components

- [ ] Dependencies are inventoried with SBOM.
- [ ] Versions are pinned where practical.
- [ ] Known vulnerabilities are triaged and VEX decisions are recorded.

## Verification And Response

- [ ] SAST, dependency, secret, and configuration checks are run before release.
- [ ] DAST or penetration testing is scheduled when runtime behavior matters.
- [ ] Vulnerability reporting, remediation, and release-note/advisory processes are documented.

## Attestation Notes

- [ ] Evidence package location:
- [ ] Responsible owner:
- [ ] Review date:
- [ ] Known limitations or compensating controls:
"""


def render_api_security_plan(project_name: str = "KODA Project") -> str:
    return f"""# API Security Plan

Project: {project_name}

Use this checklist with OWASP API Security Top 10:2023.

## Inventory

| API | Version | Auth Required | Data Class | Owner |
| --- | --- | --- | --- | --- |
| TBD | /api/v1 | yes | TBD | TBD |

## Controls

- [ ] Object-level authorization is checked for every user-controlled object ID.
- [ ] Function-level authorization is explicit for admin, payment, account, and profile routes.
- [ ] Request body schemas reject unknown properties to prevent mass assignment.
- [ ] Rate limits and quotas cover login, signup, password reset, search, export, and high-cost APIs.
- [ ] Outbound API calls use allowlisted destinations, timeouts, retry limits, and SSRF protections.
- [ ] API versions, deprecation dates, and owners are documented.
"""


def render_scvs_plan(project_name: str = "KODA Project") -> str:
    return f"""# OWASP SCVS Plan

Project: {project_name}

## V1 Inventory

- [ ] Source, package, container, plugin, model, and generated components are inventoried.
- [ ] Each component has owner, source, version, license, and business purpose.

## V2 SBOM

- [ ] CycloneDX or SPDX SBOM is generated for release builds.
- [ ] SBOM files are retained with release packages and uploaded to the selected analysis backend.

## V3 Build Environment

- [ ] CI runners are least-privilege and build from protected refs.
- [ ] GitHub Actions or equivalent build steps use pinned actions and minimal tokens.

## V4 Package Management

- [ ] Lockfiles are committed for package ecosystems that support them.
- [ ] Package registries are approved and HTTP package sources are blocked.

## V5 Component Analysis

- [ ] OSV/CVE, KEV/EPSS, and dependency scan results are triaged before release.
- [ ] VEX records explain not-affected, fixed, or accepted dependency decisions.

## V6 Pedigree And Provenance

- [ ] Release artifacts are built in CI, checksummed, signed, and linked to provenance.
- [ ] Third-party or vendored components have review notes and update owners.
"""


def render_privacy_data_map(project_name: str = "KODA Project") -> str:
    return f"""# Privacy Data Map

Project: {project_name}

## Data Inventory

| Field | Category | Purpose | Storage | Retention | Sharing | Owner |
| --- | --- | --- | --- | --- | --- | --- |
| email | personal data | account/contact | TBD | TBD | TBD | TBD |

## Handling Rules

- [ ] Personal data is not logged in raw form.
- [ ] Test fixtures and demo data avoid real personal data.
- [ ] Retention and deletion behavior is documented.
- [ ] Analytics, AI/LLM prompts, crash reports, and support exports are reviewed for personal data.
- [ ] Access to production personal data is approved, logged, and time-bound.
"""


def render_security_roadmap(project_name: str = "KODA Project") -> str:
    return f"""# Security Roadmap

Project: {project_name}

| Priority | Work Item | Standard | Owner | Due Date | Status | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| P1 | Remove critical/high KODA findings | Local / OWASP | TBD | TBD | planned | reports/ |
| P1 | Complete threat model and API inventory | OWASP API / ASVS | TBD | TBD | planned | docs/security/ |
| P2 | Complete SCVS supply-chain evidence | OWASP SCVS | TBD | TBD | planned | release package |

## Cadence

- [ ] Review this roadmap before each release.
- [ ] Convert accepted risks into `koda-ignore.yml` entries with owner, reason, and expiry.
- [ ] Re-run KODA after remediation and compare score history.
"""


def render_evidence_register(project_name: str = "KODA Project") -> str:
    return f"""# Security Evidence Register

Project: {project_name}

| Evidence | Standard | Location | Owner | Review Date | Notes |
| --- | --- | --- | --- | --- | --- |
| KODA scan report | Local / OWASP / CWE | reports/security-dashboard.html | TBD | TBD | TBD |
| SBOM | SCVS / SSDF | reports/sbom.cdx.json | TBD | TBD | TBD |
| VEX | SCVS / vulnerability response | reports/vex.cdx.json | TBD | TBD | TBD |
| Threat model | ASVS / API / Secure by Design | docs/security/THREAT_MODEL.md | TBD | TBD | TBD |
| Release package | SLSA / CISA | release-security/ | TBD | TBD | TBD |
"""


def render_security_headers_baseline(project_name: str = "KODA Project") -> str:
    return f"""# Security Headers Baseline

Project: {project_name}

Apply these headers at the edge, reverse proxy, or application layer where appropriate.

| Header | Baseline |
| --- | --- |
| Content-Security-Policy | default-src 'self'; frame-ancestors 'none'; object-src 'none' |
| Strict-Transport-Security | max-age=31536000; includeSubDomains |
| X-Content-Type-Options | nosniff |
| Referrer-Policy | no-referrer or strict-origin-when-cross-origin |
| Permissions-Policy | disable unused browser capabilities |
| Cache-Control | no-store for sensitive authenticated responses |

- [ ] Document exceptions for embedded third-party content.
- [ ] Test with browser developer tools or an approved header scanner.
"""


def render_container_hardening_baseline(project_name: str = "KODA Project") -> str:
    return f"""# Container Hardening Baseline

Project: {project_name}

## Docker / Compose

- [ ] Runtime image uses a non-root user.
- [ ] Images are pinned to reviewed tags or digests.
- [ ] Docker socket is not mounted into application containers.
- [ ] Secrets are injected at runtime and not committed in compose files.
- [ ] Filesystem is read-only where practical and writable paths are explicit.

## Kubernetes

- [ ] `runAsNonRoot: true` and `allowPrivilegeEscalation: false` are set.
- [ ] `seccompProfile.type: RuntimeDefault` is used.
- [ ] Linux capabilities are dropped by default.
- [ ] Resource requests/limits and NetworkPolicies are defined.
- [ ] Service account token auto-mounting is disabled unless required.
"""


def render_cloud_iac_security_plan(project_name: str = "KODA Project") -> str:
    return f"""# Cloud and IaC Security Plan

Project: {project_name}

## Exposure

- [ ] Public ingress is limited to intended ports and source ranges.
- [ ] Admin access uses VPN, bastion, device posture, or approved management plane controls.
- [ ] Storage buckets, databases, and queues are private by default.

## Identity

- [ ] IAM policies avoid wildcard actions and principals.
- [ ] Service identities are scoped by workload and environment.
- [ ] Break-glass and admin roles have owners, MFA, logging, and review cadence.

## Data Protection

- [ ] Storage encryption is enabled.
- [ ] Terraform outputs avoid raw secrets and use `sensitive = true` when needed.
- [ ] State files are encrypted, access-controlled, and excluded from source control.
"""


def render_release_signing_plan(project_name: str = "KODA Project", artifact_path: str = "dist/app.tar.gz") -> str:
    return f"""# SLSA / Sigstore Release Signing Plan

Project: {project_name}
Artifact: {artifact_path}

## Goal

Build release artifacts in CI, generate provenance, sign artifacts with Sigstore/cosign or your signing system, and publish verification material next to the release.

## Local Commands For Dry Run

```bash
sha256sum "{artifact_path}" > "{artifact_path}.sha256"
cosign sign-blob "{artifact_path}" --bundle "{artifact_path}.sigstore.json" --yes
cosign verify-blob "{artifact_path}" --bundle "{artifact_path}.sigstore.json" --certificate-identity-regexp ".*" --certificate-oidc-issuer-regexp ".*"
```

## CI Requirements

- [ ] Build artifacts in CI from the release tag.
- [ ] Generate SLSA provenance or an equivalent attestation.
- [ ] Sign the artifact or container digest.
- [ ] Publish checksum, signature bundle, and provenance.
- [ ] Verify the published artifact from a clean environment before release announcement.
"""


def _security_policy(project_name: str) -> str:
    return f"""# Security Policy

## Supported Versions

| Version | Supported |
| --- | --- |
| main / latest | yes |

## Reporting a Vulnerability

Please report suspected vulnerabilities privately before opening a public issue.

- Project: {project_name}
- Contact: security@example.com
- Expected first response: 3 business days
- Expected status update: 7 business days

## Handling

1. Confirm the report and assign an owner.
2. Reproduce the issue in a private branch or isolated environment.
3. Patch, test, and release the fix.
4. Rotate exposed credentials when secrets are involved.
5. Publish an advisory or release note after users have a remediation path.
"""


def _dependabot_config() -> str:
    return """version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "weekly"
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
"""


def _github_security_workflow() -> str:
    return """name: KODA Security

on:
  pull_request:
  push:
    branches: [main]
  schedule:
    - cron: "0 18 * * 1"

permissions:
  contents: read

jobs:
  local-security-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Install KODA scanner
        run: python -m pip install "git+https://gitlab.aigov.go.kr/y2kthr/koda.git"
      - name: Run KODA local scan
        run: |
          python -m security_scanner scan --target . --format sarif --output koda-results.sarif --enable-osv --enable-vuln-intel
          python -m security_scanner scan --target . --format cyclonedx --output koda-sbom.cdx.json
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: koda-results.sarif
      - name: Upload SBOM artifact
        uses: actions/upload-artifact@v4
        with:
          name: koda-sbom
          path: koda-sbom.cdx.json

  openssf-scorecard:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
      id-token: write
    steps:
      - uses: actions/checkout@v4
      - uses: ossf/scorecard-action@v2.4.0
        with:
          results_file: scorecard-results.sarif
          results_format: sarif
          publish_results: true
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: scorecard-results.sarif
"""


def _github_release_provenance_workflow() -> str:
    return """name: KODA Release Provenance

on:
  workflow_dispatch:
  release:
    types: [published]

permissions:
  contents: read
  id-token: write

jobs:
  release-provenance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build release artifacts
        run: |
          mkdir -p dist
          tar --exclude .git --exclude dist -czf dist/source-release.tar.gz .
      - name: Generate checksums
        run: sha256sum dist/* > dist/checksums.txt
      - name: Install cosign
        uses: sigstore/cosign-installer@v3
      - name: Sign artifacts with Sigstore
        run: |
          for artifact in dist/*; do
            [ -f "$artifact" ] || continue
            cosign sign-blob "$artifact" --bundle "$artifact.sigstore.json" --yes
          done
"""


def _codeowners() -> str:
    return """# Adjust owners before committing.
* @security-team
/.github/ @security-team
/platforms/shared/python/security_scanner/ @security-team
/docs/security/ @security-team
/SECURITY.md @security-team
"""


def _dockerignore() -> str:
    return """.git
.github
.env
.env.*
!.env.example
node_modules
dist
build
coverage
reports
*.pem
*.key
*.p12
*.pfx
"""


def _env_example() -> str:
    return """# Copy to .env locally and fill real values outside the repository.
APP_ENV=development
LOG_LEVEL=info
"""


def _zap_baseline_guide() -> str:
    return """# ZAP Baseline

Use this only against systems you own or are authorized to test.

```bash
python3 -m security_scanner zap-command --url https://example.com --output-dir reports/zap
```

The generated command uses the official ZAP Docker baseline image and performs passive checks without active attacks.
"""


def _dependency_track_guide(project_name: str) -> str:
    return f"""# Dependency-Track SBOM Upload

Generate a CycloneDX SBOM:

```bash
python3 -m security_scanner scan --target . --format cyclonedx --output reports/sbom.cdx.json
```

Upload it to Dependency-Track:

```bash
python3 -m security_scanner upload-sbom \\
  --server-url https://dependency-track.example.com \\
  --api-key-env DEPENDENCY_TRACK_API_KEY \\
  --project-name "{project_name}" \\
  --project-version main \\
  --sbom reports/sbom.cdx.json \\
  --auto-create
```
"""


def _vex_guide() -> str:
    return """# VEX Tracking

Use VEX to record reviewed dependency vulnerabilities after OSV, Dependency-Track, or another advisory source reports a CVE.

Create `docs/security/vex.cdx.json` or another CycloneDX/OpenVEX document with:

- the affected component and version
- the vulnerability or CVE ID
- status such as `not_affected`, `affected`, `fixed`, or `under_investigation`
- impact statement and expiry/review date

KODA treats VEX as a prevention artifact. It does not claim a vulnerability is safe automatically; it only checks that review decisions can be tracked.
"""


def _slsa_sigstore_guide() -> str:
    return """# SLSA and Sigstore Release Guardrails

For release builds, add provenance and signing controls before publishing artifacts:

1. Build release artifacts in CI, not on a developer laptop.
2. Generate SLSA provenance or an equivalent attestation.
3. Sign artifacts with Sigstore/cosign or your organization's signing system.
4. Publish checksums, signatures, and provenance next to the release.
5. Keep GitHub Actions permissions read-only by default and grant write or OIDC permissions only at job scope.

KODA detects missing signing/provenance preparation from local workflow files, but actual signature verification requires the built artifact and release metadata.
"""
