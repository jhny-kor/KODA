from __future__ import annotations

import json
import re
from pathlib import Path

from ..models import Finding, TargetConfig
from .common import is_text_candidate, read_text_lines


def _finding(path: Path, rule_id: str, severity: str, title: str, description: str, recommendation: str) -> Finding:
    return Finding(
        rule_id=rule_id, category="configuration", severity=severity, title=title,
        path=path, description=description, recommendation=recommendation,
    )


ENV_FILE_RE = re.compile(r"^\.env($|\.)")
PRIVATE_KEY_FILENAMES = {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"}
PRIVATE_KEY_SUFFIXES = {".pem", ".p12", ".pfx", ".key"}
DEBUG_RE = re.compile(
    r"(?i)\b(DEBUG|DJANGO_DEBUG|FLASK_DEBUG|APP_DEBUG)\b\s*[:=]\s*['\"]?(true|1|yes|on)['\"]?"
)
DEV_ENV_RE = re.compile(r"(?i)\b(NODE_ENV|FLASK_ENV|APP_ENV)\b\s*[:=]\s*['\"]?development['\"]?")
DEV_ENV_CONFIG_SUFFIXES = {".cfg", ".conf", ".config", ".env", ".ini", ".json", ".properties", ".toml", ".yaml", ".yml"}
DEV_ENV_CONFIG_NAMES = {"dockerfile", "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}
K8S_FILE_NAMES = {
    "deployment.yml",
    "deployment.yaml",
    "pod.yml",
    "pod.yaml",
    "daemonset.yml",
    "daemonset.yaml",
    "statefulset.yml",
    "statefulset.yaml",
}
WORKFLOW_PARTS = (".github", "workflows")
ANDROID_MANIFEST_NAMES = {"AndroidManifest.xml"}
IOS_PLIST_NAMES = {"Info.plist"}


def check_file(path: Path, target: TargetConfig) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(_check_sensitive_filenames(path))

    if is_text_candidate(path):
        lines = read_text_lines(path, target.max_file_size_bytes)
        if lines:
            findings.extend(_check_text_config(path, lines))

    if path.name.lower() == "dockerfile" or path.name.lower().startswith("dockerfile."):
        findings.extend(_check_dockerfile(path, target))
    if path.name in {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}:
        findings.extend(_check_compose(path, target))
    if _looks_like_kubernetes_manifest(path):
        findings.extend(_check_kubernetes_manifest(path, target))
    if path.suffix.lower() in {".tf", ".tfvars"}:
        findings.extend(_check_terraform(path, target))
    if _looks_like_github_workflow(path):
        findings.extend(_check_github_workflow(path, target))
    if path.name in ANDROID_MANIFEST_NAMES:
        findings.extend(_check_android_manifest(path, target))
    if path.name in IOS_PLIST_NAMES:
        findings.extend(_check_ios_plist(path, target))
    if path.name == "package.json" or path.name in _LICENSE_MANIFESTS or _looks_like_license_file(path):
        findings.extend(_check_license(path, target))
    return findings


_LICENSE_MANIFESTS = {"pyproject.toml", "setup.cfg", "package.json"}
_LICENSE_FILE_NAMES = {"license", "license.txt", "license.md", "copying", "copying.txt"}
# Strong copyleft: distributing linked/derived work usually obliges source release.
_STRONG_COPYLEFT = re.compile(
    r"\bAGPL|GNU Affero|GPL-?3|GPLv3|GPL-?2|GPLv2|GNU General Public License|"
    r"\bSSPL\b|Server Side Public License",
    re.IGNORECASE,
)
# Weak/file-level copyleft: lighter obligations, still worth a review.
_WEAK_COPYLEFT = re.compile(r"\bLGPL|Lesser General Public|Mozilla Public License|\bMPL-?2|\bEUPL", re.IGNORECASE)


def _looks_like_license_file(path: Path) -> bool:
    return path.name.lower() in _LICENSE_FILE_NAMES


def _check_license(path: Path, target: TargetConfig) -> list[Finding]:
    """Flag strong/weak copyleft licenses declared in a manifest or LICENSE file.

    Deterministic and offline: reads the declared license text only. It does not
    resolve the full dependency tree's licenses (that needs a license database).
    """
    try:
        text = path.read_text(encoding="utf-8", errors="replace")[:20000]
    except OSError:
        return []
    declared = text
    if path.name == "package.json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return []
        license_field = data.get("license")
        licenses_field = data.get("licenses")
        parts = []
        if isinstance(license_field, str):
            parts.append(license_field)
        elif isinstance(license_field, dict):
            parts.append(str(license_field.get("type", "")))
        if isinstance(licenses_field, list):
            parts.extend(str(item.get("type", "")) if isinstance(item, dict) else str(item) for item in licenses_field)
        declared = " ".join(parts)
        if not declared.strip():
            return []
    if _STRONG_COPYLEFT.search(declared):
        return [_finding(
            path, "license.strong-copyleft", "high",
            "Strong copyleft license declared (AGPL/GPL/SSPL)",
            "A strong copyleft license obliges releasing source for distributed derivative/linked works.",
            "Confirm license compatibility with your distribution model; segregate or replace the component if proprietary distribution is required.",
        )]
    if _WEAK_COPYLEFT.search(declared):
        return [_finding(
            path, "license.weak-copyleft", "low",
            "Weak/file-level copyleft license declared (LGPL/MPL/EUPL)",
            "A weak copyleft license carries file-level or dynamic-linking obligations.",
            "Review the license's linking and modification obligations against your distribution.",
        )]
    return []


def _check_sensitive_filenames(path: Path) -> list[Finding]:
    name = path.name
    lower_name = name.lower()
    findings: list[Finding] = []
    if ENV_FILE_RE.match(name) and not lower_name.endswith((".example", ".sample", ".template")):
        findings.append(
            Finding(
                rule_id="config.env-file-present",
                category="configuration",
                severity="medium",
                title="Environment file present in project tree",
                path=path,
                description="Local environment files often contain credentials or production-only settings.",
                recommendation="Keep real environment files outside repositories and commit only sanitized examples.",
            )
        )
    if name in PRIVATE_KEY_FILENAMES or path.suffix.lower() in PRIVATE_KEY_SUFFIXES:
        findings.append(
            Finding(
                rule_id="config.private-key-like-file",
                category="configuration",
                severity="high",
                title="Private-key-like file present",
                path=path,
                description="Private key material should not live inside project folders unless intentionally test-only.",
                recommendation="Move private keys to a secret store and rotate them if they were used.",
            )
        )
    return findings


def _check_text_config(path: Path, lines: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if DEBUG_RE.search(line):
            findings.append(
                Finding(
                    rule_id="config.debug-enabled",
                    category="configuration",
                    severity="medium",
                    title="Debug mode appears enabled",
                    path=path,
                    line=line_number,
                    evidence=line,
                    description="Debug mode can expose internals, stack traces, or unsafe endpoints when deployed.",
                    recommendation="Disable debug mode in shared, staging, and production configurations.",
                )
            )
        if _should_check_development_environment(path) and DEV_ENV_RE.search(line):
            findings.append(
                Finding(
                    rule_id="config.development-environment",
                    category="configuration",
                    severity="low",
                    title="Development environment flag present",
                    path=path,
                    line=line_number,
                    evidence=line,
                    description="Development environment settings can weaken runtime assumptions if reused for deployment.",
                    recommendation="Separate local development configuration from deployment configuration.",
                )
            )
    return findings


def _should_check_development_environment(path: Path) -> bool:
    lower_name = path.name.lower()
    if lower_name.endswith((".example", ".sample", ".template")):
        return False
    if path.name.lower() in DEV_ENV_CONFIG_NAMES:
        return True
    if lower_name.startswith(".env"):
        return True
    return path.suffix.lower() in DEV_ENV_CONFIG_SUFFIXES


def _check_dockerfile(path: Path, target: TargetConfig) -> list[Finding]:
    lines = read_text_lines(path, target.max_file_size_bytes)
    if lines is None:
        return []

    has_user = False
    findings: list[Finding] = []
    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        upper = line.upper()
        if upper.startswith("USER "):
            has_user = True
            if line.split(maxsplit=1)[1].strip() in {"0", "root"}:
                findings.append(
                    Finding(
                        rule_id="config.docker-root-user",
                        category="configuration",
                        severity="medium",
                        title="Docker image explicitly runs as root",
                        path=path,
                        line=line_number,
                        evidence=line,
                        description="Root containers increase impact when a process is compromised.",
                        recommendation="Create and run as a least-privileged user unless root is required.",
                    )
                )
        if upper.startswith("ADD ") and "http://" in line.lower():
            findings.append(
                Finding(
                    rule_id="config.docker-add-http",
                    category="configuration",
                    severity="medium",
                    title="Dockerfile ADD fetches over HTTP",
                    path=path,
                    line=line_number,
                    evidence=line,
                    description="HTTP downloads can be modified in transit during image builds.",
                    recommendation="Use HTTPS and verify artifact checksums.",
                )
            )

    if not has_user:
        findings.append(
            Finding(
                rule_id="config.docker-no-user",
                category="configuration",
                severity="low",
                title="Dockerfile does not set a non-root user",
                path=path,
                description="Images without a USER directive usually run as root by default.",
                recommendation="Add a non-root USER for runtime stages when possible.",
            )
        )
    return findings


def _check_compose(path: Path, target: TargetConfig) -> list[Finding]:
    lines = read_text_lines(path, target.max_file_size_bytes)
    if lines is None:
        return []

    findings: list[Finding] = []
    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        lowered = line.lower()
        if lowered == "privileged: true":
            findings.append(
                Finding(
                    rule_id="config.compose-privileged",
                    category="configuration",
                    severity="high",
                    title="Compose service enables privileged mode",
                    path=path,
                    line=line_number,
                    evidence=line,
                    description="Privileged containers have broad host access.",
                    recommendation="Remove privileged mode and grant only the specific capabilities required.",
                )
            )
        if lowered == "network_mode: host":
            findings.append(
                Finding(
                    rule_id="config.compose-host-network",
                    category="configuration",
                    severity="medium",
                    title="Compose service uses host networking",
                    path=path,
                    line=line_number,
                    evidence=line,
                    description="Host networking weakens isolation and can expose local services.",
                    recommendation="Use explicit port mappings unless host networking is required.",
                )
            )
        if "/var/run/docker.sock" in lowered:
            findings.append(
                Finding(
                    rule_id="config.compose-docker-sock",
                    category="configuration",
                    severity="high",
                    title="Compose service mounts the Docker socket",
                    path=path,
                    line=line_number,
                    evidence=line,
                    description="Docker socket access is effectively host-level control.",
                    recommendation="Avoid mounting the Docker socket or isolate it behind a purpose-built proxy.",
                )
            )
        if re.search(r"\b(cap_add|capabilities)\s*:", lowered) or lowered in {"- sys_admin", "- net_admin"}:
            findings.append(
                Finding(
                    rule_id="config.compose-dangerous-capability",
                    category="configuration",
                    severity="medium",
                    title="Compose service grants broad Linux capabilities",
                    path=path,
                    line=line_number,
                    evidence=line,
                    description="Broad capabilities such as SYS_ADMIN and NET_ADMIN can weaken container isolation.",
                    recommendation="Remove broad capabilities and grant only the minimum capability required by the workload.",
                )
            )
        if lowered == "pid: host":
            findings.append(
                Finding(
                    rule_id="config.compose-host-pid",
                    category="configuration",
                    severity="medium",
                    title="Compose service uses host PID namespace",
                    path=path,
                    line=line_number,
                    evidence=line,
                    description="Sharing the host PID namespace exposes host process metadata to the container.",
                    recommendation="Use the default container PID namespace unless host PID access is explicitly required and reviewed.",
                )
            )
        if re.search(r"\b[A-Z0-9_]*(PASSWORD|TOKEN|SECRET|API_KEY|ACCESS_KEY)[A-Z0-9_]*\s*=", line, re.IGNORECASE):
            findings.append(
                Finding(
                    rule_id="config.compose-secret-in-environment",
                    category="configuration",
                    severity="medium",
                    title="Compose environment appears to inline a secret",
                    path=path,
                    line=line_number,
                    evidence=line,
                    description="Compose environment values can be committed or exposed through container metadata.",
                    recommendation="Move sensitive values to a secret manager or runtime-only environment injection and keep only placeholder names in compose files.",
                )
            )
    return findings


def _looks_like_kubernetes_manifest(path: Path) -> bool:
    lower_name = path.name.lower()
    if lower_name in K8S_FILE_NAMES:
        return True
    if path.suffix.lower() not in {".yaml", ".yml"}:
        return False
    lowered_parts = {part.lower() for part in path.parts}
    return bool({"k8s", "kubernetes", "manifests", "helm"} & lowered_parts)


def _check_kubernetes_manifest(path: Path, target: TargetConfig) -> list[Finding]:
    lines = read_text_lines(path, target.max_file_size_bytes)
    if lines is None:
        return []

    findings: list[Finding] = []
    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        lowered = line.lower()
        if lowered == "privileged: true":
            findings.append(
                Finding(
                    rule_id="config.k8s-privileged-container",
                    category="configuration",
                    severity="high",
                    title="Kubernetes container enables privileged mode",
                    path=path,
                    line=line_number,
                    evidence=line,
                    description="Privileged Kubernetes containers can obtain broad host-level access.",
                    recommendation="Remove privileged mode and grant only the specific Linux capabilities that are required.",
                )
            )
        if lowered == "allowprivilegeescalation: true":
            findings.append(
                Finding(
                    rule_id="config.k8s-allow-privilege-escalation",
                    category="configuration",
                    severity="medium",
                    title="Kubernetes container allows privilege escalation",
                    path=path,
                    line=line_number,
                    evidence=line,
                    description="Privilege escalation weakens container isolation.",
                    recommendation="Set allowPrivilegeEscalation: false unless a documented workload requirement exists.",
                )
            )
        if lowered == "hostnetwork: true":
            findings.append(
                Finding(
                    rule_id="config.k8s-host-network",
                    category="configuration",
                    severity="medium",
                    title="Kubernetes workload uses host networking",
                    path=path,
                    line=line_number,
                    evidence=line,
                    description="Host networking bypasses normal pod network isolation.",
                    recommendation="Use pod networking and explicit Services or NetworkPolicies unless host networking is required.",
                )
            )
        if lowered == "hostpath:" or lowered.endswith(" hostpath:") or lowered.endswith("- hostpath:"):
            findings.append(
                Finding(
                    rule_id="config.k8s-hostpath-volume",
                    category="configuration",
                    severity="medium",
                    title="Kubernetes workload mounts a hostPath volume",
                    path=path,
                    line=line_number,
                    evidence=line,
                    description="hostPath volumes expose host filesystem paths to a container.",
                    recommendation="Replace hostPath with scoped PersistentVolumes or document why host access is unavoidable.",
                )
            )
        if lowered == "runasnonroot: false":
            findings.append(
                Finding(
                    rule_id="config.k8s-run-as-root",
                    category="configuration",
                    severity="medium",
                    title="Kubernetes workload allows root containers",
                    path=path,
                    line=line_number,
                    evidence=line,
                    description="Containers that can run as root increase impact after compromise.",
                    recommendation="Set runAsNonRoot: true and use a non-root runtime user where possible.",
                )
            )
        if lowered == "automountserviceaccounttoken: true":
            findings.append(
                Finding(
                    rule_id="config.k8s-service-account-token",
                    category="configuration",
                    severity="low",
                    title="Kubernetes service account token is auto-mounted",
                    path=path,
                    line=line_number,
                    evidence=line,
                    description="Default service account tokens can be abused if the workload is compromised.",
                    recommendation="Set automountServiceAccountToken: false unless the workload needs Kubernetes API access.",
                )
            )
        if lowered in {"seccompprofile: unconfined", "type: unconfined"}:
            findings.append(
                Finding(
                    rule_id="config.k8s-seccomp-unconfined",
                    category="configuration",
                    severity="medium",
                    title="Kubernetes workload disables seccomp confinement",
                    path=path,
                    line=line_number,
                    evidence=line,
                    description="Unconfined seccomp profiles remove an important kernel syscall boundary.",
                    recommendation="Use RuntimeDefault seccomp profiles unless a reviewed workload exception exists.",
                )
            )
        if lowered in {"- sys_admin", "- net_admin", "add: [sys_admin]", "add: [net_admin]"} or re.search(r"\badd:\s*\[.*(sys_admin|net_admin)", lowered):
            findings.append(
                Finding(
                    rule_id="config.k8s-dangerous-capability",
                    category="configuration",
                    severity="medium",
                    title="Kubernetes workload adds broad Linux capabilities",
                    path=path,
                    line=line_number,
                    evidence=line,
                    description="Capabilities such as SYS_ADMIN and NET_ADMIN can materially weaken pod isolation.",
                    recommendation="Drop all capabilities by default and add only the minimum reviewed capability needed.",
                )
            )
        if re.match(r"^-?\s*image:", lowered) and (":latest" in lowered or re.match(r"^-?\s*image:\s*[^:@\s]+$", lowered)):
            findings.append(
                Finding(
                    rule_id="config.k8s-unpinned-image",
                    category="configuration",
                    severity="medium",
                    title="Kubernetes image is not pinned tightly",
                    path=path,
                    line=line_number,
                    evidence=line,
                    description="Floating image tags make deployments less reproducible and harder to verify.",
                    recommendation="Pin images to reviewed version tags or immutable digests.",
                )
            )
    return findings


def _check_terraform(path: Path, target: TargetConfig) -> list[Finding]:
    lines = read_text_lines(path, target.max_file_size_bytes)
    if lines is None:
        return []

    findings: list[Finding] = []
    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        lowered = line.lower()
        if re.search(r'\bacl\s*=\s*"(public-read|public-read-write|website)"', lowered):
            findings.append(
                Finding(
                    rule_id="config.terraform-public-storage",
                    category="configuration",
                    severity="high",
                    title="Terraform storage ACL is public",
                    path=path,
                    line=line_number,
                    evidence=line,
                    description="Public storage buckets can expose data unintentionally.",
                    recommendation="Use private ACLs and explicit, reviewed public access policies only when required.",
                )
            )
        if re.search(r"\b(block_public_acls|block_public_policy|ignore_public_acls|restrict_public_buckets)\s*=\s*false\b", lowered):
            findings.append(
                Finding(
                    rule_id="config.terraform-public-access-block-disabled",
                    category="configuration",
                    severity="medium",
                    title="Terraform public access block is disabled",
                    path=path,
                    line=line_number,
                    evidence=line,
                    description="Disabling public access block controls increases the chance of accidental exposure.",
                    recommendation="Keep public access block controls enabled unless a documented public bucket design exists.",
                )
            )
        if "0.0.0.0/0" in lowered and _nearby_admin_port(lines, line_number):
            findings.append(
                Finding(
                    rule_id="config.terraform-open-admin-port",
                    category="configuration",
                    severity="high",
                    title="Terraform security group opens admin access to the internet",
                    path=path,
                    line=line_number,
                    evidence=line,
                    description="SSH or RDP exposed to 0.0.0.0/0 is a common initial access path.",
                    recommendation="Restrict admin ports to VPN, bastion, or approved source CIDRs.",
                )
            )
        if re.search(r'\b(actions?|not_actions?)\s*=\s*\[\s*"\*"\s*\]', lowered) or re.search(r'\b(actions?|not_actions?)\s*=\s*"\*"', lowered):
            findings.append(
                Finding(
                    rule_id="config.terraform-wildcard-iam-action",
                    category="configuration",
                    severity="medium",
                    title="Terraform IAM policy grants wildcard actions",
                    path=path,
                    line=line_number,
                    evidence=line,
                    description="Wildcard IAM actions are difficult to review and often exceed least privilege.",
                    recommendation="Replace wildcard actions with the minimum service actions required by the workload.",
                )
            )
        if re.search(r'\b(principals?|identifiers?)\s*=\s*\[\s*"\*"\s*\]', lowered) or re.search(r'\b(principal|identifier)\s*=\s*"\*"', lowered):
            findings.append(
                Finding(
                    rule_id="config.terraform-wildcard-principal",
                    category="configuration",
                    severity="high",
                    title="Terraform IAM policy allows wildcard principal",
                    path=path,
                    line=line_number,
                    evidence=line,
                    description="Wildcard principals can expose resources to unintended identities.",
                    recommendation="Scope principals to approved accounts, roles, services, or federated identities.",
                )
            )
        if "0.0.0.0/0" in lowered and not _nearby_admin_port(lines, line_number):
            findings.append(
                Finding(
                    rule_id="config.terraform-public-ingress",
                    category="configuration",
                    severity="medium",
                    title="Terraform security group allows public ingress",
                    path=path,
                    line=line_number,
                    evidence=line,
                    description="Broad public ingress should be reviewed even when it is not an admin port.",
                    recommendation="Restrict source CIDRs to intended clients or front traffic through an approved load balancer or edge control.",
                )
            )
        if re.search(r"\b(encrypted|enable_server_side_encryption|storage_encrypted)\s*=\s*false\b", lowered):
            findings.append(
                Finding(
                    rule_id="config.terraform-unencrypted-storage",
                    category="configuration",
                    severity="medium",
                    title="Terraform storage encryption appears disabled",
                    path=path,
                    line=line_number,
                    evidence=line,
                    description="Disabling storage encryption can expose data if disks, buckets, snapshots, or backups are accessed.",
                    recommendation="Enable encryption at rest and document any service-specific exception.",
                )
            )
        if re.search(r'\b(output)\s+"[^"]*(secret|password|token|key)[^"]*"', lowered) or re.search(r"\bsensitive\s*=\s*false\b", lowered):
            findings.append(
                Finding(
                    rule_id="config.terraform-sensitive-output",
                    category="configuration",
                    severity="medium",
                    title="Terraform output may expose sensitive values",
                    path=path,
                    line=line_number,
                    evidence=line,
                    description="Terraform outputs can leak secrets into state, logs, and CI artifacts when not marked sensitive.",
                    recommendation="Mark sensitive outputs with sensitive = true and avoid outputting raw credentials.",
                )
            )
    return findings


def _nearby_admin_port(lines: list[str], line_number: int) -> bool:
    start = max(0, line_number - 8)
    end = min(len(lines), line_number + 7)
    window = "\n".join(lines[start:end]).lower()
    return bool(re.search(r"\b(from_port|to_port|port)\s*=\s*(22|3389)\b", window))


def _looks_like_github_workflow(path: Path) -> bool:
    normalized = "/".join(part.lower() for part in path.parts)
    return all(part in normalized for part in WORKFLOW_PARTS) and path.suffix.lower() in {".yml", ".yaml"}


def _check_github_workflow(path: Path, target: TargetConfig) -> list[Finding]:
    lines = read_text_lines(path, target.max_file_size_bytes)
    if lines is None:
        return []

    findings: list[Finding] = []
    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        lowered = line.lower()
        if lowered.startswith("pull_request_target:"):
            findings.append(
                Finding(
                    rule_id="config.github-pull-request-target",
                    category="configuration",
                    severity="medium",
                    title="GitHub Actions uses pull_request_target",
                    path=path,
                    line=line_number,
                    evidence=line,
                    description="pull_request_target runs with privileged repository context and is risky with untrusted PR code.",
                    recommendation="Use pull_request for untrusted code or strictly separate checkout/build steps from privileged operations.",
                )
            )
        if (lowered.startswith("run:") or lowered.startswith("- run:")) and "${{ github.event." in lowered:
            findings.append(
                Finding(
                    rule_id="config.github-untrusted-event-in-run",
                    category="configuration",
                    severity="medium",
                    title="GitHub Actions run step interpolates untrusted event data",
                    path=path,
                    line=line_number,
                    evidence=line,
                    description="GitHub event fields can contain attacker-controlled text in pull request workflows.",
                    recommendation="Pass event values through environment variables and quote/validate them before shell use.",
                )
            )
    return findings


def _check_android_manifest(path: Path, target: TargetConfig) -> list[Finding]:
    lines = read_text_lines(path, target.max_file_size_bytes)
    if lines is None:
        return []

    findings: list[Finding] = []
    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        lowered = line.lower()
        if "android:debuggable=\"true\"" in lowered:
            findings.append(
                Finding(
                    rule_id="config.android-debuggable",
                    category="configuration",
                    severity="high",
                    title="Android app is debuggable",
                    path=path,
                    line=line_number,
                    evidence=line,
                    description="Debuggable Android builds expose runtime inspection and tampering paths.",
                    recommendation="Disable android:debuggable for release builds.",
                )
            )
        if "android:allowbackup=\"true\"" in lowered:
            findings.append(
                Finding(
                    rule_id="config.android-allow-backup",
                    category="configuration",
                    severity="medium",
                    title="Android backup is allowed",
                    path=path,
                    line=line_number,
                    evidence=line,
                    description="Application backup can expose local app data if not deliberately controlled.",
                    recommendation="Disable backups for sensitive apps or define precise backup exclusion rules.",
                )
            )
        if "android:usescleartexttraffic=\"true\"" in lowered:
            findings.append(
                Finding(
                    rule_id="config.android-cleartext-traffic",
                    category="configuration",
                    severity="high",
                    title="Android cleartext traffic is allowed",
                    path=path,
                    line=line_number,
                    evidence=line,
                    description="Cleartext traffic can expose credentials and session data in transit.",
                    recommendation="Require HTTPS and use a network security config only for reviewed exceptions.",
                )
            )
        if "android:exported=\"true\"" in lowered:
            findings.append(
                Finding(
                    rule_id="config.android-exported-component",
                    category="configuration",
                    severity="medium",
                    title="Android component is exported",
                    path=path,
                    line=line_number,
                    evidence=line,
                    description="Exported components expand the mobile app attack surface.",
                    recommendation="Export only intentional entry points and protect sensitive components with permissions.",
                )
            )
    return findings


def _check_ios_plist(path: Path, target: TargetConfig) -> list[Finding]:
    lines = read_text_lines(path, target.max_file_size_bytes)
    if lines is None:
        return []

    text = "\n".join(lines)
    findings: list[Finding] = []
    for key, rule_id, severity, title, description, recommendation in (
        (
            "NSAllowsArbitraryLoads",
            "config.ios-ats-arbitrary-loads",
            "high",
            "iOS App Transport Security allows arbitrary loads",
            "Allowing arbitrary network loads weakens TLS enforcement.",
            "Keep ATS enabled and scope any exceptions to reviewed domains.",
        ),
        (
            "UIFileSharingEnabled",
            "config.ios-file-sharing-enabled",
            "medium",
            "iOS file sharing is enabled",
            "File sharing can expose app documents through Finder or iTunes-style access.",
            "Disable file sharing unless users explicitly need access to non-sensitive documents.",
        ),
        (
            "LSSupportsOpeningDocumentsInPlace",
            "config.ios-open-documents-in-place",
            "low",
            "iOS opens documents in place",
            "Opening documents in place can widen file access and data handling assumptions.",
            "Review document-provider flows and restrict sensitive file types.",
        ),
    ):
        if key in text and _plist_key_true(text, key):
            findings.append(
                Finding(
                    rule_id=rule_id,
                    category="configuration",
                    severity=severity,
                    title=title,
                    path=path,
                    line=_line_number_for_key(lines, key),
                    evidence=key,
                    description=description,
                    recommendation=recommendation,
                )
            )
    return findings


def _plist_key_true(text: str, key: str) -> bool:
    return bool(re.search(rf"<key>\s*{re.escape(key)}\s*</key>\s*<true\s*/>", text, re.IGNORECASE))


def _line_number_for_key(lines: list[str], key: str) -> int | None:
    for index, line in enumerate(lines, start=1):
        if key in line:
            return index
    return None
