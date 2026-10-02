# KODA Documentation

This is the English documentation index. The [Korean index](README.md) contains
the Korean guides and Korean-language links. Within this index, navigation stays
on English documents; use the language link above only when intentionally
switching languages.

## Documentation baseline — 2026-10-02

The [current implementation and verification snapshot](current-status.en.md)
distinguishes committed source, unpublished local development work, and released
binaries. Development-only commands and old validation records are not evidence
that a downloaded installer or the Mac App Store app includes those changes.

## Quick starts

| Goal | Guide |
| --- | --- |
| Run the shared scanner and configure reports | [CLI and local usage](usage.md) |
| Review macOS local AI development | [Local AI development guide](macos-local-ai.md) |
| Install the macOS app | [macOS install](install/macos.md) |
| Install or build the Linux package | [Linux install and application guide](install/linux.md) |
| Deploy KODA with KODA SBOM Tracker | [Combined air-gapped Linux suite](../platforms/linux/suite/README.ko.md) |
| Diagnose a combined air-gapped installation | [Korean troubleshooting runbook](../platforms/linux/suite/TROUBLESHOOTING.ko.md) |
| Install or build the Windows package | [Windows install](install/windows.md) |
| Deliver an offline Java scanner | [Offline delivery overview](install/offline-delivery.en.md) |
| Refresh Windows vulnerability data | [Vulnerability data refresh](install/vuln-data-refresh.en.md) |
| Scan deployed JAR/WAR/EAR files | [Java SBOM and vulnerability runbook](security/java-sbom-vulnerability-scan.en.md) |
| Run an authorized 21-control web audit | [Profile-driven web audit](security/WEB_AUDIT.md) |

## Installation and delivery

- [macOS install](install/macos.md)
- [Linux install and operation](install/linux.md)
- [Windows install](install/windows.md)
- [Offline delivery overview](install/offline-delivery.en.md)
- [Vulnerability data refresh](install/vuln-data-refresh.en.md)
- [Linux Docker delivery](../platforms/linux/docker/README.en.md)
- [Linux offline distribution](../platforms/linux/README-offline.md)
- [Combined KODA + KODA SBOM Tracker suite](../platforms/linux/suite/README.ko.md)
- [Combined suite troubleshooting runbook](../platforms/linux/suite/TROUBLESHOOTING.ko.md)
- [macOS packaging](../platforms/macos/packaging/README.md)
- [Windows installer packaging](../platforms/windows/README.md)

## Security integrations

- [Java SBOM and vulnerability scan](security/java-sbom-vulnerability-scan.en.md)
- [Pre-commit security gate](security/PRE_COMMIT.md)
- [GitHub repository security checklist](security/GITHUB_REPOSITORY_SECURITY.md)
- [Dependency-Track SBOM upload](security/DEPENDENCY_TRACK.md)
- [OWASP ZAP baseline](security/ZAP_BASELINE.md)
- [Profile-driven 21-control web audit](security/WEB_AUDIT.md)
- [CycloneDX VEX tracking](security/VEX.md)
- [SLSA and Sigstore release guardrails](security/SLSA_SIGSTORE.md)
- [NIST SSDF workflow](security/NIST_SSDF_WORKFLOW.md)
- [CISA Secure by Design plan](security/SECURE_BY_DESIGN.md)

## Reports and design references

- [Report contract](report-contract.md)
- [Security dashboard research](security-dashboard-research.md)
- [SW development security 49 profile](standards/sw-development-security-49.en.md)
- [Authoritative standard mapping audit](standards/authoritative-mapping-audit.en.md)

Planning material is maintained in Korean in the [Korean documentation index](README.md).
