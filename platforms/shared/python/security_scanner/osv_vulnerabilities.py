from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path

from .models import DependencyComponent, Finding
from .vuln_intel import extract_cve_ids, prioritize_severity, query_vulnerability_intel, summarize_intel, VulnerabilityIntel


OSV_QUERY_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULNERABILITY_URL = "https://osv.dev/vulnerability"
OSV_BATCH_SIZE = 100


def query_osv_findings(
    components: tuple[DependencyComponent, ...],
    *,
    timeout_seconds: float = 12.0,
    enable_vuln_intel: bool = False,
) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    warnings: list[str] = []
    seen: set[tuple[str, str, str, str, str]] = set()
    pending: list[tuple[DependencyComponent, dict[str, object], tuple[str, ...]]] = []
    cve_ids: set[str] = set()

    for batch in _batches(components, OSV_BATCH_SIZE):
        try:
            response = _post_querybatch(batch, timeout_seconds)
        except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
            warnings.append(f"OSV query failed: {exc}")
            continue

        results = response.get("results", [])
        if not isinstance(results, list):
            warnings.append("OSV query returned an unexpected response shape.")
            continue

        for component, result in zip(batch, results, strict=False):
            if not isinstance(result, dict):
                continue
            if result.get("next_page_token"):
                warnings.append(f"OSV result for {component.name}@{component.version} was paginated; showing the first page only.")
            vulns = result.get("vulns", [])
            if not isinstance(vulns, list):
                continue
            for vuln in vulns:
                if not isinstance(vuln, dict):
                    continue
                vuln_id = str(vuln.get("id", "")).strip()
                if not vuln_id:
                    continue
                key = (*component.key(), vuln_id)
                if key in seen:
                    continue
                seen.add(key)
                vuln_cves = _cve_ids_from_vulnerability(vuln)
                cve_ids.update(vuln_cves)
                pending.append((component, vuln, vuln_cves))
    intel: dict[str, VulnerabilityIntel] = {}
    if enable_vuln_intel and cve_ids:
        intel, intel_warnings = query_vulnerability_intel(cve_ids, timeout_seconds=timeout_seconds)
        warnings.extend(intel_warnings)
    for component, vuln, vuln_cves in pending:
        findings.append(_finding_from_vulnerability(component, vuln, intel=intel, cve_ids=vuln_cves))
    return findings, warnings


def _post_querybatch(components: tuple[DependencyComponent, ...], timeout_seconds: float) -> dict[str, object]:
    body = json.dumps(
        {
            "queries": [
                {
                    "package": {
                        "ecosystem": component.ecosystem,
                        "name": component.name,
                    },
                    "version": component.version,
                }
                for component in components
            ]
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        OSV_QUERY_BATCH_URL,
        data=body,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "koda-local-security-scanner",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
        return json.loads(response.read().decode("utf-8"))


def _finding_from_vulnerability(
    component: DependencyComponent,
    vulnerability: dict[str, object],
    *,
    intel: dict[str, VulnerabilityIntel] | None = None,
    cve_ids: tuple[str, ...] | None = None,
) -> Finding:
    vuln_id = str(vulnerability.get("id", "")).strip()
    url = f"{OSV_VULNERABILITY_URL}/{vuln_id}"
    summary = str(vulnerability.get("summary", "")).strip()
    aliases = [str(alias) for alias in vulnerability.get("aliases", []) if str(alias).strip()] if isinstance(vulnerability.get("aliases"), list) else []
    alias_text = f" ({', '.join(aliases[:3])})" if aliases else ""
    intel = intel or {}
    cve_ids = cve_ids if cve_ids is not None else _cve_ids_from_vulnerability(vulnerability)
    intel_summary = summarize_intel(cve_ids, intel)
    intel_evidence = f" | {intel_summary}" if intel_summary else ""
    base_severity = _severity_from_vulnerability(vulnerability)
    location = Path(component.path)
    return Finding(
        rule_id="dependency.osv-known-vulnerability",
        category="dependencies",
        severity=prioritize_severity(base_severity, cve_ids, intel),
        title=summary[:120] if summary else "Known vulnerable dependency reported by OSV",
        path=location,
        target=component.target,
        line=component.line,
        evidence=f"{component.ecosystem} {component.name}@{component.version}: {vuln_id}{alias_text}{intel_evidence}",
        description=_description_from_vulnerability(vulnerability),
        recommendation=_recommendation(url, cve_ids, intel),
    )


def _cve_ids_from_vulnerability(vulnerability: dict[str, object]) -> tuple[str, ...]:
    values: list[str] = [str(vulnerability.get("id", ""))]
    aliases = vulnerability.get("aliases", [])
    if isinstance(aliases, list):
        values.extend(str(alias) for alias in aliases)
    return extract_cve_ids(values)


def _recommendation(url: str, cve_ids: tuple[str, ...], intel: dict[str, VulnerabilityIntel]) -> str:
    prioritized = [intel[cve] for cve in cve_ids if cve in intel and intel[cve].priority_label]
    if prioritized:
        labels = ", ".join(f"{item.cve} {item.priority_label}" for item in prioritized[:3])
        return f"Prioritize this dependency because {labels}. Review {url}, then upgrade, patch, replace, or document a compensating control."
    return f"Review {url}, then upgrade, patch, replace, or document a compensating control."


def _description_from_vulnerability(vulnerability: dict[str, object]) -> str:
    details = str(vulnerability.get("details", "")).strip()
    summary = str(vulnerability.get("summary", "")).strip()
    published = str(vulnerability.get("published", "")).strip()
    modified = str(vulnerability.get("modified", "")).strip()
    lead = summary or "OSV reports a known vulnerability for this exact dependency version."
    dates = ", ".join(item for item in (f"published {published}" if published else "", f"modified {modified}" if modified else "") if item)
    if dates:
        lead = f"{lead} ({dates})."
    if details and details != summary:
        return f"{lead} {details[:300]}"
    return lead


def _severity_from_vulnerability(vulnerability: dict[str, object]) -> str:
    for value in _severity_candidates(vulnerability):
        mapped = _map_severity(value)
        if mapped:
            return mapped
    score = _cvss_score(vulnerability)
    if score is not None:
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        if score > 0:
            return "low"
    return "high"


def _severity_candidates(vulnerability: dict[str, object]):
    database_specific = vulnerability.get("database_specific")
    if isinstance(database_specific, dict):
        yield str(database_specific.get("severity", ""))
    affected = vulnerability.get("affected")
    if isinstance(affected, list):
        for item in affected:
            if not isinstance(item, dict):
                continue
            ecosystem_specific = item.get("ecosystem_specific")
            if isinstance(ecosystem_specific, dict):
                yield str(ecosystem_specific.get("severity", ""))


def _map_severity(value: str) -> str | None:
    normalized = value.strip().lower()
    if normalized in {"critical", "crit"}:
        return "critical"
    if normalized in {"high", "important"}:
        return "high"
    if normalized in {"medium", "moderate"}:
        return "medium"
    if normalized in {"low", "minor"}:
        return "low"
    return None


def _cvss_score(vulnerability: dict[str, object]) -> float | None:
    severities = vulnerability.get("severity")
    if not isinstance(severities, list):
        return None
    for item in severities:
        if not isinstance(item, dict):
            continue
        score = str(item.get("score", ""))
        for token in score.replace("/", " ").split():
            if token.startswith("CVSS:"):
                continue
            try:
                numeric = float(token)
            except ValueError:
                continue
            if 0 <= numeric <= 10:
                return numeric
    return None


def _batches(components: tuple[DependencyComponent, ...], size: int):
    for index in range(0, len(components), size):
        yield components[index : index + size]
