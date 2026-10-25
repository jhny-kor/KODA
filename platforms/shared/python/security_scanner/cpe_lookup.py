"""NVD CVE lookup for installed desktop apps (opt-in, conservative).

OSV is ecosystem-based (PyPI/npm/...) and does not cover installed .app/.exe
software, so desktop-app CVE matching uses NVD's keyword search with best-effort
version-range matching.

WARNING: keyword + version matching is heuristic and can produce false positives
or miss CVEs. NVD also rate-limits aggressively (5 requests / 30s without an API
key). This module is therefore opt-in, processes a *bounded* set of apps, and
marks findings as medium-confidence for human verification. Failures degrade to
warnings, never exceptions.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .inventory import InstalledApp

NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# Conservative defaults to stay within NVD anonymous rate limits.
DEFAULT_MAX_APPS = 20
DEFAULT_REQUEST_DELAY_SECONDS = 6.5
DEFAULT_RESULTS_PER_PAGE = 20


def query_offline_cpe_vulnerabilities(
    cpes: Iterable[str], *, nvd_source: Path | None, cisa_source: Path | None = None,
) -> tuple[list[dict], list[str], dict]:
    """Evaluate reviewed CPEs against local NVD; never resolve names online.

    Return matched NVD/KEV records with CPE evidence, warnings, and explicit
    coverage status. No results must not be interpreted as an absence of risk.
    """
    from .offline_cpe import CONTRACT_VERSION, evaluate, prepare_inventory, product_key
    from .offline_vuln_data import load_offline_cpe_data
    values = tuple(dict.fromkeys(cpes))
    valid, invalid = [], 0
    for value in values:
        try:
            product_key(value)
            valid.append(value)
        except (TypeError, ValueError):
            invalid += 1
    summary = {"version": CONTRACT_VERSION, "status": "not_evaluated", "inputCpes": len(values),
               "invalidCpes": invalid, "evaluatedCves": 0, "unknownCves": 0, "unresolved": [], "inventoryComplete": False}
    if not valid:
        return [], ["No concrete CPE 2.3 identities supplied for offline applicability"], summary
    data = load_offline_cpe_data(nvd_source, cisa_source, valid)
    summary.update(status="unavailable" if data.fatal or not data.loaded("nvd") else "completed",
                   dataAsOf=data.data_as_of, sources=[source.payload() for source in data.sources])
    if data.fatal or not data.loaded("nvd"):
        return [], list(data.warnings), summary
    from .offline_cpe import candidate_index
    index_issues = {}
    index = candidate_index(data.nvd, issues=index_issues)
    summary["indexIncompleteCves"] = len(index_issues)
    products = {product_key(value) for value in valid}
    summary["unmatchedProducts"] = len(products.difference(index))
    findings = []
    inventory = prepare_inventory(valid)
    for cve_id, record in sorted(data.nvd.items()):
        if str(record.get("vulnStatus", "")).lower() == "rejected":
            continue
        summary["evaluatedCves"] += 1
        if cve_id in index_issues:
            summary["unknownCves"] += 1
            if len(summary["unresolved"]) < 100:
                summary["unresolved"].append({"id": cve_id, "reason": index_issues[cve_id]})
            continue
        decision = evaluate(record.get("configurations"), inventory)
        if decision.status == "unknown":
            summary["unknownCves"] += 1
            if len(summary["unresolved"]) < 100:
                summary["unresolved"].append({"id": cve_id, "reason": decision.reason})
        if decision.status == "affected":
            findings.append({"cve": cve_id, "matched_cpes": list(decision.matched_cpes),
                             "cvss": _primary_cvss(record), "description": _english_description(record),
                             "nvd": record, "cisa_kev": data.cisa_kev.get(cve_id, {}),
                             "cpeEvidence": decision.payload()})
    if invalid or summary["unknownCves"] or summary["unmatchedProducts"] or not summary["evaluatedCves"]:
        summary["status"] = "incomplete"
    summary["scope"] = "Only supplied CPE identities and imported NVD conditions; no-match is not a product safety certification"
    return findings, list(data.warnings), summary


@dataclass(frozen=True)
class AppVulnerability:
    app: InstalledApp
    cve: str
    cvss: float | None
    description: str
    url: str


def query_app_vulnerabilities(
    apps: list[InstalledApp],
    *,
    api_key: str | None = None,
    max_apps: int = DEFAULT_MAX_APPS,
    timeout_seconds: float = 20.0,
    request_delay_seconds: float = DEFAULT_REQUEST_DELAY_SECONDS,
) -> tuple[list[AppVulnerability], list[str]]:
    """Look up NVD CVEs for up to ``max_apps`` versioned apps."""

    targets = [app for app in apps if app.version][:max_apps]
    warnings: list[str] = []
    if len(apps) > len(targets):
        warnings.append(
            f"CVE lookup limited to {len(targets)} versioned app(s) of {len(apps)} (NVD rate limits)."
        )

    findings: list[AppVulnerability] = []
    for index, app in enumerate(targets):
        if index:
            time.sleep(request_delay_seconds)
        try:
            payload = _query_nvd(app.name, api_key, timeout_seconds)
        except urllib.error.HTTPError as exc:
            warnings.append(f"NVD query failed for {app.name}: HTTP {exc.code}")
            continue
        except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
            warnings.append(f"NVD query failed for {app.name}: {exc}")
            continue
        findings.extend(_match_versioned_cves(app, payload))
    return findings, warnings


def _query_nvd(keyword: str, api_key: str | None, timeout_seconds: float) -> dict:
    query = urllib.parse.urlencode(
        {"keywordSearch": keyword, "resultsPerPage": DEFAULT_RESULTS_PER_PAGE}
    )
    headers = {"User-Agent": "koda-local-security-scanner"}
    if api_key:
        headers["apiKey"] = api_key
    request = urllib.request.Request(f"{NVD_CVE_URL}?{query}", headers=headers)
    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
        payload = json.loads(response.read().decode("utf-8"))
    return payload if isinstance(payload, dict) else {}


def _match_versioned_cves(app: InstalledApp, payload: dict) -> list[AppVulnerability]:
    out: list[AppVulnerability] = []
    for item in payload.get("vulnerabilities", []) or []:
        cve = item.get("cve") if isinstance(item, dict) else None
        if not isinstance(cve, dict):
            continue
        cve_id = str(cve.get("id", "")).strip()
        if not cve_id:
            continue
        if not _version_applies(app.version, cve):
            continue
        out.append(
            AppVulnerability(
                app=app,
                cve=cve_id,
                cvss=_primary_cvss(cve),
                description=_english_description(cve),
                url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            )
        )
    return out


def _version_applies(version: str, cve: dict) -> bool:
    """Best-effort: keep the CVE only if a CPE match plausibly covers ``version``.

    Conservative: when no version-bounded CPE node is present we DROP the CVE to
    avoid flooding every keyword hit. Exact-version and bounded ranges are kept.
    """

    parsed = _parse_version(version)
    for node in _cpe_matches(cve):
        start_inc = node.get("versionStartIncluding")
        start_exc = node.get("versionStartExcluding")
        end_inc = node.get("versionEndIncluding")
        end_exc = node.get("versionEndExcluding")
        criteria = str(node.get("criteria", ""))
        exact = _cpe_exact_version(criteria)

        if not any([start_inc, start_exc, end_inc, end_exc, exact]):
            continue

        if parsed is None:
            continue
        if exact is not None:
            if parsed == exact:
                return True
            continue
        if start_inc and parsed < _parse_version(start_inc):
            continue
        if start_exc and parsed <= _parse_version(start_exc):
            continue
        if end_inc and parsed > _parse_version(end_inc):
            continue
        if end_exc and parsed >= _parse_version(end_exc):
            continue
        return True
    # Conservative: no bounded CPE node matched this version (or none were present).
    return False


def _cpe_matches(cve: dict):
    for config in cve.get("configurations", []) or []:
        for node in config.get("nodes", []) or []:
            for match in node.get("cpeMatch", []) or []:
                if isinstance(match, dict):
                    yield match


def _cpe_exact_version(criteria: str) -> tuple | None:
    # cpe:2.3:a:vendor:product:version:...
    parts = criteria.split(":")
    if len(parts) > 5:
        version = parts[5]
        if version and version not in {"*", "-"}:
            return _parse_version(version)
    return None


def _parse_version(value) -> tuple | None:
    if isinstance(value, tuple):
        return value
    if not value:
        return None
    nums: list[int] = []
    for chunk in str(value).split("."):
        digits = "".join(ch for ch in chunk if ch.isdigit())
        if digits == "":
            break
        nums.append(int(digits))
    return tuple(nums) if nums else None


def _primary_cvss(cve: dict) -> float | None:
    metrics = cve.get("metrics", {}) if isinstance(cve.get("metrics"), dict) else {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        for entry in entries:
            data = entry.get("cvssData", {}) if isinstance(entry, dict) else {}
            score = data.get("baseScore")
            if isinstance(score, (int, float)):
                return float(score)
    return None


def _english_description(cve: dict) -> str:
    for item in cve.get("descriptions", []) or []:
        if isinstance(item, str):
            return item.strip()
        if isinstance(item, dict) and item.get("lang") == "en":
            return str(item.get("value", "")).strip()
    return ""
