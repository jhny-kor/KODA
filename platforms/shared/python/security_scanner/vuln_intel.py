from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Iterable


CISA_KEV_JSON_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
FIRST_EPSS_URL = "https://api.first.org/data/v1/epss"
EPSS_QUERY_MAX_CHARS = 1800
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


@dataclass(frozen=True)
class VulnerabilityIntel:
    cve: str
    kev: bool = False
    kev_due_date: str = ""
    kev_vendor_project: str = ""
    kev_product: str = ""
    kev_ransomware: str = ""
    epss: float | None = None
    percentile: float | None = None
    epss_date: str = ""

    @property
    def priority_label(self) -> str:
        if self.kev:
            return "CISA KEV"
        if self.epss is not None and self.epss >= 0.5:
            return "high EPSS"
        if self.percentile is not None and self.percentile >= 0.95:
            return "top EPSS percentile"
        return ""


def extract_cve_ids(value: str | Iterable[str]) -> tuple[str, ...]:
    text = " ".join(value) if not isinstance(value, str) else value
    return tuple(sorted({match.upper() for match in CVE_RE.findall(text)}))


def query_vulnerability_intel(
    cve_ids: Iterable[str],
    *,
    timeout_seconds: float = 12.0,
) -> tuple[dict[str, VulnerabilityIntel], list[str]]:
    requested = tuple(sorted({cve.upper() for cve in cve_ids if CVE_RE.fullmatch(cve.upper())}))
    if not requested:
        return {}, []

    warnings: list[str] = []
    intel: dict[str, VulnerabilityIntel] = {cve: VulnerabilityIntel(cve=cve) for cve in requested}

    try:
        for cve, kev_entry in _fetch_kev(timeout_seconds).items():
            if cve not in intel:
                continue
            intel[cve] = _merge_kev(intel[cve], kev_entry)
    except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
        warnings.append(f"CISA KEV query failed: {exc}")

    try:
        for cve, epss_entry in _fetch_epss(requested, timeout_seconds).items():
            intel[cve] = _merge_epss(intel.get(cve, VulnerabilityIntel(cve=cve)), epss_entry)
    except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
        warnings.append(f"FIRST EPSS query failed: {exc}")

    return intel, warnings


def summarize_intel(cve_ids: Iterable[str], intel: dict[str, VulnerabilityIntel]) -> str:
    parts: list[str] = []
    for cve in cve_ids:
        item = intel.get(cve.upper())
        if not item:
            continue
        if item.kev:
            due = f", due {item.kev_due_date}" if item.kev_due_date else ""
            ransomware = f", ransomware {item.kev_ransomware}" if item.kev_ransomware else ""
            parts.append(f"{item.cve}: CISA KEV{due}{ransomware}")
        elif item.epss is not None:
            epss = f"{item.epss:.1%}"
            percentile = f", percentile {item.percentile:.1%}" if item.percentile is not None else ""
            date = f", {item.epss_date}" if item.epss_date else ""
            parts.append(f"{item.cve}: EPSS {epss}{percentile}{date}")
    return "; ".join(parts)


def prioritize_severity(base: str, cve_ids: Iterable[str], intel: dict[str, VulnerabilityIntel]) -> str:
    if any(intel.get(cve.upper()) and intel[cve.upper()].kev for cve in cve_ids):
        return "critical"
    if any(
        item
        and (
            (item.epss is not None and item.epss >= 0.5)
            or (item.percentile is not None and item.percentile >= 0.95)
        )
        for cve in cve_ids
        for item in [intel.get(cve.upper())]
    ):
        return _max_severity(base, "high")
    return base


def _fetch_kev(timeout_seconds: float) -> dict[str, dict[str, object]]:
    request = urllib.request.Request(
        CISA_KEV_JSON_URL,
        headers={"User-Agent": "koda-local-security-scanner"},
    )
    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
        payload = json.loads(response.read().decode("utf-8"))

    vulnerabilities = payload.get("vulnerabilities", []) if isinstance(payload, dict) else []
    output: dict[str, dict[str, object]] = {}
    if not isinstance(vulnerabilities, list):
        return output
    for item in vulnerabilities:
        if not isinstance(item, dict):
            continue
        cve = str(item.get("cveID", "")).upper()
        if CVE_RE.fullmatch(cve):
            output[cve] = item
    return output


def _fetch_epss(cve_ids: tuple[str, ...], timeout_seconds: float) -> dict[str, dict[str, object]]:
    output: dict[str, dict[str, object]] = {}
    for chunk in _cve_chunks(cve_ids):
        url = f"{FIRST_EPSS_URL}?{urllib.parse.urlencode({'cve': ','.join(chunk)})}"
        request = urllib.request.Request(url, headers={"User-Agent": "koda-local-security-scanner"})
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
            payload = json.loads(response.read().decode("utf-8"))
        data = payload.get("data", []) if isinstance(payload, dict) else []
        if not isinstance(data, list):
            continue
        for item in data:
            if not isinstance(item, dict):
                continue
            cve = str(item.get("cve", "")).upper()
            if CVE_RE.fullmatch(cve):
                output[cve] = item
    return output


def _cve_chunks(cve_ids: tuple[str, ...]):
    chunk: list[str] = []
    current_length = 0
    for cve in cve_ids:
        addition = len(cve) + (1 if chunk else 0)
        if chunk and current_length + addition > EPSS_QUERY_MAX_CHARS:
            yield tuple(chunk)
            chunk = []
            current_length = 0
        chunk.append(cve)
        current_length += addition
    if chunk:
        yield tuple(chunk)


def _merge_kev(item: VulnerabilityIntel, kev_entry: dict[str, object]) -> VulnerabilityIntel:
    return VulnerabilityIntel(
        cve=item.cve,
        kev=True,
        kev_due_date=str(kev_entry.get("dueDate", "")).strip(),
        kev_vendor_project=str(kev_entry.get("vendorProject", "")).strip(),
        kev_product=str(kev_entry.get("product", "")).strip(),
        kev_ransomware=str(kev_entry.get("knownRansomwareCampaignUse", "")).strip(),
        epss=item.epss,
        percentile=item.percentile,
        epss_date=item.epss_date,
    )


def _merge_epss(item: VulnerabilityIntel, epss_entry: dict[str, object]) -> VulnerabilityIntel:
    return VulnerabilityIntel(
        cve=item.cve,
        kev=item.kev,
        kev_due_date=item.kev_due_date,
        kev_vendor_project=item.kev_vendor_project,
        kev_product=item.kev_product,
        kev_ransomware=item.kev_ransomware,
        epss=_float_or_none(epss_entry.get("epss")),
        percentile=_float_or_none(epss_entry.get("percentile")),
        epss_date=str(epss_entry.get("date", "")).strip(),
    )


def _float_or_none(value: object) -> float | None:
    try:
        return float(str(value))
    except (TypeError, ValueError):
        return None


def _max_severity(left: str, right: str) -> str:
    rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    return left if rank.get(left, 0) >= rank.get(right, 0) else right
