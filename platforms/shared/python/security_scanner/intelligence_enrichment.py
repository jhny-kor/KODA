"""Join approved local intelligence to scan evidence without changing verdicts."""
from __future__ import annotations

import copy
import hashlib
import html
import json
import os
import re
from datetime import date, datetime, timezone
from pathlib import Path
from .data_release import approved_data_read


@approved_data_read
def load_document(path=None, *, at=None):
    from .data_release import intelligence_path, managed_data_required
    try:
        target = Path(path) if path and not managed_data_required() else intelligence_path()
        if target is None:
            return None, "missing", ""
        from .offline_intelligence import MAX_FILE_BYTES, load_intelligence
        if target.stat().st_size > MAX_FILE_BYTES:
            raise ValueError("보강 데이터 인덱스 크기 한도를 초과했습니다")
        before = hashlib.sha256(target.read_bytes()).hexdigest()
        document = load_intelligence(target.parent, target.name, at=at)
        after = hashlib.sha256(target.read_bytes()).hexdigest()
        if before != after:
            raise ValueError("검증 도중 보강 데이터가 변경되었습니다")
        document["snapshotSha256"] = before
        return document, "available", ""
    except (OSError, ValueError, TypeError, KeyError, OverflowError) as exc:
        return None, "invalid", str(exc)


def _purl_base(value):
    # Preserve namespace/type; avoid joining similarly named packages across ecosystems.
    return str(value or "").split("?", 1)[0].split("#", 1)[0].rsplit("@", 1)[0]


def _source(source, at):
    result = dict(source)
    try:
        age = (at.date() - date.fromisoformat(source["dataDate"])).days
        limit = int(source.get("maxAgeDays", 7))
        result.update(ageDays=age, status="fresh" if 0 <= age <= limit else "stale")
    except (ValueError, TypeError, KeyError):
        result["status"] = "unknown"
    return result


def records(document, kind, *, at=None):
    at = at or datetime.now(timezone.utc)
    dataset = (document or {}).get("datasets", {}).get(kind, {})
    sources = {item["id"]: _source(item, at) for item in dataset.get("sources", [])}
    return [(item, sources.get(item.get("sourceId"), {"status": "unknown"})) for item in dataset.get("records", [])]


def snapshot_summary(document=None, *, at=None):
    if document is None:
        document, status, error = load_document(at=at)
    else:
        status, error = "available", ""
    return {"status": status, "error": error, "snapshotSha256": (document or {}).get("snapshotSha256"),
            "datasets": {kind: {"recordCount": len(dataset.get("records", [])),
                                 "sources": [_source(source, at or datetime.now(timezone.utc)) for source in dataset.get("sources", [])]}
                         for kind, dataset in (document or {}).get("datasets", {}).items()}}


def _cves(item):
    values = [item.get(key) for key in ("cve", "id", "canonicalId", "vulnerability_id", "cve_ids", "vulnerability_ids", "aliases")]
    return set(re.findall(r"\bCVE-\d{4}-\d{4,}\b", json.dumps(values), re.I))


def _licenses(item):
    value = item.get("licenses", item.get("license", []))
    if not isinstance(value, list):
        value = [value]
    result = set()
    for entry in value:
        if isinstance(entry, str):
            result.update(re.findall(r"[A-Za-z0-9][A-Za-z0-9.+-]*", entry))
        elif isinstance(entry, dict):
            license_value = entry.get("license", entry)
            if isinstance(license_value, dict) and license_value.get("id"):
                result.add(license_value["id"])
    return result - {"AND", "OR", "WITH", "NOASSERTION", "NONE"}


def _cwe_ids(item):
    values = [item.get(key) for key in ("cwe_ids", "cwes", "weaknesses", "nvd", "problemTypes")]
    ids = set(re.findall(r"\bCWE-\d+\b", json.dumps(values)))
    for value in item.get("cwes", []) if isinstance(item.get("cwes"), list) else []:
        if isinstance(value, int) and not isinstance(value, bool):
            ids.add(f"CWE-{value}")
    return ids


@approved_data_read
def enrich_records(items, path=None, *, at=None, document=None, components=None):
    """Persist matching evidence. Never suppress a finding or derive severity."""
    at = at or datetime.now(timezone.utc)
    result = copy.deepcopy(items)
    from .data_release import managed_data_required
    if document is None or managed_data_required():
        document, status, error = load_document(path, at=at)
    else:
        status, error = "available", ""
    indexed = {kind: records(document, kind, at=at) for kind in (document or {}).get("datasets", {})}
    lookups = {}
    for kind, values in indexed.items():
        lookup = {}
        for index, (row, _) in enumerate(values):
            keys = [row.get("cve"), row.get("purl"), row.get("cpe"), row.get("cpeName"), row.get("criteria"), row.get("id")]
            if kind == "cwe":
                keys.append(f"CWE-{row.get('id')}")
            keys.extend(row.get("cves", []))
            if kind == "lifecycle":
                keys.append(f"{row.get('product')}/{row.get('cycle')}")
                keys.extend(value.get("id") for value in row.get("identifiers", []) if value.get("type") == "purl")
            if kind == "cpe-match":
                keys.extend(value.get("cpeName") for value in row.get("matches", []))
            for key in keys:
                if key:
                    lookup.setdefault(key, set()).add(index)
        lookups[kind] = lookup

    def enrich(item, parent=None):
        identity = {**(parent or {}), **item}
        identity.pop("offline_intelligence", None)
        cves = {value.upper() for value in _cves(identity)}
        purl = str(identity.get("purl") or identity.get("component_purl") or "")
        cpes = {str(identity.get("cpe") or ""), *(identity.get("cpes") or []), *(identity.get("matched_cpes") or [])}
        cpes.discard("")
        keys = {purl, _purl_base(purl), *cpes, *cves, *_licenses(identity),
                *_cwe_ids(identity),
                f"{identity.get('lifecycleProduct')}/{identity.get('lifecycleCycle')}"}
        evidence = []
        for kind, values in indexed.items():
            candidates = set().union(*(lookups[kind].get(key, set()) for key in keys))
            for index in sorted(candidates):
                row, source = values[index]
                match = False
                if kind in {"vulnrichment", "epss"}:
                    match = row.get("cve") in cves
                elif kind in {"csaf", "vex"}:
                    # A vendor statement with no exact product identity remains unmatched.
                    match = row.get("cve") in cves and bool((purl and row.get("purl") == purl) or (cpes and row.get("cpe") in cpes))
                elif kind == "lifecycle":
                    ids = {identifier.get("id") for identifier in row.get("identifiers", []) if identifier.get("type") == "purl"}
                    explicit = row.get("product") == identity.get("lifecycleProduct") and row.get("cycle") == identity.get("lifecycleCycle")
                    version = str(identity.get("version") or identity.get("installed_version") or "")
                    cycle = str(row.get("cycle") or "")
                    match = explicit or bool(purl and _purl_base(purl) in ids and cycle and (version == cycle or version.startswith(cycle + ".")))
                elif kind == "package-metadata":
                    match = bool(purl and row.get("purl") == purl)
                elif kind == "cpe-dictionary":
                    match = row.get("cpeName") in cpes
                elif kind == "cpe-match":
                    match = row.get("criteria") in cpes or any(value.get("cpeName") in cpes for value in row.get("matches", []))
                elif kind == "cwe":
                    match = f"CWE-{row.get('id')}" in _cwe_ids(identity)
                elif kind == "spdx":
                    match = row.get("id") in _licenses(identity)
                elif kind == "ubuntu-oval":
                    # OVAL is a logical expression, not a CVE-to-package assertion.
                    match = bool(cves.intersection(row.get("cves", [])))
                if match:
                    entry = {"kind": kind, "record": copy.deepcopy(row), "source": source, "use": "review_evidence"}
                    if kind == "ubuntu-oval":
                        from .ubuntu_oval import evaluate_definition
                        entry["evaluation"] = evaluate_definition(row, components if components is not None else [identity])
                        entry["assessment"] = entry["evaluation"]["status"]
                    evidence.append(entry)
        item["offline_intelligence"] = {"status": status, "snapshotSha256": (document or {}).get("snapshotSha256"), "evidence": evidence}
        if error:
            item["offline_intelligence"]["error"] = error
        # Unified daily EPSS is usable even when no separate CSV was packaged.
        # A malformed explicit CSV is still reported as invalid, never hidden.
        epss = [entry for entry in evidence if entry["kind"] == "epss"]
        if epss and item.get("epss_status", "missing") == "missing":
            latest = {}
            for entry in epss:
                row = entry["record"]
                if row["cve"] not in latest or row["date"] > latest[row["cve"]]["record"]["date"]:
                    latest[row["cve"]] = entry
            selected = max(latest.values(), key=lambda entry: entry["record"]["epss"])
            row, source = selected["record"], selected["source"]
            try:
                policy_age = int(os.environ.get("KODA_EPSS_MAX_AGE_DAYS", "7"))
                eligible = source["status"] == "fresh" and 0 <= policy_age <= 365 and 0 <= (at.date() - date.fromisoformat(row["date"])).days <= policy_age
            except (ValueError, TypeError):
                eligible = False
            epss_status = "stale" if source["status"] == "fresh" and not eligible else source["status"]
            item.update(epss_score=row["epss"], epss_percentile=row["percentile"], epss_date=row["date"],
                        epss_cve=row["cve"], epss_status=epss_status, epss_policy_eligible=eligible,
                        epss_source={**source, "source_kind": "offline_intelligence", "model_version": row["modelVersion"]},
                        epss_records=[{"cve": entry["record"]["cve"], "score": entry["record"]["epss"],
                                       "percentile": entry["record"]["percentile"], "date": entry["record"]["date"]} for entry in latest.values()])
        suggestions = [entry for entry in evidence if entry["kind"] == "vulnrichment" and entry["source"]["status"] == "fresh"]
        if suggestions:
            item["offline_intelligence"]["ssvcSuggestions"] = [{"cve": e["record"]["cve"], "exploitation": e["record"].get("exploitation"), "automatable": e["record"].get("automatable"), "technicalImpact": e["record"].get("technicalImpact"), "ssvcVersion": e["record"].get("ssvcVersion"), "requiresReview": True} for e in suggestions]
        for child in item.get("advisories", []):
            if isinstance(child, dict):
                enrich(child, identity)
    for item in result:
        if isinstance(item, dict):
            enrich(item)
    return result


def evidence_text(item):
    intel = item.get("offline_intelligence", {})
    if not intel:
        return ""
    parts = ["오프라인 보강 자료: " + str(intel.get("status", "missing"))]
    for entry in intel.get("evidence", []):
        row, source = entry["record"], entry["source"]
        summary = {key: row[key] for key in ("cve", "exploitation", "automatable", "technicalImpact", "product", "cycle", "eolDate", "isEol", "latestVersion", "status", "remediation", "id", "name", "deprecated") if key in row}
        parts.append(f"{entry['kind']} [{source.get('dataDate', '?')} / {source.get('status', 'unknown')}]: " + json.dumps(summary, ensure_ascii=False)
                     + f"\n출처: {source.get('sourceUrl', '?')} · SHA-256: {source.get('sha256', '?')}")
    return "\n".join(parts)


def evidence_html(item):
    value = evidence_text(item)
    return '<details class="offline-intelligence"><summary>오프라인 보강 근거</summary><pre style="white-space:pre-wrap">' + html.escape(value) + '</pre></details>' if value else ""
