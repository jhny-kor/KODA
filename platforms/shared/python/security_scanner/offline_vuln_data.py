from __future__ import annotations

import gzip
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from .data_release import approved_data_read
from .streaming_nvd import read_json_sections


@dataclass(frozen=True, slots=True)
class DataSource:
    path: str
    sha256: str
    status: str
    metadata: dict[str, object]

    def payload(self) -> dict[str, object]:
        return {"path": self.path, "sha256": self.sha256, "status": self.status, **self.metadata}


@dataclass(frozen=True, slots=True)
class OfflineVulnerabilityData:
    nvd: dict[str, dict[str, object]]
    cisa_kev: dict[str, dict[str, object]]
    sources: tuple[DataSource, ...]
    data_as_of: str
    warnings: tuple[str, ...]
    fatal: bool

    def loaded(self, name: str) -> bool:
        """Report whether a named feed was read, separating "no matches" from "no data"."""
        return any(source.status == "loaded" and source.metadata.get("name") == name for source in self.sources)


@approved_data_read
def load_offline_data(
    nvd_source: Path | None,
    cisa_source: Path | None,
    cve_ids: Iterable[str],
) -> OfflineVulnerabilityData:
    from .data_release import managed_data_required, vulnerability_paths, data_unavailable_reason
    if managed_data_required():
        nvd_source, cisa_source = vulnerability_paths()
        unavailable = data_unavailable_reason()
        if unavailable:
            return OfflineVulnerabilityData({}, {}, (), "unknown", (unavailable,), True)
    requested = {value.upper() for value in cve_ids}
    warnings: list[str] = []
    sources: list[DataSource] = []
    nvd, nvd_info, nvd_dates, nvd_fatal = _load_nvd(nvd_source, requested, warnings)
    sources.append(nvd_info)
    kev, kev_info, kev_dates, kev_fatal = _load_kev(cisa_source, requested, warnings)
    sources.append(kev_info)
    dates = sorted(value for value in (*nvd_dates, *kev_dates) if value)
    return OfflineVulnerabilityData(
        nvd=nvd,
        cisa_kev=kev,
        sources=tuple(sources),
        data_as_of=dates[-1] if dates else "unknown",
        warnings=tuple(warnings),
        fatal=nvd_fatal or kev_fatal,
    )


def _load_nvd(
    source: Path | None,
    requested: set[str] | None,
    warnings: list[str],
    *,
    cpe_products: set[tuple[str, str, str]] | None = None,
) -> tuple[dict[str, dict[str, object]], DataSource, tuple[str, ...], bool]:
    if source is None:
        return {}, _not_provided("nvd"), (), False
    files = _source_files(source, (".json", ".json.gz"))
    if not files:
        warnings.append(f"NVD data source contains no JSON files: {source}")
        return {}, _source_info(source, "invalid", {"name": "nvd"}), (), True
    records: dict[str, dict[str, object]] = {}
    dates: list[str] = []
    applicability_records = details_only = 0
    try:
        for path in files:
            selected, counts, date_values = _read_nvd_subset(path, requested, cpe_products)
            records.update(selected)
            applicability_records += counts[0]
            details_only += counts[1]
            dates.extend(date_values)
    except (OSError, EOFError, json.JSONDecodeError, UnicodeDecodeError, AttributeError, TypeError, ValueError) as exc:
        warnings.append(f"Could not load NVD data {source}: {exc}")
        return records, _source_info(source, "invalid", {"name": "nvd"}), tuple(dates), True
    return records, _source_info(source, "loaded", {"name": "nvd", "applicabilityRecords": applicability_records,
                                                   "legacyDetailsOnly": details_only}), tuple(dates), False


def _read_nvd_subset(path, requested, cpe_products):
    """Keep matching records while preserving JSON object last-value semantics.

    Per-key flags retain source counts and first insertion order without keeping
    unrelated record trees. ``None`` requests every record; an empty set does not.
    """
    sections = {}
    dates = {}
    date_names = {"lastModifiedDate", "lastModified", "timestamp"}

    def section(name, kind):
        if name in {"vulnerabilities", "CVE_Items"}:
            sections[name] = {"kind": kind, "flags": {}, "selected": {}}
        if name in date_names:
            dates.pop(name, None)

    def field(name, value):
        if name in date_names and isinstance(value, str) and value:
            dates[name] = value

    def entry(name, key, value):
        if name not in {"vulnerabilities", "CVE_Items"}:
            return
        state = sections[name]
        state["flags"][key] = None
        state["selected"].pop(key, None)
        if not isinstance(value, dict):
            return
        if state["kind"] == "dict":
            # The original compact loader overrides the outer id with its key.
            value = dict(value, id=str(key))
        cve = value.get("cve") if isinstance(value.get("cve"), dict) else value
        cve = _normalize_nvd_record(cve)
        state["flags"][key] = bool(cve.get("configurations"))
        metadata = cve.get("CVE_data_meta")
        legacy_id = metadata.get("ID", "") if isinstance(metadata, dict) else ""
        cve_id = str(cve.get("id", legacy_id)).upper()
        is_candidate = False
        if cpe_products:
            from .offline_cpe import GLOBAL_PRODUCT, candidate_index
            products = candidate_index({cve_id: cve})
            is_candidate = GLOBAL_PRODUCT in products or bool(cpe_products.intersection(products))
        if requested is None or cve_id in requested or is_candidate:
            state["selected"][key] = (cve_id, cve)

    read_json_sections(path, section_names={"vulnerabilities", "CVE_Items", "aliases", "items"},
                       on_section=section, on_entry=entry, on_field=field,
                       field_names=date_names, allow_gzip=True)
    state = sections.get("vulnerabilities", sections.get("CVE_Items"))
    records = {}
    applicable = details = 0
    if state and state["kind"] in {"dict", "list"}:
        for key, flag in state["flags"].items():
            if flag is not None:
                applicable += int(flag)
                details += int(not flag)
            if key in state["selected"]:
                identifier, record = state["selected"][key]
                records[identifier] = record
    return records, (applicable, details), tuple(dates[name] for name in ("lastModifiedDate", "lastModified", "timestamp") if name in dates)


@approved_data_read
def load_offline_cpe_data(nvd_source: Path | None, cisa_source: Path | None, cpes: Iterable[str]) -> OfflineVulnerabilityData:
    """Read local NVD applicability candidates for reviewed CPE identities.

    Full feeds and new compact indexes work. Old compact display-only CPE lists
    are never synthesized into an applicability tree.
    """
    from .data_release import managed_data_required, vulnerability_paths, data_unavailable_reason
    if managed_data_required():
        nvd_source, cisa_source = vulnerability_paths()
        unavailable = data_unavailable_reason()
        if unavailable:
            return OfflineVulnerabilityData({}, {}, (), "unknown", (unavailable,), True)
    from .offline_cpe import product_key
    warnings: list[str] = []
    products = set()
    for cpe in cpes:
        try:
            products.add(product_key(cpe))
        except (TypeError, ValueError):
            warnings.append("Invalid or ambiguous CPE 2.3 identity was not evaluated")
    nvd, nvd_info, nvd_dates, nvd_fatal = _load_nvd(nvd_source, set(), warnings, cpe_products=products)
    kev, kev_info, kev_dates, kev_fatal = _load_kev(cisa_source, set(nvd), warnings)
    dates = sorted(value for value in (*nvd_dates, *kev_dates) if value)
    return OfflineVulnerabilityData(nvd, kev, (nvd_info, kev_info), dates[-1] if dates else "unknown", tuple(warnings), nvd_fatal or kev_fatal)


def _normalize_nvd_record(record: dict[str, object]) -> dict[str, object]:
    """Expose compact tracker records through the NVD shape used by KODA."""
    if "metrics" in record or "descriptions" in record:
        return record
    normalized = dict(record)
    description = normalized.get("description")
    if isinstance(description, str) and description.strip():
        normalized["descriptions"] = [description.strip()]
    cvss = normalized.get("cvss")
    if isinstance(cvss, dict):
        metrics: dict[str, list[dict[str, object]]] = {}
        for name, value in cvss.items():
            if isinstance(value, dict):
                metrics.setdefault({"cvssV4": "cvssMetricV40", "cvssV3": "cvssMetricV31", "cvssV2": "cvssMetricV2"}.get(str(name), str(name)), []).append({"cvssData": value})
        if metrics:
            normalized["metrics"] = metrics
    return normalized


def _load_kev(
    source: Path | None,
    requested: set[str],
    warnings: list[str],
) -> tuple[dict[str, dict[str, object]], DataSource, tuple[str, ...], bool]:
    if source is None:
        return {}, _not_provided("cisa_kev"), (), False
    try:
        payload = _read_json(source)
        values = payload.get("vulnerabilities", [])
        compact = payload.get("vulnerabilities")
        if isinstance(compact, dict):
            records = {str(key).upper(): dict(value, cveID=str(key)) for key, value in compact.items() if isinstance(value, dict) and str(key).upper() in requested}
        else:
            records = {
            str(entry.get("cveID", "")).upper(): entry
            for entry in values
            if isinstance(entry, dict) and str(entry.get("cveID", "")).upper() in requested
            } if isinstance(values, list) else {}
        dates = _date_values(payload, ("dateReleased", "catalogVersion"))
        metadata = {"name": "cisa_kev", "catalog_version": payload.get("catalogVersion", ""), "date_released": payload.get("dateReleased", "")}
        return records, _source_info(source, "loaded", metadata), dates, False
    except (OSError, EOFError, json.JSONDecodeError, UnicodeDecodeError, AttributeError, TypeError, ValueError) as exc:
        warnings.append(f"Could not load CISA KEV data {source}: {exc}")
        return {}, _source_info(source, "invalid", {"name": "cisa_kev"}), (), True


def _read_json(path: Path) -> dict[str, object]:
    opener = gzip.open if path.name.endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8") as stream:
        payload = json.load(stream)
    if not isinstance(payload, dict):
        raise ValueError(f"JSON root must be an object: {path}")
    return payload


def _source_files(source: Path, suffixes: tuple[str, ...]) -> tuple[Path, ...]:
    if source.is_file():
        return (source,) if source.name.lower().endswith(suffixes) else ()
    if source.is_dir():
        return tuple(sorted(path for path in source.rglob("*") if path.is_file() and path.name.lower().endswith(suffixes)))
    return ()


def _source_info(source: Path, status: str, metadata: dict[str, object] | None = None) -> DataSource:
    details = dict(metadata or {})
    details["files"] = _source_file_digests(source)
    return DataSource(str(source), _hash_source(source), status, details)


def _not_provided(name: str) -> DataSource:
    return DataSource("", "", "not_provided", {"name": name})


def _hash_source(source: Path) -> str:
    digest = hashlib.sha256()
    if source.is_file():
        with source.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    if source.is_dir():
        for path in sorted(path for path in source.rglob("*") if path.is_file()):
            digest.update(str(path.relative_to(source)).encode("utf-8"))
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
    return digest.hexdigest()


def _source_file_digests(source: Path) -> list[dict[str, str]]:
    paths = (source,) if source.is_file() else tuple(sorted(path for path in source.rglob("*") if path.is_file())) if source.is_dir() else ()
    records: list[dict[str, str]] = []
    for path in paths:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        records.append({"path": str(path), "sha256": digest.hexdigest()})
    return records


def _date_values(payload: dict[str, object], names: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(value for name in names if isinstance(value := payload.get(name), str) and value)
