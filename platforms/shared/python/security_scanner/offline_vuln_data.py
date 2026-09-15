from __future__ import annotations

import gzip
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


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


def load_offline_data(
    nvd_source: Path | None,
    cisa_source: Path | None,
    cve_ids: Iterable[str],
) -> OfflineVulnerabilityData:
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
    requested: set[str],
    warnings: list[str],
) -> tuple[dict[str, dict[str, object]], DataSource, tuple[str, ...], bool]:
    if source is None:
        return {}, _not_provided("nvd"), (), False
    files = _source_files(source, (".json", ".json.gz"))
    if not files:
        warnings.append(f"NVD data source contains no JSON files: {source}")
        return {}, _source_info(source, "invalid", {"name": "nvd"}), (), True
    records: dict[str, dict[str, object]] = {}
    dates: list[str] = []
    try:
        for path in files:
            payload = _read_json(path)
            dates.extend(_date_values(payload, ("lastModifiedDate", "lastModified")))
            vulnerabilities = payload.get("vulnerabilities", payload.get("CVE_Items", []))
            if isinstance(vulnerabilities, dict):
                # Tracker's compact offline index stores CVE records by ID.
                vulnerabilities = [dict(value, id=str(key)) for key, value in vulnerabilities.items() if isinstance(value, dict)]
            if not isinstance(vulnerabilities, list):
                continue
            for entry in vulnerabilities:
                cve = entry.get("cve") if isinstance(entry, dict) and isinstance(entry.get("cve"), dict) else entry
                if not isinstance(cve, dict):
                    continue
                cve = _normalize_nvd_record(cve)
                metadata = cve.get("CVE_data_meta")
                legacy_id = metadata.get("ID", "") if isinstance(metadata, dict) else ""
                cve_id = str(cve.get("id", legacy_id)).upper()
                if cve_id in requested:
                    records[cve_id] = cve
    except (OSError, EOFError, json.JSONDecodeError, UnicodeDecodeError, AttributeError, TypeError, ValueError) as exc:
        warnings.append(f"Could not load NVD data {source}: {exc}")
        return records, _source_info(source, "invalid", {"name": "nvd"}), tuple(dates), True
    return records, _source_info(source, "loaded", {"name": "nvd"}), tuple(dates), False


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
