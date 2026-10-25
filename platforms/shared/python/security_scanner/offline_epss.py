"""Read approved FIRST daily EPSS snapshots without any network access.

Observed scores remain visible with their original date. Policy eligibility is a
separate age-based field; importing a file never makes an old score current.
"""
from __future__ import annotations

import copy
import csv
import gzip
import hashlib
import io
import math
import os
import re
from datetime import date, datetime, timezone
from pathlib import Path
from functools import wraps

MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_EXPANDED_BYTES = 128 * 1024 * 1024
MAX_CVES = 1_000_000
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)


def load_snapshot(path: Path | str, cve_ids: set[str], *, at: datetime | None = None) -> tuple[dict, dict[str, dict]]:
    """Validate the entire snapshot, retaining only requested CVEs in memory."""
    at = at or datetime.now(timezone.utc)
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_FILE_BYTES + 1)
    if not raw or len(raw) > MAX_FILE_BYTES:
        raise ValueError("EPSS 파일 크기는 1바이트 이상 64MiB 이하여야 합니다")
    digest = hashlib.sha256(raw).hexdigest()
    try:
        if raw.startswith(b"\x1f\x8b"):
            with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:
                decoded = stream.read(MAX_EXPANDED_BYTES + 1)
        else:
            decoded = raw
        if len(decoded) > MAX_EXPANDED_BYTES:
            raise ValueError("EPSS 압축 해제 크기가 128MiB 한도를 초과합니다")
        header, separator, body = decoded.decode("utf-8-sig").partition("\n")
        if not separator or not header.startswith("#"):
            raise ValueError("EPSS 모델·기준일 메타데이터가 필요합니다")
        parts = header[1:].strip().split(",")
        metadata = dict(part.strip().split(":", 1) for part in parts)
        if len(parts) != 2 or set(metadata) != {"model_version", "score_date"}:
            raise ValueError("EPSS 모델·기준일 형식이 올바르지 않습니다")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", metadata["model_version"]):
            raise ValueError("EPSS 모델 식별자가 올바르지 않습니다")
        raw_date = metadata["score_date"]
        if "T" in raw_date:
            timestamp = datetime.fromisoformat(raw_date.replace("Z", "+00:00"))
            if timestamp.tzinfo is None:
                raise ValueError("EPSS 기준 시각의 시간대가 필요합니다")
            day = timestamp.astimezone(timezone.utc).date()
        else:
            day = date.fromisoformat(raw_date)
        if (day - at.date()).days > 1:
            raise ValueError("EPSS 기준일이 미래입니다")
        reader = csv.DictReader(io.StringIO(body, newline=""), strict=True)
        if reader.fieldnames != ["cve", "epss", "percentile"]:
            raise ValueError("EPSS CSV 열은 cve,epss,percentile 순서여야 합니다")
        scores, seen = {}, set()
        for row in reader:
            if len(seen) >= MAX_CVES:
                raise ValueError("EPSS CVE 개수 한도를 초과했습니다")
            if None in row or any(value is None for value in row.values()):
                raise ValueError("EPSS CSV 열 개수가 올바르지 않습니다")
            cve = row["cve"].upper()
            if not CVE_RE.fullmatch(cve) or cve in seen:
                raise ValueError("EPSS CVE 식별자가 올바르지 않거나 중복되었습니다")
            try:
                score, percentile = float(row["epss"]), float(row["percentile"])
            except ValueError as exc:
                raise ValueError("EPSS 점수 형식이 올바르지 않습니다") from exc
            if not all(math.isfinite(value) and 0 <= value <= 1 for value in (score, percentile)):
                raise ValueError("EPSS 점수는 0~1의 유한수여야 합니다")
            seen.add(cve)
            if cve in cve_ids:
                scores[cve] = {"cve": cve, "score": score, "percentile": percentile, "date": day.isoformat()}
        if not seen:
            raise ValueError("EPSS 파일에 점수가 없습니다")
        return {"source_kind": "offline_snapshot", "source_url": "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
                "sha256": digest, "model_version": metadata["model_version"],
                "date": day.isoformat(), "record_count": len(seen)}, scores
    except (OSError, EOFError, UnicodeError, csv.Error, TypeError, OverflowError) as exc:
        raise ValueError("올바른 FIRST EPSS CSV(.gz) 파일이 아닙니다") from exc


def _cves(record: dict) -> set[str]:
    values = []
    for field in ("vulnerability_id", "canonicalId", "id", "cve", "cve_ids", "vulnerability_ids", "aliases"):
        value = record.get(field)
        values.extend(value if isinstance(value, (list, tuple)) else [value])
    return {match.upper() for value in values if isinstance(value, str) for match in CVE_RE.findall(value)}


def _approved_read(function):
    # Keep the raw parser importable by standalone package validators.
    @wraps(function)
    def invoke(*args, **kwargs):
        from .data_release import approved_data_read
        return approved_data_read(function)(*args, **kwargs)
    return invoke


@_approved_read
def enrich_records(records: list[dict], path: Path | str | None = None, *, at: datetime | None = None,
                   max_age_days: int | None = None) -> list[dict]:
    at = at or datetime.now(timezone.utc)
    result = copy.deepcopy(records)
    flattened = [record for record in result if isinstance(record, dict)]
    flattened += [advisory for record in result if isinstance(record, dict) for advisory in (record.get("advisories") or [])
                  if isinstance(advisory, dict)]
    requested = set().union(*(_cves(record) for record in flattened)) if flattened else set()
    source, scores, error, status = {}, {}, "", "missing"
    try:
        from .data_release import epss_path, managed_data_required
        if path is None or managed_data_required():
            path = epss_path()
        maximum_age = int(os.environ.get("KODA_EPSS_MAX_AGE_DAYS", "7")) if max_age_days is None else max_age_days
        if isinstance(maximum_age, bool) or not isinstance(maximum_age, int) or not 0 <= maximum_age <= 365:
            raise ValueError("EPSS 정책 허용 기간은 0~365일이어야 합니다")
        if path:
            source, scores = load_snapshot(path, requested, at=at)
            age = (at.date() - date.fromisoformat(source["date"])).days
            source.update(age_days=age, max_age_days=maximum_age)
            status = "fresh" if 0 <= age <= maximum_age else "stale"
    except OSError:
        status, error = "missing", "EPSS 반입 파일을 읽을 수 없습니다"
    except ValueError as exc:
        status, error = "invalid", str(exc)
    for record in flattened:
        # A re-enrichment may receive an older exported record. Clear it before
        # assigning evidence from the selected immutable data release.
        for key in tuple(record):
            if key.startswith("epss_"):
                record.pop(key)
        ids = _cves(record)
        matched = [scores[cve] for cve in sorted(ids) if cve in scores]
        record.update(epss_status=status if ids else "not_applicable", epss_policy_eligible=False,
                      epss_source=source.copy(), epss_records=matched)
        if error:
            record["epss_error"] = error
        if matched:
            selected = max(matched, key=lambda value: (value["score"], value["cve"]))
            record.update(epss_score=selected["score"], epss_percentile=selected["percentile"],
                          epss_date=selected["date"], epss_cve=selected["cve"], epss_policy_eligible=status == "fresh")
        elif ids and not error:
            record["epss_status"] = "missing"
    return result
