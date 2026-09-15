from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class GrypeMatch:
    vulnerability_id: str
    cve_ids: tuple[str, ...]
    package_name: str
    installed_version: str
    purl: str
    fixed_versions: tuple[str, ...]
    severity: str
    locations: tuple[str, ...]
    match_details: tuple[str, ...]
    vulnerability_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class GrypeResult:
    matches: tuple[GrypeMatch, ...]
    version: str
    database: dict[str, object]
    warning: str
    fatal: bool


def inspect_grype(binary: Path | None, timeout: float = 10.0) -> dict[str, object]:
    if binary is None:
        return {
            "configured": False,
            "available": False,
            "version": "",
            "database": {},
            "warning": "Grype is not configured; the vulnerability database cannot be checked.",
        }
    validation = _validate_binary(binary)
    if validation:
        return {"configured": True, "available": False, "version": "", "database": {}, "warning": validation}
    version_result = _run(binary, ("--version",), timeout)
    database, database_warning = _database_status(binary, timeout)
    version = version_result.stdout.strip() if version_result.returncode == 0 else ""
    version_warning = "" if version_result.returncode == 0 else f"Grype version check failed: {version_result.stderr.strip() or 'unknown error'}"
    warning = "; ".join(item for item in (version_warning, database_warning) if item)
    return {
        "configured": True,
        "available": version_result.returncode == 0 and database.get("status") != "unavailable",
        "version": version,
        "database": database,
        "warning": warning,
    }


def run_grype(sbom_path: Path, binary: Path | None, timeout: float) -> GrypeResult:
    if binary is None:
        return GrypeResult((), "", {}, "Grype is not configured; vulnerability comparison was not run.", False)
    validation = _validate_binary(binary)
    if validation:
        return GrypeResult((), "", {}, validation, True)
    version_result = _run(binary, ("--version",), timeout)
    version = version_result.stdout.strip() if version_result.returncode == 0 else ""
    version_warning = "" if version_result.returncode == 0 else f"Grype version check failed: {version_result.stderr.strip() or 'unknown error'}"
    database, database_warning = _database_status(binary, timeout)
    matches, warning, fatal = _scan_target(binary, f"sbom:{sbom_path}", timeout)
    if fatal:
        return GrypeResult((), version, database, warning, True)
    return GrypeResult(tuple(matches), version, database, "; ".join(item for item in (version_warning, database_warning, warning) if item), False)


def run_grype_purls(purls: tuple[str, ...], binary: Path | None, timeout: float) -> GrypeResult:
    """Scan a bounded set of package URLs using the existing local Grype DB.

    Grype supports a text file containing one PURL per line.  This helper is
    deliberately separate from ``run_grype`` so candidate-version checks do
    not repeat the version and database-status probes or mutate the database.
    """
    if not purls:
        return GrypeResult((), "", {}, "", False)
    if binary is None:
        return GrypeResult((), "", {}, "Grype is not configured; final-version verification was not run.", True)
    validation = _validate_binary(binary)
    if validation:
        return GrypeResult((), "", {}, validation, True)
    with tempfile.TemporaryDirectory(prefix="koda-grype-purls-") as directory:
        package_file = Path(directory) / "packages.txt"
        package_file.write_text("\n".join(dict.fromkeys(purls)) + "\n", encoding="utf-8")
        matches, warning, fatal = _scan_target(binary, f"purl:{package_file}", timeout)
    return GrypeResult(tuple(matches), "", {}, warning, fatal)


def _scan_target(binary: Path, target: str, timeout: float) -> tuple[tuple[GrypeMatch, ...], str, bool]:
    scan = _run(binary, (target, "-o", "json"), timeout)
    if scan.returncode != 0:
        return (), f"Grype failed: {scan.stderr.strip() or 'unknown error'}", True
    try:
        payload = json.loads(scan.stdout)
        matches = tuple(_parse_match(value) for value in payload.get("matches", []) if isinstance(value, dict))
    except (json.JSONDecodeError, AttributeError, TypeError, KeyError) as exc:
        return (), f"Grype returned invalid JSON: {exc}", True
    return tuple(match for match in matches if match is not None), "", False


def _database_status(binary: Path, timeout: float) -> tuple[dict[str, object], str]:
    status = _run(binary, ("db", "status", "-o", "json"), timeout)
    if status.returncode != 0:
        return {"status": "unavailable"}, f"Grype DB status is unavailable: {status.stderr.strip() or 'unknown error'}"
    try:
        payload = json.loads(status.stdout)
    except json.JSONDecodeError as exc:
        return {"status": "unavailable"}, f"Grype DB status is not JSON: {exc}"
    if not isinstance(payload, dict):
        return {"status": "unavailable"}, "Grype DB status has an invalid JSON shape."
    return payload, ""


def _parse_match(value: dict[str, object]) -> GrypeMatch | None:
    vulnerability = value.get("vulnerability")
    artifact = value.get("artifact")
    if not isinstance(vulnerability, dict) or not isinstance(artifact, dict):
        return None
    vulnerability_id = _string(vulnerability.get("id"))
    if not vulnerability_id:
        return None
    related = value.get("relatedVulnerabilities")
    vulnerability_ids = {vulnerability_id}
    cve_ids = set(_cve_ids(vulnerability_id))
    if isinstance(related, list):
        for entry in related:
            if isinstance(entry, dict):
                related_id = _string(entry.get("id"))
                if related_id:
                    vulnerability_ids.add(related_id)
                    cve_ids.update(_cve_ids(related_id))
    fix = vulnerability.get("fix")
    fixed_versions = tuple(_string(item) for item in fix.get("versions", []) if _string(item)) if isinstance(fix, dict) and isinstance(fix.get("versions"), list) else ()
    locations = value.get("artifact", {}).get("locations", []) if isinstance(value.get("artifact"), dict) else []
    location_values = tuple(
        _string(entry.get("path"))
        for entry in locations
        if isinstance(entry, dict) and _string(entry.get("path"))
    ) if isinstance(locations, list) else ()
    details = value.get("matchDetails", [])
    detail_values = tuple(
        _string(entry.get("matcher"))
        for entry in details
        if isinstance(entry, dict) and _string(entry.get("matcher"))
    ) if isinstance(details, list) else ()
    return GrypeMatch(
        vulnerability_id=vulnerability_id,
        cve_ids=tuple(sorted(cve_ids)),
        package_name=_string(artifact.get("name")),
        installed_version=_string(artifact.get("version")),
        purl=_string(artifact.get("purl")),
        fixed_versions=fixed_versions,
        severity=_string(vulnerability.get("severity")).lower() or "unknown",
        locations=location_values,
        match_details=detail_values,
        vulnerability_ids=tuple(sorted(vulnerability_ids)),
    )


def _cve_ids(value: str) -> tuple[str, ...]:
    return (value.upper(),) if re.fullmatch(r"CVE-\d{4}-\d{4,}", value, flags=re.IGNORECASE) else ()


def _string(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


def _validate_binary(binary: Path) -> str:
    if not binary.is_file():
        return f"Grype executable not found: {binary}"
    if not os.access(binary, os.X_OK):
        return f"Grype executable is not executable: {binary}"
    return ""


def _run(binary: Path, arguments: tuple[str, ...], timeout: float) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["GRYPE_DB_AUTO_UPDATE"] = "false"
    env["GRYPE_DB_VALIDATE_AGE"] = "false"
    try:
        from .data_release import grype_cache_dir
        cache_dir = grype_cache_dir()
    except (ImportError, OSError):
        cache_dir = None
    if cache_dir is not None:
        env["GRYPE_DB_CACHE_DIR"] = str(cache_dir)
    try:
        return subprocess.run(
            [str(binary), *arguments],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            env=env,
        )
    except FileNotFoundError:
        return subprocess.CompletedProcess([str(binary), *arguments], 127, "", f"executable not found: {binary}")
    except PermissionError:
        return subprocess.CompletedProcess([str(binary), *arguments], 126, "", f"permission denied: {binary}")
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess([str(binary), *arguments], 124, "", f"timed out after {timeout:g}s")
    except OSError as exc:
        return subprocess.CompletedProcess([str(binary), *arguments], 125, "", str(exc))
