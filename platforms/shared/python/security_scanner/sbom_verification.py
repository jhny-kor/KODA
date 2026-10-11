from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote

from .java_archives import ArchiveScan, scan_archive_targets
from .java_inventory import JavaComponent, inventory_components
from .sbom_verification_reporting import write_verification_reports

MATCHED = "MATCHED"
MATCHED_NO_HASH = "MATCHED_NO_HASH"
SBOM_COMPONENT_MISSING_ON_SERVER = "SBOM_COMPONENT_MISSING_ON_SERVER"
SERVER_COMPONENT_MISSING_IN_SBOM = "SERVER_COMPONENT_MISSING_IN_SBOM"
VERSION_MISMATCH = "VERSION_MISMATCH"
FILENAME_VERSION_MISMATCH = "FILENAME_VERSION_MISMATCH"
CONTENT_MISMATCH = "CONTENT_MISMATCH"
MULTIPLE_VERSIONS_PRESENT = "MULTIPLE_VERSIONS_PRESENT"
DUPLICATE_BINARY = "DUPLICATE_BINARY"
SAME_FILENAME_DIFFERENT_CONTENT = "SAME_FILENAME_DIFFERENT_CONTENT"
SAME_PURL_DIFFERENT_CONTENT = "SAME_PURL_DIFFERENT_CONTENT"
NESTED_COMPONENT_MISSING = "NESTED_COMPONENT_MISSING"
UNRESOLVED_COMPONENT = "UNRESOLVED_COMPONENT"
AMBIGUOUS_MATCH = "AMBIGUOUS_MATCH"
BASELINE_COMPONENT_ADDED = "BASELINE_COMPONENT_ADDED"
BASELINE_COMPONENT_REMOVED = "BASELINE_COMPONENT_REMOVED"
BASELINE_VERSION_CHANGED = "BASELINE_VERSION_CHANGED"
BASELINE_CONTENT_CHANGED = "BASELINE_CONTENT_CHANGED"

_NORMAL_STATUSES = {MATCHED, MATCHED_NO_HASH}
_VERSION_STATUSES = {VERSION_MISMATCH, FILENAME_VERSION_MISMATCH, BASELINE_VERSION_CHANGED, MULTIPLE_VERSIONS_PRESENT}


@dataclass(frozen=True, slots=True)
class SbomComponentIdentity:
    bom_ref: str
    group: str
    name: str
    version: str
    purl: str
    hashes: tuple[tuple[str, str], ...]
    locations: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ActualArchiveIdentity:
    group: str
    name: str
    version: str
    purl: str
    sha256: str
    filename: str
    locations: tuple[str, ...]
    version_source: str
    confidence: str
    identity_status: str
    nested: bool
    filename_version: str
    filename_version_mismatch: bool


@dataclass(frozen=True, slots=True)
class VerificationItem:
    status: str
    component_name: str
    sbom_component: SbomComponentIdentity | None
    actual_component: ActualArchiveIdentity | None
    expected_version: str
    actual_version: str
    expected_sha256: str
    actual_sha256: str
    locations: tuple[str, ...]
    confidence: str
    details: str
    recommendation: str
    vulnerabilities: tuple[dict[str, object], ...] = ()

    def payload(self) -> dict[str, object]:
        return {
            "status": self.status,
            "component_name": self.component_name,
            "component": self.sbom_component.purl if self.sbom_component and self.sbom_component.purl else self.component_name,
            "sbom_version": self.expected_version,
            "actual_version": self.actual_version,
            "actual_version_source": self.actual_component.version_source if self.actual_component else "",
            "sbom_sha256": self.expected_sha256,
            "actual_sha256": self.actual_sha256,
            "locations": list(self.locations),
            "confidence": self.confidence,
            "details": self.details,
            "recommendation": self.recommendation,
            "vulnerabilities": list(self.vulnerabilities),
            "cves": sorted({identifier for vulnerability in self.vulnerabilities for identifier in _vulnerability_ids(vulnerability)}),
            "kev": any(bool(v.get("known_exploited")) for v in self.vulnerabilities),
        }


@dataclass(frozen=True, slots=True)
class SbomVerificationOptions:
    target: Path
    sbom: Path | None = None
    baseline_sbom: Path | None = None
    output_dir: Path = Path("reports/sbom-verification")
    excludes: tuple[str, ...] = ()
    max_depth: int | None = None
    fail_on_mismatch: bool = False
    fail_on_version_conflict: bool = False
    fail_on_untracked: bool = False
    strict_hash: bool = False
    format: str = "html"
    vulnerabilities: tuple[dict[str, object], ...] = ()
    # ``target`` remains the primary target for compatibility; ``targets``
    # lets jar-scan verify one combined SBOM against repeated roots.
    targets: tuple[Path, ...] = ()


@dataclass(frozen=True, slots=True)
class SbomVerificationResult:
    exit_code: int
    results: tuple[VerificationItem, ...]
    baseline_changes: tuple[VerificationItem, ...]
    summary: dict[str, int]
    warnings: tuple[str, ...]
    metadata: dict[str, object]


def run_sbom_verification(options: SbomVerificationOptions) -> SbomVerificationResult:
    if options.sbom is None and options.baseline_sbom is None:
        raise ValueError("--sbom or --baseline-sbom is required")
    target_paths = tuple(dict.fromkeys(path.expanduser().resolve() for path in (options.targets or (options.target,))))
    scan = _scan_targets(target_paths, excludes=options.excludes, max_depth=options.max_depth)
    components = inventory_components(scan)
    incomplete_scan = scan.limit_exceeded or any(component.identification_source == "metadata-limit" for component in components)
    scan_warnings = scan.warnings + (("Java archive verification was incomplete because a resource limit was reached.",) if incomplete_scan else ())
    actual_components = tuple(_actual(component) for component in components)
    sbom_components = _load_components(options.sbom) if options.sbom else ()
    baseline_components = _load_components(options.baseline_sbom) if options.baseline_sbom else ()
    results = _compare_current(sbom_components, actual_components, options) if options.sbom else _inventory_anomalies(actual_components)
    baseline_changes = _compare_baseline(baseline_components, actual_components, options.vulnerabilities)
    summary = _summary(results, baseline_changes, actual_components, sbom_components)
    metadata = {
        "target": ", ".join(str(path) for path in target_paths),
        "targets": [str(path) for path in target_paths],
        "sbom": str(options.sbom.expanduser().resolve()) if options.sbom else "",
        "baseline_sbom": str(options.baseline_sbom.expanduser().resolve()) if options.baseline_sbom else "",
        "platform_target": "Linux x86_64",
        "archive_count": len(scan.artifacts),
        "max_depth": options.max_depth,
        "strict_hash": options.strict_hash,
        "warnings": list(scan_warnings),
    }
    write_verification_reports(options.output_dir, results, baseline_changes, actual_components, summary, metadata, options.format)
    exit_code = 2 if incomplete_scan else _exit_code(options, results, baseline_changes)
    return SbomVerificationResult(exit_code, results, baseline_changes, summary, scan_warnings, metadata)


def _scan_targets(
    targets: tuple[Path, ...],
    *,
    excludes: tuple[str, ...],
    max_depth: int | None,
) -> ArchiveScan:
    return scan_archive_targets(targets, excludes=excludes, max_depth=max_depth)


def _actual(component: JavaComponent) -> ActualArchiveIdentity:
    return ActualArchiveIdentity(
        component.group,
        component.name,
        component.version,
        component.purl,
        component.sha256,
        component.locations[0].rsplit("/", 1)[-1].split("!/", 1)[-1],
        component.locations,
        component.version_source,
        component.confidence,
        component.identity_status,
        any("!/" in location for location in component.locations),
        component.filename_version,
        component.filename_version_mismatch,
    )


def _load_components(path: Path | None) -> tuple[SbomComponentIdentity, ...]:
    if path is None:
        return ()
    try:
        payload = json.loads(path.expanduser().read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid SBOM {path}: {exc}") from exc
    if not isinstance(payload, dict) or payload.get("bomFormat") not in {None, "CycloneDX"}:
        raise ValueError(f"SBOM is not a CycloneDX JSON document: {path}")
    raw_components = payload.get("components", [])
    if not isinstance(raw_components, list):
        raise ValueError(f"CycloneDX components must be a list: {path}")
    return tuple(_parse_component(item) for item in raw_components if isinstance(item, dict) and item.get("type", "library") != "application")


def _parse_component(value: dict[str, object]) -> SbomComponentIdentity:
    group = str(value.get("group") or "")
    name = str(value.get("name") or "")
    version = str(value.get("version") or "")
    purl = str(value.get("purl") or "")
    purl_group, purl_name, purl_version = _purl_coordinates(purl)
    group, name, version = group or purl_group, name or purl_name, version or purl_version
    raw_hashes = value.get("hashes", [])
    hashes: list[tuple[str, str]] = []
    if isinstance(raw_hashes, list):
        for raw_hash in raw_hashes:
            if isinstance(raw_hash, dict):
                algorithm = _normalize_algorithm(str(raw_hash.get("alg") or raw_hash.get("algorithm") or ""))
                content = str(raw_hash.get("content") or "").lower()
                if algorithm and content:
                    hashes.append((algorithm, content))
    raw_properties = value.get("properties", [])
    locations: list[str] = []
    if isinstance(raw_properties, list):
        for property_value in raw_properties:
            if not isinstance(property_value, dict):
                continue
            if str(property_value.get("name") or "").casefold() == "koda:location":
                locations.append(str(property_value.get("value") or ""))
            if str(property_value.get("name") or "").casefold() in {"koda:sha256", "sha256"}:
                content = str(property_value.get("value") or "").lower()
                if content and ("SHA-256", content) not in hashes:
                    hashes.append(("SHA-256", content))
    return SbomComponentIdentity(
        str(value.get("bom-ref") or ""), group, name, version, purl, tuple(dict.fromkeys(hashes)), tuple(dict.fromkeys(location for location in locations if location)),
    )


def _normalize_algorithm(value: str) -> str:
    return "SHA-256" if value.casefold().replace("-", "") == "sha256" else value.upper()


def _purl_coordinates(purl: str) -> tuple[str, str, str]:
    if not purl.startswith("pkg:maven/"):
        return "", "", ""
    value = purl.removeprefix("pkg:maven/").split("?", 1)[0]
    if "@" not in value:
        return "", "", ""
    coordinates, version = value.rsplit("@", 1)
    if "/" not in coordinates:
        return "", "", ""
    group, name = coordinates.rsplit("/", 1)
    return unquote(group), unquote(name), unquote(version)


def _compare_current(sbom: tuple[SbomComponentIdentity, ...], actual: tuple[ActualArchiveIdentity, ...], options: SbomVerificationOptions) -> tuple[VerificationItem, ...]:
    results: list[VerificationItem] = []
    matched: set[int] = set()
    for expected in sbom:
        candidates = _match_candidates(expected, actual)
        if not candidates:
            candidates = tuple(item for item in actual if _same_name_group(expected, item))
        if not candidates:
            results.append(_item(SBOM_COMPONENT_MISSING_ON_SERVER, expected.name, expected, None, "SBOM component was not found in the server archive inventory.", ()))
            continue
        if len(candidates) > 1 and not _same_binary(candidates) and not expected.purl:
            results.append(_item(AMBIGUOUS_MATCH, expected.name, expected, None, "Multiple server archives are possible matches; automatic confirmation is unsafe.", ()))
            continue
        selected = candidates[0]
        matched.update(id(item) for item in candidates)
        results.append(_matched_item(expected, selected, options.vulnerabilities, options.strict_hash))
    for index, component in enumerate(actual):
        if id(component) in matched:
            continue
        status = UNRESOLVED_COMPONENT if component.identity_status == "unresolved" else NESTED_COMPONENT_MISSING if component.nested else SERVER_COMPONENT_MISSING_IN_SBOM
        results.append(_item(status, component.name, None, component, "Server archive is not represented by the supplied SBOM.", ()))
    results.extend(_inventory_anomalies(actual))
    return tuple(results)


def _match_candidates(expected: SbomComponentIdentity, actual: tuple[ActualArchiveIdentity, ...]) -> tuple[ActualArchiveIdentity, ...]:
    expected_hashes = {content for algorithm, content in expected.hashes if algorithm == "SHA-256"}
    if expected_hashes:
        candidates = tuple(item for item in actual if item.sha256 in expected_hashes)
        if candidates:
            return candidates
    if expected.purl:
        candidates = tuple(item for item in actual if item.purl == expected.purl)
        if candidates:
            return candidates
    if expected.group and expected.name and expected.version:
        candidates = tuple(item for item in actual if (item.group, item.name, item.version) == (expected.group, expected.name, expected.version))
        if candidates:
            return candidates
    return tuple(item for item in actual if item.name == expected.name and item.version == expected.version)


def _same_name_group(expected: SbomComponentIdentity, actual: ActualArchiveIdentity) -> bool:
    return bool(expected.name and actual.name and expected.name == actual.name and (not expected.group or not actual.group or expected.group == actual.group))


def _same_binary(candidates: tuple[ActualArchiveIdentity, ...]) -> bool:
    return len({item.sha256 for item in candidates}) == 1


def _matched_item(expected: SbomComponentIdentity, actual: ActualArchiveIdentity, vulnerabilities: tuple[dict[str, object], ...], strict_hash: bool) -> VerificationItem:
    expected_hash = next((content for algorithm, content in expected.hashes if algorithm == "SHA-256"), "")
    if actual.filename_version_mismatch:
        status, details = FILENAME_VERSION_MISMATCH, f"filename version {actual.filename_version} differs from internal version {actual.version}"
    elif expected.version and actual.version and expected.version != actual.version:
        status, details = VERSION_MISMATCH, f"SBOM version {expected.version} differs from actual version {actual.version}"
    elif expected_hash and expected_hash != actual.sha256:
        status, details = CONTENT_MISMATCH, "same component identity has a different SHA-256"
    elif strict_hash and not expected_hash:
        status, details = CONTENT_MISMATCH, "strict hash verification requires a SHA-256 in the SBOM"
    elif expected_hash:
        status, details = MATCHED, "PURL, version, and SHA-256 match"
    else:
        status, details = MATCHED_NO_HASH, "component and version match; SHA-256 comparison was unavailable"
    return _item(status, expected.name, expected, actual, details, tuple(v for v in vulnerabilities if _vulnerability_matches(v, expected, actual)))


def _item(status: str, name: str, expected: SbomComponentIdentity | None, actual: ActualArchiveIdentity | None, details: str, vulnerabilities: tuple[dict[str, object], ...]) -> VerificationItem:
    return VerificationItem(status, name or (actual.name if actual else "unknown"), expected, actual, expected.version if expected else "", actual.version if actual else "", _hash(expected) if expected else "", actual.sha256 if actual else "", actual.locations if actual else expected.locations if expected else (), actual.confidence if actual else "unresolved", details, _recommendation(status), vulnerabilities)


def _hash(component: SbomComponentIdentity) -> str:
    return next((content for algorithm, content in component.hashes if algorithm == "SHA-256"), "")


def _vulnerability_matches(value: dict[str, object], expected: SbomComponentIdentity, actual: ActualArchiveIdentity) -> bool:
    purl = str(value.get("component_purl") or "")
    name = str(value.get("component_name") or "")
    identity_matches = bool((purl and purl in {expected.purl, actual.purl}) or (name and name in {expected.name, actual.name}))
    installed_version = str(value.get("installed_version") or "")
    return identity_matches and (not installed_version or installed_version in {expected.version, actual.version})


def _vulnerability_ids(value: dict[str, object]) -> tuple[str, ...]:
    identifiers: list[str] = []
    for key in ("cve_ids", "vulnerability_ids"):
        raw = value.get(key)
        if isinstance(raw, list):
            identifiers.extend(str(item) for item in raw if item)
    if not identifiers and value.get("vulnerability_id"):
        identifiers.append(str(value["vulnerability_id"]))
    return tuple(dict.fromkeys(identifiers))


def _recommendation(status: str) -> str:
    if status in _NORMAL_STATUSES:
        return "No SBOM/archive mismatch found. Continue normal vulnerability review."
    if status == UNRESOLVED_COMPONENT:
        return "Identify the internal archive manually and add reliable Maven metadata to the SBOM."
    if status == SBOM_COMPONENT_MISSING_ON_SERVER:
        return "Confirm whether the SBOM is stale or the deployment omitted the approved library."
    if status in {SERVER_COMPONENT_MISSING_IN_SBOM, NESTED_COMPONENT_MISSING}:
        return "Regenerate the SBOM with the same deployment scope and nested-archive depth."
    if status in {CONTENT_MISMATCH, SAME_PURL_DIFFERENT_CONTENT}:
        return "Investigate repackaging or tampering before accepting the deployment."
    return "Review the deployment and approved SBOM before release."


def _inventory_anomalies(actual: tuple[ActualArchiveIdentity, ...]) -> tuple[VerificationItem, ...]:
    results: list[VerificationItem] = []
    for component in actual:
        if len(component.locations) > 1:
            results.append(_item(DUPLICATE_BINARY, component.name, None, component, "The same SHA-256 is present at multiple archive locations.", ()))
    by_filename: dict[str, list[ActualArchiveIdentity]] = {}
    by_purl: dict[str, list[ActualArchiveIdentity]] = {}
    by_name: dict[tuple[str, str], list[ActualArchiveIdentity]] = {}
    for component in actual:
        by_filename.setdefault(component.filename, []).append(component)
        if component.purl:
            by_purl.setdefault(component.purl, []).append(component)
        by_name.setdefault((component.group, component.name), []).append(component)
    for filename, values in by_filename.items():
        if len({value.sha256 for value in values}) > 1:
            results.append(_item(SAME_FILENAME_DIFFERENT_CONTENT, filename, None, values[0], "The same filename has different SHA-256 values.", ()))
    for purl, values in by_purl.items():
        if len({value.sha256 for value in values}) > 1:
            results.append(_item(SAME_PURL_DIFFERENT_CONTENT, purl, None, values[0], "The same Maven PURL has different SHA-256 values.", ()))
    for (group, name), values in by_name.items():
        versions = {value.version for value in values if value.version}
        if len(versions) > 1:
            results.append(_item(MULTIPLE_VERSIONS_PRESENT, f"{group}:{name}".strip(":"), None, values[0], f"Multiple versions are present: {', '.join(sorted(versions))}", ()))
    return tuple(results)


def _compare_baseline(baseline: tuple[SbomComponentIdentity, ...], actual: tuple[ActualArchiveIdentity, ...], vulnerabilities: tuple[dict[str, object], ...]) -> tuple[VerificationItem, ...]:
    if not baseline:
        return ()
    changes: list[VerificationItem] = []
    used: set[int] = set()
    for expected in baseline:
        candidates = tuple(item for item in actual if expected.purl and item.purl == expected.purl) or tuple(item for item in actual if _same_name_group(expected, item))
        if not candidates:
            changes.append(_item(BASELINE_COMPONENT_REMOVED, expected.name, expected, None, "Baseline component is absent from the current server inventory.", ()))
            continue
        current = candidates[0]
        used.add(id(current))
        if expected.version != current.version:
            changes.append(_item(BASELINE_VERSION_CHANGED, current.name, expected, current, f"baseline {expected.version} -> current {current.version} ({_version_direction(expected.version, current.version)})", tuple(v for v in vulnerabilities if _vulnerability_matches(v, expected, current))))
        if _hash(expected) and _hash(expected) != current.sha256:
            changes.append(_item(BASELINE_CONTENT_CHANGED, current.name, expected, current, "baseline and current SHA-256 values differ", ()))
    for current in actual:
        if id(current) not in used and not any(_same_name_group(expected, current) for expected in baseline):
            changes.append(_item(BASELINE_COMPONENT_ADDED, current.name, None, current, "Current server inventory contains a component not present in the baseline SBOM.", ()))
    return tuple(changes)


def _version_direction(old: str, new: str) -> str:
    old_key, new_key = _version_key(old), _version_key(new)
    if old_key is None or new_key is None:
        return "unknown"
    return "upgrade" if new_key > old_key else "downgrade" if new_key < old_key else "unchanged"


def _version_key(version: str) -> tuple[tuple[int, str], ...] | None:
    if not version or re.search(r"[^0-9A-Za-z.+_-]", version):
        return None
    tokens = re.findall(r"\d+|[A-Za-z]+", version)
    if not tokens:
        return None
    return tuple((0, token.zfill(12)) if token.isdigit() else (1, {"snapshot": "000000000001", "alpha": "000000000002", "beta": "000000000003", "rc": "000000000004", "final": "000000000010", "ga": "000000000010", "release": "000000000010"}.get(token.casefold(), token.casefold())) for token in tokens)


def _summary(results: tuple[VerificationItem, ...], baseline: tuple[VerificationItem, ...], actual: tuple[ActualArchiveIdentity, ...], sbom: tuple[SbomComponentIdentity, ...]) -> dict[str, int]:
    counts = {"sbom_component_count": len(sbom), "actual_component_count": len(actual), "actual_identified_component_count": sum(item.identity_status != "unresolved" for item in actual), "matched": 0, "sbom_component_missing_on_server": 0, "server_component_missing_in_sbom": 0, "version_mismatch": 0, "hash_mismatch": 0, "multiple_versions": 0, "unresolved": 0, "baseline_added": 0, "baseline_removed": 0, "baseline_changed": 0}
    for item in (*results, *baseline):
        if item.status in _NORMAL_STATUSES:
            counts["matched"] += 1
        elif item.status == SBOM_COMPONENT_MISSING_ON_SERVER:
            counts["sbom_component_missing_on_server"] += 1
        elif item.status in {SERVER_COMPONENT_MISSING_IN_SBOM, NESTED_COMPONENT_MISSING}:
            counts["server_component_missing_in_sbom"] += 1
        elif item.status in _VERSION_STATUSES:
            counts["version_mismatch"] += 1
        elif item.status in {CONTENT_MISMATCH, SAME_PURL_DIFFERENT_CONTENT, SAME_FILENAME_DIFFERENT_CONTENT, BASELINE_CONTENT_CHANGED}:
            counts["hash_mismatch"] += 1
        elif item.status == MULTIPLE_VERSIONS_PRESENT:
            counts["multiple_versions"] += 1
        elif item.status in {UNRESOLVED_COMPONENT, AMBIGUOUS_MATCH}:
            counts["unresolved"] += 1
        elif item.status == BASELINE_COMPONENT_ADDED:
            counts["baseline_added"] += 1
        elif item.status == BASELINE_COMPONENT_REMOVED:
            counts["baseline_removed"] += 1
        if item.status in {BASELINE_VERSION_CHANGED, BASELINE_CONTENT_CHANGED}:
            counts["baseline_changed"] += 1
    return counts


def _exit_code(options: SbomVerificationOptions, results: tuple[VerificationItem, ...], baseline: tuple[VerificationItem, ...]) -> int:
    all_items = (*results, *baseline)
    if options.fail_on_mismatch and any(item.status not in _NORMAL_STATUSES for item in all_items):
        return 1
    if options.fail_on_version_conflict and any(item.status in _VERSION_STATUSES for item in all_items):
        return 1
    if options.fail_on_untracked and any(item.status in {SERVER_COMPONENT_MISSING_IN_SBOM, NESTED_COMPONENT_MISSING, UNRESOLVED_COMPONENT} for item in all_items):
        return 1
    return 0
