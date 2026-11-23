"""Bounded, positive-only SARIF 2.1.0 importer."""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urljoin, urlsplit
from urllib.request import url2pathname

from .models import Finding

MAX_SARIF_BYTES = 8 * 1024 * 1024
MAX_SARIF_RESULTS = 10_000
_SPOTBUGS_NULL_RULES = frozenset({
    "NP_ALWAYS_NULL", "NP_NULL_ON_SOME_PATH", "NP_NULL_ON_SOME_PATH_EXCEPTION",
    "NP_NULL_ON_SOME_PATH_FROM_RETURN_VALUE",
})


def _local_analyzer_mapping(analyzer: str, rule: str) -> Mapping[str, Any] | None:
    if analyzer == "spotbugs" and rule in _SPOTBUGS_NULL_RULES:
        return {
            "rule_id": "code.null-pointer-dereference",
            "title": "Null 역참조 가능성",
            "cwe_ids": ("CWE-476",),
            "recommendation": "메서드 반환값과 조건 분기에서 null을 확인한 뒤 사용하세요.",
        }
    if analyzer == "spotbugs" and re.fullmatch(r"[A-Z][A-Z0-9_]{0,199}", rule):
        return {"rule_id": f"code.spotbugs.{rule}", "title": f"SpotBugs · {rule}"}
    if analyzer in {"semgrep", "semgrep oss"} and re.fullmatch(r"[\w.-]{1,200}", rule, re.ASCII):
        return {"rule_id": f"code.semgrep.{rule}", "title": f"Semgrep · {rule}"}
    return None


class SarifImportError(ValueError):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def load_sarif(path: Path, *, max_bytes: int = MAX_SARIF_BYTES) -> dict[str, Any]:
    return load_sarif_with_digest(path, max_bytes=max_bytes)[0]


def load_sarif_with_digest(path: Path, *, max_bytes: int = MAX_SARIF_BYTES) -> tuple[dict[str, Any], str]:
    try:
        if not path.is_file():
            raise SarifImportError("sarif_unreadable")
        with path.open("rb") as stream:
            raw = stream.read(max_bytes + 1)
        if len(raw) > max_bytes:
            raise SarifImportError("sarif_oversized")
    except SarifImportError:
        raise
    except OSError as exc:
        raise SarifImportError("sarif_unreadable") from exc
    try:
        value = json.loads(raw.decode("utf-8-sig"))
    except (ValueError, RecursionError) as exc:
        raise SarifImportError("sarif_invalid_json") from exc
    if not isinstance(value, dict):
        raise SarifImportError("sarif_invalid_document")
    return value, hashlib.sha256(raw).hexdigest()


def import_sarif(
    document: Mapping[str, Any],
    target: Path,
    allowlist: Mapping[tuple[str, str], Mapping[str, Any]] | None = None,
    *,
    allowed_paths: frozenset[str] | None = None,
) -> tuple[tuple[Finding, ...], tuple[str, ...]]:
    if document.get("version") != "2.1.0":
        raise SarifImportError("sarif_wrong_version")
    runs = document.get("runs")
    if not isinstance(runs, list) or not runs:
        raise SarifImportError("sarif_missing_runs")
    root = target.resolve()
    findings: list[Finding] = []
    warnings: list[str] = []
    for run in runs:
        if not isinstance(run, dict):
            raise SarifImportError("sarif_invalid_run")
        tool = run.get("tool")
        driver = tool.get("driver") if isinstance(tool, dict) else None
        if not isinstance(driver, dict) or not isinstance(driver.get("name"), str):
            raise SarifImportError("sarif_missing_tool")
        analyzer = driver["name"]
        analyzer_key = analyzer.strip().lower()
        local_tool = analyzer_key in {"spotbugs", "semgrep", "semgrep oss"}
        uri_bases = run.get("originalUriBaseIds", {}) if local_tool else None
        if local_tool and not isinstance(uri_bases, dict):
            raise SarifImportError("sarif_invalid_uri_bases")
        version = str(driver.get("version") or driver.get("semanticVersion") or "")
        declared_rules = driver.get("rules", [])
        if not isinstance(declared_rules, list):
            raise SarifImportError("sarif_invalid_rules")
        declared_rule_metadata = {
            item["id"]: item for item in declared_rules
            if isinstance(item, dict) and isinstance(item.get("id"), str)
        }
        results = run.get("results", [])
        if not isinstance(results, list):
            raise SarifImportError("sarif_invalid_results")
        if len(results) > MAX_SARIF_RESULTS:
            raise SarifImportError("sarif_too_many_results")
        for result in results:
            if not isinstance(result, dict):
                warnings.append("sarif_result_ignored")
                continue
            kind = result.get("kind", "fail")
            if kind not in ("fail", "review") or result.get("baselineState") == "absent":
                continue
            rule = result.get("ruleId")
            mapping = allowlist.get((analyzer_key, rule)) if allowlist is not None and isinstance(rule, str) else None
            if mapping is None and local_tool and isinstance(rule, str):
                mapping = _local_analyzer_mapping(analyzer_key, rule)
            if mapping is None:
                warnings.append(f"sarif_rule_unmapped:{str(rule)[:128]}")
                continue
            if rule not in declared_rule_metadata:
                warnings.append(f"sarif_rule_undeclared:{str(rule)[:128]}")
                continue
            expected_versions = tuple(str(item) for item in mapping.get("analyzer_versions", ()))
            if expected_versions and version not in expected_versions:
                warnings.append(f"sarif_analyzer_version_unmapped:{version[:64]}")
                continue
            locations = result.get("locations")
            if not isinstance(locations, list) or not locations:
                warnings.append("sarif_location_missing")
                continue
            primary = _location(locations[0], root, uri_bases=uri_bases, allowed_paths=allowed_paths)
            if primary is None:
                warnings.append("sarif_path_outside_target")
                continue
            path, line, _, message = primary
            base = root if root.is_dir() else root.parent
            rel = path.relative_to(base).as_posix()
            if allowed_paths is not None and rel not in allowed_paths:
                warnings.append("sarif_path_not_in_manifest")
                continue
            if not message and isinstance(result.get("message"), dict):
                message = str(result["message"].get("text", ""))
            trace = _trace(result, root, allowed_paths, uri_bases=uri_bases)
            evidence_kind = "dataflow" if trace else str(mapping.get("evidence_kind", "candidate"))
            if evidence_kind not in {"direct", "dataflow", "control_flow", "lifetime", "candidate"}:
                evidence_kind = "candidate"
            status = str(mapping.get("verification_status", "needs_review"))
            if kind == "review" or status not in {"confirmed", "needs_review"}:
                status = "needs_review"
            if bool(mapping.get("trace_required")) and len(trace) < 2:
                status = "needs_review"
                evidence_kind = "candidate"
            level = result.get("level")
            if level is None and local_tool:
                defaults = declared_rule_metadata[rule].get("defaultConfiguration")
                if isinstance(defaults, dict):
                    level = defaults.get("level")
            evidence_id = hashlib.sha256(f"{analyzer}|{version}|{rule}|{rel}|{line}|{trace}".encode()).hexdigest()
            findings.append(Finding(
                rule_id=str(mapping.get("rule_id", rule)), category=str(mapping.get("category", "code")),
                severity=_severity(level), title=str(mapping.get("title", rule)), path=path,
                line=line, target=str(mapping.get("target", "")), evidence=message,
                description=str(mapping.get("description", "")), recommendation=str(mapping.get("recommendation", "")),
                verification_status=status, verification_note="Imported from validated SARIF positive evidence.",
                analyzer=analyzer, analyzer_version=version, analyzer_rule_id=rule, cwe_ids=tuple(mapping.get("cwe_ids", ())),
                evidence_kind=evidence_kind, trace=trace, evidence_id=evidence_id,
                issue_key=f"{mapping.get('rule_id', rule)}|{rel}|{line}",
            ))
    return tuple(findings), tuple(warnings[:100])


def _location(value: Any, root: Path, *, uri_bases: dict | None = None,
              allowed_paths: frozenset[str] | None = None) -> tuple[Path, int | None, int | None, str] | None:
    if not isinstance(value, dict):
        return None
    physical = value.get("physicalLocation")
    if not isinstance(physical, dict):
        return None
    artifact = physical.get("artifactLocation")
    uri = artifact.get("uri") if isinstance(artifact, dict) else None
    if not isinstance(uri, str) or not uri:
        return None
    base = root if root.is_dir() else root.parent
    variants = [uri]
    try:
        if uri_bases is None:
            if uri.startswith(("file:", "/", "\\")) or Path(uri).is_absolute():
                return None
        else:
            base_id = artifact.get("uriBaseId")
            if base_id is not None and not isinstance(base_id, str):
                return None
            if base_id in uri_bases:
                base_entry = uri_bases[base_id]
                base_uri = base_entry.get("uri") if isinstance(base_entry, dict) else None
                if not isinstance(base_uri, str):
                    return None
                uri = urljoin(base_uri, uri)
            elif base_id not in {None, "%SRCROOT%"}:
                return None
            parts = urlsplit(uri)
            if parts.scheme == "file" and parts.netloc in {"", "localhost"} and not parts.query and not parts.fragment:
                variants = [url2pathname(parts.path)]
            elif parts.scheme or parts.netloc:
                return None
            else:
                variants = [uri, unquote(uri, errors="strict")]
    except (ValueError, OSError, RuntimeError):
        return None

    candidate = None
    for variant in dict.fromkeys(variants):
        path = Path(variant)
        if ".." in path.parts or variant.startswith(("//", "\\\\")):
            continue
        lexical = base / path
        try:
            relative = lexical.relative_to(base).as_posix()
            if uri_bases is not None and allowed_paths is not None and relative not in allowed_paths:
                continue
            resolved = lexical.resolve()
            resolved.relative_to(base)
            if resolved.is_file() and (not root.is_file() or resolved == root):
                candidate = resolved
                break
        except (ValueError, OSError, RuntimeError):
            continue
    if candidate is None:
        return None
    region = physical.get("region")
    line = region.get("startLine") if isinstance(region, dict) else None
    column = region.get("startColumn") if isinstance(region, dict) else None
    if line is not None and (isinstance(line, bool) or not isinstance(line, int) or line < 1):
        return None
    return candidate, line, column if isinstance(column, int) else None, str(value.get("message", {}).get("text", "")) if isinstance(value.get("message"), dict) else ""


def _trace(result: Mapping[str, Any], root: Path, allowed_paths: frozenset[str] | None = None, *,
           uri_bases: dict | None = None) -> tuple[dict[str, object], ...]:
    steps: list[dict[str, object]] = []
    for flow in result.get("codeFlows", []) if isinstance(result.get("codeFlows", []), list) else []:
        for thread in flow.get("threadFlows", []) if isinstance(flow, dict) and isinstance(flow.get("threadFlows", []), list) else []:
            for item in thread.get("locations", []) if isinstance(thread, dict) and isinstance(thread.get("locations", []), list) else []:
                loc = item.get("location") if isinstance(item, dict) else None
                parsed = _location(loc, root, uri_bases=uri_bases, allowed_paths=allowed_paths)
                if parsed:
                    path, line, column, message = parsed
                    rel = path.relative_to(root if root.is_dir() else root.parent).as_posix()
                    if allowed_paths is None or rel in allowed_paths:
                        steps.append({"path": rel, "line": line, "column": column, "message": message})
    return tuple(steps[:256])


def _severity(level: Any) -> str:
    return {"error": "high", "warning": "medium", "note": "low", "none": "info"}.get(
        level.lower() if isinstance(level, str) else "", "medium",
    )
