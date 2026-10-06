from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from .models import CATEGORIES, DEFAULT_CATEGORIES, SEVERITIES, ReportConfig, ScannerConfig, TargetConfig


SUPPORTED_LANGUAGES = {"en", "ko"}


class ConfigError(ValueError):
    """Raised when scanner configuration is invalid."""


def load_config(path: Path) -> ScannerConfig:
    config_path = path.expanduser().resolve()
    try:
        raw = json.loads(config_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ConfigError(f"Invalid JSON config {config_path}: {exc}") from exc
    return config_from_dict(raw, base_dir=config_path.parent)


def config_from_dict(raw: dict[str, Any], base_dir: Path | None = None) -> ScannerConfig:
    base = base_dir or Path.cwd()
    targets_raw = raw.get("targets")
    if not isinstance(targets_raw, list) or not targets_raw:
        raise ConfigError("Config must define a non-empty 'targets' list.")

    targets = tuple(_target_from_dict(item, base) for item in targets_raw)
    report = _report_from_dict(raw.get("report", {}), base)
    enable_vuln_intel = bool(raw.get("enable_vuln_intel", False))
    enable_osv = bool(raw.get("enable_osv", False)) or enable_vuln_intel
    enable_reachability = bool(raw.get("enable_reachability", False))
    enable_ai_triage = bool(raw.get("enable_ai_triage", False))
    enable_ai_remediate = bool(raw.get("enable_ai_remediate", False))
    llm_model_raw = raw.get("llm_model")
    llm_model = str(llm_model_raw) if isinstance(llm_model_raw, str) and llm_model_raw.strip() else None
    changed_only = bool(raw.get("changed_only", False))
    diff_base_raw = raw.get("diff_base")
    diff_base = str(diff_base_raw) if isinstance(diff_base_raw, str) and diff_base_raw.strip() else None
    standard = str(raw.get("standard", "local")).strip().lower()
    standard_category = str(raw.get("standard_category", "all")).strip().lower()
    analyzer = str(raw.get("source_analyzer", "")).strip().lower()
    if analyzer not in {"", "codeql"}:
        raise ConfigError("source_analyzer must be empty or 'codeql'.")
    binary = expand_path(raw["source_analyzer_binary"], base) if isinstance(raw.get("source_analyzer_binary"), str) else None
    sarif = expand_path(raw["source_analyzer_sarif"], base) if isinstance(raw.get("source_analyzer_sarif"), str) else None
    if analyzer and sarif is not None:
        raise ConfigError("source_analyzer and source_analyzer_sarif are mutually exclusive.")
    wrapper = expand_path(raw["source_analyzer_sandbox_wrapper"], base) if isinstance(raw.get("source_analyzer_sandbox_wrapper"), str) else None
    sandbox_config = expand_path(raw["source_analyzer_sandbox_config"], base) if isinstance(raw.get("source_analyzer_sandbox_config"), str) else None
    timeout = float(raw.get("source_analyzer_timeout", 120.0))
    if timeout <= 0:
        raise ConfigError("source_analyzer_timeout must be positive.")
    return ScannerConfig(
        targets=targets,
        report=report,
        enable_osv=enable_osv,
        enable_vuln_intel=enable_vuln_intel,
        enable_reachability=enable_reachability,
        enable_ai_triage=enable_ai_triage,
        enable_ai_remediate=enable_ai_remediate,
        llm_model=llm_model,
        changed_only=changed_only,
        diff_base=diff_base,
        standard=standard,
        standard_category=standard_category,
        source_analyzer=analyzer,
        source_analyzer_binary=binary,
        source_analyzer_timeout=timeout,
        source_analyzer_sarif=sarif,
        source_analyzer_license_attested=bool(raw.get("source_analyzer_license_attested", False)),
        source_analyzer_sandbox_wrapper=wrapper,
        source_analyzer_sandbox_config=sandbox_config,
    )


def _target_from_dict(raw: dict[str, Any], base_dir: Path) -> TargetConfig:
    if not isinstance(raw, dict):
        raise ConfigError("Each target must be an object.")

    path_value = raw.get("path")
    if not isinstance(path_value, str) or not path_value.strip():
        raise ConfigError("Each target requires a non-empty string 'path'.")

    target_path = expand_path(path_value, base_dir)
    name = raw.get("name") or target_path.name or str(target_path)
    categories = _normalize_categories(raw.get("categories", DEFAULT_CATEGORIES))
    exclude_globs = tuple(str(item) for item in raw.get("exclude_globs", ()))
    max_file_size_bytes = int(raw.get("max_file_size_bytes", 524288))
    if max_file_size_bytes <= 0:
        raise ConfigError("max_file_size_bytes must be positive.")
    discover_projects = bool(raw.get("discover_projects", False))
    raw_discovery_depth = raw.get("discovery_depth")
    discovery_depth = int(raw_discovery_depth) if raw_discovery_depth is not None else None
    if discovery_depth is not None and discovery_depth < 0:
        raise ConfigError("discovery_depth must be zero or greater.")

    return TargetConfig(
        name=str(name),
        path=target_path,
        categories=categories,
        exclude_globs=exclude_globs,
        max_file_size_bytes=max_file_size_bytes,
        discover_projects=discover_projects,
        discovery_depth=discovery_depth,
    )


def _report_from_dict(raw: dict[str, Any], base_dir: Path) -> ReportConfig:
    if not isinstance(raw, dict):
        raise ConfigError("'report' must be an object when present.")

    report_format = str(raw.get("format", "markdown")).lower()
    if report_format not in {"markdown", "json", "html", "sarif", "cyclonedx", "nis-sbom", "cyclonedx-vex"}:
        raise ConfigError("report.format must be 'markdown', 'json', 'html', 'sarif', 'cyclonedx', 'nis-sbom', or 'cyclonedx-vex'.")

    min_severity = str(raw.get("min_severity", "low")).lower()
    if min_severity not in SEVERITIES:
        raise ConfigError(f"Unknown min_severity: {min_severity}")

    language = str(raw.get("language", "ko")).lower()
    if language not in SUPPORTED_LANGUAGES:
        raise ConfigError("report.language must be 'en' or 'ko'.")

    output_raw = raw.get("output")
    output = expand_path(output_raw, base_dir) if isinstance(output_raw, str) else None
    return ReportConfig(format=report_format, output=output, min_severity=min_severity, language=language)


def _normalize_categories(raw: Any) -> tuple[str, ...]:
    if raw == "all":
        # "all" covers file-based checks; host posture is opt-in (list it explicitly).
        return DEFAULT_CATEGORIES
    if not isinstance(raw, list | tuple):
        raise ConfigError("categories must be a list or 'all'.")

    normalized = tuple(str(item).lower() for item in raw)
    unknown = sorted(set(normalized) - set(CATEGORIES))
    if unknown:
        raise ConfigError(f"Unknown categories: {', '.join(unknown)}")
    if not normalized:
        raise ConfigError("categories must not be empty.")
    return normalized


def expand_path(value: str, base_dir: Path) -> Path:
    expanded = os.path.expandvars(os.path.expanduser(_expand_env_defaults(value)))
    path = Path(expanded)
    if not path.is_absolute():
        path = base_dir / path
    return path.resolve()


def _expand_env_defaults(value: str) -> str:
    pattern = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*):-([^}]*)\}")

    def replace(match: re.Match[str]) -> str:
        env_value = os.environ.get(match.group(1))
        return env_value if env_value else match.group(2)

    return pattern.sub(replace, value)
