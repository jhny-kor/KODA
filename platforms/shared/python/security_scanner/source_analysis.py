"""Small, fail-closed source-analysis ledger used by the scanner."""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .models import Finding

ANALYZER_STATES = ("SUCCESS", "MISSING", "FAILED", "SKIPPED")
STRATEGY_STATES = ("COMPLETE", "PARTIAL", "NOT_RUN", "NOT_APPLICABLE")
SOURCE_SUFFIXES = frozenset({
    ".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".cs", ".go", ".htm", ".html", ".java", ".js", ".cjs", ".jsp",
    ".jsx", ".mjs", ".kt", ".php", ".py", ".rb", ".rs", ".swift", ".ts", ".tsx", ".vue", ".xml",
    ".env", ".yaml", ".yml", ".properties", ".conf", ".config", ".json", ".toml", ".tf", ".tfvars", ".plist", ".pem", ".key",
})
SOURCE_FILENAMES = frozenset({".env", "Dockerfile", "dockerfile", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"})

SOURCE_LANGUAGE_BY_SUFFIX = {
    ".c": "C", ".h": "C", ".cc": "C++", ".cpp": "C++", ".cxx": "C++", ".hpp": "C++",
    ".cs": "C#", ".go": "Go", ".java": "Java", ".jsp": "JSP", ".js": "JavaScript",
    ".cjs": "JavaScript", ".jsx": "JavaScript", ".mjs": "JavaScript", ".vue": "JavaScript",
    ".kt": "Kotlin", ".php": "PHP", ".py": "Python", ".rb": "Ruby",
    ".rs": "Rust", ".swift": "Swift", ".ts": "TypeScript", ".tsx": "TypeScript",
    ".htm": "HTML", ".html": "HTML", ".xml": "XML", ".yaml": "YAML", ".yml": "YAML", ".env": "Configuration",
    ".properties": "Configuration", ".conf": "Configuration", ".config": "Configuration",
}


def _digest(payload: object) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class SourceManifest:
    root: Path
    files: tuple[tuple[str, int, str], ...]
    digest: str

    @classmethod
    def build(cls, root: Path, files: Iterable[Path]) -> "SourceManifest":
        root = root.resolve()
        entries = []
        for path in sorted((Path(p) for p in files), key=lambda p: p.as_posix()):
            try:
                resolved = path.resolve()
                rel = resolved.relative_to(root).as_posix() if root.is_dir() else resolved.name
                data = resolved.read_bytes()
            except (OSError, ValueError):
                continue
            entries.append((rel, len(data), hashlib.sha256(data).hexdigest()))
        entries.sort()
        doc = {"schema": "koda.source-manifest.v1", "root_kind": "directory" if root.is_dir() else "single_file", "files": [{"path": p, "size": s, "sha256": h} for p, s, h in entries]}
        return cls(root, tuple(entries), _digest(doc))


@dataclass(frozen=True, slots=True)
class AnalyzerRun:
    analyzer: str
    version: str = ""
    profile_id: str = ""
    run_id: str = ""
    status: str = "SKIPPED"
    target: str = ""
    duration_seconds: float = 0.0
    failure_reason: str = ""
    message: str = ""
    manifest_digest: str = ""
    config_digest: str = ""
    rulepack_digest: str = ""
    output_origin: str = "executed"
    sarif_digest: str = ""

    def __post_init__(self) -> None:
        if self.status not in ANALYZER_STATES:
            object.__setattr__(self, "status", "FAILED")
            object.__setattr__(self, "failure_reason", "invalid_status")


@dataclass(frozen=True, slots=True)
class StrategyExecution:
    official_control: str
    language: str = ""
    profile_id: str = ""
    strategy: str = ""
    status: str = "NOT_RUN"
    analyzer_run_id: str = ""
    required_rule_ids: tuple[str, ...] = ()
    present_rule_ids: tuple[str, ...] = ()
    requested_rule_ids: tuple[str, ...] = ()
    executed_rule_ids: tuple[str, ...] = ()
    expected_files: tuple[str, ...] = ()
    analyzed_files: tuple[str, ...] = ()
    reason: str = ""
    negative_coverage_certified: bool = False
    scope: str = "project"
    manifest_digest: str = ""
    config_digest: str = ""
    rulepack_digest: str = ""

    def __post_init__(self) -> None:
        if self.status not in STRATEGY_STATES:
            object.__setattr__(self, "status", "NOT_RUN")
        if self.status != "COMPLETE":
            object.__setattr__(self, "negative_coverage_certified", False)

    @property
    def missing_rule_ids(self) -> tuple[str, ...]:
        return tuple(sorted(set(self.required_rule_ids) - set(self.present_rule_ids)))

    @property
    def unexecuted_rule_ids(self) -> tuple[str, ...]:
        return tuple(sorted(set(self.present_rule_ids) - set(self.executed_rule_ids)))


@dataclass(frozen=True, slots=True)
class SourceAnalysisSummary:
    manifest: SourceManifest | None = None
    analyzer_runs: tuple[AnalyzerRun, ...] = ()
    strategies: tuple[StrategyExecution, ...] = ()
    all_findings: tuple[Finding, ...] = ()
    report_findings: tuple[Finding, ...] = ()
    warnings: tuple[str, ...] = ()
    analyzed_languages: tuple[str, ...] = ()

    @property
    def coverage_complete(self) -> bool:
        return bool(self.strategies) and all(s.status == "COMPLETE" and s.negative_coverage_certified for s in self.strategies)


def enumerate_source_files(root: Path, *, exclude: Iterable[str] = ()) -> tuple[Path, ...]:
    """Deterministic regular-file inventory; symlinks and special files are excluded."""
    root = root.resolve()
    if root.is_file():
        return (root,)
    excluded = set(exclude)
    result: list[Path] = []
    for base, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in excluded and not (Path(base) / d).is_symlink())
        for name in sorted(names):
            path = Path(base) / name
            if path.is_file() and not path.is_symlink():
                result.append(path)
    return tuple(result)


def is_source_file(path: Path) -> bool:
    return (
        path.name in SOURCE_FILENAMES
        or path.name.lower() == "dockerfile"
        or path.name.lower().startswith("dockerfile.")
        or path.suffix.lower() in SOURCE_SUFFIXES
    )


def source_languages(path: Path) -> frozenset[str]:
    """Return the language labels used by SW49 applicability matching."""
    if path.name in SOURCE_FILENAMES or path.name.lower() == "dockerfile" or path.name.lower().startswith("dockerfile."):
        return frozenset({"Configuration"})
    language = SOURCE_LANGUAGE_BY_SUFFIX.get(path.suffix.lower())
    return frozenset({language}) if language else frozenset()
