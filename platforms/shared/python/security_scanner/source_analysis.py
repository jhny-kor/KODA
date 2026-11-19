"""Small, fail-closed source-analysis ledger used by the scanner."""
from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import dataclass
from itertools import islice
from pathlib import Path
from typing import Callable, Iterable, Mapping

from .config import ConfigError
from .models import Finding

ANALYZER_STATES = ("SUCCESS", "MISSING", "FAILED", "SKIPPED")
STRATEGY_STATES = ("COMPLETE", "PARTIAL", "NOT_RUN", "NOT_APPLICABLE")
MAX_MANIFEST_FILES = 100_000
MAX_MANIFEST_TREE_ENTRIES = 400_000
MAX_MANIFEST_BYTES = 1024**3
MANIFEST_HASH_CHUNK_BYTES = 1024 * 1024
DEFAULT_MANIFEST_FILE_BYTES = 512 * 1024
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
    unhashed_files: tuple[str, ...] = ()

    @classmethod
    def build(
        cls,
        root: Path,
        files: Iterable[Path],
        *,
        file_byte_limits: Mapping[Path, int] | None = None,
    ) -> "SourceManifest":
        input_root = root.absolute()
        root = root.resolve()
        root_is_dir = root.is_dir()
        paths = list(islice(files, MAX_MANIFEST_FILES + 1))
        if len(paths) > MAX_MANIFEST_FILES:
            raise ConfigError(f"Source manifest file limit exceeded ({MAX_MANIFEST_FILES})")
        entries = []
        unhashed = set()
        remaining = MAX_MANIFEST_BYTES
        for path in sorted(map(Path, paths), key=Path.as_posix):
            absolute = path.absolute()
            try:
                if root_is_dir:
                    lexical_root = input_root if absolute.is_relative_to(input_root) else root
                    lexical = absolute.relative_to(lexical_root)
                else:
                    lexical = Path(root.name) if absolute in (input_root, root) else None
            except ValueError:
                lexical = None
            try:
                resolved = path.resolve(strict=True)
                if path.is_symlink() or (not root_is_dir and resolved != root):
                    raise ValueError("Source manifest input is outside the scan scope")
                rel = resolved.relative_to(root).as_posix() if root_is_dir else resolved.name
            except (OSError, RuntimeError, ValueError):
                if lexical is not None and ".." not in lexical.parts:
                    unhashed.add(lexical.as_posix())
                continue
            try:
                flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
                with os.fdopen(os.open(resolved, flags), "rb", buffering=0) as source:
                    initial = os.fstat(source.fileno())
                    file_limit = file_byte_limits.get(path, DEFAULT_MANIFEST_FILE_BYTES) if file_byte_limits else DEFAULT_MANIFEST_FILE_BYTES
                    if not stat.S_ISREG(initial.st_mode) or initial.st_size > min(file_limit, remaining):
                        unhashed.add(rel)
                        continue
                    digest = hashlib.sha256()
                    size = 0
                    while size < initial.st_size:
                        chunk = source.read(min(MANIFEST_HASH_CHUNK_BYTES, initial.st_size - size))
                        if not chunk:
                            break
                        digest.update(chunk)
                        size += len(chunk)
                        remaining -= len(chunk)
                    final = os.fstat(source.fileno())
                    if size != initial.st_size or (final.st_size, final.st_mtime_ns) != (size, initial.st_mtime_ns):
                        unhashed.add(rel)
                        continue
            except OSError:
                unhashed.add(rel)
                continue
            entries.append((rel, size, digest.hexdigest()))
        entries.sort()
        omitted = tuple(sorted(unhashed))
        doc = {"schema": "koda.source-manifest.v1", "root_kind": "directory" if root_is_dir else "single_file", "files": [{"path": p, "size": s, "sha256": h} for p, s, h in entries]}
        if omitted:
            doc["unhashed_files"] = omitted
        return cls(root, tuple(entries), _digest(doc), omitted)


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


@dataclass(slots=True)
class SourceInventoryBudget:
    entries: int = 0

    def add_entry(self) -> None:
        self.entries += 1
        if self.entries > MAX_MANIFEST_TREE_ENTRIES:
            raise ConfigError(f"Source manifest inventory limit exceeded ({MAX_MANIFEST_TREE_ENTRIES} filesystem entries)")


def iter_source_files(
    root: Path,
    *,
    exclude: Iterable[str] = (),
    exclude_path: Callable[[Path], bool] | None = None,
    budget: SourceInventoryBudget | None = None,
) -> Iterable[Path]:
    """Walk regular files without materializing all entries in one directory."""
    budget = budget or SourceInventoryBudget()
    if root.is_file():
        budget.add_entry()
        yield root
        return
    excluded = set(exclude)
    pending = [root]
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as children:
            for entry in children:
                budget.add_entry()
                if entry.is_dir(follow_symlinks=False):
                    if entry.name in excluded:
                        continue
                    path = Path(entry.path)
                    if exclude_path is None or not exclude_path(path):
                        pending.append(path)
                elif entry.is_file(follow_symlinks=False):
                    path = Path(entry.path)
                    if exclude_path is None or not exclude_path(path):
                        yield path


def enumerate_source_files(root: Path, *, exclude: Iterable[str] = ()) -> tuple[Path, ...]:
    """Return a deterministic regular-file inventory without symlinks or special files."""
    return tuple(sorted(iter_source_files(root.resolve(), exclude=exclude)))


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
