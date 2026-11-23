from __future__ import annotations

import fnmatch
import os
from dataclasses import replace
from functools import partial
from pathlib import Path
from typing import Callable

from . import git_changes, reachability
from .checks import code_patterns, configuration, dependencies, prevention, screen_quality, secrets
from .checks.common import clear_read_text_cache, is_text_candidate, normalized_relpath, read_text_lines
from .checks.host import HostScanOptions, check_host
from .config import ConfigError
from .dependency_inventory import components_from_file, queryable_osv_components, unique_components
from .discovery import discover_projects
from .ignore import filter_ignored_findings
from .models import DependencyComponent, Finding, ScanResult, ScannerConfig, TargetConfig
from .source_analysis import (
    MAX_MANIFEST_FILES, AnalyzerRun, SourceAnalysisSummary, SourceInventoryBudget,
    SourceManifest, is_source_file, iter_source_files, source_languages,
)
from .sarif_import import SarifImportError, import_sarif, load_sarif_with_digest
from .osv_vulnerabilities import query_osv_findings


DEFAULT_EXCLUDE_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".cache",
    ".build",
    ".mypy_cache",
    ".next",
    ".omx",
    ".playwright-cli",
    ".pytest_cache",
    ".terraform",
    ".venv",
    "DerivedData",
    "__pycache__",
    "build",
    "coverage",
    "dist",
    "node_modules",
    "output",
    "reports",
    "target",
    "venv",
}

DEFAULT_EXCLUDE_GLOBS = (
    "**/.git/**",
    "**/.build/**",
    "**/node_modules/**",
    "**/.venv/**",
    "**/venv/**",
    "**/dist/**",
    "**/build/**",
    "**/reports/**",
    "**/.omx/**",
    "**/.playwright-cli/**",
    "**/output/**",
)

CHECKS: dict[str, Callable[[Path, TargetConfig], list[Finding]]] = {
    "secrets": secrets.check_file,
    "dependencies": dependencies.check_file,
    "configuration": configuration.check_file,
    "code": code_patterns.check_file,
    "prevention": prevention.check_file,
    "screen_quality": screen_quality.check_file,
}


class SecurityScanner:
    def __init__(self, config: ScannerConfig):
        self.config = config
        self.warnings: list[str] = []
        self.effective_targets: tuple[TargetConfig, ...] = ()
        self.components: tuple[DependencyComponent, ...] = ()
        self._python_imports: set[str] = set()
        self._js_imports: set[str] = set()
        self._changed_scope: set[Path] = set()
        self._changed_scope_active = False
        self._analyzed_languages: set[str] = set()

    def scan(self) -> ScanResult:
        clear_read_text_cache()
        self._changed_scope.clear()
        self._changed_scope_active = False
        self._analyzed_languages.clear()
        findings: list[Finding] = []
        components: list[DependencyComponent] = []
        source_profile = self.config.standard == "sw-dev-security-49"
        self.effective_targets = self._expand_targets()
        for target in self.effective_targets:
            target_findings, target_components = self._scan_target(target)
            components.extend(target_components)
            findings.extend(target_findings)
        if not source_profile:
            findings.extend(self._scan_host())
        self.components = unique_components(components)
        if self.config.enable_reachability:
            index = reachability.ImportIndex(
                python=frozenset(self._python_imports),
                js=frozenset(self._js_imports),
            )
            findings = reachability.annotate_reachability(findings, tuple(components), index)
        if self.config.enable_ai_triage:
            from .ai import triage as ai_triage

            findings, triage_warnings = ai_triage.triage_findings(
                findings,
                model=self.config.llm_model,
                language=self.config.report.language,
                timeout_seconds=self.config.llm_timeout,
            )
            self.warnings.extend(triage_warnings)
        if self.config.enable_ai_remediate:
            from .ai import remediate as ai_remediate

            findings, remediate_warnings = ai_remediate.remediate_findings(
                findings,
                model=self.config.llm_model,
                language=self.config.report.language,
                timeout_seconds=self.config.llm_timeout,
            )
            self.warnings.extend(remediate_warnings)
        ordered = tuple(sorted(findings, key=lambda finding: finding.sort_key()))
        # A pre-generated SARIF is positive evidence only; it never certifies coverage.
        analyzer_runs: list[AnalyzerRun] = []
        external: list[Finding] = []
        sarif_warnings: tuple[str, ...] = ()
        manifest = None
        manifest_root = self.effective_targets[0].path if self.effective_targets else Path.cwd()
        if source_profile or self.config.source_analyzer or self.config.source_analyzer_sarif:
            manifest_root, file_byte_limits = self._source_manifest_inputs()
            manifest = SourceManifest.build(manifest_root, file_byte_limits, file_byte_limits=file_byte_limits)
            if manifest.unhashed_files:
                self.warnings.append(
                    f"Source manifest omitted {len(manifest.unhashed_files)} file(s) that exceeded "
                    "the hashing budget, changed during hashing, or could not be read."
                )
        if self.config.source_analyzer or self.config.source_analyzer_sarif:
            if self.config.source_analyzer_sarif:
                try:
                    from .standards import sw49_sarif_allowlist

                    payload, digest = load_sarif_with_digest(self.config.source_analyzer_sarif)
                    imported, sarif_warnings = import_sarif(
                        payload,
                        manifest_root,
                        sw49_sarif_allowlist(),
                        allowed_paths=frozenset(entry[0] for entry in manifest.files) if manifest else frozenset(),
                    )
                    external.extend(imported)
                    self.warnings.extend(sarif_warnings)
                    for run in payload["runs"]:
                        driver = run["tool"]["driver"]
                        analyzer = driver["name"].strip()[:128]
                        version = str(driver.get("version") or driver.get("semanticVersion") or "")[:128]
                        status, reason = self._sarif_run_status(run, analyzer)
                        analyzer_runs.append(AnalyzerRun(
                            analyzer,
                            version=version,
                            profile_id="codeql-java-none-2.26.1" if analyzer.lower() == "codeql" and version == "2.26.1" else "",
                            output_origin="pre_generated",
                            status=status,
                            failure_reason=reason,
                            target=str(manifest_root),
                            manifest_digest=manifest.digest if manifest else "",
                            sarif_digest=digest,
                        ))
                except SarifImportError as exc:
                    analyzer_runs.append(AnalyzerRun("sarif", output_origin="pre_generated", status="FAILED", target=str(manifest_root), manifest_digest=manifest.digest if manifest else "", failure_reason=exc.reason))
            elif self.config.source_analyzer == "codeql":
                from .codeql_adapter import preflight, SandboxCapability

                analyzer_runs.append(preflight(
                    self.config.source_analyzer_binary,
                    sandbox=SandboxCapability(
                        wrapper=self.config.source_analyzer_sandbox_wrapper,
                        config=self.config.source_analyzer_sandbox_config,
                    ),
                    license_attested=self.config.source_analyzer_license_attested,
                    target=manifest_root,
                ))
            ordered = self._merge_findings((*ordered, *external))
        strategies = ()
        if source_profile:
            from .standards import build_sw49_strategy_executions

            scanned_categories = tuple(dict.fromkeys(category for target in self.effective_targets for category in target.categories))
            strategies = build_sw49_strategy_executions(manifest, scanned_categories, tuple(analyzer_runs), sarif_warnings)
        report_findings = ordered
        if source_profile and self._changed_scope_active:
            report_findings = tuple(
                finding for finding in ordered
                if self._finding_in_changed_scope(finding, manifest_root, self._changed_scope)
            )
        summary = SourceAnalysisSummary(
            manifest=manifest,
            analyzer_runs=tuple(analyzer_runs), strategies=strategies,
            all_findings=ordered, report_findings=report_findings,
            warnings=tuple(self.warnings),
            analyzed_languages=tuple(sorted(self._analyzed_languages)),
        )
        return ScanResult(report_findings, summary, tuple(self.components), tuple(self.warnings))

    def _changed_files(self, target: TargetConfig) -> set[Path] | None:
        if self.config.file_selection is not None:
            root = target.path.resolve()
            return {path.resolve() for path in self.config.file_selection
                    if path.resolve() == root or root in path.resolve().parents}
        if not self.config.changed_only:
            return None
        changed, warnings = git_changes.changed_files(self.config.diff_base, target.path)
        self.warnings.extend(warnings)
        return changed

    def _collect_imports(self, path: Path, target: TargetConfig) -> None:
        if not self.config.enable_reachability or not reachability.is_analyzable(path.suffix):
            return
        lines = read_text_lines(path, target.max_file_size_bytes)
        if lines is None:
            return
        index = reachability.imported_names_from_lines(lines, path.suffix)
        self._python_imports |= index.python
        self._js_imports |= index.js

    def _scan_host(self) -> list[Finding]:
        host_targets = [target for target in self.effective_targets if "host" in target.categories]
        if not host_targets:
            return []
        options = HostScanOptions(
            enable_inventory=self.config.enable_host_inventory,
            enable_eol=self.config.enable_host_eol,
            enable_cve=self.config.enable_host_cve,
            nvd_api_key=self.config.nvd_api_key,
        )
        host_findings, warnings = check_host(options=options)
        self.warnings.extend(warnings)
        if not host_findings:
            return []
        target_name = host_targets[0].name
        tagged = [
            replace(finding, target=target_name) if not finding.target else finding
            for finding in host_findings
        ]
        filtered, ignored = filter_ignored_findings(tagged, host_targets[0].path)
        if ignored:
            self.warnings.append(f"Ignored {ignored} host finding(s) using KODA ignore rules")
        return filtered

    def _expand_targets(self) -> tuple[TargetConfig, ...]:
        targets: list[TargetConfig] = []
        for target in self.config.targets:
            if not target.discover_projects:
                targets.append(target)
                continue

            discovered = discover_projects(target.path, target.discovery_depth)
            if not discovered:
                self.warnings.append(f"No project markers found under: {target.path}")
                targets.append(replace(target, discover_projects=False))
                continue

            for project in discovered:
                targets.append(
                    replace(
                        target,
                        name=f"{target.name}/{project.name}",
                        path=project.path,
                        discover_projects=False,
                    )
                )
        return tuple(targets)

    def _scan_target(self, target: TargetConfig) -> tuple[list[Finding], list[DependencyComponent]]:
        if target.path.is_symlink():
            self.warnings.append(f"Refused symlink scan target: {target.path}")
            return [], []
        if not target.path.exists():
            raise ValueError(f"Target does not exist: {target.path}")
        if target.path.is_file():
            if self.config.file_selection is not None and target.path.resolve() not in self._changed_files(target):
                return [], []
            source_profile = self.config.standard == "sw-dev-security-49"
            if source_profile and not (is_source_file(target.path) or is_text_candidate(target.path)):
                return [], []
            components = [] if source_profile else self._components_from_file(target.path, target)
            self._analyzed_languages.update(source_languages(target.path))
            findings = self._scan_file(target.path, target)
            self._collect_imports(target.path, target)
            if self.config.standard != "sw-dev-security-49":
                findings.extend(self._osv_findings(components))
            filtered, ignored = filter_ignored_findings(findings, target.path.parent)
            if ignored:
                self.warnings.append(f"Ignored {ignored} finding(s) using KODA ignore rules for: {target.path.parent}")
            return filtered, components

        findings: list[Finding] = []
        components: list[DependencyComponent] = []
        scanned_files: list[Path] = []
        changed = self._changed_files(target)
        if changed is not None:
            self._changed_scope_active = True
            self._changed_scope.update(path.resolve() for path in changed)
        # SW49 needs whole-project context. Only the user-facing result is
        # diff-scoped; the evidence ledger and status use the full project.
        filtering = changed is not None and self.config.standard != "sw-dev-security-49"
        for file_path in self._iter_files(target):
            if self.config.standard == "sw-dev-security-49" and not (is_source_file(file_path) or is_text_candidate(file_path)):
                continue
            if filtering and file_path.resolve() not in changed:
                continue
            scanned_files.append(file_path)
            self._analyzed_languages.update(source_languages(file_path))
            file_components = [] if self.config.standard == "sw-dev-security-49" else self._components_from_file(file_path, target)
            components.extend(file_components)
            findings.extend(self._scan_file(file_path, target))
            self._collect_imports(file_path, target)
        # Project-level prevention reasons over the whole project; skip it while diff-scoping
        # so a partial file list does not produce spurious "missing control" findings.
        if "prevention" in target.categories and not filtering:
            findings.extend(
                replace(finding, target=target.name) if not finding.target else finding
                for finding in prevention.check_project(target.path, scanned_files, target)
            )
        if self.config.standard != "sw-dev-security-49":
            findings.extend(self._osv_findings(components))
        filtered, ignored = filter_ignored_findings(findings, target.path)
        if ignored:
            self.warnings.append(f"Ignored {ignored} finding(s) using KODA ignore rules for: {target.path}")
        return filtered, components

    def _source_manifest_inputs(self) -> tuple[Path, dict[Path, int]]:
        # SARIF paths are rooted in the submitted inputs, including when
        # discovery schedules the built-in checks against nested projects.
        inputs = self.config.targets if self.config.source_analyzer_sarif else self.effective_targets
        targets = [(target, target.path.resolve()) for target in inputs if not target.path.is_symlink()]
        if not targets:
            root = self.effective_targets[0].path.parent.resolve() if self.effective_targets else Path.cwd()
            return root, {}
        roots: list[Path] = []
        limits: dict[Path, int] = {}
        inventory = SourceInventoryBudget()
        for target, path in targets:
            directory = path.is_dir()
            roots.append(path if directory or len(targets) == 1 else path.parent)
            # SW49 coverage uses whole-project context, even when the report
            # displays changed findings only.
            selected = None if self.config.standard == "sw-dev-security-49" else self._changed_files(target)
            exclude_path = None
            if directory and target.exclude_globs:
                exclude_path = partial(self._matches_exclude, root=path, patterns=target.exclude_globs)
            for item in iter_source_files(path, exclude=DEFAULT_EXCLUDE_DIRS,
                                          exclude_path=exclude_path, budget=inventory):
                if selected is not None and item not in selected:
                    continue
                if not (is_source_file(item) or is_text_candidate(item)):
                    continue
                limits[item] = max(limits.get(item, 0), target.max_file_size_bytes)
                if len(limits) > MAX_MANIFEST_FILES:
                    raise ConfigError(f"Source manifest file limit exceeded ({MAX_MANIFEST_FILES})")
        return Path(os.path.commonpath(roots)).resolve(), limits

    def _sarif_run_status(self, run: dict, analyzer: str) -> tuple[str, str]:
        invocations = run.get("invocations", [])
        if not isinstance(invocations, list):
            self.warnings.append("sarif_invocations_invalid")
            return "FAILED", "sarif_invocations_invalid"
        missing_classes = False
        for invocation in invocations:
            if not isinstance(invocation, dict):
                self.warnings.append("sarif_invocations_invalid")
                return "FAILED", "sarif_invocations_invalid"
            if analyzer.lower() == "spotbugs" and invocation.get("exitCode") in (2, 3):
                missing_classes = True
            elif invocation.get("executionSuccessful") is False:
                self.warnings.append(f"sarif_analyzer_execution_failed: {analyzer}")
                return "FAILED", "sarif_analyzer_execution_failed"
        if missing_classes:
            self.warnings.append("sarif_spotbugs_missing_classes: SpotBugs reported incomplete class resolution.")
            return "PARTIAL", "sarif_spotbugs_missing_classes"
        return "SUCCESS", ""

    @staticmethod
    def _merge_findings(findings: tuple[Finding, ...]) -> tuple[Finding, ...]:
        merged: dict[tuple[str, str, int, str], Finding] = {}
        for finding in findings:
            key = (finding.rule_id, str(finding.path.resolve()), finding.line or 0, finding.target)
            current = merged.get(key)
            if current is None:
                merged[key] = finding
                continue
            current_score = (current.verification_status == "confirmed", len(current.trace), bool(current.evidence_id))
            candidate_score = (finding.verification_status == "confirmed", len(finding.trace), bool(finding.evidence_id))
            if candidate_score > current_score:
                merged[key] = finding
        return tuple(sorted(merged.values(), key=lambda finding: finding.sort_key()))

    def _scan_file(self, path: Path, target: TargetConfig) -> list[Finding]:
        findings: list[Finding] = []
        for category in target.categories:
            check = CHECKS.get(category)
            if check is None:  # e.g. "host" is not file-based; handled in _scan_host
                continue
            findings.extend(
                replace(finding, target=target.name) if not finding.target else finding
                for finding in check(path, target)
            )
        return findings

    def _components_from_file(self, path: Path, target: TargetConfig) -> list[DependencyComponent]:
        if "dependencies" not in target.categories:
            return []
        return components_from_file(path, target)

    def _osv_findings(self, components: list[DependencyComponent]) -> list[Finding]:
        if not (self.config.enable_osv or self.config.enable_vuln_intel):
            return []
        queryable_components = queryable_osv_components(tuple(components))
        if not queryable_components:
            return []
        findings, warnings = query_osv_findings(queryable_components, enable_vuln_intel=self.config.enable_vuln_intel)
        self.warnings.extend(warnings)
        return findings

    def _iter_files(self, target: TargetConfig):
        exclude_globs = DEFAULT_EXCLUDE_GLOBS + target.exclude_globs

        def on_error(error: OSError) -> None:
            self.warnings.append(f"Could not read {error.filename}: {error.strerror}")

        for root, dirs, files in os.walk(target.path, onerror=on_error):
            root_path = Path(root)
            dirs[:] = [
                dirname
                for dirname in dirs
                if dirname not in DEFAULT_EXCLUDE_DIRS
                and not self._matches_exclude(root_path / dirname, target.path, exclude_globs)
            ]
            for filename in files:
                file_path = root_path / filename
                if file_path.is_symlink() or not file_path.is_file():
                    continue
                try:
                    file_path.resolve().relative_to(target.path.resolve())
                except (OSError, ValueError):
                    continue
                if self._matches_exclude(file_path, target.path, exclude_globs):
                    continue
                yield file_path

    @staticmethod
    def _matches_exclude(path: Path, root: Path, patterns: tuple[str, ...]) -> bool:
        rel = normalized_relpath(path, root)
        name = path.name
        return any(fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch(name, pattern) for pattern in patterns)

    @staticmethod
    def _finding_in_changed_scope(finding: Finding, root: Path, changed: set[Path]) -> bool:
        try:
            if finding.path.resolve() in changed:
                return True
        except OSError:
            pass
        for step in finding.trace:
            raw_path = step.get("path") if isinstance(step, dict) else None
            if not isinstance(raw_path, str) or not raw_path:
                continue
            try:
                candidate = (root / raw_path).resolve()
            except OSError:
                continue
            if candidate in changed:
                return True
        return False
