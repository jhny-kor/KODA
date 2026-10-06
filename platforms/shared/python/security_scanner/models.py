from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


SECURITY_CATEGORIES = ("secrets", "dependencies", "configuration", "code", "prevention")
FILE_CATEGORIES = SECURITY_CATEGORIES + ("screen_quality",)
HOST_CATEGORIES = ("host",)
CATEGORIES = FILE_CATEGORIES + HOST_CATEGORIES
DEFAULT_CATEGORIES = SECURITY_CATEGORIES
SCAN_SCOPE_CATEGORIES = {
    "all": DEFAULT_CATEGORIES,
    "library": ("dependencies",),
    "source": ("secrets", "configuration", "code", "prevention"),
}
SEVERITIES = ("info", "low", "medium", "high", "critical")
SEVERITY_RANK = {severity: index for index, severity in enumerate(SEVERITIES)}
# ``unverified`` means the scanner could not evaluate the control at all (a
# probe was unavailable, blocked, or unsupported). It is an evidence gap, not a
# risk judgement, and never counts toward scores or gates.
VERIFICATION_STATUSES = ("confirmed", "needs_review", "unverified")


@dataclass(frozen=True)
class Finding:
    rule_id: str
    category: str
    severity: str
    title: str
    path: Path
    target: str = ""
    line: int | None = None
    evidence: str = ""
    description: str = ""
    recommendation: str = ""
    # For host/endpoint findings that are not tied to a file: a stable resource
    # identifier such as "macos/system-integrity-protection". Empty for file findings.
    resource: str = ""
    # Optional reachability label for dependency findings (see reachability.py).
    # "" when not analyzed; otherwise "reachable" / "unreachable" / "unknown".
    reachable: str = ""
    # Deterministic source-analysis judgement. ``confirmed`` means the scanner
    # proved the required local context; ``needs_review`` is only a candidate.
    verification_status: str = "confirmed"
    verification_note: str = ""
    # Optional AI triage labels (see ai/triage.py). Severity is never derived from these.
    # verdict: "" when not triaged; otherwise "likely_true" / "likely_false" / "uncertain".
    triage_verdict: str = ""
    triage_confidence: float | None = None
    triage_note: str = ""
    analyzer: str = "koda-local"
    analyzer_version: str = ""
    analyzer_rule_id: str = ""
    cwe_ids: tuple[str, ...] = ()
    evidence_kind: str = "direct"
    trace: tuple[dict[str, object], ...] = ()
    evidence_id: str = ""
    issue_key: str = ""

    def __post_init__(self) -> None:
        # Imported/merged reports are untrusted input. Unknown states must not
        # silently become confirmed findings or trigger compliance gates.
        if self.verification_status not in VERIFICATION_STATUSES:
            object.__setattr__(self, "verification_status", "needs_review")
            if not self.verification_note:
                object.__setattr__(
                    self,
                    "verification_note",
                    "알 수 없는 판정 상태를 안전하게 검토 필요로 변환했습니다.",
                )

    def sort_key(self) -> tuple[int, str, str, int]:
        return (
            -SEVERITY_RANK[self.severity],
            self.target,
            self.category,
            str(self.path),
            self.line or 0,
        )


@dataclass(frozen=True)
class DependencyComponent:
    name: str
    ecosystem: str
    version: str
    path: Path
    target: str = ""
    line: int | None = None
    scope: str = "required"
    source: str = ""
    purl: str = ""

    def key(self) -> tuple[str, str, str, str]:
        return (self.ecosystem.lower(), self.name.lower(), self.version, self.target)


@dataclass(frozen=True)
class TargetConfig:
    name: str
    path: Path
    categories: tuple[str, ...] = DEFAULT_CATEGORIES
    exclude_globs: tuple[str, ...] = ()
    max_file_size_bytes: int = 524288
    discover_projects: bool = False
    discovery_depth: int | None = None


@dataclass(frozen=True)
class ReportConfig:
    format: str = "markdown"
    output: Path | None = None
    min_severity: str = "low"
    language: str = "ko"


@dataclass(frozen=True)
class ScannerConfig:
    targets: tuple[TargetConfig, ...]
    report: ReportConfig = ReportConfig()
    enable_osv: bool = False
    enable_vuln_intel: bool = False
    # Opt-in host inventory checks (only used when a target includes the "host" category).
    enable_host_inventory: bool = False
    enable_host_eol: bool = False
    enable_host_cve: bool = False
    nvd_api_key: str | None = None
    # Opt-in reachability analysis: annotate OSV dependency findings with whether the
    # vulnerable package is actually imported by the scanned source (see reachability.py).
    enable_reachability: bool = False
    # Opt-in AI triage of findings (see ai/triage.py). llm_model overrides the KODA_LLM
    # environment variable when set (e.g. "ollama/qwen2.5-coder:7b").
    enable_ai_triage: bool = False
    # Opt-in AI remediation suggestions (see ai/remediate.py); appends a concrete
    # fix to each finding's recommendation. Shares llm_model with triage.
    enable_ai_remediate: bool = False
    llm_model: str | None = None
    # Opt-in CI diff-scope: scan only files changed versus diff_base (see git_changes.py).
    changed_only: bool = False
    diff_base: str | None = None
    # Optional standards profile selected for source-code scans.  The local
    # profile keeps the historic category behaviour; named profiles narrow the
    # scanner to the rules that belong to that standard/category.
    standard: str = "local"
    standard_category: str = "all"
    source_analyzer: str = ""
    source_analyzer_binary: Path | None = None
    source_analyzer_timeout: float = 120.0
    source_analyzer_sarif: Path | None = None
    source_analyzer_license_attested: bool = False
    source_analyzer_sandbox_wrapper: Path | None = None
    source_analyzer_sandbox_config: Path | None = None


@dataclass(frozen=True, slots=True)
class ScanResult:
    """Immutable scan result; findings are scoped to the requested output."""

    findings: tuple[Finding, ...]
    source_analysis: object | None = None
    components: tuple[DependencyComponent, ...] = ()
    warnings: tuple[str, ...] = ()

    def __iter__(self):
        return iter(self.findings)

    def __len__(self) -> int:
        return len(self.findings)
