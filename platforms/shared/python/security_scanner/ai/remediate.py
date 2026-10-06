"""Opt-in LLM remediation suggestions.

For actionable findings, an LLM proposes a concrete fix (what to change, briefly)
which is appended to the finding's ``recommendation``. Same guardrails as triage:

- **Severity and rule are never changed** — only ``recommendation`` text grows.
- **No secrets.** ``secrets`` findings never get a source snippet; only the
  redacted evidence is sent. Source context is included for code findings so the
  fix is specific, but a raw key is never forwarded.
- **Graceful degradation** — no backend means findings pass through with a
  one-line warning; the first external call warns once.
"""

from __future__ import annotations

from dataclasses import replace

from ..checks.common import read_text_lines
from ..models import Finding
from . import provider

_DEFAULT_MAX = 15
_MAX_SNIPPET_BYTES = 1_000_000
_SYSTEM = (
    "You are a secure-coding assistant. Given a security finding, propose the "
    "smallest concrete fix in at most two sentences — what to change and to what. "
    "No preamble, no restating the problem, no markdown."
)


def _should_remediate(finding: Finding) -> bool:
    return finding.triage_verdict != "likely_false"


def _context_snippet(finding: Finding) -> str:
    """A few source lines around the finding — but never for secrets findings."""
    if finding.category == "secrets" or finding.line is None:
        return ""
    try:
        lines = read_text_lines(finding.path, _MAX_SNIPPET_BYTES)
    except (OSError, ValueError):
        return ""
    if not lines:
        return ""
    start = max(0, finding.line - 3)
    end = min(len(lines), finding.line + 2)
    return "\n".join(lines[start:end])


def remediate_findings(
    findings: list[Finding],
    *,
    complete=None,
    model: str | None = None,
    language: str = "en",
    max_findings: int = _DEFAULT_MAX,
    timeout_seconds: float = 30.0,
) -> tuple[list[Finding], list[str]]:
    """Return findings with an LLM fix suggestion appended to ``recommendation``."""
    warnings: list[str] = []
    if not findings:
        return findings, warnings
    complete_fn = complete or provider.complete
    annotated = list(findings)
    budget = max_findings
    external_warned = False

    for index, finding in enumerate(annotated):
        if budget <= 0:
            break
        if not _should_remediate(finding):
            continue
        lang_hint = "Answer in Korean." if language == "ko" else "Answer in English."
        snippet = _context_snippet(finding)
        prompt = (
            f"{lang_hint}\nrule: {finding.rule_id}\ntitle: {finding.title}\n"
            f"evidence: {finding.evidence}"
        )
        if snippet:
            prompt += f"\ncode:\n{snippet}"
        try:
            result = complete_fn(prompt, system=_SYSTEM, json_mode=False, model=model, timeout_seconds=timeout_seconds)
        except provider.LLMUnavailable as exc:
            warnings.append(f"AI remediation skipped: {exc}")
            return annotated, warnings
        budget -= 1
        if result.sent_externally and not external_warned:
            warnings.append(f"AI remediation sent finding context to the '{result.backend}' backend (external network call).")
            external_warned = True
        fix = " ".join(result.text.split()).strip()
        if fix:
            recommendation = f"{finding.recommendation} Suggested fix: {fix}".strip() if finding.recommendation else f"Suggested fix: {fix}"
            annotated[index] = replace(finding, recommendation=recommendation)
    return annotated, warnings
