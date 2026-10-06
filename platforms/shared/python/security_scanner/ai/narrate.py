"""Opt-in LLM narrative for high-impact findings.

For confirmed-exploit and attack-path findings, an LLM writes a one- or two-
sentence "how this is exploited and why it matters" note that is appended to the
finding's ``description``. This is report enrichment, not a judgement:

- **Severity is never changed** — only ``description`` text is appended.
- **No secrets / no source** are sent: only the rule id, title and the already-
  redacted evidence string are forwarded.
- **Graceful degradation** — if no backend is configured the findings pass
  through unchanged with a one-line warning; the first external call warns once.
"""

from __future__ import annotations

from dataclasses import replace

from ..models import Finding
from . import provider

# Only narrate findings that are actually impactful; keeps latency/cost bounded.
_NARRATE_PREFIXES = ("attack-path.",)
_NARRATE_RULES = frozenset({
    "web.sql-injection-exploited", "web.command-injection-exploited",
    "web.command-injection-oob", "web.ssti-exploited", "web.ssrf-cloud-metadata",
    "web.ssrf-oob-verified", "net.default-credentials", "net.docker-unauth",
})
_DEFAULT_MAX = 12
_SYSTEM = (
    "You are a security analyst. In at most two sentences, explain how the given "
    "finding is exploited in practice and its business impact. No remediation, no "
    "preamble, no markdown — just the explanation."
)


def _should_narrate(finding: Finding) -> bool:
    return finding.rule_id in _NARRATE_RULES or finding.rule_id.startswith(_NARRATE_PREFIXES)


def explain_findings(
    findings: list[Finding],
    *,
    complete=None,
    model: str | None = None,
    language: str = "en",
    max_findings: int = _DEFAULT_MAX,
    timeout_seconds: float = 30.0,
) -> tuple[list[Finding], list[str]]:
    """Return findings with an LLM narrative appended to high-impact ones."""
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
        if not _should_narrate(finding):
            continue
        lang_hint = "Answer in Korean." if language == "ko" else "Answer in English."
        prompt = (
            f"{lang_hint}\nrule: {finding.rule_id}\ntitle: {finding.title}\n"
            f"evidence: {finding.evidence}"
        )
        try:
            result = complete_fn(prompt, system=_SYSTEM, json_mode=False, model=model, timeout_seconds=timeout_seconds)
        except provider.LLMUnavailable as exc:
            warnings.append(f"AI narrative skipped: {exc}")
            return annotated, warnings
        budget -= 1
        if result.sent_externally and not external_warned:
            warnings.append(f"AI narrative sent finding context to the '{result.backend}' backend (external network call).")
            external_warned = True
        note = " ".join(result.text.split()).strip()
        if note:
            description = f"{finding.description} AI: {note}".strip() if finding.description else f"AI: {note}"
            annotated[index] = replace(finding, description=description)
    return annotated, warnings
