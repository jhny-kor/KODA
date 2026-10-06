"""Opt-in LLM assists over a finished finding set.

Three read-mostly helpers, all layered on the same provider and guardrails:

- ``executive_summary``: a short risk narrative built from deterministic severity
  counts plus the top finding titles. Returns text; changes no finding.
- ``suggest_mappings``: for findings with no CWE attached, append a suggested
  CWE/OWASP category to the description (a hint for manual confirmation, never a
  deterministic mapping).
- ``select_by_query``: given a natural-language question, return the subset of
  findings the model judges relevant. Read-only — it never hides a finding from
  the saved report, only answers the query.

No secrets or source are sent (only rule id, title, severity, redacted evidence);
every call degrades gracefully when no backend is configured.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import replace

from ..models import Finding
from . import provider

_SUMMARY_SYSTEM = (
    "You are a security lead. Write a concise risk summary (3-5 sentences) of the "
    "scan results: overall posture, the most serious issues, and what to fix first. "
    "No markdown, no preamble."
)
_MAP_SYSTEM = (
    "You map a security finding to the single most relevant CWE id and OWASP Top 10 "
    "2021 category. Answer as strict JSON: {\"cwe\": \"CWE-79\", \"owasp\": \"A03\"}."
)
_QUERY_SYSTEM = (
    "You filter security findings by a user question. Given a numbered list, answer "
    "with strict JSON {\"keep\": [<indices>]} listing only the findings that match."
)


def executive_summary(
    findings: list[Finding], *, complete=None, language: str = "en", timeout_seconds: float = 30.0
) -> tuple[str, list[str]]:
    warnings: list[str] = []
    if not findings:
        return "", warnings
    complete_fn = complete or provider.complete
    counts = Counter(f.severity for f in findings)
    count_line = ", ".join(f"{sev}:{counts[sev]}" for sev in ("critical", "high", "medium", "low", "info") if counts.get(sev))
    top = "; ".join(f"{f.severity} {f.title}" for f in sorted(findings, key=lambda x: x.sort_key())[:8])
    lang_hint = "Answer in Korean." if language == "ko" else "Answer in English."
    prompt = f"{lang_hint}\ncounts: {count_line}\ntop findings: {top}"
    try:
        result = complete_fn(prompt, system=_SUMMARY_SYSTEM, json_mode=False, model=None, timeout_seconds=timeout_seconds)
    except provider.LLMUnavailable as exc:
        warnings.append(f"AI summary skipped: {exc}")
        return "", warnings
    if result.sent_externally:
        warnings.append(f"AI summary sent finding titles to the '{result.backend}' backend (external network call).")
    return " ".join(result.text.split()).strip(), warnings


def suggest_mappings(
    findings: list[Finding], *, complete=None, max_findings: int = 15, timeout_seconds: float = 30.0
) -> tuple[list[Finding], list[str]]:
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
        if finding.cwe_ids:
            continue  # already has a deterministic CWE
        prompt = f"rule: {finding.rule_id}\ntitle: {finding.title}\nevidence: {finding.evidence}"
        try:
            result = complete_fn(prompt, system=_MAP_SYSTEM, json_mode=True, model=None, timeout_seconds=timeout_seconds)
        except provider.LLMUnavailable as exc:
            warnings.append(f"AI mapping skipped: {exc}")
            return annotated, warnings
        budget -= 1
        if result.sent_externally and not external_warned:
            warnings.append(f"AI mapping sent finding titles to the '{result.backend}' backend (external network call).")
            external_warned = True
        suggestion = _parse_mapping(result.text)
        if suggestion:
            note = f"Suggested mapping (review): {suggestion}"
            description = f"{finding.description} {note}".strip() if finding.description else note
            annotated[index] = replace(finding, description=description)
    return annotated, warnings


def select_by_query(
    findings: list[Finding], query: str, *, complete=None, timeout_seconds: float = 30.0
) -> tuple[list[Finding], list[str]]:
    warnings: list[str] = []
    if not findings or not query.strip():
        return [], warnings
    complete_fn = complete or provider.complete
    numbered = "\n".join(f"{i}: {f.severity} {f.rule_id} {f.title}" for i, f in enumerate(findings))
    prompt = f"question: {query}\nfindings:\n{numbered}"
    try:
        result = complete_fn(prompt, system=_QUERY_SYSTEM, json_mode=True, model=None, timeout_seconds=timeout_seconds)
    except provider.LLMUnavailable as exc:
        warnings.append(f"AI query skipped: {exc}")
        return [], warnings
    if result.sent_externally:
        warnings.append(f"AI query sent finding titles to the '{result.backend}' backend (external network call).")
    keep = _parse_indices(result.text, len(findings))
    return [findings[i] for i in keep], warnings


def _parse_mapping(text: str) -> str:
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return ""
    if not isinstance(data, dict):
        return ""
    parts = [str(data[key]) for key in ("cwe", "owasp") if data.get(key)]
    return " / ".join(parts)


def _parse_indices(text: str, count: int) -> list[int]:
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return []
    raw = data.get("keep") if isinstance(data, dict) else None
    if not isinstance(raw, list):
        return []
    seen: list[int] = []
    for item in raw:
        if isinstance(item, int) and 0 <= item < count and item not in seen:
            seen.append(item)
    return seen
