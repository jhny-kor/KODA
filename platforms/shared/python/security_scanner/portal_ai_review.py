"""Bounded facts for advisory review of an immutable portal finding."""
from __future__ import annotations

import re

from .checks.secrets import SECRET_RULES
from .models import SCAN_SCOPE_CATEGORIES, SEVERITIES


_FACT_ID = re.compile(r"[A-Za-z0-9._:-]{1,100}")
_PRIVATE_KEY = re.compile(r"-----\s*(?:BEGIN|END)\b[^\r\n]*PRIVATE KEY", re.IGNORECASE)
_CREDENTIAL = re.compile(
    r"\b(?:(?:Bearer|Basic)\s+[\w.~/+=-]{8,}|(?:glpat-|github_pat_)[\w-]+|eyJ[\w-]+\.[\w-]+\.[\w-]+)"
    r"|\b(?:password|passwd|pwd|secret|token|api[_-]?key|(?:access|auth|refresh)[_-]?token|"
    r"client[_-]?secret|private[_-]?key|authorization)\b"
    r"['\"]?\s*[:=]\s*(?:['\"][^'\"\r\n]+['\"]|[^\s,;\r\n]+)"
    r"|\b[a-z][a-z0-9+.-]*://[^\s/]+:[^\s/@]+@",
    re.IGNORECASE,
)
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\ud800-\udfff\ufffe\uffff]")
_REDACTED = "<redacted sensitive content>"
REVIEW_VERDICTS = {"likely_true", "likely_false", "not_affected", "needs_review"}
REVIEW_TEXT_FIELDS = ("reasoning", "impact", "remediation", "retest")


def review_kind(finding: dict) -> str | None:
    rule = finding.get("rule_id")
    if not isinstance(rule, str) or not _FACT_ID.fullmatch(rule):
        return None
    category = finding.get("category")
    if category == "dependencies":
        return "library"
    if category in SCAN_SCOPE_CATEGORIES["source"]:
        return "source"
    return None


def clean_review_text(value: object, limit: int) -> str:
    if not isinstance(value, str):
        return ""
    if _PRIVATE_KEY.search(value):
        return _REDACTED
    lines = (
        _REDACTED if (_CREDENTIAL.search(line) or any(rule.pattern.search(line) for rule in SECRET_RULES)) else line
        for line in value.splitlines()
    )
    return _CONTROL.sub("", "\n".join(lines)).strip()[:limit]


def _location(path: object, line: object) -> str:
    if not isinstance(path, str):
        return ""
    # Avoid forwarding server roots or source upload URLs.
    tail = path.replace("\\", "/").rsplit("/", 1)[-1]
    return f"{tail}:{line}" if type(line) is int and line > 0 else tail


def _rows(value: object, limit: int) -> list[dict]:
    return [row for row in value[:limit] if isinstance(row, dict)] if isinstance(value, list) else []


def library_identity(finding: dict) -> tuple[str, set[str]]:
    """Grype stores the exact package and aliases together in the finding key."""
    key = finding.get("issue_key")
    if not isinstance(key, str):
        return "", set()
    parts = key.split("|", 2)
    if len(parts) != 3 or parts[0] != "dependency.osv-known-vulnerability" or not parts[1].startswith("pkg:"):
        return "", set()
    return parts[1], {item for item in parts[2].split(",") if _FACT_ID.fullmatch(item)}


def finding_review_facts(finding: dict, library_records: list[dict]) -> dict:
    rule = finding["rule_id"]
    severity = finding.get("severity")
    facts = {"ruleId": rule, "severity": severity if severity in SEVERITIES else "unknown"}

    def add(field: str, value: object, limit: int) -> None:
        text = clean_review_text(value, limit)
        if text:
            facts[field] = text

    add("verificationStatus", finding.get("verification_status"), 40)
    if finding.get("category") == "secrets" or rule.lower().startswith(("secret.", "secrets.")):
        return facts

    for field, limit in (("title", 300), ("evidence", 2000), ("description", 1400), ("recommendation", 1200)):
        add(field, finding.get(field), limit)
    add("location", _location(finding.get("path"), finding.get("line")), 400)
    if review_kind(finding) == "library":
        purl, identifiers = library_identity(finding)
        add("package", purl, 500)
        if len(identifiers) == 1:
            add("vulnerabilityId", next(iter(identifiers)), 100)
        for record in library_records:
            values = record.get("cve_ids") or record.get("vulnerability_ids")
            record_ids = {value for value in values if isinstance(value, str)} if isinstance(values, list) else set()
            primary = record.get("vulnerability_id")
            if isinstance(primary, str) and not record_ids:
                record_ids.add(primary)
            if record.get("purl") != purl or not identifiers or record_ids != identifiers:
                continue
            add("version", record.get("installed_version"), 160)
            versions = record.get("fixed_versions")
            if isinstance(versions, list):
                add("fixedVersions", ", ".join(v for v in versions[:25] if isinstance(v, str)), 500)
            nvd = record.get("nvd")
            if len(identifiers) == 1 and isinstance(nvd, dict) and isinstance(nvd.get("descriptions"), list):
                descriptions = [item.get("value") if isinstance(item, dict) else item for item in nvd["descriptions"][:5]]
                advisory = " ".join(item for item in descriptions if isinstance(item, str))
                if advisory:
                    add("description", f"{facts.get('description', '')}\nNVD: {advisory}", 1400)
            break
        return facts

    trace = []
    for step in _rows(finding.get("trace"), 12):
        location = _location(step.get("path"), step.get("line"))
        message = clean_review_text(step.get("message"), 160)
        trace.append(f"{location} {message}".strip())
    add("trace", "\n".join(trace), 2200)
    context = finding.get("source_context")
    if isinstance(context, dict):
        rows = _rows(context.get("lines"), 12)
        raw = "\n".join(row["text"] for row in rows if isinstance(row.get("text"), str))
        if not _PRIVATE_KEY.search(raw) and not any(row.get("redacted") for row in rows):
            excerpt = []
            for row in rows:
                if type(row.get("number")) is int and isinstance(row.get("text"), str):
                    excerpt.append(clean_review_text(f"{row['number']}: {row['text']}", 550))
            add("sourceContext", "\n".join(excerpt), 3200)
    return facts
