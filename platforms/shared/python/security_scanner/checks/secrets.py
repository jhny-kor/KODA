from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from ..models import Finding, TargetConfig
from .common import is_text_candidate, read_text_lines


PLACEHOLDER_RE = re.compile(
    r"^(changeme|change-me|example|sample|dummy|fake|placeholder|test|todo|none|null|"
    r"your[_-]?(key|token|secret|password)|x{4,}|0{8,})$",
    re.IGNORECASE,
)
SAFE_SECRET_REFERENCE_RE = re.compile(
    r"(?i)\b(os\.getenv|os\.environ|process\.env|getenv|config\.get|settings\.|"
    r"decouple\.config|argparse|args\.|argv\.|required\s*=\s*true)\b"
)


@dataclass(frozen=True)
class SecretRule:
    rule_id: str
    title: str
    severity: str
    pattern: re.Pattern[str]
    secret_group: int = 0
    recommendation: str = "Move the secret into a local secret store or environment variable and rotate it if it was real."


SECRET_RULES = (
    SecretRule(
        "secret.private-key",
        "Private key material",
        "critical",
        re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"),
    ),
    SecretRule(
        "secret.aws-access-key",
        "AWS access key ID",
        "high",
        re.compile(r"\b(?:A3T[A-Z0-9]|AKIA|ASIA)[A-Z0-9]{16}\b"),
    ),
    SecretRule(
        "secret.github-token",
        "GitHub token",
        "high",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,255}\b"),
    ),
    SecretRule(
        "secret.openai-key",
        "OpenAI API key",
        "high",
        re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    ),
    SecretRule(
        "secret.slack-token",
        "Slack token",
        "high",
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    ),
    SecretRule(
        "secret.generic-assignment",
        "Hard-coded secret-like assignment",
        "medium",
        re.compile(
            r"(?i)^\s*(?:self\.)?['\"]?(password|passwd|pwd|secret|api[_-]?key|access[_-]?token|"
            r"auth[_-]?token|client[_-]?secret|private[_-]?key)['\"]?\s*[:=]\s*['\"]?([^'\"\s#;,]{8,})"
        ),
        secret_group=2,
    ),
    SecretRule(
        # SW49 S-13: credential-like assignments left inside comments. The
        # generic-assignment rule is anchored to line starts, so commented-out
        # credentials need their own comment-aware pattern. Evidence is redacted
        # by the shared _redact_line path like every other secret rule.
        "secret.sensitive-comment",
        "Sensitive data in a comment",
        "medium",
        re.compile(
            r"(?i)^\s*(?:#|//|/\*|\*|<!--|;)\s*.*?\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?token|"
            r"auth[_-]?token|client[_-]?secret|private[_-]?key)\b\s*[:=]\s*['\"]?([^'\"\s#;,]{8,})"
        ),
        secret_group=2,
        recommendation="Remove credentials from comments and rotate the value if it was ever real.",
    ),
)


def check_file(path: Path, target: TargetConfig) -> list[Finding]:
    if not is_text_candidate(path):
        return []

    lines = read_text_lines(path, target.max_file_size_bytes)
    if lines is None:
        return []

    findings: list[Finding] = []
    per_rule_counts: dict[str, int] = {}
    for line_number, line in enumerate(lines, start=1):
        for rule in SECRET_RULES:
            for match in rule.pattern.finditer(line):
                if per_rule_counts.get(rule.rule_id, 0) >= 5:
                    continue
                secret_value = match.group(rule.secret_group)
                if rule.rule_id in ("secret.generic-assignment", "secret.sensitive-comment") and _looks_like_secret_reference(line, secret_value):
                    continue
                if _looks_like_placeholder(secret_value):
                    continue
                findings.append(
                    Finding(
                        rule_id=rule.rule_id,
                        category="secrets",
                        severity=rule.severity,
                        title=rule.title,
                        path=path,
                        line=line_number,
                        evidence=_redact_line(line.strip(), secret_value),
                        description="A secret-like value appears in a local project file.",
                        recommendation=rule.recommendation,
                        verification_status=(
                            "needs_review"
                            if rule.rule_id in ("secret.generic-assignment", "secret.sensitive-comment")
                            else "confirmed"
                        ),
                        verification_note=(
                            "비밀값 형태의 휴리스틱 탐지입니다. 실제 자격증명인지 저장소와 사용 문맥을 확인해야 합니다."
                            if rule.rule_id in ("secret.generic-assignment", "secret.sensitive-comment")
                            else "비밀 제공자 고유 형식 또는 개인 키 본문을 확인했습니다."
                        ),
                    )
                )
                per_rule_counts[rule.rule_id] = per_rule_counts.get(rule.rule_id, 0) + 1
    return findings


def _shannon_entropy(value: str) -> float:
    """Shannon entropy in bits per character (0 for a single repeated char)."""
    if not value:
        return 0.0
    import math
    from collections import Counter

    counts = Counter(value)
    length = len(value)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def _looks_like_placeholder(value: str) -> bool:
    cleaned = value.strip().strip("'\"").strip()
    if not cleaned:
        return True
    if PLACEHOLDER_RE.match(cleaned):
        return True
    lowered = cleaned.lower()
    if lowered.startswith(("example_", "sample_", "dummy_", "fake_")):
        return True
    # Very low entropy over a reasonable length (e.g. "aaaaaaaa", "abcabcabc",
    # "12341234") is a filler/pattern value, not a real secret. The threshold is
    # conservative so high-entropy real keys are never skipped.
    return len(cleaned) >= 8 and _shannon_entropy(cleaned) < 2.0


def _looks_like_secret_reference(line: str, value: str) -> bool:
    if SAFE_SECRET_REFERENCE_RE.search(line):
        return True
    stripped = value.strip().strip("'\"")
    lowered = stripped.lower()
    if "(" in stripped or ")" in stripped:
        return True
    return lowered.startswith(("os.", "process.", "config.", "settings.", "self.", "args.", "argv."))


def _redact_line(line: str, secret_value: str) -> str:
    return line.replace(secret_value, _redact_value(secret_value))


def _redact_value(value: str) -> str:
    if len(value) <= 8:
        return "<redacted>"
    return f"{value[:4]}...{value[-4:]} ({len(value)} chars)"
