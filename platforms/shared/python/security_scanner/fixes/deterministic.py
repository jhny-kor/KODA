"""Deterministic, line-scoped fixers.

Each fixer takes a single source line and returns the corrected line, or ``None`` when it
has nothing safe to change. Fixes are intentionally conservative and idempotent: they only
rewrite forms with an unambiguous safe equivalent, leaving anything uncertain untouched so
the user can fix it manually. The dry-run diff and ``--apply`` approval gate in ``apply.py``
are the safety net around these.
"""

from __future__ import annotations

import re

# Qualified weak-hash calls like ``hashlib.md5(`` / ``crypto.sha1(`` -> ``.sha256(``.
# Bare ``md5(`` (no attribute access) is left alone because it might not be a hash call.
_QUALIFIED_WEAK_HASH = re.compile(r"\.(?:md5|sha1)\(", re.IGNORECASE)

# ``yaml.load(`` without an explicit (safe) Loader -> ``yaml.safe_load(``.
_YAML_LOAD = re.compile(r"\byaml\.load\(")

# Config hardening: flip an insecure boolean to its safe value, preserving layout.
_PRIVILEGE_ESCALATION = re.compile(r"(allowPrivilegeEscalation\s*:\s*)true\b", re.IGNORECASE)
_PRIVILEGED = re.compile(r"(\bprivileged\s*:\s*)true\b", re.IGNORECASE)


def fix_weak_hash(line: str) -> str | None:
    """Rewrite ``<x>.md5(`` / ``<x>.sha1(`` to ``<x>.sha256(``."""
    fixed = _QUALIFIED_WEAK_HASH.sub(".sha256(", line)
    return fixed if fixed != line else None


def fix_yaml_load(line: str) -> str | None:
    """Rewrite ``yaml.load(`` to ``yaml.safe_load(`` unless a Loader is already specified."""
    if "yaml.load(" not in line:
        return None
    if "safe_load" in line or "Loader" in line:
        # Already safe, or an explicit Loader is in play (safe_load takes no Loader): skip.
        return None
    fixed = _YAML_LOAD.sub("yaml.safe_load(", line)
    return fixed if fixed != line else None


def fix_allow_privilege_escalation(line: str) -> str | None:
    """Flip ``allowPrivilegeEscalation: true`` to ``false`` (Kubernetes securityContext)."""
    fixed = _PRIVILEGE_ESCALATION.sub(r"\1false", line)
    return fixed if fixed != line else None


def fix_privileged(line: str) -> str | None:
    """Flip ``privileged: true`` to ``false`` (Compose / Kubernetes securityContext)."""
    fixed = _PRIVILEGED.sub(r"\1false", line)
    return fixed if fixed != line else None
