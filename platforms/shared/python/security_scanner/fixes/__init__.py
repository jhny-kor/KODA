"""Opt-in auto-fix layer.

Maps finding ``rule_id`` values to deterministic, line-scoped fixers. Only findings whose
rule has a registered fixer can be auto-fixed; everything else is left for manual review.
Fixes are never applied automatically — see ``apply.py`` for the dry-run / ``--apply`` gate.
"""

from __future__ import annotations

from collections.abc import Callable

from . import deterministic

LineFixer = Callable[[str], "str | None"]

# rule_id -> fixer. A fixer returns the corrected line or None when it changes nothing.
FIXERS: dict[str, LineFixer] = {
    "code.weak-hash": deterministic.fix_weak_hash,
    "code.unsafe-deserialization": deterministic.fix_yaml_load,
    "config.k8s-allow-privilege-escalation": deterministic.fix_allow_privilege_escalation,
    "config.compose-privileged": deterministic.fix_privileged,
    "config.k8s-privileged-container": deterministic.fix_privileged,
}


def fixer_for(rule_id: str) -> LineFixer | None:
    return FIXERS.get(rule_id)


def is_fixable(rule_id: str) -> bool:
    return rule_id in FIXERS
