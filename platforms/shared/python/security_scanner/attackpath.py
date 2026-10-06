"""Correlate individual findings into named attack paths.

Deterministic post-processing: it groups a scan's findings by target and emits a
higher-level ``attack-path.*`` finding when a combination that materially raises
impact is present (e.g. an SSRF that reaches cloud metadata, or an exposed service
with no authentication). This turns a flat finding list into "why this is
exploitable end to end" without any model — the LLM narrative (``ai.narrate``) is
a separate, opt-in enrichment layered on top.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Sequence
from pathlib import Path

from .models import Finding

# Each chain: (id, severity, title, why, trigger rule_ids). A chain fires when the
# target has at least one triggering rule_id. Ordered most-severe first.
_CHAINS: tuple[tuple[str, str, str, str, frozenset[str]], ...] = (
    (
        "attack-path.metadata-credential-theft", "critical",
        "SSRF → cloud metadata → instance credential theft",
        ("A server-side request forgery reaches the instance metadata service; its IAM "
         "credentials can be read and reused to pivot into the cloud account."),
        frozenset({"web.ssrf-cloud-metadata"}),
    ),
    (
        "attack-path.docker-host-takeover", "critical",
        "Exposed Docker API → container escape → host takeover",
        ("The Docker Engine API answers without authentication; it can launch a "
         "privileged container that mounts and controls the host filesystem."),
        frozenset({"net.docker-unauth"}),
    ),
    (
        "attack-path.injection-to-compromise", "critical",
        "Injection → server command/data compromise",
        ("A confirmed injection executes attacker input on the server or database, "
         "enabling data theft or remote code execution."),
        frozenset({
            "web.sql-injection-exploited", "web.command-injection-exploited",
            "web.command-injection-oob", "web.ssti-exploited",
        }),
    ),
    (
        "attack-path.unauthenticated-data-store", "high",
        "Exposed data store → unauthenticated read/write",
        ("A data store is reachable from this network without credentials; its "
         "contents can be read or altered directly."),
        frozenset({"net.redis-unauth", "net.elasticsearch-unauth", "net.couchdb-unauth"}),
    ),
    (
        "attack-path.default-credential-takeover", "high",
        "Default credentials → administrative takeover",
        ("A published default credential is accepted, giving an attacker the "
         "privileges of that account without any exploitation."),
        frozenset({"net.default-credentials"}),
    ),
)


def correlate(findings: Sequence[Finding]) -> list[Finding]:
    """Return one ``attack-path.*`` finding per chain present on each target."""
    by_target: dict[str, set[str]] = defaultdict(set)
    sample_path: dict[str, str] = {}
    for finding in findings:
        key = finding.target or str(finding.path)
        by_target[key].add(finding.rule_id)
        sample_path.setdefault(key, str(finding.path))

    results: list[Finding] = []
    for target, rule_ids in by_target.items():
        for path_id, severity, title, why, triggers in _CHAINS:
            hit = rule_ids & triggers
            if not hit:
                continue
            results.append(_path_finding(
                path_id, severity, title, why, target, sample_path.get(target, target), sorted(hit)
            ))
    return results


def _path_finding(
    path_id: str, severity: str, title: str, why: str,
    target: str, path: str, contributing: Iterable[str],
) -> Finding:
    chain = ", ".join(contributing)
    return Finding(
        rule_id=path_id, category="web", severity=severity, title=title,
        path=Path(path), target=target,
        evidence=f"chained from: {chain}",
        description=why,
        recommendation="Break the chain at any link: fix the underlying finding(s) and restrict exposure/credentials.",
        resource=f"attack-path/{target}",
    )
