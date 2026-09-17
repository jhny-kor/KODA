from __future__ import annotations

import json
import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .integrations import (
    ZAP_AUTOMATION_REPORT_PREFIX,
    ZAP_REPORT_PREFIX,
    build_zap_plan,
    render_zap_plan,
    zap_automation_command,
    zap_scan_command,
)
from .models import Finding


RISK_TO_SEVERITY = {
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "info",
    "info": "info",
}


@dataclass(frozen=True)
class ZAPRunResult:
    exit_code: int
    command: str
    output_dir: Path
    findings: tuple[Finding, ...]
    stdout: str = ""
    stderr: str = ""


def _run_zap_command(command: str, timeout_seconds: int) -> subprocess.CompletedProcess[str]:
    """Run the validated Docker command without invoking a shell."""
    _, separator, docker_command = command.partition("&&")
    if not separator:
        raise ValueError("ZAP command is missing its Docker command")
    docker_command = docker_command.strip().replace("$PWD/", f"{Path.cwd()}/", 1)
    return subprocess.run(
        shlex.split(docker_command),
        text=True,
        capture_output=True,
        timeout=timeout_seconds,
        check=False,
    )


def run_zap_scan(
    target_url: str,
    *,
    output_dir: Path,
    mode: str = "baseline",
    minutes: int = 1,
    context_file: str | None = None,
    user: str | None = None,
    min_level: str | None = None,
    api_format: str | None = None,
    dry_run: bool = False,
    timeout_seconds: int = 900,
) -> ZAPRunResult:
    command = zap_scan_command(
        target_url,
        mode=mode,
        output_dir=str(output_dir),
        minutes=minutes,
        context_file=context_file,
        user=user,
        min_level=min_level,
        api_format=api_format,
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    if dry_run:
        return ZAPRunResult(exit_code=0, command=command, output_dir=output_dir, findings=())

    completed = _run_zap_command(command, timeout_seconds)
    json_path = output_dir / f"{ZAP_REPORT_PREFIX[mode]}.json"
    findings = tuple(findings_from_zap_json(json_path, target_url=target_url)) if json_path.exists() else ()
    return ZAPRunResult(
        exit_code=completed.returncode,
        command=command,
        output_dir=output_dir,
        findings=findings,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )


def run_zap_automation(
    target_url: str,
    *,
    output_dir: Path,
    minutes: int = 1,
    ajax_spider: bool = False,
    active_scan: bool = False,
    include_paths: tuple[str, ...] = (),
    exclude_paths: tuple[str, ...] = (),
    openapi_url: str | None = None,
    openapi_file: str | None = None,
    auth: dict[str, object] | None = None,
    zap_rps: float | None = None,
    zap_threads_per_host: int | None = None,
    zap_rule_minutes: int | None = None,
    max_response_bytes: int | None = None,
    plan_filename: str = "koda-zap-plan.yaml",
    image: str | None = None,
    host_mappings: tuple[tuple[str, str], ...] = (),
    environment_vars: tuple[str, ...] = (),
    pull_never: bool = False,
    dry_run: bool = False,
    timeout_seconds: int = 1800,
) -> ZAPRunResult:
    """Run a ZAP Automation Framework plan, writing it into ``output_dir`` first."""
    plan = build_zap_plan(
        target_url,
        minutes=minutes,
        ajax_spider=ajax_spider,
        active_scan=active_scan,
        include_paths=include_paths,
        exclude_paths=exclude_paths,
        openapi_url=openapi_url,
        openapi_file=openapi_file,
        auth=auth,
        zap_rps=zap_rps,
        zap_threads_per_host=zap_threads_per_host,
        zap_rule_minutes=zap_rule_minutes,
        max_response_bytes=max_response_bytes,
    )
    command = zap_automation_command(
        str(output_dir),
        plan_filename=plan_filename,
        image=image,
        host_mappings=host_mappings,
        environment_vars=environment_vars,
        pull_never=pull_never,
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / plan_filename).write_text(render_zap_plan(plan), encoding="utf-8")
    if dry_run:
        return ZAPRunResult(exit_code=0, command=command, output_dir=output_dir, findings=())

    completed = _run_zap_command(command, timeout_seconds)
    json_path = output_dir / f"{ZAP_AUTOMATION_REPORT_PREFIX}.json"
    findings = tuple(findings_from_zap_json(json_path, target_url=target_url)) if json_path.exists() else ()
    return ZAPRunResult(
        exit_code=completed.returncode,
        command=command,
        output_dir=output_dir,
        findings=findings,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )


def run_zap_baseline(
    target_url: str,
    *,
    output_dir: Path,
    minutes: int = 1,
    dry_run: bool = False,
    timeout_seconds: int = 900,
) -> ZAPRunResult:
    """Passive baseline scan (back-compat wrapper over :func:`run_zap_scan`)."""
    return run_zap_scan(
        target_url,
        output_dir=output_dir,
        mode="baseline",
        minutes=minutes,
        dry_run=dry_run,
        timeout_seconds=timeout_seconds,
    )


def findings_from_zap_json(path: Path, *, target_url: str = "") -> list[Finding]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    findings: list[Finding] = []
    for alert in _iter_alerts(payload):
        risk = str(alert.get("riskdesc") or alert.get("risk") or "informational")
        severity = _severity_from_risk(risk)
        name = str(alert.get("name") or alert.get("alert") or "ZAP baseline finding")
        plugin_id = str(alert.get("pluginid") or alert.get("pluginId") or "unknown")
        instances = _alert_instances(alert)
        uri = (instances[0]["uri"] if instances else "") or _first_uri(alert) or target_url
        findings.append(
            Finding(
                rule_id=f"dast.zap.{plugin_id}",
                category="configuration",
                severity=severity,
                title=f"ZAP: {name}",
                path=Path(uri or target_url or path),
                evidence=_format_instances(alert, instances),
                description=_format_description(alert, plugin_id),
                recommendation=_plain_text(str(alert.get("solution") or alert.get("recommendation") or "Review the ZAP alert and remediate the affected endpoint.")),
            )
        )
    return findings


def _alert_instances(alert: dict[str, object]) -> list[dict[str, str]]:
    """All affected instances with method/param/attack/evidence preserved."""
    raw = alert.get("instances")
    result: list[dict[str, str]] = []
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict) and item.get("uri"):
                result.append(
                    {
                        "uri": str(item.get("uri") or ""),
                        "method": str(item.get("method") or "GET"),
                        "param": str(item.get("param") or ""),
                        "attack": str(item.get("attack") or ""),
                        "evidence": str(item.get("evidence") or ""),
                    }
                )
    return result


def _format_instances(alert: dict[str, object], instances: list[dict[str, str]], limit: int = 20) -> str:
    """Preserve every affected URL (not just the first) with request detail."""
    if not instances:
        return str(alert.get("evidence") or alert.get("param") or alert.get("uri") or "")
    lines: list[str] = []
    for inst in instances[:limit]:
        line = f"{inst['method']} {inst['uri']}".strip()
        extra = [f"{k}={inst[k]}" for k in ("param", "attack", "evidence") if inst[k]]
        if extra:
            line += " (" + ", ".join(extra) + ")"
        lines.append(line)
    if len(instances) > limit:
        lines.append(f"... +{len(instances) - limit} more affected URL(s)")
    return "\n".join(lines)


def _format_description(alert: dict[str, object], plugin_id: str) -> str:
    """Prepend ZAP classification metadata (CWE/WASC/confidence/plugin) to the text."""
    meta: list[str] = []
    for key, label in (("cweid", "CWE"), ("wascid", "WASC"), ("confidence", "Confidence")):
        value = str(alert.get(key) or "").strip()
        if value and value not in {"-1", "0"}:
            meta.append(f"{label}={value}")
    meta.append(f"PluginID={plugin_id}")
    parts = [f"[{', '.join(meta)}]"]
    desc = _plain_text(str(alert.get("desc") or alert.get("description") or ""))
    if desc:
        parts.append(desc)
    reference = _plain_text(str(alert.get("reference") or ""))
    if reference:
        parts.append(f"Reference: {reference}")
    return "\n".join(parts)


def render_zap_findings_json(findings: list[Finding] | tuple[Finding, ...]) -> str:
    return json.dumps(
        [
            {
                "rule_id": finding.rule_id,
                "category": finding.category,
                "severity": finding.severity,
                "title": finding.title,
                "path": str(finding.path),
                "evidence": finding.evidence,
                "description": finding.description,
                "recommendation": finding.recommendation,
            }
            for finding in findings
        ],
        indent=2,
        ensure_ascii=False,
    )


def _iter_alerts(payload: object):
    if isinstance(payload, dict):
        alerts = payload.get("alerts")
        if isinstance(alerts, list):
            yield from (alert for alert in alerts if isinstance(alert, dict))
        site = payload.get("site")
        if isinstance(site, list):
            for site_item in site:
                if isinstance(site_item, dict):
                    site_alerts = site_item.get("alerts")
                    if isinstance(site_alerts, list):
                        yield from (alert for alert in site_alerts if isinstance(alert, dict))
    elif isinstance(payload, list):
        yield from (alert for alert in payload if isinstance(alert, dict))


def _severity_from_risk(risk: str) -> str:
    lowered = risk.lower().split()[0].strip("()")
    return RISK_TO_SEVERITY.get(lowered, "info")


def _first_uri(alert: dict[str, object]) -> str:
    instances = alert.get("instances")
    if isinstance(instances, list):
        for item in instances:
            if isinstance(item, dict) and item.get("uri"):
                return str(item["uri"])
    return str(alert.get("uri") or alert.get("url") or "")


def _plain_text(value: str) -> str:
    return value.replace("<p>", "").replace("</p>", "").replace("<br>", "\n").strip()
