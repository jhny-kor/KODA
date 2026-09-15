from __future__ import annotations

import json
import os
import platform
import secrets
import subprocess
import tempfile
import time
from dataclasses import replace
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from .archive_input import prepare_input_target
from .config import expand_path
from .dependency_inventory import queryable_osv_components
from .grype_adapter import GrypeMatch, inspect_grype, run_grype_purls
from .models import CATEGORIES, DEFAULT_CATEGORIES, SCAN_SCOPE_CATEGORIES, SEVERITIES, Finding, ScannerConfig, TargetConfig
from .reporting import (
    build_dashboard_payload,
    build_rule_catalog,
    filter_by_min_severity,
    filter_disabled_rules,
    render_html,
    render_html_pair_zip_from_payload,
    render_hwpx,
    render_markdown_from_payload,
    render_pdf,
    PdfExportError,
    render_xlsx,
)
from .scanner import SecurityScanner
from .standards import (
    DEFAULT_STANDARD,
    DEFAULT_STANDARD_CATEGORY,
    SECURITY_STANDARD_IDS,
    filter_findings_by_standard,
    resolve_standard_selection,
)
from .web_audit import approve_request, plan_profile, run_web_audit


DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765
LOCAL_CORS_HOSTS = {"127.0.0.1", "localhost", "::1"}
DEFAULT_UPLOAD_MAX_BYTES = 256 * 1024 * 1024
DEFAULT_UPLOAD_MAX_EXTRACTED_BYTES = 256 * 1024 * 1024
DEFAULT_UPLOAD_MAX_FILES = 10_000


class UploadTooLargeError(ValueError):
    pass


def create_dashboard_server(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT, language: str = "ko") -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), _handler(language))
    server.daemon_threads = True
    server.koda_session_token = secrets.token_urlsafe(32)
    return server


def dashboard_url(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> str:
    display_host = "127.0.0.1" if host in {"", "0.0.0.0"} else host
    return f"http://{display_host}:{port}/security-dashboard.html"


def serve_dashboard(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT, language: str = "ko") -> int:
    server = create_dashboard_server(host, port, language)
    url = dashboard_url(host, port)
    print(f"Serving local security dashboard: {url}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping local security dashboard.")
    finally:
        server.server_close()
    return 0


def scan_directory_payload(
    path_value: str,
    *,
    language: str = "ko",
    min_severity: str = "low",
    discover_projects: bool = True,
    discovery_depth: int | None = None,
    categories: tuple[str, ...] = DEFAULT_CATEGORIES,
    standard: str = DEFAULT_STANDARD,
    standard_category: str = DEFAULT_STANDARD_CATEGORY,
    max_file_size_bytes: int = 524288,
    base_dir: Path | None = None,
    enable_osv: bool = False,
    enable_local_vulnerabilities: bool = False,
    grype_binary: Path | None = None,
    include_host: bool = False,
    disabled_rules: tuple[str, ...] = (),
    allow_file: bool = False,
    display_path: str | None = None,
    scan_scope: str | None = None,
    cve_only: bool = False,
) -> dict[str, object]:
    if min_severity not in SEVERITIES:
        raise ValueError(f"Unsupported min_severity: {min_severity}")
    unknown_categories = sorted(set(categories) - set(CATEGORIES))
    if unknown_categories:
        raise ValueError(f"Unsupported categories: {', '.join(unknown_categories)}")
    standard_selection = resolve_standard_selection(standard, standard_category, categories)
    scanner_categories = standard_selection.scanner_categories
    if scan_scope is not None:
        if scan_scope not in SCAN_SCOPE_CATEGORIES:
            raise ValueError(f"Unsupported scan scope: {scan_scope}")
        allowed_categories = set(SCAN_SCOPE_CATEGORIES[scan_scope])
        scanner_categories = tuple(category for category in scanner_categories if category in allowed_categories)
        if not scanner_categories:
            raise ValueError(f"Selected standard has no checks for the {scan_scope} scan")
    if include_host and standard_selection.standard != "sw-dev-security-49" and "host" not in scanner_categories:
        scanner_categories = scanner_categories + ("host",)
    if discovery_depth is not None and discovery_depth < 0:
        raise ValueError("discovery_depth must be zero or greater")
    if max_file_size_bytes <= 0:
        raise ValueError("max_file_size_bytes must be positive")

    target_path = expand_path(path_value, base_dir or Path.cwd())
    if not target_path.exists():
        raise ValueError(f"Path does not exist: {target_path}")
    if not target_path.is_dir() and not (allow_file and target_path.is_file()):
        raise ValueError(f"Path is not a directory: {target_path}")

    target = TargetConfig(
        name=target_path.name or "scan-target",
        path=target_path,
        categories=scanner_categories,
        max_file_size_bytes=max_file_size_bytes,
        discover_projects=discover_projects and target_path.is_dir(),
        discovery_depth=discovery_depth,
    )
    source_only = standard_selection.standard == "sw-dev-security-49"
    config = ScannerConfig(
        targets=(target,),
        enable_osv=enable_osv and not source_only,
        enable_vuln_intel=enable_osv and not source_only,
        standard=standard_selection.standard,
        standard_category=standard_selection.category,
    )
    scanner = SecurityScanner(config)
    scan_result = scanner.scan()
    raw_findings = list(scan_result.findings)
    if cve_only:
        # Library scans report only CVE-backed Grype findings; dependency
        # hygiene and other advisory sources remain available to normal scans.
        raw_findings = [item for item in raw_findings if item.category != "dependencies"]
    scan_warnings = list(scanner.warnings)
    library_vulnerabilities: list[dict[str, object]] = []
    local_vulnerability: dict[str, object] = {
        "status": "disabled",
        "queried_components": 0,
        "matched_vulnerabilities": 0,
    }
    if source_only:
        local_vulnerability["status"] = "skipped"
        local_vulnerability["warning"] = "선택한 소스코드 전용 기준은 라이브러리 취약점 점검을 실행하지 않습니다."
    elif enable_local_vulnerabilities:
        components = queryable_osv_components(scanner.components)
        binary = grype_binary or _environment_path("KODA_GRYPE_BIN")
        local_vulnerability.update(inspect_grype(binary))
        local_vulnerability["queried_components"] = len(tuple(component for component in components if component.purl))
        grype = run_grype_purls(
            tuple(component.purl for component in components if component.purl),
            binary,
            300.0,
        )
        grype_matches = tuple(match for match in grype.matches if not cve_only or match.cve_ids)
        raw_findings.extend(_grype_findings(grype_matches, components))
        library_vulnerabilities = _grype_vulnerability_payloads(grype_matches, components, binary)
        local_vulnerability["matched_vulnerabilities"] = len(grype_matches)
        local_vulnerability["status"] = "failed" if grype.fatal or not local_vulnerability.get("available") else ("warning" if grype.warning or local_vulnerability.get("warning") else "completed")
        for warning in (local_vulnerability.get("warning"), grype.warning):
            if warning and str(warning) not in scan_warnings:
                scan_warnings.append(str(warning))
    findings = filter_findings_by_standard(raw_findings, standard_selection)
    if include_host:
        # Host posture is opt-in and orthogonal to the selected standard's rule_id
        # filter, so keep host findings that the standard filter would have dropped.
        host_findings = [item for item in raw_findings if item.category == "host"]
        findings = findings + [item for item in host_findings if item not in findings]
    findings = filter_by_min_severity(findings, min_severity)
    findings = filter_disabled_rules(findings, disabled_rules)
    effective_targets = scanner.effective_targets or config.targets
    target_names = tuple(item.name for item in effective_targets)
    target_paths = {item.name: display_path or str(item.path) for item in effective_targets}
    payload = build_dashboard_payload(
        findings,
        target_names,
        language,
        target_paths=target_paths,
        warnings=tuple(scan_warnings),
        scan_path=display_path or str(target_path),
        kind="upload" if display_path else "directory",
        standard=standard_selection.standard,
        standard_category=standard_selection.category,
        components=scanner.components,
        enable_osv=enable_osv,
        scanned_categories=scanner_categories,
        source_analysis=scan_result.source_analysis,
    )
    payload["scan"]["enable_local_vulnerabilities"] = enable_local_vulnerabilities
    payload["scan"]["local_vulnerability"] = local_vulnerability
    payload["scan"]["scope"] = scan_scope or "all"
    if library_vulnerabilities:
        payload["vulnerabilities"] = library_vulnerabilities
    return _replace_upload_path(payload, str(target_path.resolve()), display_path) if display_path else payload


def _environment_path(name: str) -> Path | None:
    value = os.environ.get(name, "").strip()
    return Path(value).expanduser() if value else None


def _grype_findings(matches: tuple[GrypeMatch, ...], components) -> list[Finding]:
    by_purl = {component.purl: component for component in components if component.purl}
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for match in matches:
        component = by_purl.get(match.purl) or next(
            (item for item in components if item.name == match.package_name and item.version == match.installed_version),
            None,
        )
        if component is None:
            continue
        identifiers = match.cve_ids or match.vulnerability_ids or (match.vulnerability_id,)
        key = component.purl, ",".join(identifiers)
        if key in seen:
            continue
        seen.add(key)
        fixed = ", ".join(match.fixed_versions)
        findings.append(Finding(
            rule_id="dependency.osv-known-vulnerability",
            category="dependencies",
            severity=match.severity if match.severity in SEVERITIES else "high",
            title=f"Known vulnerable dependency: {component.name}@{component.version}",
            path=component.path,
            target=component.target,
            line=component.line,
            evidence=f"{component.purl}: {', '.join(identifiers)}" + (f"; fixed in {fixed}" if fixed else ""),
            description="The bundled local Grype database reports a vulnerability for this exact dependency version.",
            recommendation=f"Upgrade to {fixed}." if fixed else "Review the vulnerability identifiers and upgrade, patch, replace, or document a compensating control.",
            issue_key=f"dependency.osv-known-vulnerability|{component.purl}|{','.join(sorted(identifiers))}",
        ))
    return findings


def _grype_vulnerability_payloads(matches: tuple[GrypeMatch, ...], components, grype_binary: Path | None = None) -> list[dict[str, object]]:
    """Build report-ready library records from the pinned offline feeds."""
    try:
        from .data_release import vulnerability_paths
        from .offline_vuln_data import load_offline_data
        nvd_path, kev_path = vulnerability_paths()
        ids = tuple(identifier for match in matches for identifier in match.cve_ids)
        data = load_offline_data(nvd_path, kev_path, ids)
    except (ImportError, OSError, TypeError, ValueError):
        data = None
    by_purl = {component.purl: component for component in components if component.purl}
    records = []
    for match in matches:
        component = by_purl.get(match.purl) or next((item for item in components if item.name == match.package_name and item.version == match.installed_version), None)
        if component is None:
            continue
        cve_ids = tuple(match.cve_ids or (match.vulnerability_id,))
        nvd_records = {cve: data.nvd.get(cve, {}) for cve in cve_ids} if data is not None else {}
        nvd = next((value for value in nvd_records.values() if isinstance(value, dict) and value), {})
        kev = next((data.cisa_kev.get(cve, {}) for cve in cve_ids), {}) if data is not None else {}
        cvss_score = max((_nvd_cvss(record) for record in nvd_records.values()), default=None)
        advisories = [{
            "vulnerability_id": cve, "vulnerability_ids": [cve], "cve_ids": [cve],
            "fixed_versions": list(match.fixed_versions), "severity": match.severity,
            "cvss_score": _nvd_cvss(nvd_records.get(cve, {})),
            "known_exploited": bool(data and data.cisa_kev.get(cve)),
            "nvd": nvd_records.get(cve, {}), "cisa_kev": data.cisa_kev.get(cve, {}) if data else {},
            "locations": list(match.locations or (str(component.path),)), "match_details": list(match.match_details),
        } for cve in cve_ids]
        final_version = ""
        final_status = "unresolved"
        final_checked_versions: tuple[str, ...] = ()
        if grype_binary is not None and match.fixed_versions and getattr(component, "purl", ""):
            # Reuse the Windows library-report verifier at scan time so the
            # Linux payload remains complete when exported after the target
            # checkout or Grype process is gone.
            from types import SimpleNamespace
            from .java_vulnerability_scan import _resolve_final_version
            final_version, final_status, final_checked_versions, _ = _resolve_final_version(
                SimpleNamespace(
                    component_purl=component.purl,
                    component_name=component.name,
                    installed_version=component.version,
                    fixed_versions=tuple(match.fixed_versions),
                ),
                grype_binary,
                300.0,
            )
        records.append({
            "vulnerability_id": match.vulnerability_id, "vulnerability_ids": list(match.vulnerability_ids or (match.vulnerability_id,)), "cve_ids": list(match.cve_ids),
            "component_name": component.name, "installed_version": component.version, "fixed_versions": list(match.fixed_versions),
            "severity": match.severity, "cvss_score": cvss_score, "known_exploited": bool(kev), "nvd": nvd, "cisa_kev": kev,
            "locations": list(match.locations or (str(component.path),)), "identity_status": getattr(component, "identity_status", "resolved"),
            "recommendation": f"Upgrade to {', '.join(match.fixed_versions)}." if match.fixed_versions else "Review the advisory and remediate with the vendor-supported release.",
            "match_details": list(match.match_details),
            "advisories": advisories,
            "final_version": final_version,
            "final_status": final_status,
            "final_checked_versions": list(final_checked_versions),
        })
    return records


def _nvd_cvss(record: object) -> float | None:
    if not isinstance(record, dict):
        return None
    cvss = record.get("cvss")
    if isinstance(cvss, dict):
        values = [value.get("baseScore") for value in cvss.values() if isinstance(value, dict)]
        numeric = [float(value) for value in values if isinstance(value, (int, float))]
        if numeric:
            return max(numeric)
    metrics = record.get("metrics")
    if isinstance(metrics, dict):
        values = []
        for entries in metrics.values():
            if isinstance(entries, list):
                values.extend(entry.get("cvssData", {}).get("baseScore") for entry in entries if isinstance(entry, dict) and isinstance(entry.get("cvssData"), dict))
        numeric = [float(value) for value in values if isinstance(value, (int, float))]
        if numeric:
            return max(numeric)
    return None


def _replace_upload_path(value: Any, private_path: str, public_path: str) -> Any:
    if isinstance(value, dict):
        return {key: _replace_upload_path(item, private_path, public_path) for key, item in value.items()}
    if isinstance(value, list):
        return [_replace_upload_path(item, private_path, public_path) for item in value]
    if isinstance(value, str):
        return value.replace(private_path, public_path)
    return value


def web_scan_payload(
    url: str,
    *,
    language: str = "ko",
    min_severity: str = "info",
    timeout: float = 15.0,
    crawl: bool = False,
    # ponytail: bounded interactive default; CLI flags cover larger authorized sites.
    max_pages: int | None = 50,
    max_depth: int | None = 3,
    delay: float = 0.3,
    render: bool = False,
    discover_assets: bool = False,
    capture_network: bool = False,
    interact: bool = False,
    max_clicks: int | None = None,
    seeds: tuple[str, ...] = (),
    scan_js_secrets: bool = False,
    ingest_sitemap: bool = False,
    probe_paths: bool = False,
    active: bool = False,
    compare_unauth: bool = False,
    secondary_headers_text: str = "",
    api_spec_text: str = "",
    auth: dict[str, object] | None = None,
    allowed_origins: tuple[str, ...] = (),
) -> dict[str, object]:
    if min_severity not in SEVERITIES:
        raise ValueError(f"Unsupported min_severity: {min_severity}")
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Enter an http(s) URL, e.g. https://example.com")

    from .web import build_auth_opener, crawl_web, login

    auth = auth or {}
    extra_headers = _headers_from_text(str(auth.get("headers") or ""))
    opener = build_auth_opener()
    warnings: list[str] = []
    auth_result: dict[str, object] = {
        "status": "not-requested",
        "login_url": "",
        "final_url": "",
        "session_cookie_received": False,
        "session_rotated": False,
        "message": "",
    }
    login_url = str(auth.get("login_url") or "").strip()
    if login_url:
        username = str(auth.get("username") or "")
        password = str(auth.get("password") or "")
        if not username or not password:
            raise ValueError("Form login requires both a username and a password.")
        login_warnings, login_findings = login(
            opener,
            login_url,
            username,
            password,
            user_field=(str(auth.get("user_field")) or None) if auth.get("user_field") else None,
            pass_field=(str(auth.get("pass_field")) or None) if auth.get("pass_field") else None,
            timeout=timeout,
            result=auth_result,
        )
        warnings.extend(login_warnings)
    else:
        login_findings = []
    origins = _validated_origins(url, allowed_origins)

    seeds = tuple(seeds)
    if api_spec_text.strip():
        from .api_spec import parse_api_spec

        spec_urls, spec_warnings = parse_api_spec(api_spec_text, url)
        seeds = seeds + tuple(spec_urls)
        warnings.extend(spec_warnings)
    secondary_headers = _headers_from_text(secondary_headers_text)

    scanned_pages: list[str] = []
    page_results: list[dict[str, object]] = []
    findings, crawl_warnings, pages = crawl_web(
        url,
        timeout=timeout,
        max_pages=max_pages if (crawl or seeds) else 1,
        max_depth=max_depth if crawl else 0,
        delay=delay,
        opener=opener,
        extra_headers=extra_headers or None,
        render=render,
        discover_assets=discover_assets,
        capture_network=capture_network,
        interact=interact,
        max_clicks=max_clicks,
        seeds=seeds,
        scan_js_secrets=scan_js_secrets,
        ingest_sitemap=ingest_sitemap,
        probe_paths=probe_paths,
        active=active,
        compare_unauth=compare_unauth,
        secondary_headers=secondary_headers or None,
        scanned_pages=scanned_pages,
        page_results=page_results,
        allowed_origins=origins,
    )
    warnings.extend(crawl_warnings)
    if auth_result["status"] == "uncertain" and any(item["auth_state"] == "authenticated" for item in page_results):
        auth_result["status"] = "authenticated"
        auth_result["message"] = "Authenticated content was reached during the crawl."
    findings = filter_by_min_severity(login_findings + list(findings), min_severity)
    target_name = parsed.netloc
    payload = build_dashboard_payload(
        findings,
        (target_name,),
        language,
        target_paths={target_name: url},
        warnings=tuple(warnings),
        scan_path=url,
        kind="web",
    )
    payload["pages_scanned"] = pages
    payload["scanned_pages"] = scanned_pages
    payload["page_results"] = page_results
    payload["auth"] = auth_result
    return payload


def _require_docker() -> None:
    """Fail with a clear, actionable message when Docker is unusable for ZAP.

    ZAP scans run as a ``docker run`` shell-out; without this precheck the caller
    gets a cryptic ``command not found`` / exit-code from deep inside the run.
    """
    try:
        probe = subprocess.run(
            ["docker", "info"], capture_output=True, text=True, timeout=20, check=False
        )
    except FileNotFoundError as exc:
        raise ValueError(
            "Docker is required for ZAP scans but was not found on PATH. "
            "Install Docker Desktop / Engine and retry."
        ) from exc
    except (OSError, subprocess.SubprocessError) as exc:
        raise ValueError(f"Docker could not be reached: {exc}") from exc
    if probe.returncode != 0:
        raise ValueError(
            "Docker is installed but the daemon is not running or not reachable. "
            "Start Docker and retry."
        )


def zap_scan_payload(
    url: str,
    *,
    language: str = "ko",
    min_severity: str = "info",
    ajax_spider: bool = False,
    active_scan: bool = False,
    authorization_confirmed: bool = False,
    minutes: int = 1,
    include_paths: tuple[str, ...] = (),
    exclude_paths: tuple[str, ...] = (),
    auth: dict[str, object] | None = None,
    merge: dict[str, object] | None = None,
    output_dir: Path | None = None,
    dry_run: bool = False,
    timeout_seconds: int = 1800,
) -> dict[str, object]:
    """Run an OWASP ZAP Automation Framework plan and return a dashboard payload.

    Wraps the existing :func:`security_scanner.dast.run_zap_automation` (spider +
    optional AJAX spider + optional active scan, plus an optional authenticated
    Context) so the local dashboard can drive the ZAP engine that already ships in
    this repo. Active scanning sends real attack traffic, so it is gated behind
    ``authorization_confirmed``.
    """
    if min_severity not in SEVERITIES:
        raise ValueError(f"Unsupported min_severity: {min_severity}")
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Enter an http(s) URL, e.g. https://staging.example.com")
    if active_scan and not authorization_confirmed:
        raise ValueError(
            "Active scan sends real attack traffic. Confirm you own or are "
            "explicitly authorized to test this target before enabling it."
        )
    zap_auth = _zap_auth_from_request(auth)
    if not dry_run:
        _require_docker()

    from .dast import run_zap_automation

    out_dir = output_dir or Path("reports") / "zap" / f"koda-zap-{int(time.time())}"
    try:
        result = run_zap_automation(
            url,
            output_dir=out_dir,
            minutes=minutes,
            ajax_spider=ajax_spider,
            active_scan=active_scan,
            include_paths=include_paths,
            exclude_paths=exclude_paths,
            auth=zap_auth,
            dry_run=dry_run,
            timeout_seconds=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        raise ValueError(f"ZAP scan timed out after {timeout_seconds}s.") from exc
    except (OSError, subprocess.SubprocessError) as exc:
        raise ValueError(f"ZAP scan could not run: {exc}") from exc

    target_name = parsed.netloc
    # Attribute every ZAP finding to the scanned host so it groups under that
    # target in the results table (ZAP JSON has no per-finding target field).
    zap_findings = [replace(finding, target=target_name) for finding in result.findings]
    findings = filter_by_min_severity(zap_findings, min_severity)
    warnings: list[str] = []
    # A non-zero exit with no parsed findings means the run itself failed
    # (unreachable target, bad plan, ZAP error) rather than "clean scan".
    if not dry_run and result.exit_code != 0 and not findings:
        tail = (result.stderr or result.stdout or "").strip()[-500:]
        warnings.append(
            f"ZAP exited with code {result.exit_code} and produced no findings. {tail}".strip()
        )

    if merge:
        # Fold the ZAP (DAST) findings into the currently displayed report so one
        # results table and one export hold both static and dynamic findings. The
        # prior report is rebuilt through the same pipeline, keeping every summary
        # count, category, and risk score authoritative (no client-side math).
        prior_findings = _findings_from_payload(merge)
        prior_scan = merge.get("scan") if isinstance(merge.get("scan"), dict) else {}
        prior_summary = merge.get("summary") if isinstance(merge.get("summary"), dict) else {}
        prior_paths = prior_summary.get("target_paths") if isinstance(prior_summary.get("target_paths"), dict) else {}
        payload = build_dashboard_payload(
            prior_findings + findings,
            (),
            language,
            target_paths={**prior_paths, target_name: url},
            warnings=tuple(warnings) + tuple(str(w) for w in (prior_scan.get("warnings") or []) if isinstance(w, str)),
            scan_path=str(prior_scan.get("path") or url),
            kind=str(prior_scan.get("kind") or "directory"),
            standard=str(prior_scan.get("standard") or DEFAULT_STANDARD),
            standard_category=str(prior_scan.get("standard_category") or DEFAULT_STANDARD_CATEGORY),
            scanned_categories=tuple(
                str(item) for item in (prior_scan.get("scanned_categories") or []) if isinstance(item, str)
            ),
        )
        # SBOM/components are independent of findings; carry them over so a merged
        # report keeps the code scan's dependency inventory intact.
        if isinstance(merge.get("components"), list):
            payload["components"] = merge["components"]
        if isinstance(merge.get("sbom"), dict):
            payload["sbom"] = merge["sbom"]
    else:
        payload = build_dashboard_payload(
            findings,
            (target_name,),
            language,
            target_paths={target_name: url},
            warnings=tuple(warnings),
            scan_path=url,
            kind="web",
        )
    payload["zap"] = {
        "mode": "automation",
        "ajax_spider": ajax_spider,
        "active_scan": active_scan,
        "authenticated": zap_auth is not None,
        "merged": bool(merge),
        "exit_code": result.exit_code,
        "output_dir": str(result.output_dir),
        "command": result.command,
    }
    return payload


def _zap_auth_from_request(auth: dict[str, object] | None) -> dict[str, str] | None:
    """Normalize dashboard login fields into a ZAP Automation auth Context.

    Returns ``None`` when no login URL is supplied (unauthenticated scan). When a
    login URL is present, a username and password are required — an authenticated
    scan with blank credentials would silently degrade to an anonymous one.
    """
    auth = auth or {}
    login_url = str(auth.get("login_url") or "").strip()
    if not login_url:
        return None
    username = str(auth.get("username") or "")
    password = str(auth.get("password") or "")
    if not username or not password:
        raise ValueError("Authenticated ZAP scan requires both a username and a password.")
    zap_auth: dict[str, str] = {
        "method": str(auth.get("method") or "form"),
        "login_url": login_url,
        "username": username,
        "password": password,
    }
    for key in ("login_request_url", "login_body", "logged_in_regex", "logged_out_regex"):
        value = auth.get(key)
        if value:
            zap_auth[key] = str(value)
    return zap_auth


def _finding_from_payload(data: dict[str, object]) -> Finding:
    """Reconstruct a Finding from a dashboard finding payload (for merge/round-trip).

    The finding payload carries every Finding field, so a prior report's findings
    can be rebuilt and re-aggregated by the normal pipeline.
    """
    severity = str(data.get("severity") or "info")
    if severity not in SEVERITIES:
        severity = "info"
    line = data.get("line")
    confidence = data.get("triage_confidence")
    return Finding(
        rule_id=str(data.get("rule_id") or ""),
        category=str(data.get("category") or "configuration"),
        severity=severity,
        title=str(data.get("title") or ""),
        path=Path(str(data.get("path") or "")),
        target=str(data.get("target") or ""),
        line=line if isinstance(line, int) else None,
        evidence=str(data.get("evidence") or ""),
        description=str(data.get("description") or ""),
        recommendation=str(data.get("recommendation") or ""),
        resource=str(data.get("resource") or ""),
        reachable=str(data.get("reachable") or ""),
        verification_status=str(data.get("verification_status") or "confirmed"),
        verification_note=str(data.get("verification_note") or ""),
        triage_verdict=str(data.get("triage_verdict") or ""),
        triage_confidence=float(confidence) if isinstance(confidence, (int, float)) else None,
        triage_note=str(data.get("triage_note") or ""),
    )


def _findings_from_payload(payload: dict[str, object]) -> list[Finding]:
    """Reconstruct the (English, canonical) findings list from a dashboard payload."""
    by_language = payload.get("findings_by_language")
    raw = by_language.get("en") if isinstance(by_language, dict) else None
    if not isinstance(raw, list):
        return []
    return [_finding_from_payload(item) for item in raw if isinstance(item, dict)]


def _validated_origins(seed_url: str, raw_origins: tuple[str, ...]) -> tuple[str, ...]:
    origins = {_origin_value(seed_url)}
    for raw in raw_origins:
        parsed = urlparse(raw)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.path not in {"", "/"} or parsed.params or parsed.query or parsed.fragment:
            raise ValueError("Allowed origins must use exactly http(s)://host[:port].")
        origins.add(_origin_value(raw))
    return tuple(sorted(origins))


def _origin_value(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _headers_from_text(raw: str) -> dict[str, str]:
    """Parse a textarea of ``Name: value`` lines into a header dict.

    A line whose name-part contains ``=`` (or that has no colon at all) is a bare
    cookie string pasted from the browser (``a=b; c=d``); treat it as a Cookie
    value rather than dropping it — that silent drop is the common "I pasted a
    cookie and nothing happened" failure.
    """
    headers: dict[str, str] = {}
    bare_cookies: list[str] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        name, sep, value = line.partition(":")
        if sep and name.strip() and "=" not in name:
            if name.strip().lower() == "cookie":
                bare_cookies.append(value.strip())
            else:
                headers[name.strip()] = value.strip()
        else:
            bare_cookies.append(line)
    if bare_cookies:
        headers["Cookie"] = "; ".join(bare_cookies)
    return headers


PREVENTION_KIT_ACTIONS = {"toolkit", "hook", "ignore"}


def prevention_kit_payload(
    action: str,
    path_value: str,
    *,
    base_dir: Path | None = None,
) -> dict[str, object]:
    if action not in PREVENTION_KIT_ACTIONS:
        raise ValueError(f"Unsupported action: {action}")
    target_path = expand_path(path_value, base_dir or Path.cwd())
    if not target_path.exists():
        raise ValueError(f"Path does not exist: {target_path}")
    if not target_path.is_dir():
        raise ValueError(f"Path is not a directory: {target_path}")

    from .toolkit import (
        install_pre_commit_hook,
        write_ignore_template,
        write_security_template_files,
    )

    if action == "toolkit":
        results = write_security_template_files(target_path)
    elif action == "hook":
        results = [install_pre_commit_hook(target_path)]
    else:
        results = [write_ignore_template(target_path)]

    return {
        "action": action,
        "results": [{"path": str(item.path), "status": item.status} for item in results],
    }


def _handler(language: str):
    initial_html = render_html([], language=language)

    class DashboardHandler(BaseHTTPRequestHandler):
        server_version = "KODADashboard/0.1"

        def do_GET(self) -> None:
            path = urlparse(self.path).path
            if path in {"/", "/security-dashboard.html"}:
                self._send_html(initial_html)
                return
            if path == "/api/health":
                self._send_json({"ok": True})
                return
            if path == "/api/rules":
                lang = _choice_value_query(urlparse(self.path).query, "lang", {"en", "ko"}, language)
                self._send_json({"groups": build_rule_catalog(lang)})
                return
            self.send_error(HTTPStatus.NOT_FOUND)

        def do_OPTIONS(self) -> None:
            path = urlparse(self.path).path
            if path in {"/api/health", "/api/scan", "/api/scan-upload", "/api/web-scan", "/api/zap-scan", "/api/select-directory", "/api/prevention-kit", "/api/export", "/api/web-audit/plan", "/api/web-audit/approve", "/api/web-audit/run"}:
                if path.startswith("/api/web-audit/") and not self._require_web_audit_access(options=True):
                    return
                self.send_response(HTTPStatus.NO_CONTENT)
                self._send_cors_headers()
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self.send_error(HTTPStatus.NOT_FOUND)

        def do_POST(self) -> None:
            path = urlparse(self.path).path
            if path in {"/api/web-audit/plan", "/api/web-audit/approve", "/api/web-audit/run"}:
                if not self._require_web_audit_access():
                    return
                if path.endswith("/plan"):
                    self._handle_web_audit_plan()
                elif path.endswith("/approve"):
                    self._handle_web_audit_approve()
                else:
                    self._handle_web_audit_run()
                return
            if path == "/api/select-directory":
                self._handle_select_directory()
                return
            if path == "/api/scan-upload":
                self._handle_scan_upload()
                return
            if path == "/api/web-scan":
                self._handle_web_scan()
                return
            if path == "/api/zap-scan":
                self._handle_zap_scan()
                return
            if path == "/api/prevention-kit":
                self._handle_prevention_kit()
                return
            if path == "/api/export":
                self._handle_export()
                return
            if path != "/api/scan":
                self.send_error(HTTPStatus.NOT_FOUND)
                return

            try:
                request = self._read_json()
                payload = scan_directory_payload(
                    _string_value(request, "path"),
                    language=_choice_value(request, "language", {"en", "ko"}, language),
                    min_severity=_choice_value(request, "min_severity", set(SEVERITIES), "low"),
                    discover_projects=bool(request.get("discover_projects", True)),
                    discovery_depth=None,
                    categories=_categories_value(request),
                    standard=_choice_value(
                        request,
                        "standard",
                        set(SECURITY_STANDARD_IDS),
                        DEFAULT_STANDARD,
                    ),
                    standard_category=_string_value(request, "standard_category", default=DEFAULT_STANDARD_CATEGORY),
                    max_file_size_bytes=int(request.get("max_file_size_bytes", 524288)),
                    enable_osv=bool(request.get("enable_osv", False)),
                    include_host=bool(request.get("include_host", False)),
                    disabled_rules=_disabled_rules_value(request),
                )
            except (json.JSONDecodeError, TypeError, ValueError) as exc:
                self._send_json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
                return

            self._send_json(payload)

        def _handle_scan_upload(self) -> None:
            if not self._require_upload_access():
                return
            try:
                query = parse_qs(urlparse(self.path).query)
                filename = _upload_filename(self.headers.get("X-KODA-Filename"))
                max_upload_bytes = _environment_limit("KODA_UPLOAD_MAX_BYTES", DEFAULT_UPLOAD_MAX_BYTES)
                max_extracted_bytes = _environment_limit(
                    "KODA_UPLOAD_MAX_EXTRACTED_BYTES", DEFAULT_UPLOAD_MAX_EXTRACTED_BYTES
                )
                max_archive_files = _environment_limit("KODA_UPLOAD_MAX_FILES", DEFAULT_UPLOAD_MAX_FILES)
                with tempfile.TemporaryDirectory(prefix="koda-upload-") as temp_dir:
                    temp_root = Path(temp_dir)
                    upload_path = temp_root / filename
                    self._receive_upload(upload_path, max_upload_bytes)
                    target_path = prepare_input_target(
                        upload_path,
                        temp_root / "extracted",
                        max_files=max_archive_files,
                        max_bytes=max_extracted_bytes,
                    )
                    payload = scan_directory_payload(
                        str(target_path),
                        language=_query_choice(query, "language", {"en", "ko"}, language),
                        min_severity="low",
                        discover_projects=target_path.is_dir(),
                        discovery_depth=None,
                        categories=DEFAULT_CATEGORIES,
                        standard=_query_choice(query, "standard", set(SECURITY_STANDARD_IDS), DEFAULT_STANDARD),
                        standard_category=_query_text(query, "standard_category", DEFAULT_STANDARD_CATEGORY),
                        max_file_size_bytes=_environment_limit("KODA_UPLOAD_SCAN_MAX_FILE_BYTES", 10 * 1024 * 1024),
                        enable_osv=_query_flag(query, "enable_osv"),
                        include_host=False,
                        disabled_rules=tuple(query.get("disabled_rule", ())),
                        allow_file=True,
                        display_path=filename,
                    )
            except UploadTooLargeError as exc:
                self._send_json({"error": str(exc)}, status=HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
                return
            except (OSError, TypeError, ValueError) as exc:
                self._send_json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
                return
            self._send_json(payload)

        def _handle_web_scan(self) -> None:
            try:
                request = self._read_json(max_bytes=4_194_304)  # allow a pasted API spec
                if bool(request.get("active")) and not self._require_web_audit_access():
                    return
                auth = request.get("auth") if isinstance(request.get("auth"), dict) else {}
                payload = web_scan_payload(
                    _string_value(request, "url"),
                    language=_choice_value(request, "language", {"en", "ko"}, language),
                    min_severity=_choice_value(request, "min_severity", set(SEVERITIES), "info"),
                    timeout=_bounded_float(request.get("timeout"), default=10.0, low=0.5, high=30.0),
                    crawl=bool(request.get("crawl")),
                    max_pages=_bounded_int(request.get("max_pages"), default=50, low=1, high=500),
                    max_depth=_bounded_int(request.get("max_depth"), default=3, low=0, high=10),
                    delay=_bounded_float(request.get("delay"), default=0.3, low=0.0, high=10.0),
                    render=bool(request.get("render")),
                    discover_assets=bool(request.get("discover_assets")),
                    capture_network=bool(request.get("capture_network")),
                    interact=bool(request.get("interact")),
                    max_clicks=20,
                    seeds=tuple(s for s in request.get("seeds", []) if isinstance(s, str))
                    if isinstance(request.get("seeds"), list)
                    else (),
                    scan_js_secrets=bool(request.get("scan_js_secrets")),
                    ingest_sitemap=bool(request.get("ingest_sitemap")),
                    probe_paths=bool(request.get("probe_paths")),
                    active=bool(request.get("active")),
                    compare_unauth=bool(request.get("compare_unauth")),
                    secondary_headers_text=str(request.get("secondary_headers") or ""),
                    api_spec_text=str(request.get("api_spec") or ""),
                    auth=auth,
                    allowed_origins=tuple(origin for origin in request.get("allowed_origins", []) if isinstance(origin, str))
                    if isinstance(request.get("allowed_origins"), list)
                    else (),
                )
            except (json.JSONDecodeError, TypeError, ValueError) as exc:
                self._send_json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
                return
            self._send_json(payload)

        def _handle_zap_scan(self) -> None:
            try:
                request = self._read_json(max_bytes=8_388_608)  # allow a prior report to merge into
                # Preserve the legacy 400 authorization diagnostic for an
                # unconfirmed request; an actually authorized active request
                # must also carry the stricter local web-audit session gate.
                if bool(request.get("active_scan")) and bool(request.get("authorization_confirmed")) and not self._require_web_audit_access():
                    return
                payload = zap_scan_payload(
                    _string_value(request, "url"),
                    language=_choice_value(request, "language", {"en", "ko"}, language),
                    min_severity=_choice_value(request, "min_severity", set(SEVERITIES), "info"),
                    ajax_spider=bool(request.get("ajax_spider")),
                    active_scan=bool(request.get("active_scan")),
                    authorization_confirmed=bool(request.get("authorization_confirmed")),
                    minutes=_bounded_int(request.get("minutes"), default=1, low=1, high=60),
                    include_paths=tuple(p for p in request.get("include_paths", []) if isinstance(p, str))
                    if isinstance(request.get("include_paths"), list)
                    else (),
                    exclude_paths=tuple(p for p in request.get("exclude_paths", []) if isinstance(p, str))
                    if isinstance(request.get("exclude_paths"), list)
                    else (),
                    auth=request.get("auth") if isinstance(request.get("auth"), dict) else {},
                    merge=request.get("merge") if isinstance(request.get("merge"), dict) else None,
                )
            except (json.JSONDecodeError, TypeError, ValueError) as exc:
                self._send_json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
                return
            self._send_json(payload)

        def _handle_web_audit_plan(self) -> None:
            try:
                request = self._read_json(max_bytes=2_097_152)
                profile = request.get("profile")
                if not isinstance(profile, dict):
                    raise ValueError("'profile' must be an object")
                payload = plan_profile(profile)
            except (json.JSONDecodeError, TypeError, ValueError, RuntimeError) as exc:
                self._send_json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
                return
            self._send_json(payload)

        def _handle_web_audit_approve(self) -> None:
            try:
                request = self._read_json(max_bytes=2_097_152)
                approval_request = request.get("request")
                approver = _string_value(request, "approver")
                if not isinstance(approval_request, dict):
                    raise ValueError("'request' must be an object")
                payload = approve_request(approval_request, approver)
            except (json.JSONDecodeError, TypeError, ValueError, RuntimeError) as exc:
                self._send_json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
                return
            self._send_json(payload)

        def _handle_web_audit_run(self) -> None:
            try:
                request = self._read_json(max_bytes=4_194_304)
                profile = request.get("profile")
                approval = request.get("approval")
                confirm_origin = _string_value(request, "confirm_origin")
                if not isinstance(profile, dict) or not isinstance(approval, dict):
                    raise ValueError("'profile' and 'approval' must be objects")
                payload = run_web_audit(
                    profile,
                    approval,
                    confirm_origin=confirm_origin,
                    dry_run=bool(request.get("dry_run")),
                )
            except (json.JSONDecodeError, TypeError, ValueError, RuntimeError) as exc:
                self._send_json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
                return
            self._send_json(payload)

        def _handle_prevention_kit(self) -> None:
            try:
                request = self._read_json()
                payload = prevention_kit_payload(
                    _choice_value(request, "action", PREVENTION_KIT_ACTIONS, "toolkit"),
                    _string_value(request, "path"),
                )
            except (json.JSONDecodeError, TypeError, ValueError) as exc:
                self._send_json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
                return
            self._send_json(payload)

        def _handle_export(self) -> None:
            try:
                request = self._read_json(max_bytes=4_194_304)
                report_format = _choice_value(request, "format", {"md", "markdown", "xlsx", "hwpx", "pdf", "html"}, "md")
                lang = _choice_value(request, "language", {"en", "ko"}, language)
                payload = request.get("payload")
                if not isinstance(payload, dict):
                    raise ValueError("'payload' must be an object")
            except (json.JSONDecodeError, TypeError, ValueError) as exc:
                self._send_json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
                return

            if report_format == "html":
                body = render_html_pair_zip_from_payload(payload, lang)
                content_type, extension = "application/zip", "zip"
            elif report_format in {"md", "markdown"}:
                body = render_markdown_from_payload(payload, lang).encode("utf-8")
                content_type, extension = "text/markdown; charset=utf-8", "md"
            elif report_format == "xlsx":
                body = render_xlsx(payload, lang)
                content_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                extension = "xlsx"
            elif report_format == "pdf":
                try:
                    body = render_pdf(payload, lang)
                except PdfExportError as exc:
                    self._send_json({"error": str(exc)}, status=HTTPStatus.SERVICE_UNAVAILABLE)
                    return
                content_type, extension = "application/pdf", "pdf"
            else:
                body = render_hwpx(payload, lang)
                content_type, extension = "application/hwp+zip", "hwpx"
            self._send_bytes(body, content_type, f"koda-report.{extension}")

        def _handle_select_directory(self) -> None:
            try:
                request = self._read_json(required=False)
                selected = select_directory(str(request.get("current_path", "")))
            except (json.JSONDecodeError, TypeError, ValueError, RuntimeError) as exc:
                self._send_json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
                return
            if selected is None:
                self._send_json({"path": "", "cancelled": True})
                return
            self._send_json({"path": selected, "cancelled": False})

        def log_message(self, format: str, *args: object) -> None:
            print(f"{self.address_string()} - {format % args}")

        def _require_web_audit_access(self, *, options: bool = False) -> bool:
            bound_host = str(self.server.server_address[0])
            client_host = str(self.client_address[0])
            if bound_host not in LOCAL_CORS_HOSTS or client_host not in LOCAL_CORS_HOSTS:
                if not options:
                    self._send_json({"error": "web-audit execution API is disabled for non-loopback bindings"}, status=HTTPStatus.FORBIDDEN)
                else:
                    self.send_error(HTTPStatus.FORBIDDEN)
                return False
            port = int(self.server.server_address[1])
            allowed_origins = {f"http://127.0.0.1:{port}", f"http://localhost:{port}", f"http://[::1]:{port}"}
            if self.headers.get("Origin") not in allowed_origins:
                if not options:
                    self._send_json({"error": "exact loopback Origin is required"}, status=HTTPStatus.FORBIDDEN)
                else:
                    self.send_error(HTTPStatus.FORBIDDEN)
                return False
            if not options and self.headers.get("X-KODA-Session") != getattr(self.server, "koda_session_token", ""):
                self._send_json({"error": "invalid X-KODA-Session"}, status=HTTPStatus.FORBIDDEN)
                return False
            return True

        def _require_upload_access(self) -> bool:
            host = self.headers.get("Host", "")
            origin = self.headers.get("Origin", "")
            if not host or origin not in {f"http://{host}", f"https://{host}"}:
                self._send_json({"error": "same-origin upload is required"}, status=HTTPStatus.FORBIDDEN)
                return False
            if self.headers.get("X-KODA-Session") != getattr(self.server, "koda_session_token", ""):
                self._send_json({"error": "invalid X-KODA-Session"}, status=HTTPStatus.FORBIDDEN)
                return False
            return True

        def _receive_upload(self, destination: Path, max_bytes: int) -> None:
            try:
                content_length = int(self.headers.get("Content-Length", "0"))
            except ValueError as exc:
                raise ValueError("Invalid Content-Length") from exc
            if content_length <= 0:
                raise ValueError("Uploaded file is empty")
            if content_length > max_bytes:
                raise UploadTooLargeError(f"Uploaded file exceeds {max_bytes} bytes")
            remaining = content_length
            with destination.open("wb") as output:
                while remaining:
                    chunk = self.rfile.read(min(1024 * 1024, remaining))
                    if not chunk:
                        raise ValueError("Uploaded file ended before Content-Length")
                    output.write(chunk)
                    remaining -= len(chunk)

        def _read_json(self, *, required: bool = True, max_bytes: int = 32768) -> dict[str, Any]:
            content_length = int(self.headers.get("Content-Length", "0"))
            if content_length <= 0:
                if required:
                    raise ValueError("Missing JSON body")
                return {}
            if content_length > max_bytes:
                raise ValueError("JSON body is too large")
            data = json.loads(self.rfile.read(content_length).decode("utf-8"))
            if not isinstance(data, dict):
                raise ValueError("JSON body must be an object")
            return data

        def _send_html(self, content: str) -> None:
            body = content.encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("X-KODA-Session", getattr(self.server, "koda_session_token", ""))
            self._send_cors_headers()
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _send_json(self, payload: dict[str, object], status: HTTPStatus = HTTPStatus.OK) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("X-KODA-Session", getattr(self.server, "koda_session_token", ""))
            self._send_cors_headers()
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _send_bytes(self, body: bytes, content_type: str, filename: str) -> None:
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
            self._send_cors_headers()
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _send_cors_headers(self) -> None:
            origin = allowed_cors_origin(self.headers.get("Origin"))
            if origin is None:
                return
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, X-KODA-Session, X-KODA-Filename")
            self.send_header("Access-Control-Expose-Headers", "X-KODA-Session")
            self.send_header("Vary", "Origin")

    return DashboardHandler


def select_directory(current_path: str = "") -> str | None:
    initial_dir = _initial_directory(current_path)
    try:
        return _select_directory_tk(initial_dir)
    except RuntimeError as tk_error:
        if platform.system() == "Darwin":
            try:
                return _select_directory_macos(initial_dir)
            except RuntimeError as mac_error:
                raise RuntimeError(f"Folder picker is not available: {mac_error}") from mac_error
        raise RuntimeError("Folder picker is not available in this Python environment") from tk_error


def _select_directory_tk(initial_dir: Path) -> str | None:
    try:
        import tkinter as tk
        from tkinter import filedialog
    except Exception as exc:  # pragma: no cover - depends on local Python build
        raise RuntimeError("Tk folder picker is not available") from exc

    try:
        root = tk.Tk()
    except Exception as exc:  # pragma: no cover - depends on local GUI/session state
        raise RuntimeError("Tk folder picker could not start") from exc
    try:
        root.withdraw()
        root.update()
        selected = filedialog.askdirectory(
            parent=root,
            initialdir=str(initial_dir),
            mustexist=True,
            title="Select folder to scan",
        )
    finally:
        root.destroy()

    return _normalize_selected_directory(selected)


def _select_directory_macos(initial_dir: Path) -> str | None:
    result = _run_macos_folder_picker(initial_dir)
    if result.returncode != 0 and _should_retry_macos_picker_without_default(result):
        result = _run_macos_folder_picker(None)
    if result.returncode != 0:
        message = (result.stderr or result.stdout or "").strip()
        if "User canceled" in message or "-128" in message:
            return None
        raise RuntimeError(message or "macOS folder picker failed")
    return _normalize_selected_directory(result.stdout.strip())


def _run_macos_folder_picker(initial_dir: Path | None) -> subprocess.CompletedProcess[str]:
    if initial_dir is None:
        script_lines = (
            'set selectedFolder to choose folder with prompt "Select folder to scan"',
            "POSIX path of selectedFolder",
        )
    else:
        script_lines = (
            f'set initialFolder to POSIX file "{_applescript_string(str(initial_dir))}" as alias',
            'set selectedFolder to choose folder with prompt "Select folder to scan" default location initialFolder',
            "POSIX path of selectedFolder",
        )
    command = ["osascript"]
    for line in script_lines:
        command.extend(("-e", line))
    try:
        return subprocess.run(command, capture_output=True, text=True, check=False)
    except FileNotFoundError as exc:  # pragma: no cover - macOS normally provides osascript
        raise RuntimeError("macOS folder picker command was not found") from exc


def _should_retry_macos_picker_without_default(result: subprocess.CompletedProcess[str]) -> bool:
    message = (result.stderr or result.stdout or "").lower()
    return "expected pattern" in message or "can't make" in message or "cannot make" in message


def allowed_cors_origin(origin: str | None) -> str | None:
    if origin is None:
        return None
    parsed = urlparse(origin)
    if parsed.scheme in {"http", "https"} and parsed.hostname in LOCAL_CORS_HOSTS:
        return origin
    return None


def _applescript_string(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _normalize_selected_directory(selected: str) -> str | None:
    if not selected:
        return None
    selected_path = Path(selected).expanduser().resolve()
    if not selected_path.is_dir():
        raise ValueError(f"Selected path is not a directory: {selected_path}")
    return str(selected_path)


def _initial_directory(current_path: str) -> Path:
    if current_path:
        candidate = Path(current_path).expanduser()
        if candidate.is_dir():
            return candidate.resolve()
        if candidate.parent.is_dir():
            return candidate.parent.resolve()
    return Path.home().resolve()


def _string_value(request: dict[str, Any], key: str, *, default: str | None = None) -> str:
    value = request.get(key, default)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"'{key}' must be a non-empty string")
    return value


def _bounded_int(value: object, *, default: int, low: int, high: int) -> int:
    try:
        result = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default
    return max(low, min(high, result))


def _bounded_float(value: object, *, default: float, low: float, high: float) -> float:
    try:
        result = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default
    return max(low, min(high, result))


def _choice_value(request: dict[str, Any], key: str, choices: set[str], default: str) -> str:
    value = request.get(key, default)
    if not isinstance(value, str):
        raise ValueError(f"'{key}' must be a string")
    normalized = value.lower()
    if normalized not in choices:
        raise ValueError(f"Unsupported {key}: {value}")
    return normalized


def _choice_value_query(query: str, key: str, choices: set[str], default: str) -> str:
    values = parse_qs(query).get(key)
    if not values:
        return default
    normalized = values[0].lower()
    return normalized if normalized in choices else default


def _upload_filename(raw: str | None) -> str:
    filename = unquote(raw or "").strip()
    if not filename or len(filename) > 255 or "\0" in filename or "/" in filename or "\\" in filename:
        raise ValueError("X-KODA-Filename must contain one safe filename")
    if filename in {".", ".."}:
        raise ValueError("X-KODA-Filename must contain one safe filename")
    return filename


def _environment_limit(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be a positive integer") from exc
    if value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


def _query_choice(query: dict[str, list[str]], key: str, choices: set[str], default: str) -> str:
    value = _query_text(query, key, default).lower()
    if value not in choices:
        raise ValueError(f"Unsupported {key}: {value}")
    return value


def _query_text(query: dict[str, list[str]], key: str, default: str) -> str:
    values = query.get(key)
    value = values[0].strip() if values else default
    if not value:
        raise ValueError(f"'{key}' must be a non-empty string")
    return value


def _query_flag(query: dict[str, list[str]], key: str) -> bool:
    values = query.get(key)
    return bool(values and values[0].lower() in {"1", "true", "yes", "on"})


def _disabled_rules_value(request: dict[str, Any]) -> tuple[str, ...]:
    value = request.get("disabled_rules", ())
    if not isinstance(value, list | tuple):
        return ()
    return tuple(str(item) for item in value if isinstance(item, str))


def _categories_value(request: dict[str, Any]) -> tuple[str, ...]:
    value = request.get("categories", DEFAULT_CATEGORIES)
    if value == "all":
        # "all" means all file-based categories; host posture is opt-in only.
        return DEFAULT_CATEGORIES
    if not isinstance(value, list | tuple):
        raise ValueError("'categories' must be a list or 'all'")
    categories = tuple(str(item).lower() for item in value)
    if not categories:
        raise ValueError("'categories' must not be empty")
    unknown = sorted(set(categories) - set(CATEGORIES))
    if unknown:
        raise ValueError(f"Unsupported categories: {', '.join(unknown)}")
    return categories
