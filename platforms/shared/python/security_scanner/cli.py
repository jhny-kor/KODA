from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import urllib.parse
from contextlib import contextmanager
from pathlib import Path

from .archive_input import prepare_input_target
from .config import ConfigError, expand_path, load_config
from .models import CATEGORIES, DEFAULT_CATEGORIES, SEVERITIES, ReportConfig, ScannerConfig, TargetConfig
from .reporting import filter_by_min_severity, render_html_pair, render_report, write_report
from .scanner import SecurityScanner
from .standards import (
    DEFAULT_STANDARD,
    DEFAULT_STANDARD_CATEGORY,
    SOURCE_STANDARD_IDS,
    filter_findings_by_standard,
    resolve_standard_selection,
    source_standard_help,
)

def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 0

    if args.command == "list-categories":
        for category in CATEGORIES:
            print(category)
        return 0

    if args.command == "jar-scan":
        from .java_vulnerability_scan import JavaScanOptions, run_java_scan

        try:
            target_paths = tuple(expand_path(value, Path.cwd()) for value in args.target)
            result = run_java_scan(
                JavaScanOptions(
                    target=target_paths[0],
                    targets=target_paths,
                    output_dir=expand_path(args.output_dir, Path.cwd()),
                    syft_bin=Path(args.syft_bin).expanduser() if args.syft_bin else None,
                    grype_bin=Path(args.grype_bin).expanduser() if args.grype_bin else None,
                    nvd_data=Path(args.nvd_data).expanduser() if args.nvd_data else None,
                    cisa_kev=Path(args.cisa_kev).expanduser() if args.cisa_kev else None,
                    language=args.language,
                    excludes=tuple(args.exclude),
                    max_depth=args.max_depth,
                    timeout=args.timeout,
                    fail_on=args.fail_on,
                    fail_on_kev=args.fail_on_kev,
                    no_grype=args.no_grype,
                    builtin_only=args.builtin_only,
                    format=args.format,
                    verify_sbom=args.verify_sbom,
                    baseline_sbom=Path(args.baseline_sbom).expanduser() if args.baseline_sbom else None,
                    fail_on_mismatch=args.fail_on_mismatch,
                    fail_on_version_conflict=args.fail_on_version_conflict,
                    fail_on_untracked=args.fail_on_untracked,
                    strict_hash=args.strict_hash,
                    sbom_format=args.sbom_format,
                )
            )
        except (OSError, ValueError, RuntimeError) as exc:
            print(f"Java archive scan error: {exc}", file=sys.stderr)
            return 2
        for warning in result.warnings:
            print(f"warning: {warning}", file=sys.stderr)
        unique_vulnerabilities = sum(len(group.advisories) for group in result.vulnerabilities)
        print(
            f"Java scan: {result.archive_count} archive(s), {len(result.components)} component(s), "
            f"{len(result.vulnerabilities)} affected library version(s), {unique_vulnerabilities} unique vulnerability type(s).",
            file=sys.stderr,
        )
        return result.exit_code

    if args.command == "sbom-verify":
        from .sbom_verification import SbomVerificationOptions, run_sbom_verification

        try:
            result = run_sbom_verification(
                SbomVerificationOptions(
                    target=expand_path(args.target, Path.cwd()),
                    sbom=expand_path(args.sbom, Path.cwd()) if args.sbom else None,
                    baseline_sbom=expand_path(args.baseline_sbom, Path.cwd()) if args.baseline_sbom else None,
                    output_dir=expand_path(args.output_dir, Path.cwd()),
                    excludes=tuple(args.exclude),
                    max_depth=args.max_depth,
                    fail_on_mismatch=args.fail_on_mismatch,
                    fail_on_version_conflict=args.fail_on_version_conflict,
                    fail_on_untracked=args.fail_on_untracked,
                    strict_hash=args.strict_hash,
                    format=args.format,
                )
            )
        except (OSError, ValueError, RuntimeError) as exc:
            print(f"SBOM verification error: {exc}", file=sys.stderr)
            return 2
        for warning in result.warnings:
            print(f"warning: {warning}", file=sys.stderr)
        print(
            f"SBOM verification: {result.summary['actual_component_count']} actual component(s), "
            f"{result.summary['matched']} matched, {len(result.results) - result.summary['matched']} review item(s).",
            file=sys.stderr,
        )
        return result.exit_code

    if args.command == "discover":
        from .discovery import discover_projects

        target = expand_path(args.target, Path.cwd())
        for project in discover_projects(target):
            markers = ", ".join(project.markers)
            ecosystems = ", ".join(project.ecosystems)
            print(f"{project.name}\t{project.path}\t{ecosystems}\t{markers}")
        return 0

    if args.command == "schedule-worker":
        from .schedule_worker import main as schedule_worker_main

        worker_args = ["--db", args.db]
        if args.work_dir:
            worker_args.extend(("--work-dir", args.work_dir))
        if args.once:
            worker_args.append("--once")
        return schedule_worker_main(worker_args)

    if args.command == "serve":
        # Linux is the portal deployment; desktop/local app keeps the legacy dashboard.
        if sys.platform.startswith("linux") and not getattr(args, "legacy_dashboard", False):
            from .linux_portal import serve_portal
            return serve_portal(args.host, args.port, args.language, getattr(args, "db", None))
        if sys.platform.startswith("linux") and args.host not in {"127.0.0.1", "::1", "localhost"}:
            print("Legacy dashboard is restricted to a loopback host on Linux.", file=sys.stderr)
            return 2
        from .server import serve_dashboard
        return serve_dashboard(args.host, args.port, args.language)

    if args.command == "portal-bootstrap":
        from .portal_store import PortalStore
        try:
            PortalStore(args.db).bootstrap(args.tracker_user_id)
        except ValueError as exc:
            print(f"Portal bootstrap error: {exc}", file=sys.stderr)
            return 2
        print(f"Enabled portal system administrator: {args.tracker_user_id}")
        return 0

    if args.command == "app":
        from .app import run_app

        try:
            return run_app(args.host, args.port, args.language, open_browser=not args.no_browser)
        except (OSError, RuntimeError, ValueError) as exc:
            print(f"App error: {exc}", file=sys.stderr)
            return 2

    if args.command == "web-audit":
        from .web_audit import (
            ApprovalError,
            ProfileError,
            approve_request,
            plan_profile,
            run_web_audit,
        )

        try:
            if args.web_audit_action == "plan":
                plan = plan_profile(args.profile)
                request = plan["approval_request"]
                if args.out:
                    args.out.expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)
                    args.out.expanduser().resolve().write_text(
                        json.dumps(request, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
                    )
                print(json_dumps(plan))
                return 0
            if args.web_audit_action == "approve":
                request_value = json.loads(args.request.expanduser().read_text(encoding="utf-8"))
                if isinstance(request_value, dict) and request_value.get("kind") == "koda.web-audit.plan":
                    request_value = request_value.get("approval_request")
                if not isinstance(request_value, dict):
                    raise ApprovalError("approval request must be a JSON object")
                approval = approve_request(request_value, args.approver, key=os.environ.get(args.key_env))
                if args.out:
                    args.out.expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)
                    args.out.expanduser().resolve().write_text(
                        json.dumps(approval, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
                    )
                print(json_dumps(approval))
                return 0
            result = run_web_audit(
                args.profile,
                args.approval,
                confirm_origin=args.confirm_origin,
                key=os.environ.get(args.key_env),
                state_dir=args.state_dir,
                output_dir=args.output_dir,
                dry_run=bool(args.dry_run),
            )
            if args.format == "markdown":
                from .reporting import render_web_audit_markdown

                content = render_web_audit_markdown(result, language=args.language)
                if args.output:
                    args.output.expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)
                    args.output.expanduser().resolve().write_text(content, encoding="utf-8")
                else:
                    print(content, end="")
            else:
                content = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
                if args.output:
                    args.output.expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)
                    args.output.expanduser().resolve().write_text(content, encoding="utf-8")
                else:
                    print(content, end="")
            return 1 if result.get("status") == "VULNERABLE" else 0
        except (OSError, json.JSONDecodeError, ProfileError, ApprovalError, ValueError, RuntimeError) as exc:
            print(f"Web audit error: {exc}", file=sys.stderr)
            return 2

    if args.command == "init-security":
        from .toolkit import write_security_template_files

        try:
            target = expand_path(args.target, Path.cwd())
            if args.dry_run:
                from .toolkit import security_template_files

                for relative_path in security_template_files(args.project_name or target.name):
                    print(target / relative_path)
                return 0
            results = write_security_template_files(target, project_name=args.project_name, force=bool(args.force))
        except (OSError, ValueError) as exc:
            print(f"Template error: {exc}", file=sys.stderr)
            return 2
        for result in results:
            print(f"{result.status}\t{result.path}")
        return 0

    if args.command == "install-hook":
        from .toolkit import install_pre_commit_hook

        try:
            result = install_pre_commit_hook(expand_path(args.target, Path.cwd()), fail_on=args.fail_on, force=bool(args.force))
        except (OSError, ValueError) as exc:
            print(f"Hook install error: {exc}", file=sys.stderr)
            return 2
        print(f"{result.status}\t{result.path}")
        return 0

    if args.command in {"repo-security-checklist", "ssdf-plan", "secure-by-design-plan", "sigstore-plan"}:
        from .toolkit import (
            render_release_signing_plan,
            render_repository_security_checklist,
            render_secure_by_design_plan,
            render_ssdf_workflow_plan,
        )

        project_name = args.project_name or Path(args.target).expanduser().name or "KODA Project"
        if args.command == "repo-security-checklist":
            content = render_repository_security_checklist(project_name)
        elif args.command == "ssdf-plan":
            content = render_ssdf_workflow_plan(project_name)
        elif args.command == "secure-by-design-plan":
            content = render_secure_by_design_plan(project_name)
        else:
            content = render_release_signing_plan(project_name, artifact_path=args.artifact)
        write_report(content, expand_path(str(args.output), Path.cwd()) if args.output else None)
        return 0

    if args.command == "zap-command":
        from .integrations import zap_baseline_command

        try:
            print(zap_baseline_command(args.url, output_dir=args.output_dir, minutes=args.minutes))
        except ValueError as exc:
            print(f"ZAP command error: {exc}", file=sys.stderr)
            return 2
        return 0

    if args.command == "zap-run":
        from .dast import render_zap_findings_json, run_zap_automation, run_zap_scan

        # Active traffic (full/api, or automation + active scan) requires authorization.
        active_requested = args.mode in {"full", "api"} or (args.mode == "automation" and args.active_scan)
        if active_requested and not args.authorize_active:
            label = f"--mode {args.mode}" + (" --active-scan" if args.mode == "automation" else "")
            print(
                f"error: {label} runs an ACTIVE scan (attack traffic). "
                "Re-run with --authorize-active and only against systems you are authorized to test.",
                file=sys.stderr,
            )
            return 2
        try:
            if args.mode == "automation":
                auth = None
                if args.af_login_url:
                    auth = {
                        "method": args.af_auth_method or "form",
                        "login_url": args.af_login_url,
                        "login_body": args.af_login_body or "",
                        "logged_in_regex": args.af_logged_in_regex or "",
                        "username": args.af_username or "",
                        "password": args.af_password or "",
                    }
                result = run_zap_automation(
                    args.url,
                    output_dir=expand_path(args.output_dir, Path.cwd()),
                    minutes=args.minutes,
                    ajax_spider=args.ajax_spider,
                    active_scan=args.active_scan,
                    include_paths=tuple(args.include_path),
                    exclude_paths=tuple(args.exclude_path),
                    openapi_url=args.openapi_url,
                    openapi_file=args.openapi_file,
                    auth=auth,
                    dry_run=args.dry_run,
                    timeout_seconds=args.timeout,
                )
            else:
                result = run_zap_scan(
                    args.url,
                    output_dir=expand_path(args.output_dir, Path.cwd()),
                    mode=args.mode,
                    minutes=args.minutes,
                    context_file=args.context_file,
                    user=args.user,
                    min_level=args.fail_on_level,
                    api_format=args.api_format,
                    dry_run=args.dry_run,
                    timeout_seconds=args.timeout,
                )
        except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
            print(f"ZAP run error: {exc}", file=sys.stderr)
            return 2
        if args.dry_run:
            print(result.command)
            return 0
        findings_path = result.output_dir / "koda-zap-findings.json"
        findings_path.write_text(render_zap_findings_json(result.findings), encoding="utf-8")
        print(
            json_dumps(
                {
                    "exit_code": result.exit_code,
                    "output_dir": str(result.output_dir),
                    "finding_count": len(result.findings),
                    "findings": str(findings_path),
                    "command": result.command,
                }
            )
        )
        if result.exit_code not in {0, 1, 2}:
            return result.exit_code
        # ZAP exit codes: 1 = FAIL alerts, 2 = WARN alerts, 3 = error.
        if args.respect_exit_code and result.exit_code != 0:
            return result.exit_code
        if args.fail_on_alerts and result.findings:
            return 1
        return 0

    if args.command == "evidence-checklist":
        from .evidence import write_evidence_checklist

        output = expand_path(args.output, Path.cwd())
        try:
            write_evidence_checklist(
                output,
                project_name=args.project_name or Path(args.target).expanduser().name or "project",
                language=args.language,
                json_format=args.format == "json",
            )
        except OSError as exc:
            print(f"Evidence checklist error: {exc}", file=sys.stderr)
            return 2
        print(output)
        return 0

    if args.command == "diff-reports":
        from .diffing import diff_reports, render_diff_json, render_diff_markdown

        try:
            diff = diff_reports(expand_path(args.baseline, Path.cwd()), expand_path(args.current, Path.cwd()))
            content = render_diff_json(diff) if args.format == "json" else render_diff_markdown(diff, language=args.language)
            write_report(content, expand_path(str(args.output), Path.cwd()) if args.output else None)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            print(f"Diff report error: {exc}", file=sys.stderr)
            return 2
        return 0

    if args.command == "manifest":
        from .manifest import (
            compare_manifest_to_target,
            create_manifest,
            load_manifest,
            render_manifest_compare_json,
            render_manifest_json,
        )

        try:
            if args.manifest_command == "create":
                content = render_manifest_json(create_manifest(expand_path(args.target, Path.cwd())))
            else:
                baseline = load_manifest(expand_path(args.baseline, Path.cwd()))
                content = render_manifest_compare_json(
                    compare_manifest_to_target(baseline, expand_path(args.target, Path.cwd()))
                )
            write_report(content, expand_path(str(args.output), Path.cwd()) if args.output else None)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"Manifest error: {exc}", file=sys.stderr)
            return 2
        return 0

    if args.command == "deploy-check":
        from .manifest import create_manifest, render_manifest_json

        try:
            target_path = expand_path(args.target, Path.cwd())
            output_dir = expand_path(args.output_dir, Path.cwd())
            output_dir.mkdir(parents=True, exist_ok=True)
            report = ReportConfig(
                format="json",
                output=output_dir / "koda-deploy-scan.json",
                min_severity=args.min_severity,
                language=args.language,
            )
            config = ScannerConfig(
                targets=(TargetConfig(name=target_path.name or "deploy-target", path=target_path),),
                report=report,
            )
            scanner = SecurityScanner(config)
            scan_result = scanner.scan()
            findings = list(scan_result.findings)
            source_analysis = scan_result.source_analysis
            filtered_findings = filter_by_min_severity(findings, config.report.min_severity)
            content = render_report(
                filtered_findings,
                config.report.format,
                target_names=(config.targets[0].name,),
                target_paths={config.targets[0].name: str(target_path)},
                language=config.report.language,
                components=scanner.components,
                warnings=tuple(scanner.warnings),
                source_analysis=source_analysis,
            )
            write_report(content, config.report.output)
            write_report(render_manifest_json(create_manifest(target_path)), output_dir / "koda-deploy-manifest.json")
        except (OSError, ValueError) as exc:
            print(f"Deploy check error: {exc}", file=sys.stderr)
            return 2
        if args.fail_on and _has_failure(filtered_findings, args.fail_on):
            return 1
        return 0

    if args.command == "release-package":
        from .release import build_release_security_package

        try:
            manifest = build_release_security_package(
                target=expand_path(args.target, Path.cwd()),
                output_dir=expand_path(args.output_dir, Path.cwd()),
                project_name=args.project_name,
                language=args.language,
                enable_vuln_intel=args.enable_vuln_intel,
            )
        except (OSError, ValueError) as exc:
            print(f"Release package error: {exc}", file=sys.stderr)
            return 2
        print(json_dumps(manifest))
        return 0

    if args.command == "dependency-track-command":
        from .integrations import dependency_track_upload_command

        try:
            print(
                dependency_track_upload_command(
                    server_url=args.server_url,
                    project_name=args.project_name,
                    project_version=args.project_version,
                    sbom_path=args.sbom,
                    api_key_env=args.api_key_env,
                    auto_create=args.auto_create,
                )
            )
        except ValueError as exc:
            print(f"Dependency-Track command error: {exc}", file=sys.stderr)
            return 2
        return 0

    if args.command == "upload-sbom":
        from .integrations import api_key_from_env, upload_sbom_to_dependency_track

        try:
            api_key = args.api_key or api_key_from_env(args.api_key_env)
            payload = upload_sbom_to_dependency_track(
                server_url=args.server_url,
                api_key=api_key,
                project_name=args.project_name,
                project_version=args.project_version,
                sbom_path=expand_path(args.sbom, Path.cwd()),
                auto_create=args.auto_create,
            )
        except (RuntimeError, ValueError, OSError) as exc:
            print(f"Dependency-Track upload error: {exc}", file=sys.stderr)
            return 2
        print(json_dumps(payload))
        return 0

    if args.command == "host-scan":
        report = ReportConfig(
            format=args.format or "markdown",
            output=expand_path(str(args.output), Path.cwd()) if args.output else None,
            min_severity=args.min_severity or "info",
            language=args.language or "en",
        )
        target = TargetConfig(name="host", path=Path.cwd(), categories=("host",))
        config = ScannerConfig(
            targets=(target,),
            report=report,
            enable_host_inventory=args.inventory or args.check_cve,
            enable_host_eol=args.eol,
            enable_host_cve=args.check_cve,
            nvd_api_key=os.environ.get(args.nvd_api_key_env) if args.nvd_api_key_env else None,
        )
        scanner = SecurityScanner(config)
        scan_result = scanner.scan()
        findings = list(scan_result.findings)
        source_analysis = scan_result.source_analysis
        filtered_findings = filter_by_min_severity(findings, config.report.min_severity)
        content = render_report(
            filtered_findings,
            config.report.format,
            target_names=("host",),
            language=config.report.language,
            warnings=tuple(scanner.warnings),
            source_analysis=source_analysis,
        )
        write_report(content, config.report.output)
        for warning in scanner.warnings:
            print(f"warning: {warning}", file=sys.stderr)
        print(
            f"Host scan: {len(filtered_findings)} finding(s) at or above {config.report.min_severity}.",
            file=sys.stderr,
        )
        if args.fail_on and _has_failure(filtered_findings, args.fail_on):
            return 1
        return 0

    if args.command == "web-scan":
        from .web import build_auth_opener, crawl_web, login

        extra_headers = _parse_headers(args.header)
        if args.active:
            print(
                "warning: --active sends attack payloads (XSS/SQLi/open-redirect) to query "
                "parameters. Run only against systems you are explicitly authorized to test.",
                file=sys.stderr,
            )
        seeds = list(args.seed)
        if args.api_spec:
            from .api_spec import parse_api_spec

            spec_urls, spec_warnings = parse_api_spec(
                expand_path(str(args.api_spec), Path.cwd()).read_text(encoding="utf-8"), args.url
            )
            seeds.extend(spec_urls)
            for warning in spec_warnings:
                print(f"warning: {warning}", file=sys.stderr)
            print(f"API spec: seeded {len(spec_urls)} GET endpoint(s).", file=sys.stderr)
        secondary_headers = _parse_headers(args.secondary_header)
        opener = build_auth_opener()
        warnings: list[str] = []
        login_findings: list = []
        if args.login_url:
            password = os.environ.get(args.password_env) if args.password_env else args.password
            if not args.username or not password:
                print("error: --login-url requires --username and --password/--password-env", file=sys.stderr)
                return 2
            login_warnings, login_findings = login(
                opener,
                args.login_url,
                args.username,
                password,
                user_field=args.user_field,
                pass_field=args.pass_field,
                timeout=args.timeout,
            )
            warnings.extend(login_warnings)
        crawl_findings, crawl_warnings, pages = crawl_web(
            args.url,
            timeout=args.timeout,
            # Seeds (an API spec or --seed) are scanned even without --crawl, at
            # depth 0 (no link-following) unless --crawl is also given.
            max_pages=args.max_pages if (args.crawl or seeds) else 1,
            max_depth=args.max_depth if args.crawl else 0,
            delay=args.delay,
            opener=opener,
            extra_headers=extra_headers or None,
            render=args.render,
            seeds=tuple(seeds),
            discover_assets=args.discover_assets,
            capture_network=args.capture_network,
            interact=args.interact,
            max_clicks=20,
            scan_js_secrets=args.scan_js_secrets,
            ingest_sitemap=args.ingest_sitemap,
            probe_paths=args.probe_paths,
            active=args.active,
            compare_unauth=args.compare_unauth,
            secondary_headers=secondary_headers or None,
        )
        findings = login_findings + crawl_findings
        warnings.extend(crawl_warnings)
        report = ReportConfig(
            format=args.format or "markdown",
            output=expand_path(str(args.output), Path.cwd()) if args.output else None,
            min_severity=args.min_severity or "info",
            language=args.language or "en",
        )
        target_name = urllib.parse.urlparse(args.url).netloc or args.url
        filtered_findings = filter_by_min_severity(findings, report.min_severity)
        content = render_report(
            filtered_findings,
            report.format,
            target_names=(target_name,),
            target_paths={target_name: args.url},
            language=report.language,
            warnings=tuple(warnings),
        )
        write_report(content, report.output)
        for warning in warnings:
            print(f"warning: {warning}", file=sys.stderr)
        print(
            f"Web scan: {len(filtered_findings)} finding(s) at or above {report.min_severity} "
            f"for {target_name} across {pages} page(s).",
            file=sys.stderr,
        )
        if args.fail_on and _has_failure(filtered_findings, args.fail_on):
            return 1
        return 0

    if args.command == "fix":
        from .fixes import apply as fixes_apply

        target_path = expand_path(args.target, Path.cwd())
        categories = tuple(args.category) if args.category else ("code",)
        config = ScannerConfig(
            targets=(TargetConfig(name=target_path.name or "target", path=target_path, categories=categories),),
        )
        scanner = SecurityScanner(config)
        scan_result = scanner.scan()
        findings = list(scan_result.findings)
        source_analysis = scan_result.source_analysis
        plans, warnings = fixes_apply.plan_fixes(findings, rule=args.rule)
        for warning in (*scanner.warnings, *warnings):
            print(f"warning: {warning}", file=sys.stderr)
        if not plans:
            print("No auto-fixable findings.", file=sys.stderr)
            return 0
        total = sum(len(plan.fixes) for plan in plans)
        if not args.apply:
            print(fixes_apply.render_diff(plans), end="")
            print(
                f"Dry run: {total} fix(es) across {len(plans)} file(s). "
                "Review the diff, then re-run with --apply to write changes.",
                file=sys.stderr,
            )
            return 0
        result = fixes_apply.apply_plans(plans, make_backup=not args.no_backup)
        for warning in result.warnings:
            print(f"warning: {warning}", file=sys.stderr)
        backup_note = "" if args.no_backup else " Backups written as *.bak."
        print(
            f"Applied fixes to {len(result.applied)} file(s); skipped {len(result.skipped)}.{backup_note}",
            file=sys.stderr,
        )
        return 0

    if args.command in {None, "scan"}:
        try:
            with _build_scan_config_context(args) as config:
                scanner = SecurityScanner(config)
                scan_result = scanner.scan()
                findings = list(scan_result.findings)
                source_analysis = scan_result.source_analysis
                standard_selection = resolve_standard_selection(
                    config.standard,
                    config.standard_category,
                    tuple(args.category)
                    if getattr(args, "category", None)
                    and config.standard == DEFAULT_STANDARD
                    and config.standard_category == DEFAULT_STANDARD_CATEGORY
                    and not getattr(args, "standard_category", None)
                    else None,
                )
                findings = filter_findings_by_standard(findings, standard_selection)
                filtered_findings = filter_by_min_severity(findings, config.report.min_severity)
                effective_targets = scanner.effective_targets or config.targets
                target_names = tuple(target.name for target in effective_targets)
                target_paths = {target.name: str(target.path) for target in effective_targets}
                if config.report.format == "html":
                    output = config.report.output or (Path.cwd() / "reports" / "security-dashboard.html")
                    detail_path = output.with_name(f"{output.stem}-detail{output.suffix}")
                    main_html, detail_html = render_html_pair(
                        filtered_findings,
                        target_names=target_names,
                        target_paths=target_paths,
                        language=config.report.language,
                        detail_href=detail_path.name,
                        components=scanner.components,
                        warnings=tuple(scanner.warnings),
                        scan_path=", ".join(target_paths.values()),
                        kind="source",
                        summary_href=None,
                        standard=standard_selection.standard,
                        standard_category=standard_selection.category,
                        scanned_categories=standard_selection.scanner_categories,
                        source_analysis=source_analysis,
                    )
                    write_report(main_html, output)
                    write_report(detail_html, detail_path)
                    print(f"HTML reports: {output} (main), {detail_path} (detail)", file=sys.stderr)
                else:
                    content = render_report(
                        filtered_findings,
                        config.report.format,
                        target_names=target_names,
                        target_paths=target_paths,
                        language=config.report.language,
                        components=scanner.components,
                        warnings=tuple(scanner.warnings),
                        standard=standard_selection.standard,
                        standard_category=standard_selection.category,
                        scanned_categories=standard_selection.scanner_categories,
                        source_analysis=source_analysis,
                    )
                    write_report(content, config.report.output)

                for warning in scanner.warnings:
                    print(f"warning: {warning}", file=sys.stderr)

                print(
                    f"Scanned {len(target_names)} target(s); "
                    f"{len(filtered_findings)} finding(s) at or above {config.report.min_severity}.",
                    file=sys.stderr,
                )
                gate_findings = filtered_findings
                if getattr(args, "reachable_only", False):
                    gate_findings = [
                        finding for finding in filtered_findings if finding.reachable != "unreachable"
                    ]
                if args.fail_on and _has_failure(gate_findings, args.fail_on):
                    return 1
        except (ConfigError, ValueError) as exc:
            print(f"Config error: {exc}", file=sys.stderr)
            return 2
        return 0

    parser.print_help()
    return 2


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("value must be positive")
    return parsed


def _positive_float(value: str) -> float:
    parsed = float(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be positive")
    return parsed


def _nonnegative_int(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("value must be zero or positive")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="local-security-scan",
        description="Read-only local project security scanner.",
    )
    subparsers = parser.add_subparsers(dest="command")

    scan = subparsers.add_parser(
        "scan",
        help="scan configured local project folders",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "HTML output writes a summary page and a linked -detail.html page.\n"
            "--standard accepts only the current registered source-analysis profiles;\n"
            "mappings are not a full SAST or compliance claim.\n\n"
            f"{source_standard_help()}"
        ),
    )
    scan.add_argument("--config", type=Path, help="JSON config file")
    scan.add_argument(
        "--target",
        action="append",
        help="target folder, file, or supported archive; can be passed multiple times",
    )
    scan.add_argument(
        "--category",
        action="append",
        choices=CATEGORIES,
        help="category to run; can be passed multiple times",
    )
    scan.add_argument(
        "--standard",
        choices=SOURCE_STANDARD_IDS,
        help="source-analysis standard profile; only configured standards can be selected",
    )
    scan.add_argument(
        "--standard-category",
        help="optional category within --standard (for example sw-dev-security-49/input-validation-expression)",
    )
    scan.add_argument("--format", choices=("markdown", "json", "html", "sarif", "cyclonedx", "nis-sbom", "cyclonedx-vex"), help="report format")
    scan.add_argument("--output", type=Path, help="report output path")
    scan.add_argument("--language", choices=("ko",), default="ko", help="report language (Korean only)")
    scan.add_argument("--min-severity", choices=SEVERITIES, help="minimum severity to include")
    scan.add_argument("--fail-on", choices=SEVERITIES, help="exit 1 when findings meet or exceed severity")
    scan.add_argument("--max-file-size", type=int, help="maximum file size to scan in bytes")
    scan.add_argument("--discover-projects", action="store_true", help="discover project roots under target folders")
    scan.add_argument("--enable-osv", action="store_true", help="query OSV.dev for exact-version dependency vulnerabilities")
    scan.add_argument(
        "--enable-vuln-intel",
        action="store_true",
        help="enrich OSV CVEs with CISA KEV and FIRST EPSS exploit intelligence; implies --enable-osv",
    )
    scan.add_argument(
        "--reachability",
        action="store_true",
        help="label OSV dependency findings as reachable/unreachable by analyzing source imports (offline)",
    )
    scan.add_argument(
        "--reachable-only",
        action="store_true",
        help="with --fail-on, ignore findings labelled unreachable when deciding the exit code",
    )
    scan.add_argument(
        "--ai-triage",
        action="store_true",
        help="label findings as likely true/false positives via an LLM (opt-in; local Ollama keeps data offline)",
    )
    scan.add_argument(
        "--llm",
        dest="llm",
        help="LLM model spec for --ai-triage, e.g. ollama/qwen2.5-coder:7b (overrides KODA_LLM env)",
    )
    scan.add_argument(
        "--changed-only",
        action="store_true",
        help="scan only files changed versus --base (for fast per-pull-request CI checks)",
    )
    scan.add_argument(
        "--base",
        dest="base",
        help="base git ref for --changed-only, e.g. origin/main",
    )

    jar_scan = subparsers.add_parser(
        "jar-scan",
        help="offline JAR/WAR/EAR SBOM and vulnerability scan",
        epilog=(
            "HTML writes server-library-report.html and server-library-report-detail.html. "
            "Final is a candidate with no vulnerability match in the report's Grype DB as of its database date; "
            "it is not a compatibility guarantee."
        ),
    )
    jar_scan.add_argument(
        "--target",
        action="append",
        required=True,
        help="JAR/WAR/EAR file or directory containing deployed Java archives; repeat for multiple roots",
    )
    jar_scan.add_argument("--output-dir", default="reports/java-scan", help="report directory")
    jar_scan.add_argument("--syft-bin", help="Syft executable; no automatic download")
    jar_scan.add_argument("--grype-bin", help="Grype executable; no automatic download")
    jar_scan.add_argument("--nvd-data", help="NVD JSON 2.0 file, .json.gz file, or directory")
    jar_scan.add_argument("--cisa-kev", help="CISA known_exploited_vulnerabilities.json")
    jar_scan.add_argument("--language", choices=("ko",), default="ko", help="report language (Korean only)")
    jar_scan.add_argument("--exclude", action="append", default=[], help="archive relative-path/name glob to skip")
    jar_scan.add_argument("--max-depth", type=_positive_int, help="optional nested archive depth limit; the default scans all depths")
    jar_scan.add_argument("--timeout", type=_positive_float, default=300.0, help="Syft/Grype timeout in seconds")
    jar_scan.add_argument("--fail-on", choices=SEVERITIES, help="exit 1 at or above this severity")
    jar_scan.add_argument("--fail-on-kev", action="store_true", help="exit 1 when a CISA KEV match exists")
    jar_scan.add_argument("--no-grype", action="store_true", help="write SBOM and skip vulnerability comparison")
    jar_scan.add_argument("--builtin-only", action="store_true", help="skip Syft and use the built-in Java identifier")
    jar_scan.add_argument("--sbom-format", choices=("cyclonedx-1.6", "nis-1.0"), default="cyclonedx-1.6", help="SBOM output: CycloneDX 1.6 JSON or NIS-SBOM 1.0 CSV")
    jar_scan.add_argument("--verify-sbom", action="store_true", help="compare the generated SBOM with deployed archives")
    jar_scan.add_argument("--baseline-sbom", help="approved baseline CycloneDX SBOM")
    jar_scan.add_argument("--fail-on-mismatch", action="store_true", help="with --verify-sbom, exit 1 for any mismatch")
    jar_scan.add_argument("--fail-on-version-conflict", action="store_true", help="with --verify-sbom, exit 1 for version conflicts")
    jar_scan.add_argument("--fail-on-untracked", action="store_true", help="with --verify-sbom, exit 1 for archives missing from the SBOM")
    jar_scan.add_argument("--strict-hash", action="store_true", help="with --verify-sbom, require a SHA-256 in the SBOM")
    jar_scan.add_argument("--format", choices=("json", "html", "markdown"), default="html", help="primary report format; HTML writes the main and detail report pair")

    sbom_verify = subparsers.add_parser("sbom-verify", help="compare a CycloneDX SBOM with deployed JAR/WAR/EAR archives")
    sbom_verify.add_argument("--target", required=True, help="directory containing deployed JAR, WAR, and EAR files")
    sbom_verify.add_argument("--sbom", help="current CycloneDX SBOM")
    sbom_verify.add_argument("--baseline-sbom", help="approved baseline CycloneDX SBOM")
    sbom_verify.add_argument("--output-dir", default="reports/sbom-verification", help="verification report directory")
    sbom_verify.add_argument("--exclude", action="append", default=[], help="archive relative-path/name glob to skip")
    sbom_verify.add_argument("--max-depth", type=_positive_int, default=3, help="maximum nested archive depth")
    sbom_verify.add_argument("--fail-on-mismatch", action="store_true", help="exit 1 when any mismatch is found")
    sbom_verify.add_argument("--fail-on-version-conflict", action="store_true", help="exit 1 when a version conflict is found")
    sbom_verify.add_argument("--fail-on-untracked", action="store_true", help="exit 1 when an archive is missing from the SBOM")
    sbom_verify.add_argument("--strict-hash", action="store_true", help="treat a missing or different SBOM SHA-256 as a mismatch")
    sbom_verify.add_argument("--format", choices=("json", "html", "markdown"), default="html", help="primary report format; all five artifacts are written")

    fix = subparsers.add_parser(
        "fix",
        help="apply safe deterministic fixes for auto-fixable findings (dry-run by default)",
    )
    fix.add_argument("--target", default=".", help="folder or file to scan and fix")
    fix.add_argument("--category", action="append", choices=CATEGORIES, help="categories to scan (default: code)")
    fix.add_argument("--rule", help="only fix findings with this rule id")
    fix.add_argument("--apply", action="store_true", help="write changes (default prints a dry-run diff)")
    fix.add_argument("--no-backup", action="store_true", help="do not write *.bak backups when applying")

    host_scan = subparsers.add_parser("host-scan", help="check this computer's security posture (host/endpoint)")
    host_scan.add_argument("--format", choices=("markdown", "json", "html", "sarif"), help="report format")
    host_scan.add_argument("--output", type=Path, help="report output path")
    host_scan.add_argument("--language", choices=("en", "ko"), help="report display language")
    host_scan.add_argument("--min-severity", choices=SEVERITIES, help="minimum severity to include (default info)")
    host_scan.add_argument("--fail-on", choices=SEVERITIES, help="exit 1 when findings meet or exceed severity")
    host_scan.add_argument("--inventory", action="store_true", help="collect installed application inventory")
    host_scan.add_argument("--eol", action="store_true", help="check OS end-of-life status via endoflife.date (network)")
    host_scan.add_argument(
        "--check-cve",
        action="store_true",
        help="look up installed-app CVEs via NVD (network, rate-limited, implies --inventory)",
    )
    host_scan.add_argument(
        "--nvd-api-key-env",
        help="environment variable holding an NVD API key (raises NVD rate limits)",
    )

    web_scan = subparsers.add_parser("web-scan", help="check a live website's security posture (headers, TLS, cookies, CORS)")
    web_scan.add_argument("--url", required=True, help="authorized http(s) URL to check")
    web_scan.add_argument("--format", choices=("markdown", "json", "html", "sarif"), help="report format")
    web_scan.add_argument("--output", type=Path, help="report output path")
    web_scan.add_argument("--language", choices=("en", "ko"), help="report display language")
    web_scan.add_argument("--min-severity", choices=SEVERITIES, help="minimum severity to include (default info)")
    web_scan.add_argument("--fail-on", choices=SEVERITIES, help="exit 1 when findings meet or exceed severity")
    web_scan.add_argument("--timeout", type=float, default=15.0, help="per-request timeout in seconds")
    web_scan.add_argument("--crawl", action="store_true", help="follow same-host links and scan sub-pages")
    web_scan.add_argument("--max-pages", type=_positive_int, default=50, help="maximum URLs to process while crawling (default 50)")
    web_scan.add_argument("--max-depth", type=_nonnegative_int, default=3, help="maximum same-host link depth while crawling (default 3)")
    web_scan.add_argument(
        "--render",
        action="store_true",
        help="render pages in headless Chromium to follow JS/SPA links (needs the 'render' extra)",
    )
    web_scan.add_argument(
        "--discover-assets",
        action="store_true",
        help="mine same-host JS bundles for route/API paths (no browser needed)",
    )
    web_scan.add_argument(
        "--capture-network",
        action="store_true",
        help="with --render, record same-host URLs the page fetches",
    )
    web_scan.add_argument(
        "--interact",
        action="store_true",
        help="with --render, click bounded elements to discover button/router routes",
    )
    web_scan.add_argument("--scan-js-secrets", action="store_true", help="scan same-host JS bundles for leaked secrets (keys/tokens)")
    web_scan.add_argument("--ingest-sitemap", action="store_true", help="enqueue URLs from /robots.txt and /sitemap.xml")
    web_scan.add_argument("--probe-paths", action="store_true", help="probe well-known sensitive paths (/.env, /.git/config, ...)")
    web_scan.add_argument(
        "--active",
        action="store_true",
        help="send bounded, non-destructive attack payloads to URL query params to verify reflected XSS / error-based SQLi / open redirect (authorized targets only)",
    )
    web_scan.add_argument(
        "--api-spec",
        type=Path,
        metavar="FILE",
        help="OpenAPI/HAR/Postman JSON to seed the crawl with the API's GET endpoints",
    )
    web_scan.add_argument(
        "--compare-unauth",
        action="store_true",
        help="access-control check: re-request authenticated pages without auth and flag matching content",
    )
    web_scan.add_argument(
        "--secondary-header",
        action="append",
        default=[],
        metavar="'Name: value'",
        help="a second account's header/cookie for cross-account IDOR/BOLA comparison (repeatable)",
    )
    web_scan.add_argument(
        "--seed",
        action="append",
        default=[],
        metavar="URL",
        help="extra same-host URL/path to scan (known route, sitemap entry); repeatable",
    )
    web_scan.add_argument("--delay", type=float, default=0.3, help="seconds to wait between crawl requests (default 0.3)")
    web_scan.add_argument("--login-url", help="URL of a login form to authenticate before scanning")
    web_scan.add_argument("--username", help="username for form login")
    web_scan.add_argument("--password", help="password for form login")
    web_scan.add_argument("--password-env", help="env var holding the login password (preferred over --password)")
    web_scan.add_argument("--user-field", help="login form field name for the username (auto-detected if omitted)")
    web_scan.add_argument("--pass-field", help="login form field name for the password (auto-detected if omitted)")
    web_scan.add_argument(
        "--header",
        action="append",
        default=[],
        metavar="'Name: value'",
        help="extra request header, e.g. --header 'Cookie: session=...' (repeatable)",
    )

    web_audit = subparsers.add_parser(
        "web-audit",
        help="run a profile-driven, approval-gated audit of 21 web controls",
    )
    web_audit_subparsers = web_audit.add_subparsers(dest="web_audit_action", required=True)
    web_audit_plan = web_audit_subparsers.add_parser("plan", help="validate a profile and create a no-traffic approval request")
    web_audit_plan.add_argument("--profile", type=Path, required=True)
    web_audit_plan.add_argument("--out", type=Path, required=True)
    web_audit_approve = web_audit_subparsers.add_parser("approve", help="sign an approval request with KODA_APPROVAL_KEY")
    web_audit_approve.add_argument("--request", type=Path, required=True)
    web_audit_approve.add_argument("--approver", required=True)
    web_audit_approve.add_argument("--out", type=Path, required=True)
    web_audit_approve.add_argument("--key-env", default="KODA_APPROVAL_KEY")
    web_audit_run = web_audit_subparsers.add_parser("run", help="consume approval once and execute the declared audit")
    web_audit_run.add_argument("--profile", type=Path, required=True)
    web_audit_run.add_argument("--approval", type=Path, required=True)
    web_audit_run.add_argument("--confirm-origin", required=True)
    web_audit_run.add_argument("--key-env", default="KODA_APPROVAL_KEY")
    web_audit_run.add_argument("--state-dir", type=Path, default=None)
    web_audit_run.add_argument("--output-dir", type=Path, default=None)
    web_audit_run.add_argument("--output", type=Path, default=None)
    web_audit_run.add_argument("--format", choices=("json", "markdown"), default="json")
    web_audit_run.add_argument("--language", choices=("en", "ko"), default="ko")
    web_audit_run.add_argument("--dry-run", action="store_true", help="verify approval without target requests or nonce consumption")

    discover = subparsers.add_parser("discover", help="list project roots under a folder")
    discover.add_argument("--target", default=".", help="folder to inspect")

    serve = subparsers.add_parser("serve", help="run the local dashboard server")
    serve.add_argument("--host", default="127.0.0.1", help="host interface to bind")
    serve.add_argument("--port", type=int, default=8765, help="port to bind")
    serve.add_argument("--language", choices=("en", "ko"), default="ko", help="initial dashboard language")
    serve.add_argument("--portal", action="store_true", help="run the authenticated Linux portal")
    serve.add_argument("--legacy-dashboard", action="store_true", help="keep the unauthenticated local dashboard (development only)")
    serve.add_argument("--db", default=os.environ.get("KODA_PORTAL_DB", "koda-portal.sqlite3"), help="portal SQLite database")

    schedule_worker = subparsers.add_parser("schedule-worker", help="run the nightly remote-directory schedule worker")
    schedule_worker.add_argument("--db", default=os.environ.get("KODA_PORTAL_DB", "koda-portal.sqlite3"), help="portal SQLite database")
    schedule_worker.add_argument("--work-dir", default=os.environ.get("KODA_SCHEDULE_WORK_DIR"), help="temporary schedule work directory")
    schedule_worker.add_argument("--once", action="store_true", help="run the current KST schedule date once")

    bootstrap = subparsers.add_parser("portal-bootstrap", help="explicitly enable the first portal administrator")
    bootstrap.add_argument("--tracker-user-id", required=True, help="Tracker UUID")
    bootstrap.add_argument("--db", default=os.environ.get("KODA_PORTAL_DB", "koda-portal.sqlite3"), help="portal SQLite database")

    app = subparsers.add_parser("app", help="run the dashboard like a local desktop app")
    app.add_argument("--host", default="127.0.0.1", help="host interface to bind")
    app.add_argument("--port", type=int, default=8765, help="first port to try")
    app.add_argument("--language", choices=("en", "ko"), default="ko", help="initial dashboard language")
    app.add_argument("--no-browser", action="store_true", help="do not open the default browser automatically")

    init_security = subparsers.add_parser("init-security", help="write preventive security templates into a project")
    init_security.add_argument("--target", default=".", help="project folder to initialize")
    init_security.add_argument("--project-name", default="", help="project name to include in templates")
    init_security.add_argument("--force", action="store_true", help="overwrite existing template files")
    init_security.add_argument("--dry-run", action="store_true", help="print files that would be created")

    install_hook = subparsers.add_parser("install-hook", help="install a KODA pre-commit security gate into a Git repository")
    install_hook.add_argument("--target", default=".", help="Git repository folder")
    install_hook.add_argument("--fail-on", choices=SEVERITIES, default="high", help="block commits at or above this severity")
    install_hook.add_argument("--force", action="store_true", help="overwrite an existing pre-commit hook")

    repo_security = subparsers.add_parser("repo-security-checklist", help="write a GitHub repository security settings checklist")
    repo_security.add_argument("--target", default=".", help="project folder name used for the checklist")
    repo_security.add_argument("--project-name", default="", help="project name")
    repo_security.add_argument("--output", type=Path, help="checklist output path")

    ssdf_plan = subparsers.add_parser("ssdf-plan", help="write a NIST SSDF workflow plan")
    ssdf_plan.add_argument("--target", default=".", help="project folder name used for the plan")
    ssdf_plan.add_argument("--project-name", default="", help="project name")
    ssdf_plan.add_argument("--output", type=Path, help="plan output path")

    secure_by_design = subparsers.add_parser("secure-by-design-plan", help="write a CISA Secure by Design prevention plan")
    secure_by_design.add_argument("--target", default=".", help="project folder name used for the plan")
    secure_by_design.add_argument("--project-name", default="", help="project name")
    secure_by_design.add_argument("--output", type=Path, help="plan output path")

    sigstore_plan = subparsers.add_parser("sigstore-plan", help="write a SLSA/Sigstore release signing plan")
    sigstore_plan.add_argument("--target", default=".", help="project folder name used for the plan")
    sigstore_plan.add_argument("--project-name", default="", help="project name")
    sigstore_plan.add_argument("--artifact", default="dist/app.tar.gz", help="artifact path to reference in commands")
    sigstore_plan.add_argument("--output", type=Path, help="plan output path")

    zap_command = subparsers.add_parser("zap-command", help="print an OWASP ZAP baseline Docker command")
    zap_command.add_argument("--url", required=True, help="authorized http(s) URL to check")
    zap_command.add_argument("--output-dir", default="reports/zap", help="folder for ZAP reports")
    zap_command.add_argument("--minutes", type=int, default=1, help="spider duration in minutes")

    zap_run = subparsers.add_parser("zap-run", help="run OWASP ZAP baseline against an authorized URL")
    zap_run.add_argument("--url", required=True, help="authorized http(s) URL to check")
    zap_run.add_argument("--output-dir", default="reports/zap", help="folder for ZAP reports")
    zap_run.add_argument("--minutes", type=int, default=1, help="spider duration in minutes")
    zap_run.add_argument("--timeout", type=int, default=900, help="maximum runtime in seconds")
    zap_run.add_argument("--mode", choices=("baseline", "full", "api", "automation"), default="baseline",
                         help="baseline=passive, full=active attack scan, api=OpenAPI/GraphQL/SOAP active scan, automation=YAML plan (spider/ajax/active/auth/openapi)")
    zap_run.add_argument("--authorize-active", action="store_true",
                         help="required to run --mode full/api, or automation with --active-scan (active attack traffic)")
    # ZAP Automation Framework (--mode automation) options:
    zap_run.add_argument("--ajax-spider", action="store_true", help="[automation] add an Ajax (browser) spider job")
    zap_run.add_argument("--active-scan", action="store_true", help="[automation] add an active scan job (attack traffic)")
    zap_run.add_argument("--include-path", action="append", default=[], metavar="REGEX", help="[automation] context include path regex (repeatable)")
    zap_run.add_argument("--exclude-path", action="append", default=[], metavar="REGEX", help="[automation] context exclude path regex (repeatable)")
    zap_run.add_argument("--openapi-url", help="[automation] OpenAPI definition URL to import")
    zap_run.add_argument("--openapi-file", help="[automation] OpenAPI filename placed in --output-dir")
    zap_run.add_argument("--af-auth-method", choices=("form", "json"), help="[automation] authentication method")
    zap_run.add_argument("--af-login-url", help="[automation] login page/request URL for authenticated scan")
    zap_run.add_argument("--af-login-body", help="[automation] login request body (use {%%username%%}/{%%password%%})")
    zap_run.add_argument("--af-logged-in-regex", help="[automation] regex proving a logged-in response")
    zap_run.add_argument("--af-username", help="[automation] scan user's username")
    zap_run.add_argument("--af-password", help="[automation] scan user's password")
    zap_run.add_argument("--context-file", help="ZAP .context filename placed in --output-dir (for authenticated scans)")
    zap_run.add_argument("--user", help="context user to scan as (authenticated scan)")
    zap_run.add_argument("--api-format", choices=("openapi", "soap", "graphql"), help="spec format for --mode api")
    zap_run.add_argument("--fail-on-level", choices=("PASS", "IGNORE", "INFO", "WARN", "FAIL"),
                         help="minimum ZAP alert level to include/fail on")
    zap_run.add_argument("--respect-exit-code", action="store_true", help="propagate ZAP's non-zero exit code (1=FAIL, 2=WARN)")
    zap_run.add_argument("--dry-run", action="store_true", help="print the Docker command without running ZAP")
    zap_run.add_argument("--fail-on-alerts", action="store_true", help="exit 1 when ZAP reports any finding")

    evidence = subparsers.add_parser("evidence-checklist", help="write a manual evidence checklist for standards that require evidence review")
    evidence.add_argument("--target", default=".", help="project folder name used for the checklist")
    evidence.add_argument("--project-name", default="", help="project name to include in the checklist")
    evidence.add_argument("--output", default="manual-evidence-checklist.md", help="checklist output path")
    evidence.add_argument("--language", choices=("en", "ko"), default="ko", help="checklist language")
    evidence.add_argument("--format", choices=("markdown", "json"), default="markdown", help="checklist format")

    diff_reports = subparsers.add_parser("diff-reports", help="compare two JSON scan reports")
    diff_reports.add_argument("--baseline", required=True, help="older JSON scan report")
    diff_reports.add_argument("--current", required=True, help="newer JSON scan report")
    diff_reports.add_argument("--output", type=Path, help="diff report output path")
    diff_reports.add_argument("--format", choices=("markdown", "json"), default="markdown", help="diff report format")
    diff_reports.add_argument("--language", choices=("en", "ko"), default="ko", help="diff report language")

    manifest = subparsers.add_parser("manifest", help="create or compare deployment file manifests")
    manifest_subparsers = manifest.add_subparsers(dest="manifest_command", required=True)
    manifest_create = manifest_subparsers.add_parser("create", help="create a SHA-256 file manifest for a target")
    manifest_create.add_argument("--target", required=True, help="file or directory to inventory")
    manifest_create.add_argument("--output", type=Path, help="manifest JSON output path")
    manifest_compare = manifest_subparsers.add_parser("compare", help="compare a manifest against a target")
    manifest_compare.add_argument("--baseline", required=True, help="baseline manifest JSON")
    manifest_compare.add_argument("--target", required=True, help="file or directory to compare")
    manifest_compare.add_argument("--output", type=Path, help="comparison JSON output path")

    deploy_check = subparsers.add_parser("deploy-check", help="scan a deployment target and write a file manifest")
    deploy_check.add_argument("--target", required=True, help="deployment file or directory to check")
    deploy_check.add_argument("--output-dir", default="reports/koda-deploy", help="directory for scan and manifest outputs")
    deploy_check.add_argument("--language", choices=("en", "ko"), default="ko", help="report language")
    deploy_check.add_argument("--min-severity", choices=SEVERITIES, default="low", help="minimum severity to include")
    deploy_check.add_argument("--fail-on", choices=SEVERITIES, default="high", help="exit 1 when findings meet or exceed severity")

    release_package = subparsers.add_parser("release-package", help="create a release security package with SBOM, VEX, checklist, findings, and checksums")
    release_package.add_argument("--target", default=".", help="project folder to package")
    release_package.add_argument("--output-dir", default="KODA-release-security-package", help="output folder")
    release_package.add_argument("--project-name", default="", help="project name")
    release_package.add_argument("--language", choices=("en", "ko"), default="ko", help="package language")
    release_package.add_argument("--enable-vuln-intel", action="store_true", help="query OSV/CVE and KEV/EPSS while building package")

    dependency_track_command = subparsers.add_parser("dependency-track-command", help="print a Dependency-Track SBOM upload curl command")
    dependency_track_command.add_argument("--server-url", required=True, help="Dependency-Track backend URL")
    dependency_track_command.add_argument("--project-name", required=True, help="Dependency-Track project name")
    dependency_track_command.add_argument("--project-version", default="main", help="Dependency-Track project version")
    dependency_track_command.add_argument("--sbom", default="reports/sbom.cdx.json", help="CycloneDX SBOM path")
    dependency_track_command.add_argument("--api-key-env", default="DEPENDENCY_TRACK_API_KEY", help="environment variable used in the generated command")
    dependency_track_command.add_argument("--auto-create", action=argparse.BooleanOptionalAction, default=True, help="allow project auto-creation")

    upload_sbom = subparsers.add_parser("upload-sbom", help="upload a CycloneDX SBOM to Dependency-Track")
    upload_sbom.add_argument("--server-url", required=True, help="Dependency-Track backend URL")
    upload_sbom.add_argument("--project-name", required=True, help="Dependency-Track project name")
    upload_sbom.add_argument("--project-version", default="main", help="Dependency-Track project version")
    upload_sbom.add_argument("--sbom", required=True, help="CycloneDX SBOM path")
    upload_sbom.add_argument("--api-key", default="", help="Dependency-Track API key; prefer --api-key-env for shell history safety")
    upload_sbom.add_argument("--api-key-env", default="DEPENDENCY_TRACK_API_KEY", help="environment variable containing the API key")
    upload_sbom.add_argument("--auto-create", action=argparse.BooleanOptionalAction, default=True, help="allow project auto-creation")

    subparsers.add_parser("list-categories", help="show available check categories")
    return parser


@contextmanager
def _build_scan_config_context(args: argparse.Namespace):
    with tempfile.TemporaryDirectory(prefix="koda-inputs-") as temp_dir:
        yield _build_scan_config(args, archive_extract_root=Path(temp_dir))


def _build_scan_config(args: argparse.Namespace, *, archive_extract_root: Path | None = None) -> ScannerConfig:
    if args.config:
        config = load_config(args.config)
    elif args.target:
        config = _config_from_cli(args, archive_extract_root=archive_extract_root)
    elif Path("scanner_config.json").exists():
        config = load_config(Path("scanner_config.json"))
    elif Path("scanner_config.example.json").exists():
        config = load_config(Path("scanner_config.example.json"))
    else:
        config = _config_from_cli(args, archive_extract_root=archive_extract_root)

    return _apply_overrides(config, args, archive_extract_root=archive_extract_root)


def _config_from_cli(args: argparse.Namespace, *, archive_extract_root: Path | None = None) -> ScannerConfig:
    target_values = args.target or ["."]
    explicit_categories = tuple(args.category) if args.category else None
    standard = getattr(args, "standard", None) or DEFAULT_STANDARD
    standard_category = getattr(args, "standard_category", None) or DEFAULT_STANDARD_CATEGORY
    selection = resolve_standard_selection(
        standard,
        standard_category,
        explicit_categories=explicit_categories
        if standard == DEFAULT_STANDARD and standard_category == DEFAULT_STANDARD_CATEGORY and not getattr(args, "standard_category", None)
        else None,
    )
    categories = selection.scanner_categories
    base_dir = Path.cwd()
    targets = tuple(
        TargetConfig(
            name=Path(target).expanduser().name or target,
            path=prepare_input_target(expand_path(target, base_dir), archive_extract_root),
            categories=categories,
            max_file_size_bytes=args.max_file_size or 524288,
            discover_projects=bool(args.discover_projects),
            discovery_depth=None,
        )
        for target in target_values
    )
    report = ReportConfig(
        format=args.format or "markdown",
        output=args.output.resolve() if args.output else None,
        min_severity=args.min_severity or "low",
        language=args.language or "ko",
    )
    enable_vuln_intel = bool(getattr(args, "enable_vuln_intel", False))
    return ScannerConfig(
        targets=targets,
        report=report,
        enable_osv=bool(args.enable_osv) or enable_vuln_intel,
        enable_vuln_intel=enable_vuln_intel,
        enable_reachability=bool(getattr(args, "reachability", False)),
        enable_ai_triage=bool(getattr(args, "ai_triage", False)),
        llm_model=getattr(args, "llm", None),
        changed_only=bool(getattr(args, "changed_only", False)),
        diff_base=getattr(args, "base", None),
        standard=selection.standard,
        standard_category=selection.category,
    )


def _apply_overrides(
    config: ScannerConfig,
    args: argparse.Namespace,
    *,
    archive_extract_root: Path | None = None,
) -> ScannerConfig:
    targets = config.targets
    selected_standard = config.standard
    selected_category = config.standard_category
    if getattr(args, "standard", None) or getattr(args, "standard_category", None) or getattr(args, "category", None):
        selected_standard = getattr(args, "standard", None) or selected_standard or DEFAULT_STANDARD
        selected_category = getattr(args, "standard_category", None) or DEFAULT_STANDARD_CATEGORY
        selection = resolve_standard_selection(
            selected_standard,
            selected_category,
            explicit_categories=tuple(args.category)
            if args.category and selected_standard == DEFAULT_STANDARD and selected_category == DEFAULT_STANDARD_CATEGORY and not getattr(args, "standard_category", None)
            else None,
        )
        selected_standard, selected_category = selection.standard, selection.category
        if not args.target:
            targets = tuple(
                TargetConfig(
                    name=target.name,
                    path=target.path,
                    categories=selection.scanner_categories,
                    exclude_globs=target.exclude_globs,
                    max_file_size_bytes=target.max_file_size_bytes,
                    discover_projects=target.discover_projects,
                    discovery_depth=target.discovery_depth,
                )
                for target in config.targets
            )
    if args.target:
        cli_config = _config_from_cli(args, archive_extract_root=archive_extract_root)
        targets = cli_config.targets
    elif args.category or args.max_file_size or args.discover_projects:
        targets = tuple(
            TargetConfig(
                name=target.name,
                path=target.path,
                categories=tuple(args.category) if args.category else target.categories,
                exclude_globs=target.exclude_globs,
                max_file_size_bytes=args.max_file_size or target.max_file_size_bytes,
                discover_projects=True if args.discover_projects else target.discover_projects,
                discovery_depth=None if args.discover_projects else target.discovery_depth,
            )
            for target in config.targets
        )

    report = ReportConfig(
        format=args.format or config.report.format,
        output=args.output.resolve() if args.output else config.report.output,
        min_severity=args.min_severity or config.report.min_severity,
        language=args.language or config.report.language,
    )
    enable_vuln_intel = bool(getattr(args, "enable_vuln_intel", False)) or config.enable_vuln_intel
    return ScannerConfig(
        targets=targets,
        report=report,
        enable_osv=bool(args.enable_osv) or config.enable_osv or enable_vuln_intel,
        enable_vuln_intel=enable_vuln_intel,
        enable_reachability=bool(getattr(args, "reachability", False)) or config.enable_reachability,
        enable_ai_triage=bool(getattr(args, "ai_triage", False)) or config.enable_ai_triage,
        llm_model=getattr(args, "llm", None) or config.llm_model,
        changed_only=bool(getattr(args, "changed_only", False)) or config.changed_only,
        diff_base=getattr(args, "base", None) or config.diff_base,
        standard=selected_standard,
        standard_category=selected_category,
        source_analyzer=config.source_analyzer,
        source_analyzer_binary=config.source_analyzer_binary,
        source_analyzer_timeout=config.source_analyzer_timeout,
        source_analyzer_sarif=config.source_analyzer_sarif,
        source_analyzer_license_attested=config.source_analyzer_license_attested,
        source_analyzer_sandbox_wrapper=config.source_analyzer_sandbox_wrapper,
        source_analyzer_sandbox_config=config.source_analyzer_sandbox_config,
    )


def _has_failure(findings, fail_on: str) -> bool:
    from .models import SEVERITY_RANK

    threshold = SEVERITY_RANK[fail_on]
    return any(
        finding.verification_status == "confirmed"
        and SEVERITY_RANK[finding.severity] >= threshold
        for finding in findings
    )


def _parse_headers(raw: list[str]) -> dict[str, str]:
    """Parse ``--header 'Name: value'`` args into a dict. Malformed items skipped."""
    headers: dict[str, str] = {}
    for item in raw:
        name, sep, value = item.partition(":")
        if sep and name.strip():
            headers[name.strip()] = value.strip()
    return headers


def json_dumps(payload: object) -> str:
    return json.dumps(payload, indent=2, ensure_ascii=False)
