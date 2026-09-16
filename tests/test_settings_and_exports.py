from __future__ import annotations

import csv
import io
import importlib.util
import sys
import http.client
import json
import os
import re
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SHARED_PYTHON = ROOT / "platforms" / "shared" / "python"
if str(SHARED_PYTHON) not in sys.path:
    sys.path.insert(0, str(SHARED_PYTHON))

from security_scanner.grype_adapter import GrypeMatch, GrypeResult
from security_scanner.models import DependencyComponent, Finding
from security_scanner.reporting import (
    build_rule_catalog,
    filter_disabled_rules,
    PdfExportError,
    render_html,
    render_html_pair,
    render_html_pair_zip_from_payload,
    render_hwpx,
    render_markdown_from_payload,
    render_pdf,
    render_xlsx,
)
from security_scanner.server import (
    DEFAULT_UPLOAD_MAX_BYTES, DEFAULT_UPLOAD_MAX_EXTRACTED_BYTES, DEFAULT_UPLOAD_MAX_FILES,
    create_dashboard_server, scan_directory_payload, zap_scan_payload,
)
from security_scanner.sbom import NIS_SBOM_COLUMNS, cyclonedx_payload, render_nis_sbom
from security_scanner.standards import standards_payload

SAMPLE_PAYLOAD = {
    "findings": [
        {
            "severity": "high",
            "category": "secrets",
            "rule_id": "secret.aws-access-key",
            "title": "AWS access key",
            "path": "config.env",
            "line": 1,
            "recommendation": "Rotate the key.",
        },
        {
            "severity": "low",
            "category": "code",
            "rule_id": "code.weak-hash",
            "title": "Weak hash",
            "path": "app.py",
            "line": None,
            "recommendation": "Use SHA-256.",
        },
    ]
}


class RuleCatalogTests(unittest.TestCase):
    def test_security_grouped_by_standard_plus_quality(self) -> None:
        catalog = build_rule_catalog("ko")
        kinds = {group["kind"] for group in catalog}
        self.assertEqual(kinds, {"security", "quality"})
        keys = {group["key"] for group in catalog}
        # Security groups are standards, e.g. "소프트웨어 개발보안 49".
        self.assertIn("sw-dev-security-49", keys)
        # The default "local" profile is every rule at once; it would duplicate
        # the per-standard groups, so it is not listed.
        self.assertNotIn("local", keys)
        self.assertIn("screen_quality", keys)
        # The example standard is labelled and non-empty.
        sw49 = next(g for g in catalog if g["key"] == "sw-dev-security-49")
        self.assertEqual(sw49["label"], "소프트웨어 개발보안 49")
        self.assertTrue(sw49["rules"])

    def test_every_rule_has_id_and_title(self) -> None:
        for language in ("ko", "en"):
            for group in build_rule_catalog(language):
                self.assertTrue(group["rules"], f"{group['key']} has no rules")
                for rule in group["rules"]:
                    self.assertTrue(rule["id"])
                    self.assertTrue(rule["title"])

    def test_korean_titles_use_translations(self) -> None:
        group = next(g for g in build_rule_catalog("ko") if g["key"] == "owasp-top-10-2025")
        titles = {rule["id"]: rule["title"] for rule in group["rules"]}
        # secret.private-key has a Korean translation in RULE_TRANSLATIONS_KO.
        self.assertIn("secret.private-key", titles)
        self.assertNotEqual(titles["secret.private-key"], "Private key")

    def test_local_standard_uses_koda_branding(self) -> None:
        local = next(item for item in standards_payload() if item["id"] == "local")
        text = json.dumps(local, ensure_ascii=False)
        self.assertIn("KODA", text)
        self.assertNotIn("SecChk", text)


class SbomBrandingTests(unittest.TestCase):
    def test_cyclonedx_uses_koda_branding(self) -> None:
        component = DependencyComponent(
            name="requests",
            version="2.32.0",
            ecosystem="PyPI",
            target="app",
            source="requirements.txt",
            path=Path("requirements.txt"),
        )
        payload = cyclonedx_payload([component])
        tool = payload["metadata"]["tools"]["components"][0]  # type: ignore[index]
        properties = payload["components"][0]["properties"]  # type: ignore[index]
        self.assertEqual(tool["name"], "KODA")
        self.assertTrue(all(item["name"].startswith("koda:") for item in properties))
        self.assertNotIn("purl", payload["components"][0])  # type: ignore[index]
        self.assertNotIn("sec-chk", json.dumps(payload))


class DisabledRuleFilterTests(unittest.TestCase):
    def _finding(self, rule_id: str) -> Finding:
        return Finding(rule_id=rule_id, category="secrets", severity="high", title="t", path=Path("a"))

    def test_disabled_rule_is_dropped(self) -> None:
        findings = [self._finding("secret.aws-access-key"), self._finding("code.weak-hash")]
        kept = filter_disabled_rules(findings, ["secret.aws-access-key"])
        self.assertEqual([f.rule_id for f in kept], ["code.weak-hash"])

    def test_empty_disabled_is_noop(self) -> None:
        findings = [self._finding("secret.aws-access-key")]
        self.assertEqual(filter_disabled_rules(findings, []), findings)
        self.assertEqual(filter_disabled_rules(findings, None), findings)


class LocalVulnerabilityScanTests(unittest.TestCase):
    def test_scan_scope_limits_the_scanner_categories(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "requirements.txt").write_text("requests==2.32.0\n", encoding="utf-8")
            (root / "app.py").write_text("password = 'secret'\n", encoding="utf-8")
            library = scan_directory_payload(str(root), discover_projects=False, scan_scope="library")
            source = scan_directory_payload(str(root), discover_projects=False, scan_scope="source")
        self.assertEqual(library["scan"]["scanned_categories"], ["dependencies"])
        self.assertEqual(source["scan"]["scanned_categories"], ["secrets", "configuration", "code", "prevention"])
        self.assertEqual(library["scan"]["scope"], "library")
        self.assertEqual(source["scan"]["scope"], "source")

    def test_local_grype_findings_are_added_to_source_scan(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            requirements = Path(directory) / "requirements.txt"
            requirements.write_text("requests==2.19.1\n", encoding="utf-8")
            match = GrypeMatch(
                "CVE-2018-18074", ("CVE-2018-18074",), "requests", "2.19.1",
                "pkg:pypi/requests@2.19.1", ("2.20.0",), "high", (), ("exact-direct-match",),
            )
            with patch("security_scanner.server.run_grype_purls", return_value=GrypeResult((match,), "", {}, "", False)) as grype:
                payload = scan_directory_payload(
                    str(requirements), allow_file=True, enable_local_vulnerabilities=True,
                    grype_binary=Path("/opt/koda/tools/grype"),
                )
            self.assertEqual(grype.call_args.args[0], ("pkg:pypi/requests@2.19.1",))
            finding = next(item for item in payload["findings_by_language"]["en"] if item["rule_id"] == "dependency.osv-known-vulnerability")
            self.assertEqual((finding["severity"], finding["path"]), ("high", str(requirements.resolve())))
            self.assertIn("CVE-2018-18074", finding["evidence"])


class ExportTests(unittest.TestCase):
    def test_nis_sbom_uses_the_official_twenty_columns(self) -> None:
        component = DependencyComponent(
            name="requests",
            ecosystem="PyPI",
            version="2.32.0",
            path=Path("requirements.txt"),
            target="src",
            purl="pkg:pypi/requests@2.32.0",
        )

        document = render_nis_sbom((component,), product_name="sample")
        rows = list(csv.DictReader(io.StringIO(document.lstrip("\ufeff"))))

        self.assertTrue(document.startswith("\ufeff"))
        self.assertIn("\r\n", document)
        self.assertEqual(tuple(rows[0]), NIS_SBOM_COLUMNS)
        self.assertEqual(rows[0]["SBOM Standard"], "NIS 1.0")
        self.assertEqual(rows[0]["SBOM Type"], "Analyzed")
        self.assertRegex(rows[0]["SBOM ID"], rf"^KODA-\d{{8}}-\d{{6}}$")
        self.assertEqual(rows[0]["Product Name"], "sample")
        self.assertEqual(rows[0]["Unique Identifier"], "pkg:pypi/requests@2.32.0")

    def test_shared_windows_dashboard_exposes_nis_sbom_download(self) -> None:
        component = DependencyComponent(
            name="requests",
            ecosystem="PyPI",
            version="2.32.0",
            path=Path("requirements.txt"),
            target="src",
            purl="pkg:pypi/requests@2.32.0",
        )

        document = render_html([], target_names=("sample",), language="ko", components=(component,))
        payload_text = re.search(
            r'<script id="findings-data" type="application/json">(.*?)</script>',
            document,
            re.DOTALL,
        )

        self.assertIsNotNone(payload_text)
        payload = json.loads(payload_text.group(1))
        self.assertEqual(payload["nis_sbom"]["columns"], list(NIS_SBOM_COLUMNS))
        self.assertEqual(payload["nis_sbom"]["rows"][0]["Product Name"], "sample")
        self.assertIn('<option value="nis-sbom"></option>', document)
        self.assertIn('"koda-nis-sbom-1.0.csv"', document)

    def test_optional_sbom_tracker_link_is_opt_in_and_safe(self) -> None:
        with patch.dict(os.environ, {"KODA_SSBOM_TRACKER_URL": "http://127.0.0.1:8088/"}):
            document = render_html([], language="ko")
        self.assertIn('href="http://127.0.0.1:8088/"', document)
        self.assertIn("SBOM Tracker 열기", document)
        self.assertIn('target="_blank"', document)
        self.assertIn('rel="noopener noreferrer"', document)

        with patch.dict(os.environ, {"KODA_SSBOM_TRACKER_URL": "javascript:alert(1)"}):
            unsafe_document = render_html([], language="ko")
        self.assertNotIn("javascript:alert", unsafe_document)
        self.assertNotIn("SBOM Tracker 열기", unsafe_document)

    def test_markdown_export_lists_findings(self) -> None:
        markdown = render_markdown_from_payload(SAMPLE_PAYLOAD, "ko")
        self.assertIn("secret.aws-access-key", markdown)
        self.assertIn("code.weak-hash", markdown)
        self.assertIn("전체 발견 항목: 2", markdown)

    def test_xlsx_is_valid_zip_with_worksheet(self) -> None:
        data = render_xlsx(SAMPLE_PAYLOAD, "ko")
        self.assertTrue(zipfile.is_zipfile(io.BytesIO(data)))
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            names = archive.namelist()
            self.assertIn("[Content_Types].xml", names)
            self.assertIn("xl/worksheets/sheet1.xml", names)
            sheet = archive.read("xl/worksheets/sheet1.xml").decode("utf-8")
            self.assertIn("secret.aws-access-key", sheet)

    def test_html_export_contains_linked_main_and_detail_reports(self) -> None:
        payload = {
            **SAMPLE_PAYLOAD,
            "scan": {"kind": "source", "path": "src", "standard": "owasp-asvs-5"},
        }
        data = render_html_pair_zip_from_payload(payload, "ko")
        self.assertTrue(zipfile.is_zipfile(io.BytesIO(data)))
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            self.assertEqual(set(archive.namelist()), {"report.html", "report-detail.html"})
            main = archive.read("report.html").decode("utf-8")
            detail = archive.read("report-detail.html").decode("utf-8")
            self.assertNotIn("source-main-guide-open", main)
            self.assertIn('href="report-detail.html"', main)
            self.assertIn("상세 보고서 더보기", main)
            self.assertNotIn("source-detail-guide-open", detail)
            self.assertNotIn('href="report.html"', detail)
            self.assertIn("owasp-asvs-5", detail)

    def test_html_export_matches_cli_pair_context(self) -> None:
        finding = Finding(
            rule_id="code.weak-hash",
            category="code",
            severity="high",
            title="Weak hash",
            path=Path("app.py"),
            target="src",
            line=4,
            recommendation="Use SHA-256.",
        )
        component = DependencyComponent(
            name="requests",
            ecosystem="PyPI",
            version="2.32.0",
            path=Path("requirements.txt"),
            target="src",
            line=1,
        )
        payload = {
            "findings": [{**SAMPLE_PAYLOAD["findings"][1], "severity": "high", "target": "src", "line": 4}],
            "summary": {
                "by_target": {"src": 1},
                "target_paths": {"src": "/tmp/project"},
            },
            "components": [{
                "name": "requests",
                "ecosystem": "PyPI",
                "version": "2.32.0",
                "path": "requirements.txt",
                "target": "src",
                "line": 1,
                "scope": "required",
            }],
            "scan": {
                "kind": "source",
                "path": "/tmp/project",
                "standard": "owasp-asvs-5",
                "standard_category": "all",
                "scanned_categories": ["code"],
                "warnings": ["example warning"],
                "enable_osv": True,
            },
            "source_analysis": {"analyzed_languages": ["Python"]},
        }
        with patch("security_scanner.reporting._generated_at", return_value=("2026-08-07T00:00:00+00:00", "2026-08-07 00:00:00 UTC")):
            expected_main, expected_detail = render_html_pair(
                [finding],
                target_names=("src",),
                target_paths={"src": "/tmp/project"},
                language="ko",
                detail_href="report-detail.html",
                summary_href=None,
                components=(component,),
                warnings=("example warning",),
                scan_path="/tmp/project",
                kind="source",
                standard="owasp-asvs-5",
                standard_category="all",
                enable_osv=True,
                scanned_categories=("code",),
                source_analysis=payload["source_analysis"],
            )
            data = render_html_pair_zip_from_payload(payload, "ko")
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            self.assertEqual(archive.read("report.html").decode("utf-8"), expected_main)
            self.assertEqual(archive.read("report-detail.html").decode("utf-8"), expected_detail)

    def test_hwpx_is_valid_zip_with_hwp_mimetype(self) -> None:
        data = render_hwpx(SAMPLE_PAYLOAD, "ko")
        self.assertTrue(zipfile.is_zipfile(io.BytesIO(data)))
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            self.assertEqual(archive.namelist()[0], "mimetype")
            self.assertEqual(archive.read("mimetype").decode("utf-8"), "application/hwp+zip")
            section = archive.read("Contents/section0.xml").decode("utf-8")
            self.assertIn("AWS access key", section)
            # section0.xml must remain well-formed after substitution.
            import xml.dom.minidom as minidom

            minidom.parseString(section)

    @unittest.skipUnless(importlib.util.find_spec("playwright"), "requires bundled Chromium renderer")
    def test_pdf_export_is_a_downloadable_pdf_document(self) -> None:
        data = render_pdf(SAMPLE_PAYLOAD, "ko")
        self.assertTrue(data.startswith(b"%PDF-"))
        self.assertIn(b"startxref", data)

    def test_pdf_export_rejects_oversized_report_before_renderer(self) -> None:
        payload = {"findings": [{"title": "x" * 500_001}]}
        with self.assertRaises(PdfExportError):
            render_pdf(payload, "ko")

    def test_export_endpoint_returns_pdf_attachment(self) -> None:
        server = create_dashboard_server(port=0)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            connection = http.client.HTTPConnection("127.0.0.1", server.server_port)
            connection.request(
                "POST",
                "/api/export",
                body=json.dumps({"format": "pdf", "language": "ko", "payload": SAMPLE_PAYLOAD}),
                headers={"Content-Type": "application/json"},
            )
            response = connection.getresponse()
            if importlib.util.find_spec("playwright"):
                self.assertEqual(response.status, 200)
                self.assertEqual(response.getheader("Content-Type"), "application/pdf")
                self.assertEqual(response.getheader("Content-Disposition"), 'attachment; filename="koda-report.pdf"')
                self.assertTrue(response.read().startswith(b"%PDF-"))
            else:
                self.assertEqual(response.status, 503)
                self.assertIn("bundled Chromium renderer", response.read().decode("utf-8"))
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_export_endpoint_returns_html_pair_zip(self) -> None:
        server = create_dashboard_server(port=0)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            connection = http.client.HTTPConnection("127.0.0.1", server.server_port)
            connection.request(
                "POST",
                "/api/export",
                body=json.dumps({"format": "html", "language": "ko", "payload": SAMPLE_PAYLOAD}),
                headers={"Content-Type": "application/json"},
            )
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            self.assertEqual(response.getheader("Content-Type"), "application/zip")
            self.assertEqual(response.getheader("Content-Disposition"), 'attachment; filename="koda-report.zip"')
            with zipfile.ZipFile(io.BytesIO(response.read())) as archive:
                self.assertEqual(set(archive.namelist()), {"report.html", "report-detail.html"})
        finally:
            server.shutdown()
            server.server_close()
            thread.join()


class ZapScanTests(unittest.TestCase):
    def test_dry_run_builds_automation_plan_and_dashboard_payload(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "zap"
            payload = zap_scan_payload(
                "https://staging.example.com",
                language="ko",
                ajax_spider=True,
                active_scan=False,
                output_dir=out,
                dry_run=True,
            )
            # Dashboard-shaped payload the existing UI can render.
            self.assertIn("summary", payload)
            self.assertIn("findings_by_language", payload)
            self.assertEqual(payload["zap"]["ajax_spider"], True)
            self.assertEqual(payload["zap"]["active_scan"], False)
            self.assertIn("docker run", payload["zap"]["command"])
            plan = (out / "koda-zap-plan.yaml").read_text(encoding="utf-8")
            self.assertIn("spiderAjax", plan)
            self.assertNotIn("activeScan", plan)

    def test_auth_context_builds_authentication_in_plan(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "zap"
            payload = zap_scan_payload(
                "https://staging.example.com",
                auth={
                    "login_url": "https://staging.example.com/login",
                    "username": "alice",
                    "password": "secret",
                },
                output_dir=out,
                dry_run=True,
            )
            self.assertEqual(payload["zap"]["authenticated"], True)
            plan = (out / "koda-zap-plan.yaml").read_text(encoding="utf-8")
            self.assertIn("authentication", plan)
            self.assertIn("loginPageUrl", plan)
            self.assertIn("koda-user", plan)

    def test_auth_requires_both_credentials(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            zap_scan_payload(
                "https://staging.example.com",
                auth={"login_url": "https://staging.example.com/login", "username": "alice", "password": ""},
                dry_run=True,
            )
        self.assertIn("password", str(ctx.exception).lower())

    def test_no_login_url_is_unauthenticated(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "zap"
            payload = zap_scan_payload(
                "https://staging.example.com", auth={}, output_dir=out, dry_run=True
            )
            self.assertEqual(payload["zap"]["authenticated"], False)
            plan = (out / "koda-zap-plan.yaml").read_text(encoding="utf-8")
            self.assertNotIn("authentication", plan)

    def test_merge_folds_zap_into_prior_report(self) -> None:
        import tempfile

        from security_scanner.models import Finding
        from security_scanner.reporting import build_dashboard_payload

        prior = build_dashboard_payload(
            [
                Finding(rule_id="secrets.aws-key", category="secrets", severity="high",
                        title="AWS key", path=Path("app/config.py"), target="myapp", line=12),
                Finding(rule_id="deps.lodash", category="dependencies", severity="medium",
                        title="lodash CVE", path=Path("package.json"), target="myapp"),
            ],
            ("myapp",), "ko", target_paths={"myapp": "/repo/myapp"},
            scan_path="/repo/myapp", kind="directory",
        )
        prior["components"] = [{"name": "lodash", "version": "4.0.0"}]
        prior["sbom"] = {"bomFormat": "CycloneDX"}

        with tempfile.TemporaryDirectory() as directory:
            merged = zap_scan_payload(
                "https://staging.example.com", language="ko",
                output_dir=Path(directory) / "z", dry_run=True, merge=prior,
            )
            # Prior findings preserved and re-aggregated by the normal pipeline.
            self.assertEqual(len(merged["findings_by_language"]["en"]), 2)
            self.assertEqual(merged["zap"]["merged"], True)
            self.assertEqual(merged["summary"]["by_severity"].get("high"), 1)
            self.assertEqual(merged["summary"]["by_category"].get("secrets"), 1)
            # Both targets present; SBOM and scan context carried over.
            self.assertIn("myapp", merged["summary"]["target_paths"])
            self.assertIn("staging.example.com", merged["summary"]["target_paths"])
            self.assertEqual(merged["components"], [{"name": "lodash", "version": "4.0.0"}])
            self.assertEqual(merged["scan"]["kind"], "directory")
            self.assertEqual(merged["scan"]["path"], "/repo/myapp")

    def test_active_scan_requires_authorization(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            zap_scan_payload(
                "https://staging.example.com",
                active_scan=True,
                authorization_confirmed=False,
                dry_run=True,
            )
        self.assertIn("authorized", str(ctx.exception).lower())

    def test_authorized_active_scan_adds_active_job(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "zap"
            zap_scan_payload(
                "https://staging.example.com",
                active_scan=True,
                authorization_confirmed=True,
                output_dir=out,
                dry_run=True,
            )
            plan = (out / "koda-zap-plan.yaml").read_text(encoding="utf-8")
            self.assertIn("activeScan", plan)

    def test_route_rejects_unauthorized_active_scan(self) -> None:
        server = create_dashboard_server(port=0)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            connection = http.client.HTTPConnection("127.0.0.1", server.server_port)
            connection.request(
                "POST",
                "/api/zap-scan",
                body=json.dumps(
                    {"url": "https://staging.example.com", "active_scan": True, "authorization_confirmed": False}
                ),
                headers={"Content-Type": "application/json"},
            )
            response = connection.getresponse()
            self.assertEqual(response.status, 400)
            self.assertIn("authorized", json.loads(response.read())["error"].lower())
        finally:
            server.shutdown()
            server.server_close()
            thread.join()


class UploadScanTests(unittest.TestCase):
    def test_linux_upload_defaults_match_the_large_portal_limits(self) -> None:
        self.assertEqual(DEFAULT_UPLOAD_MAX_BYTES, 2 * 1024 * 1024 * 1024)
        self.assertEqual(DEFAULT_UPLOAD_MAX_EXTRACTED_BYTES, 4 * 1024 * 1024 * 1024)
        self.assertEqual(DEFAULT_UPLOAD_MAX_FILES, 400_000)

    def _upload(self, server, filename: str, body: bytes):
        connection = http.client.HTTPConnection("127.0.0.1", server.server_port)
        connection.request("GET", "/api/health")
        response = connection.getresponse()
        session = response.getheader("X-KODA-Session")
        response.read()
        self.assertTrue(session)

        connection = http.client.HTTPConnection("127.0.0.1", server.server_port)
        connection.request(
            "POST",
            "/api/scan-upload?language=ko&standard=local&standard_category=all",
            body=body,
            headers={
                "Content-Type": "application/octet-stream",
                "Origin": f"http://127.0.0.1:{server.server_port}",
                "X-KODA-Session": session,
                "X-KODA-Filename": filename,
            },
        )
        return connection.getresponse()

    def test_file_and_archive_uploads_scan_without_exposing_temp_paths(self) -> None:
        server = create_dashboard_server(port=0)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            response = self._upload(server, "config.env", b"AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP\n")
            payload = json.loads(response.read())
            self.assertEqual(response.status, 200)
            self.assertEqual((payload["scan"]["kind"], payload["scan"]["path"]), ("upload", "config.env"))
            self.assertIn("secret.aws-access-key", {item["rule_id"] for item in payload["findings_by_language"]["en"]})
            self.assertEqual(set(payload["summary"]["target_paths"].values()), {"config.env"})

            archive_body = io.BytesIO()
            with zipfile.ZipFile(archive_body, "w") as archive:
                archive.writestr("src/config.env", "AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP\n")
            response = self._upload(server, "source.zip", archive_body.getvalue())
            payload = json.loads(response.read())
            self.assertEqual(response.status, 200)
            self.assertEqual(payload["scan"]["path"], "source.zip")
            self.assertIn("secret.aws-access-key", {item["rule_id"] for item in payload["findings_by_language"]["en"]})
            self.assertNotIn("koda-upload-", json.dumps(payload))
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_upload_rejects_archive_path_traversal(self) -> None:
        archive_body = io.BytesIO()
        with zipfile.ZipFile(archive_body, "w") as archive:
            archive.writestr("../escape.py", "print('no')")
        server = create_dashboard_server(port=0)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            response = self._upload(server, "unsafe.zip", archive_body.getvalue())
            payload = json.loads(response.read())
            self.assertEqual(response.status, 400)
            self.assertIn("unsafe path", payload["error"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join()


class WebAuditRouteTests(unittest.TestCase):
    @patch("security_scanner.server.web_scan_payload", return_value={"ok": True})
    def test_active_web_scan_uses_session_and_bounded_defaults(self, scan_payload) -> None:
        server = create_dashboard_server(port=0)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            connection = http.client.HTTPConnection("127.0.0.1", server.server_port)
            connection.request("GET", "/")
            response = connection.getresponse()
            html = response.read().decode("utf-8")
            self.assertIn('id="web-options-content"', html)
            self.assertIn('byId("web-options-content").querySelectorAll', html)
            self.assertIn('fetch(apiEndpoint("/api/health"))', html)
            self.assertIn("max_pages: 50", html)

            connection = http.client.HTTPConnection("127.0.0.1", server.server_port)
            connection.request("GET", "/api/health")
            response = connection.getresponse()
            session = response.getheader("X-KODA-Session")
            response.read()
            self.assertTrue(session)

            connection = http.client.HTTPConnection("127.0.0.1", server.server_port)
            connection.request(
                "POST",
                "/api/web-scan",
                body=json.dumps({"url": "https://example.com", "crawl": True, "active": True}),
                headers={
                    "Content-Type": "application/json",
                    "Origin": f"http://127.0.0.1:{server.server_port}",
                    "X-KODA-Session": session,
                },
            )
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            response.read()
            kwargs = scan_payload.call_args.kwargs
            self.assertEqual((kwargs["timeout"], kwargs["max_pages"], kwargs["max_depth"]), (10.0, 50, 3))
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_web_audit_plan_requires_loopback_origin_and_session(self) -> None:
        server = create_dashboard_server(port=0)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        profile = {
            "schema_version": 1,
            "target": {
                "environment": "fixture",
                "origins": ["http://127.0.0.1:1"],
                "include_paths": ["/"],
                "scopes": ["passive"],
            },
            "limits": {"requests": 2, "timeout_seconds": 1},
            "accounts": {},
            "auth": {},
            "resources": [],
            "scenarios": [],
            "oast": {},
            "applicability": {},
        }
        body = json.dumps({"profile": profile})
        try:
            connection = http.client.HTTPConnection("127.0.0.1", server.server_port)
            connection.request("POST", "/api/web-audit/plan", body=body, headers={"Content-Type": "application/json"})
            response = connection.getresponse()
            self.assertEqual(response.status, 403)
            response.read()

            connection = http.client.HTTPConnection("127.0.0.1", server.server_port)
            connection.request("GET", "/")
            response = connection.getresponse()
            session = response.getheader("X-KODA-Session")
            response.read()
            self.assertTrue(session)

            connection = http.client.HTTPConnection("127.0.0.1", server.server_port)
            connection.request(
                "POST",
                "/api/web-audit/plan",
                body=body,
                headers={
                    "Content-Type": "application/json",
                    "Origin": f"http://127.0.0.1:{server.server_port}",
                    "X-KODA-Session": session,
                },
            )
            response = connection.getresponse()
            payload = json.loads(response.read())
            self.assertEqual(response.status, 200)
            self.assertEqual(payload["kind"], "koda.web-audit.plan")
        finally:
            server.shutdown()
            server.server_close()
            thread.join()


if __name__ == "__main__":
    unittest.main()
