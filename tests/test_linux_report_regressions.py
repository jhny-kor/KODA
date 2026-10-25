import io
import tempfile
import unittest
import zipfile
import json
import os
from html.parser import HTMLParser
from datetime import datetime, timezone
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import patch

from security_scanner.reporting import _java_library_payload, render_html_pair_zip_from_payload
from security_scanner.offline_vuln_data import load_offline_data


class LinuxReportRegressions(unittest.TestCase):
    def test_web_audit_table_keeps_complete_values_in_own_scroll_container(self):
        from security_scanner.reporting import _web_audit_html

        class TableContainers(HTMLParser):
            def __init__(self):
                super().__init__()
                self.divs = []
                self.scrolling_tables = []

            def handle_starttag(self, tag, attrs):
                if tag == "div":
                    self.divs.append(dict(attrs).get("class", "").split())
                if tag == "table":
                    self.scrolling_tables.append(any("table-wrap" in value for value in self.divs))

            def handle_endtag(self, tag):
                if tag == "div":
                    self.divs.pop()

        value = "긴 원본 점검 근거 " * 50
        document = _web_audit_html({"status": "NEEDS_REVIEW", "controls": [
            {"id": "WEB-01", "title": value, "status": "NEEDS_REVIEW", "reason_code": value},
        ]})
        parser = TableContainers()
        parser.feed(document)
        self.assertEqual(parser.scrolling_tables, [True])
        self.assertEqual(document.count(value), 2)
        self.assertIn("NEEDS_REVIEW", document)

    def setUp(self):
        # Explicit local-file development fixtures; Linux production defaults
        # are exercised independently by test_managed_data_current_only.
        local_profile = patch("security_scanner.data_release.sys", SimpleNamespace(platform="darwin"))
        local_profile.start()
        self.addCleanup(local_profile.stop)

    def _files(self, payload):
        with zipfile.ZipFile(io.BytesIO(render_html_pair_zip_from_payload(payload))) as archive:
            return {name: archive.read(name).decode("utf-8") for name in archive.namelist()}

    def test_stored_source_context_survives_deleted_original(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "gone.py"
            path.write_text("secret = 'gone'\n", encoding="utf-8")
            payload = {"scan": {"kind": "source"}, "findings": [{"rule_id": "secret.literal", "path": str(path), "line": 1, "evidence": "stored", "severity": "high", "source_context": {"available": True, "lines": [{"number": 1, "text": "persisted context", "is_focus": True}]}}]}
            path.unlink()
            with patch.object(Path, "read_text", side_effect=AssertionError("export reread source")):
                files = self._files(payload)
            self.assertIn("persisted context", files["report-detail.html"])

    def test_library_main_links_each_cve_to_offline_detail(self):
        payload = {"scan": {"scope": "library"}, "vulnerabilities": [
            {"component_name": "alpha", "installed_version": "1.0", "cve_ids": ["CVE-2024-0001"], "severity": "high", "cvss_score": 8.1},
            {"component_name": "beta", "installed_version": "2.0", "cve_ids": ["CVE-2024-0001"], "severity": "medium", "cvss_score": 5.0},
        ]}
        files = self._files(payload)
        self.assertIn("report-vulnerabilities.html", files)
        main, detail = files["report.html"], files["report-vulnerabilities.html"]
        prefix = "report-vulnerabilities.html#"
        target = main.split(prefix, 1)[1].split('"', 1)[0]
        self.assertIn(f'id="{target}"', detail)
        self.assertGreaterEqual(detail.count("vulnerability-CVE-2024-0001-"), 2)
        self.assertIn("alpha", detail)
        self.assertIn("beta", detail)

    def test_offline_epss_survives_scan_payload_and_export_without_rereading(self):
        from security_scanner.server import _grype_vulnerability_payloads
        with tempfile.TemporaryDirectory() as directory:
            snapshot = Path(directory) / "epss.csv"
            day = datetime.now(timezone.utc).date().isoformat()
            snapshot.write_text(f"#model_version:v2025.03.14,score_date:{day}\ncve,epss,percentile\nCVE-2024-0001,0.91,0.99\n")
            component = SimpleNamespace(name="demo", version="1", purl="pkg:pypi/demo@1", path=Path("demo.whl"), identity_status="resolved")
            match = SimpleNamespace(package_name="demo", installed_version="1", purl=component.purl, cve_ids=("CVE-2024-0001",), vulnerability_id="CVE-2024-0001", vulnerability_ids=("CVE-2024-0001",), fixed_versions=(), severity="medium", locations=("demo.whl",), match_details=())
            with patch.dict(os.environ, {"KODA_EPSS_DATA": str(snapshot), "KODA_OFFLINE_MODE": "1"}), patch("urllib.request.urlopen", side_effect=AssertionError("unexpected HTTP")):
                records = _grype_vulnerability_payloads((match,), (component,))
            self.assertEqual(records[0]["epss_score"], .91)
            self.assertEqual(records[0]["severity"], "medium")
            snapshot.unlink()
            files = self._files({"scan": {"scope": "library"}, "vulnerabilities": records})
            for name in ("report.html", "report-vulnerabilities.html"):
                self.assertIn("EPSS 91.00%", files[name])
                self.assertIn(day, files[name])

    def test_compact_nvd_record_keeps_cvss_vector_and_description(self):
        with tempfile.TemporaryDirectory() as directory:
            nvd = Path(directory) / "nvd.json"
            nvd.write_text(json.dumps({"vulnerabilities": {"CVE-2026-12345": {
                "id": "CVE-2026-12345", "description": "compact description",
                "cvss": {"cvssV3": {"baseScore": 8.8, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"}},
            }}}), encoding="utf-8")
            loaded = load_offline_data(nvd, None, ("CVE-2026-12345",))
            record = loaded.nvd["CVE-2026-12345"]
            self.assertEqual(record["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"], 8.8)
            payload = {"scan": {"scope": "library"}, "vulnerabilities": [{
                "component_name": "demo", "installed_version": "1.0", "cve_ids": ["CVE-2026-12345"],
                "vulnerability_ids": ["CVE-2026-12345"], "severity": "high", "cvss_score": 8.8,
                "nvd": record, "advisories": [{"cve_ids": ["CVE-2026-12345"], "vulnerability_ids": ["CVE-2026-12345"], "severity": "high", "cvss_score": 8.8, "nvd": record}],
            }]}
            files = self._files(payload)
            self.assertIn("compact description", files["report-vulnerabilities.html"])
            self.assertIn("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", files["report-vulnerabilities.html"])

    def test_linux_summary_counts_actual_rows(self):
        payload = {"scan": {"scope": "library", "local_vulnerability": {"database": {"built": "2026-09-10T06:30:24Z"}},}, "components": [{"name": "demo", "version": "1.0", "identity_status": "resolved", "locations": ["pom.xml"]}], "vulnerabilities": [
            {"component_name": "demo", "installed_version": "1.0", "cve_ids": ["CVE-2026-0001"], "severity": "critical", "known_exploited": True},
            {"component_name": "demo", "installed_version": "1.0", "cve_ids": ["CVE-2026-0002"], "severity": "high", "known_exploited": False},
            {"component_name": "demo", "installed_version": "1.0", "cve_ids": ["CVE-2026-0003"], "severity": "medium", "known_exploited": False},
        ]}
        report = _java_library_payload(payload)
        self.assertEqual(report["summary"]["severity_counts"], {"critical": 1, "high": 1, "medium": 1})
        self.assertEqual(report["summary"]["unique_vulnerability_count"], 3)
        self.assertEqual(report["summary"]["affected_library_version_count"], 1)
        self.assertEqual(report["data_as_of"], "2026-09-10T06:30:24Z")

    def test_empty_and_legacy_library_payloads_remain_renderable(self):
        empty = self._files({"scan": {"scope": "library"}, "vulnerabilities": []})
        legacy = self._files({"scan": {"scope": "library"}})
        self.assertIn("탐지된 취약점이 없습니다.", empty["report-vulnerabilities.html"])
        self.assertIn("레거시 결과", legacy["report-vulnerabilities.html"])


if __name__ == "__main__":
    unittest.main()
