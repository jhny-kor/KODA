from __future__ import annotations

import json
import socket
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SHARED_PYTHON = ROOT / "platforms" / "shared" / "python"
if str(SHARED_PYTHON) not in sys.path:
    sys.path.insert(0, str(SHARED_PYTHON))

from security_scanner.java_archives import scan_archives
from security_scanner.java_inventory import inventory_components
from security_scanner.java_vulnerability_scan import JavaScanOptions, VulnerabilityRecord, _merge_syft, aggregate_vulnerabilities, run_java_scan
from security_scanner.grype_adapter import GrypeMatch, GrypeResult
from security_scanner.java_vulnerability_reporting import write_reports
from security_scanner.syft_adapter import run_syft
from security_scanner.xml_safe import XmlInputError, parse_xml


def _write_jar(path: Path, files: dict[str, str | bytes]) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for name, content in files.items():
            archive.writestr(name, content)


class JavaInventoryTests(unittest.TestCase):
    def test_xml_metadata_rejects_dtd_and_entity_declarations(self) -> None:
        with self.assertRaises(XmlInputError):
            parse_xml(b'<!DOCTYPE project [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><project>&xxe;</project>')

    def test_manifest_version_is_resolved_without_maven_coordinates(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_jar(root / "manifest.jar", {"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\nImplementation-Title: internal-lib\nImplementation-Version: 4.2\n"})
            component = inventory_components(scan_archives(root))[0]
            self.assertEqual(component.identification_source, "manifest")
            self.assertEqual(component.version, "4.2")
            self.assertEqual(component.identity_status, "resolved")
            self.assertFalse(component.manual_review_required)

    def test_maven_coordinates_and_nested_war_library_are_identified(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            nested = root / "nested.jar"
            _write_jar(
                nested,
                {
                    "META-INF/maven/org.example/demo/pom.properties":
                    "groupId=org.example\nartifactId=demo\nversion=1.2.3\n",
                },
            )
            war = root / "service.war"
            with zipfile.ZipFile(war, "w") as archive:
                archive.writestr("WEB-INF/lib/demo-1.2.3.jar", nested.read_bytes())
            ear = root / "enterprise.ear"
            with zipfile.ZipFile(ear, "w") as archive:
                archive.writestr("lib/demo-1.2.3.jar", nested.read_bytes())

            artifacts = scan_archives(root)
            components = inventory_components(artifacts)
            purls = {component.purl for component in components}
            self.assertIn("pkg:maven/org.example/demo@1.2.3", purls)
            nested_component = next(component for component in components if component.name == "demo")
            self.assertTrue(any("service.war!/WEB-INF/lib/demo-1.2.3.jar" in location for location in nested_component.locations))
            self.assertTrue(any("enterprise.ear!/lib/demo-1.2.3.jar" in location for location in nested_component.locations))

    def test_unresolved_archive_keeps_manual_review_flag_and_duplicate_locations(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "common.jar"
            _write_jar(source, {"README.txt": "no coordinates"})
            duplicate = root / "backup-common.jar"
            duplicate.write_bytes(source.read_bytes())

            components = inventory_components(scan_archives(root))
            unresolved = next(component for component in components if component.sha256)
            self.assertEqual(unresolved.identity_status, "unresolved")
            self.assertTrue(unresolved.manual_review_required)
            self.assertEqual(len(unresolved.locations), 2)

    def test_zip_path_escape_is_warned_and_not_read(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.jar"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("../outside.jar", b"bad")
                archive.writestr("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n")

            result = scan_archives(Path(directory))
            self.assertTrue(any("unsafe ZIP path" in warning for warning in result.warnings))
            self.assertFalse((Path(directory).parent / "outside.jar").exists())

    def test_corrupt_zip_and_nested_depth_are_warnings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "corrupt.jar").write_bytes(b"not a zip")
            deep = Path(directory) / "deep.jar"
            _write_jar(deep, {"inner.txt": "x"})
            nested = Path(directory) / "nested.jar"
            with zipfile.ZipFile(nested, "w") as archive:
                archive.writestr("BOOT-INF/lib/deep.jar", deep.read_bytes())
            outer = root / "outer.jar"
            with zipfile.ZipFile(outer, "w") as archive:
                archive.writestr("BOOT-INF/lib/inner.jar", nested.read_bytes())
            result = scan_archives(root, max_depth=1)
            self.assertTrue(any("Corrupt ZIP" in warning for warning in result.warnings))
            self.assertTrue(any("Maximum nested archive depth" in warning for warning in result.warnings))

    def test_spring_boot_fat_jar_library_is_inventoried(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            nested = root / "spring-core.jar"
            _write_jar(nested, {"META-INF/maven/org.springframework/spring-core/pom.properties": "groupId=org.springframework\nartifactId=spring-core\nversion=6.1.0\n"})
            with zipfile.ZipFile(root / "application.jar", "w") as archive:
                archive.writestr("BOOT-INF/lib/spring-core-6.1.0.jar", nested.read_bytes())

            components = inventory_components(scan_archives(root))
            self.assertIn("pkg:maven/org.springframework/spring-core@6.1.0", {component.purl for component in components})


class JavaScanTests(unittest.TestCase):
    def test_syft_components_omit_null_purl(self) -> None:
        payload = _merge_syft(
            {"components": [{"type": "library", "name": "internal", "version": "1.0", "purl": None}]},
            (),
        )
        self.assertNotIn("purl", payload["components"][0])  # type: ignore[index]

    @staticmethod
    def _record(
        vulnerability_id: str,
        cve_ids: tuple[str, ...],
        fixed_versions: tuple[str, ...],
        severity: str,
        location: str,
        purl: str = "pkg:maven/org.example/demo@1.0.0",
        installed_version: str = "1.0.0",
        identity_status: str = "resolved",
    ) -> VulnerabilityRecord:
        return VulnerabilityRecord(
            vulnerability_id,
            cve_ids,
            purl,
            "demo",
            installed_version,
            fixed_versions,
            severity,
            8.0 if severity == "high" else 5.0,
            severity.upper(),
            False,
            {},
            {},
            (location,),
            identity_status,
            "upgrade",
            ("java-matcher",),
        )

    def test_vulnerabilities_are_grouped_by_library_version_and_final_is_verified(self) -> None:
        records = (
            self._record("GHSA-demo", ("CVE-2026-0001",), ("1.1.0",), "high", "/apps/a/demo.jar"),
            self._record("CVE-2026-0001", ("CVE-2026-0001",), ("1.1.0",), "high", "/apps/b/demo.jar"),
            self._record("CVE-2026-0002", ("CVE-2026-0002",), ("1.2.0",), "medium", "/apps/a/demo.jar"),
            self._record("CVE-2026-0003", ("CVE-2026-0003",), ("2.1.0",), "low", "/apps/c/demo.jar", purl="pkg:maven/org.example/demo@2.0.0", installed_version="2.0.0"),
        )
        candidate_match = GrypeMatch("CVE-2026-0004", ("CVE-2026-0004",), "demo", "1.1.0", "pkg:maven/org.example/demo@1.1.0", ("1.2.0",), "medium", (), ())
        with patch("security_scanner.java_vulnerability_scan.run_grype_purls", side_effect=(GrypeResult((candidate_match,), "", {}, "", False), GrypeResult((), "", {}, "", False))):
            groups, warnings = aggregate_vulnerabilities(records, Path("/tmp/grype"), 5.0)

        self.assertFalse(warnings)
        self.assertEqual(len(groups), 2)
        group = groups[0]
        self.assertEqual(group.component_name, "demo")
        self.assertEqual(group.installed_version, "1.0.0")
        self.assertEqual(len(group.advisories), 2)
        self.assertEqual(set(group.locations), {"/apps/a/demo.jar", "/apps/b/demo.jar"})
        self.assertEqual(group.final_version, "1.2.0")
        self.assertEqual(group.final_status, "verified_clean")
        self.assertEqual(group.final_checked_versions, ("1.1.0", "1.2.0"))
        self.assertIn("CVE-2026-0001", group.fixed_by_vulnerability)
        self.assertNotIn("GHSA", group.vulnerability_id)

    def test_ghsa_only_records_are_excluded_from_cve_report(self) -> None:
        record = self._record("GHSA-only", (), ("1.1.0",), "high", "/apps/demo.jar")
        groups, warnings = aggregate_vulnerabilities((record,), None, 5.0)
        self.assertEqual(groups, ())
        self.assertEqual(warnings, ())

    def test_final_is_unknown_when_every_fixed_candidate_remains_vulnerable(self) -> None:
        record = self._record("CVE-2026-0010", ("CVE-2026-0010",), ("1.1.0",), "high", "/apps/demo.jar")
        still_vulnerable = GrypeMatch("CVE-2026-0011", ("CVE-2026-0011",), "demo", "1.1.0", "pkg:maven/org.example/demo@1.1.0", (), "high", (), ())
        with patch("security_scanner.java_vulnerability_scan.run_grype_purls", return_value=GrypeResult((still_vulnerable,), "", {}, "", False)):
            groups, warnings = aggregate_vulnerabilities((record,), Path("/tmp/grype"), 5.0)

        self.assertEqual(groups[0].final_version, "")
        self.assertEqual(groups[0].final_status, "unresolved")
        self.assertTrue(any("No verified clean candidate" in warning for warning in warnings))

    def test_final_follows_each_advisory_fix_until_purl_is_clean(self) -> None:
        record = self._record(
            "CVE-2026-0100",
            ("CVE-2026-0100",),
            ("1.1.0",),
            "high",
            "/apps/demo.jar",
            identity_status="partial",
        )
        first_fix_still_vulnerable = GrypeMatch(
            "CVE-2026-0101",
            ("CVE-2026-0101",),
            "demo",
            "1.1.0",
            "pkg:maven/org.example/demo@1.1.0",
            ("1.2.0",),
            "high",
            (),
            (),
        )
        second_fix_still_vulnerable = GrypeMatch(
            "CVE-2026-0102",
            ("CVE-2026-0102",),
            "demo",
            "1.2.0",
            "pkg:maven/org.example/demo@1.2.0",
            ("1.3.0",),
            "medium",
            (),
            (),
        )
        results = (
            GrypeResult((first_fix_still_vulnerable,), "", {}, "", False),
            GrypeResult((second_fix_still_vulnerable,), "", {}, "", False),
            GrypeResult((), "", {}, "", False),
        )
        with patch("security_scanner.java_vulnerability_scan.run_grype_purls", side_effect=results):
            groups, warnings = aggregate_vulnerabilities((record,), Path("/tmp/grype"), 5.0)

        self.assertFalse(warnings)
        self.assertEqual(groups[0].identity_status, "partial")
        self.assertEqual(groups[0].final_version, "1.3.0")
        self.assertEqual(groups[0].final_status, "verified_clean")
        self.assertEqual(groups[0].final_checked_versions, ("1.1.0", "1.2.0", "1.3.0"))

    def test_reports_are_korean_only_and_main_links_to_detail(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            write_reports(output, (), (), 0, (), "2026-07-23", language=None)
            html_report = (output / "server-library-report-detail.html").read_text(encoding="utf-8")
            main_report = (output / "server-library-report.html").read_text(encoding="utf-8")
            self.assertIn('href="server-library-report-detail.html"', main_report)
            self.assertIn("상세 보고서 더보기", main_report)
            self.assertIn("아카이브", main_report)
            self.assertIn("확인불가", main_report)
            self.assertIn("KEV", main_report)
            self.assertIn('grid-template-columns:repeat(4,minmax(0,1fr))', main_report)
            self.assertIn('grid-template-columns:repeat(5,minmax(0,1fr))', main_report)
            self.assertIn('data-column-index="5"', main_report)
            self.assertNotIn("summary-edge-hint", main_report)
            self.assertNotIn("← 왼쪽 끝", main_report)
            self.assertIn("max-width:1560px", main_report)
            self.assertIn("대외 비공개", main_report)
            self.assertIn("border:2px solid #ef4444", main_report)
            self.assertIn("border-radius:0", main_report)
            self.assertIn("background:none", main_report)
            markdown_report = (output / "server-library-report.md").read_text(encoding="utf-8")
            self.assertIn('<html lang="ko">', html_report)
            self.assertNotIn('id="language-ko"', html_report)
            self.assertNotIn('id="language-en"', html_report)
            self.assertIn("대외 비공개", html_report)
            self.assertIn("border:2px solid #ef4444", html_report)
            self.assertIn("border-radius:0", html_report)
            self.assertIn("background:none", html_report)
            self.assertNotIn("← 왼쪽 끝", html_report)
            self.assertNotIn('class="library-card-accordion" open', html_report)
            self.assertNotIn('class="workspace-accordion"', html_report)
            self.assertNotIn('id="severity"', html_report)
            self.assertIn('href="server-library-report.html"', html_report)
            self.assertIn("KODA Java 라이브러리 취약점 보고서", markdown_report)

            write_reports(output, (), (), 0, (), "2026-07-23", language="en")
            html_report = (output / "server-library-report-detail.html").read_text(encoding="utf-8")
            markdown_report = (output / "server-library-report.md").read_text(encoding="utf-8")
            self.assertIn('<html lang="ko">', html_report)
            self.assertNotIn('id="language-ko"', html_report)
            self.assertIn("KODA Java 라이브러리 취약점 보고서", markdown_report)

    def test_library_detail_expands_nvd_evidence_and_links_to_summary(self) -> None:
        record = self._record("CVE-2026-0301", ("CVE-2026-0301",), ("1.1.0",), "critical", "/apps/demo.jar")
        with patch("security_scanner.java_vulnerability_scan.run_grype_purls", return_value=GrypeResult((), "", {}, "", False)):
            groups, _ = aggregate_vulnerabilities((record,), Path("/tmp/grype"), 5.0)
        advisory = dict(groups[0].advisories[0])
        advisory["nvd"] = {
            "id": "CVE-2026-0301",
            "published": "2026-01-01T00:00:00Z",
            "last_modified": "2026-01-02T00:00:00Z",
            "descriptions": ["A test vulnerability description."],
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-0301"],
            "cwe": ["CWE-89"],
            "cvss_score": 9.8,
            "cvss_version": "3.1",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        }
        group = replace(groups[0], advisories=(advisory,))

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            write_reports(output, (), (group,), 1, (), "2026-07-23", language="ko")
            main_html = (output / "server-library-report.html").read_text(encoding="utf-8")
            detail_html = (output / "server-library-report-detail.html").read_text(encoding="utf-8")
            vulnerability_details_html = (output / "server-vulnerability-details.html").read_text(encoding="utf-8")

        self.assertIn("전체 취약점", main_html)
        self.assertIn("치명", main_html)
        self.assertIn('id="main-vulnerability-library"', main_html)
        self.assertIn('id="main-vulnerability-kev"', main_html)
        self.assertIn('id="main-vulnerability-table"', main_html)
        self.assertIn("server-vulnerability-details.html", main_html)
        self.assertIn(">KEV<span class=\"column-resizer\"", main_html)
        self.assertIn(">CVSS<span class=\"column-resizer\"", main_html)
        self.assertIn(">조치<span class=\"column-resizer\"", main_html)
        self.assertIn("vulnerability-action-link", main_html)
        self.assertIn('card card--critical', main_html)
        self.assertIn("우선 조치", main_html)
        self.assertIn("라이브러리별 조치 현황", main_html)
        self.assertIn('class="library-summary-table"', main_html)
        self.assertIn("demo", main_html)
        self.assertIn("CVE-2026-0301", main_html)
        self.assertIn("9.8", main_html)
        self.assertIn("1.1.0", main_html)
        self.assertIn('class="final-version"', main_html)
        self.assertIn("최종 버전", main_html)
        self.assertIn('href="server-library-report.html"', detail_html)
        self.assertIn("라이브러리 취약점 상세", detail_html)
        self.assertIn('class="library"', detail_html)
        self.assertIn("CVE 설명", detail_html)
        self.assertIn("발견 경로", detail_html)
        self.assertNotIn("라이브러리별 조치 현황", detail_html)
        self.assertNotIn("조치 안내", detail_html)
        self.assertNotIn("class=\"workspace-accordion\"", detail_html)
        self.assertNotIn("class=\"library-details action-details\"", detail_html)
        self.assertIn("A test vulnerability description.", detail_html)
        self.assertIn("CVE-2026-0301", detail_html)
        self.assertIn("CVSS", detail_html)
        self.assertIn("9.8", detail_html)
        self.assertIn("취약점별 상세 리포트", vulnerability_details_html)
        self.assertIn("원문 보기", vulnerability_details_html)
        self.assertIn("문제 파일", vulnerability_details_html)
        self.assertIn("CVE-2026-0301", vulnerability_details_html)
        self.assertIn("CVSS", vulnerability_details_html)
        self.assertIn("9.8", vulnerability_details_html)
        self.assertIn('class="vulnerability-report-toolbar"', vulnerability_details_html)
        self.assertIn('id="vulnerability-detail-count"', vulnerability_details_html)
        self.assertIn("#vulnerability-detail-count", vulnerability_details_html)
        self.assertIn("minmax(220px,auto)", vulnerability_details_html)
        self.assertIn('class="vulnerability-remediation"', vulnerability_details_html)
        self.assertIn("설치 버전", vulnerability_details_html)
        self.assertIn("최종 후보", vulnerability_details_html)

    def test_library_detail_orders_target_groups_by_cvss(self) -> None:
        records = (
            self._record(
                "CVE-2026-0401",
                ("CVE-2026-0401",),
                ("1.1.0",),
                "medium",
                "/target-low/demo.jar",
            ),
            self._record(
                "CVE-2026-0402",
                ("CVE-2026-0402",),
                ("2.1.0",),
                "high",
                "/target-high/demo.jar",
                purl="pkg:maven/org.example/demo@2.0.0",
                installed_version="2.0.0",
            ),
        )
        with patch("security_scanner.java_vulnerability_scan.run_grype_purls", return_value=GrypeResult((), "", {}, "", False)):
            vulnerabilities, _ = aggregate_vulnerabilities(records, Path("/tmp/grype"), 5.0)

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            write_reports(output, (), vulnerabilities, 2, (), "2026-07-23", language="ko", targets=("target-low", "target-high"))
            detail_html = (output / "server-library-report-detail.html").read_text(encoding="utf-8")

        self.assertLess(detail_html.index("CVSS 8"), detail_html.index("CVSS 5"))

    def test_fixed_versions_render_one_line_per_vulnerability_id(self) -> None:
        records = (
            self._record("CVE-2026-0201", ("CVE-2026-0201",), ("1.1.0",), "high", "/apps/demo.jar"),
            self._record("CVE-2026-0202", ("CVE-2026-0202",), ("1.2.0",), "medium", "/apps/demo.jar"),
        )
        with patch("security_scanner.java_vulnerability_scan.run_grype_purls", return_value=GrypeResult((), "", {}, "", False)):
            groups, _ = aggregate_vulnerabilities(records, Path("/tmp/grype"), 5.0)

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            write_reports(output, (), groups, 1, (), "2026-07-23", language="ko")
            html_report = (output / "server-library-report.html").read_text(encoding="utf-8")
            markdown_report = (output / "server-library-report.md").read_text(encoding="utf-8")

        expected = "CVE-2026-0202: 1.2.0<br>CVE-2026-0201: 1.1.0"
        self.assertIn('<span class="fixed-entry collapse-item"', html_report)
        self.assertIn('class="fixed-id">CVE-2026-0202</code><code class="fixed-version-value">1.2.0</code>', html_report)
        self.assertIn('class="vulnerability-id collapse-item">CVE-2026-0202</code>', html_report)
        self.assertLess(html_report.index('CVE-2026-0202'), html_report.index('CVE-2026-0201'))
        self.assertIn(expected, markdown_report)
        self.assertIn('data-severity="high"', html_report)
        self.assertIn(">높음</span>", html_report)
        self.assertNotIn('data-severity="높음"', html_report)

    def test_identifiers_and_fixed_versions_collapse_after_three_and_counts_use_grouping(self) -> None:
        records = tuple(
            self._record(
                f"CVE-2026-{index:04d}",
                (f"CVE-2026-{index:04d}",),
                (f"1.{index}.0",),
                "high",
                f"/apps/demo-{index}.jar",
            )
            for index in range(1, 5)
        )
        with patch("security_scanner.java_vulnerability_scan.run_grype_purls", return_value=GrypeResult((), "", {}, "", False)):
            groups, _ = aggregate_vulnerabilities(records, Path("/tmp/grype"), 5.0)

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            write_reports(output, (), groups, 1319, (), "2026-07-23", language="ko")
            main_rendered = (output / "server-library-report.html").read_text(encoding="utf-8")
            detail_rendered = (output / "server-library-report-detail.html").read_text(encoding="utf-8")

        self.assertIn("더보기 (1)", main_rendered)
        self.assertIn(">접기</button>", main_rendered)
        self.assertIn('collapse-item" hidden', main_rendered)
        self.assertNotIn(":scope > .collapse-item", main_rendered)
        self.assertIn("1,319", detail_rendered)
        self.assertIn("라이브러리 취약점 상세", detail_rendered)
        self.assertIn('href="server-library-report.html"', detail_rendered)
        self.assertNotIn("라이브러리별 조치 현황", detail_rendered)
        self.assertIn("border-right:1px solid", detail_rendered)
        self.assertNotIn("더보기 (1)", detail_rendered)

    def test_offline_run_writes_all_reports_and_combines_local_feeds(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "app"
            target.mkdir()
            jar = target / "log4j-core.jar"
            _write_jar(
                jar,
                {
                    "META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties":
                    "groupId=org.apache.logging.log4j\nartifactId=log4j-core\nversion=2.14.1\n",
                },
            )
            nvd = root / "nvd.json"
            nvd.write_text(
                json.dumps(
                    {
                        "lastModifiedDate": "2026-07-15T00:00:00.000Z",
                        "vulnerabilities": [
                            {
                                "cve": {
                                    "id": "CVE-2021-44228",
                                    "published": "2021-12-10T00:00:00.000Z",
                                    "lastModified": "2026-07-15T00:00:00.000Z",
                                    "descriptions": [{"lang": "en", "value": "JNDI injection"}],
                                    "metrics": {
                                        "cvssMetricV31": [
                                            {"cvssData": {"baseScore": 10.0, "baseSeverity": "CRITICAL", "vectorString": "AV:N"}}
                                        ]
                                    },
                                }
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            kev = root / "kev.json"
            kev.write_text(
                json.dumps(
                    {
                        "catalogVersion": "2026.07.15",
                        "dateReleased": "2026-07-15",
                        "vulnerabilities": [{"cveID": "CVE-2021-44228", "dateAdded": "2021-12-10", "dueDate": "2022-01-10", "requiredAction": "Patch", "knownRansomwareCampaignUse": "Known"}],
                    }
                ),
                encoding="utf-8",
            )
            fake_grype = root / "grype"
            fake_grype.write_text("#!/bin/sh\n", encoding="utf-8")
            fake_grype.chmod(fake_grype.stat().st_mode | stat.S_IXUSR)

            grype_payload = {
                "descriptor": {"version": "0.80.0"},
                "matches": [
                    {
                        "vulnerability": {"id": "GHSA-test", "severity": "critical", "fix": {"versions": ["2.17.1"]}},
                        "relatedVulnerabilities": [{"id": "CVE-2021-44228"}],
                        "artifact": {"name": "log4j-core", "version": "2.14.1", "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "locations": [{"path": str(jar)}]},
                    }
                ],
            }
            with patch("security_scanner.grype_adapter.subprocess.run") as run:
                run.side_effect = [
                    type("Completed", (), {"returncode": 0, "stdout": "grype 0.80.0", "stderr": ""})(),
                    type("Completed", (), {"returncode": 0, "stdout": json.dumps({"database": {"built": "2026-07-15T00:00:00Z"}}), "stderr": ""})(),
                    type("Completed", (), {"returncode": 0, "stdout": json.dumps(grype_payload), "stderr": ""})(),
                    type("Completed", (), {"returncode": 0, "stdout": json.dumps({"matches": []}), "stderr": ""})(),
                ]
                result = run_java_scan(
                    JavaScanOptions(
                        target=target,
                        output_dir=root / "reports",
                        grype_bin=fake_grype,
                        nvd_data=nvd,
                        cisa_kev=kev,
                        language="ko",
                        fail_on="high",
                    )
                )

            self.assertEqual(result.exit_code, 1)
            self.assertEqual(len(result.vulnerabilities), 1)
            vulnerability = result.vulnerabilities[0]
            self.assertTrue(vulnerability.known_exploited)
            self.assertEqual(vulnerability.final_version, "2.17.1")
            self.assertEqual(vulnerability.final_status, "verified_clean")
            self.assertEqual(vulnerability.cisa_kev["kev_date_added"], "2021-12-10")
            self.assertEqual(vulnerability.cisa_kev["kev_required_action"], "Patch")
            self.assertTrue((root / "reports/server-sbom.cdx.json").exists())
            self.assertTrue((root / "reports/server-vulnerabilities.json").exists())
            self.assertTrue((root / "reports/server-library-report.html").exists())
            self.assertTrue((root / "reports/server-library-report-detail.html").exists())
            self.assertTrue((root / "reports/server-vulnerability-details.html").exists())
            self.assertTrue((root / "reports/server-library-report.md").exists())
            self.assertTrue((root / "reports/scan-metadata.json").exists())
            self.assertTrue((root / "reports/warnings.json").exists())
            metadata = json.loads((root / "reports/scan-metadata.json").read_text(encoding="utf-8"))
            self.assertEqual(set(metadata["data_sources"]), {"nvd", "cisa_kev"})
            self.assertEqual(metadata["report_language"], "ko")
            self.assertFalse(metadata["report_language_toggle"])
            self.assertEqual(metadata["grype_database"]["database"]["built"], "2026-07-15T00:00:00Z")
            self.assertTrue(all(len(source["files"][0]["sha256"]) == 64 for source in metadata["data_sources"].values()))
            report = json.loads((root / "reports/server-vulnerabilities.json").read_text(encoding="utf-8"))
            self.assertEqual(report["archives"][0]["archive_type"], "jar")
            self.assertEqual(report["target"], str(target.resolve()))
            self.assertEqual(report["summary"]["raw_match_count"], 1)
            self.assertEqual(report["summary"]["unique_vulnerability_count"], 1)
            self.assertEqual(report["summary"]["affected_library_version_count"], 1)
            self.assertEqual(report["vulnerabilities"][0]["final_version"], "2.17.1")
            self.assertIn("CVE-2021-44228", report["vulnerabilities"][0]["fixed_by_vulnerability"])
            self.assertNotIn("kn" + "vd", report)
            self.assertNotIn("manual_review_candidates", report)
            rendered = (root / "reports/server-library-report-detail.html").read_text(encoding="utf-8")
            self.assertIn('<html lang="ko">', rendered)
            self.assertIn('id="report-help"', rendered)
            self.assertNotIn("language-switch", rendered)
            self.assertNotIn("KN" + "VD", rendered)

    def test_missing_explicit_grype_is_exit_two_without_network(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "app"
            target.mkdir()
            _write_jar(target / "empty.jar", {})
            result = run_java_scan(JavaScanOptions(target=target, output_dir=root / "reports", grype_bin=root / "missing-grype"))
            self.assertEqual(result.exit_code, 2)
            self.assertTrue(any("Grype" in warning for warning in result.warnings))

    def test_builtin_only_scan_does_not_open_network_connections(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "app"
            target.mkdir()
            _write_jar(target / "demo.jar", {"META-INF/maven/org.example/demo/pom.properties": "groupId=org.example\nartifactId=demo\nversion=1.2.3\n"})
            with patch.object(socket, "create_connection", side_effect=AssertionError("network access is forbidden")):
                result = run_java_scan(JavaScanOptions(target=target, output_dir=root / "reports", builtin_only=True, no_grype=True))
            self.assertEqual(result.exit_code, 0)

    def test_fail_on_kev_returns_one(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "app"
            target.mkdir()
            _write_jar(target / "demo.jar", {"META-INF/maven/org.example/demo/pom.properties": "groupId=org.example\nartifactId=demo\nversion=1.2.3\n"})
            kev = root / "kev.json"
            kev.write_text(json.dumps({"vulnerabilities": [{"cveID": "CVE-2026-0001"}]}), encoding="utf-8")
            match = GrypeMatch("CVE-2026-0001", ("CVE-2026-0001",), "demo", "1.2.3", "pkg:maven/org.example/demo@1.2.3", (), "low", (), ())
            with patch("security_scanner.java_vulnerability_scan.run_grype", return_value=GrypeResult((match,), "test", {}, "", False)):
                result = run_java_scan(JavaScanOptions(target=target, output_dir=root / "reports", cisa_kev=kev, fail_on_kev=True))
            self.assertEqual(result.exit_code, 1)

    def test_fail_on_kev_without_kev_data_is_exit_two(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "app"
            target.mkdir()
            _write_jar(target / "demo.jar", {"META-INF/maven/org.example/demo/pom.properties": "groupId=org.example\nartifactId=demo\nversion=1.2.3\n"})
            match = GrypeMatch("CVE-2026-0001", ("CVE-2026-0001",), "demo", "1.2.3", "pkg:maven/org.example/demo@1.2.3", (), "low", (), ())
            with patch("security_scanner.java_vulnerability_scan.run_grype", return_value=GrypeResult((match,), "test", {}, "", False)):
                result = run_java_scan(JavaScanOptions(target=target, output_dir=root / "reports", fail_on_kev=True))
            self.assertEqual(result.exit_code, 2)
            self.assertTrue(any("--fail-on-kev requires CISA KEV data" in warning for warning in result.warnings))

    def test_syft_timeout_is_controlled_and_does_not_raise(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "syft"
            binary.write_text("placeholder", encoding="utf-8")
            binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
            with patch("security_scanner.syft_adapter.subprocess.run", side_effect=subprocess.TimeoutExpired(str(binary), 1)):
                result = run_syft(root, binary, 1)
            self.assertTrue(result.fatal)
            self.assertIn("Syft failed", result.warning)

    def test_syft_json_and_missing_binary_paths_are_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "syft"
            binary.write_text("placeholder", encoding="utf-8")
            binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
            payload = {"bomFormat": "CycloneDX", "components": []}
            with patch("security_scanner.syft_adapter.subprocess.run") as run:
                run.side_effect = [
                    type("Completed", (), {"returncode": 0, "stdout": "syft 1.0.0", "stderr": ""})(),
                    type("Completed", (), {"returncode": 0, "stdout": json.dumps(payload), "stderr": ""})(),
                ]
                result = run_syft(root, binary, 1)
            self.assertFalse(result.fatal)
            self.assertEqual(result.payload, payload)
            missing = run_syft(root, root / "missing-syft", 1)
            self.assertTrue(missing.fatal)
            self.assertIn("not found", missing.warning)


if __name__ == "__main__":
    unittest.main()
