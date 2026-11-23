from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase

from security_scanner.server import scan_directory_payload


class LocalSastReportTests(TestCase):
    def test_multiple_analyzers_keep_their_provenance_and_resolve_only_project_files(self) -> None:
        with TemporaryDirectory(prefix="koda local sast ") as directory:
            root = Path(directory).resolve()
            project = root / "project"
            java_root = project / "src" / "main" / "java"
            java_root.mkdir(parents=True)
            (java_root / "Example.java").write_text("class Example {}\n", encoding="utf-8")
            nested = project / "nested"
            nested.mkdir()
            (nested / "pyproject.toml").write_text('[project]\nname = "nested"\nversion = "0.1.0"\n', encoding="utf-8")
            (nested / "application entry.py").write_text("print('status')\n", encoding="utf-8")
            outside = root / "outside.py"
            outside.write_text("print('outside')\n", encoding="utf-8")

            def result(rule: str, uri: str, base_id=None):
                artifact = {"uri": uri}
                if base_id is not None:
                    artifact["uriBaseId"] = base_id
                return {
                    "ruleId": rule,
                    "message": {"text": "Review this finding."},
                    "locations": [{"physicalLocation": {
                        "artifactLocation": artifact,
                        "region": {"startLine": 1},
                    }}],
                }

            report = root / "external.sarif"
            report.write_text(json.dumps({"version": "2.1.0", "runs": [
                {
                    "tool": {"driver": {"name": "SpotBugs", "version": "4.10.5", "rules": [{"id": "NP_ALWAYS_NULL"}]}},
                    "originalUriBaseIds": {"java-root": {"uri": java_root.as_uri() + "/"}},
                    "invocations": [{"exitCode": 3, "executionSuccessful": False}],
                    "results": [result("NP_ALWAYS_NULL", "Example.java", "java-root")],
                },
                {
                    "tool": {"driver": {
                        "name": "Semgrep OSS", "semanticVersion": "1.186.0",
                        "rules": [{"id": "team.review-print", "defaultConfiguration": {"level": "error"}}],
                    }},
                    "results": [
                        result("team.review-print", "nested/application entry.py", "%SRCROOT%"),
                        result("team.review-print", outside.as_uri()),
                    ],
                },
            ]}), encoding="utf-8")
            data = scan_directory_payload(str(project), source_analyzer_sarif=report)

            candidates = data["findings_by_language"]["en"]
            findings = {item["analyzer"]: item for item in candidates if item["analyzer"] in {"SpotBugs", "Semgrep OSS"}}
            self.assertEqual(set(findings), {"SpotBugs", "Semgrep OSS"})
            self.assertEqual(findings["SpotBugs"]["rule_id"], "code.null-pointer-dereference")
            self.assertEqual(findings["Semgrep OSS"]["rule_id"], "code.semgrep.team.review-print")
            self.assertEqual(sum(item["analyzer"] == "Semgrep OSS" for item in candidates), 1)
            self.assertEqual(findings["Semgrep OSS"]["severity"], "high")
            self.assertTrue(all(item["verification_status"] == "needs_review" for item in findings.values()))
            runs = data["source_analysis"]["analyzer_runs"]
            self.assertEqual([(run["analyzer"], run["version"], run["status"]) for run in runs],
                             [("SpotBugs", "4.10.5", "PARTIAL"), ("Semgrep OSS", "1.186.0", "SUCCESS")])
            self.assertIn("sarif_path_outside_target", data["scan"]["warnings"])
            self.assertTrue(any("sarif_spotbugs_missing_classes" in line for line in data["scan"]["warnings"]))

            document = json.loads(report.read_text(encoding="utf-8"))
            document["runs"][1]["invocations"] = [{"executionSuccessful": False}]
            report.write_text(json.dumps(document), encoding="utf-8")
            failed = scan_directory_payload(str(project), source_analyzer_sarif=report)
            self.assertEqual(failed["source_analysis"]["analyzer_runs"][1]["status"], "FAILED")
