from __future__ import annotations

import json
import copy
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "platforms" / "shared" / "python"))

from security_scanner.sarif_import import SarifImportError, import_sarif, load_sarif  # noqa: E402
from security_scanner.codeql_adapter import PROFILE_ID, SandboxCapability, preflight  # noqa: E402
from security_scanner.cli import _build_scan_config, build_parser  # noqa: E402
from security_scanner.config import ConfigError, config_from_dict  # noqa: E402
from security_scanner.models import Finding, ScannerConfig, TargetConfig  # noqa: E402
from security_scanner.release import _findings_json  # noqa: E402
from security_scanner.reporting import build_dashboard_payload, render_json, render_report  # noqa: E402
from security_scanner.scanner import SecurityScanner  # noqa: E402
from security_scanner.server import scan_directory_payload  # noqa: E402
from security_scanner.source_analysis import (  # noqa: E402
    AnalyzerRun,
    SourceAnalysisSummary,
    SourceManifest,
    StrategyExecution,
    enumerate_source_files,
)
from security_scanner.standards import sw49_contracts_payload, sw49_payload, validate_sw49_contracts  # noqa: E402


FIXTURES = ROOT / "tests" / "fixtures" / "sw49"
SARIF = FIXTURES / "sarif"


class SourceAnalysisTests(unittest.TestCase):
    def test_manifest_inventory_is_deterministic_and_excludes_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "b.java").write_text("class B {}", encoding="utf-8")
            (root / "a.java").write_text("class A {}", encoding="utf-8")
            files = enumerate_source_files(root)
            manifest = SourceManifest.build(root, files)
            self.assertEqual([entry[0] for entry in manifest.files], ["a.java", "b.java"])
            self.assertEqual(manifest.digest, SourceManifest.build(root, files).digest)

    def test_explicit_symlink_target_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            outside = root / "Outside.java"
            link = root / "Link.java"
            outside.write_text("Object value = null; value.toString();", encoding="utf-8")
            link.symlink_to(outside)
            result = SecurityScanner(ScannerConfig(targets=(TargetConfig("link", link),), standard="sw-dev-security-49")).scan()
        self.assertFalse(result.findings)
        self.assertFalse(result.source_analysis.manifest.files)
        self.assertTrue(any("Refused symlink scan target" in warning for warning in result.warnings))

    def test_sw49_source_profile_only_scans_supported_extensions(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ("Main.java", "config.XML", "app.js", "view.jsp", "index.HTML", "script.py", "template.ts", "component.TSX"):
                (root / name).write_text("source", encoding="utf-8")
            for name in ("native.c", "settings.properties", "component.jsx", "Dockerfile", ".env"):
                (root / name).write_text("not scanned", encoding="utf-8")
            (root / "artifact.bin").write_bytes(b"not source")
            result = SecurityScanner(ScannerConfig(
                targets=(TargetConfig("root", root, categories=("code", "secrets", "configuration", "dependencies", "prevention")),),
                standard="sw-dev-security-49",
            )).scan()
        self.assertTrue(any(finding.category == "prevention" for finding in result.findings))
        self.assertEqual(
            [entry[0] for entry in result.source_analysis.manifest.files],
            [".env", "Dockerfile", "Main.java", "app.js", "component.TSX", "component.jsx", "config.XML", "index.HTML", "native.c", "script.py", "settings.properties", "template.ts", "view.jsp"],
        )

    def test_strategy_expected_files_are_language_applicable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Main.java").write_text("class Main {}", encoding="utf-8")
            (root / "native.c").write_text("int main(void) {}", encoding="utf-8")
            result = SecurityScanner(ScannerConfig(
                targets=(TargetConfig("root", root, categories=("code",)),),
                standard="sw-dev-security-49",
            )).scan()
        java = next(s for s in result.source_analysis.strategies if s.official_control == "C-01")
        self.assertEqual(java.expected_files, ("Main.java",))
        self.assertEqual(java.analyzed_files, ("Main.java",))

    def test_javascript_modules_vue_and_jsp_are_scanned_and_applicable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ("app.mjs", "legacy.cjs", "component.vue", "view.jsp"):
                (root / name).write_text("target.innerHTML = location.hash;", encoding="utf-8")
            result = SecurityScanner(ScannerConfig(
                targets=(TargetConfig("root", root, categories=("code",)),),
                standard="sw-dev-security-49",
            )).scan()
        finding_paths = {finding.path.name for finding in result.findings if finding.rule_id == "code.xss-dom-sink"}
        self.assertEqual(finding_paths, {"app.mjs", "legacy.cjs", "component.vue", "view.jsp"})
        xss = next(strategy for strategy in result.source_analysis.strategies if strategy.official_control == "I-04" and "code.xss-dom-sink" in strategy.required_rule_ids)
        self.assertEqual(set(xss.expected_files), {"app.mjs", "component.vue", "legacy.cjs", "view.jsp"})

    def test_controls_without_applicable_language_are_not_misreported_as_unscanned(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Main.java").write_text("class Main {}", encoding="utf-8")
            result = SecurityScanner(ScannerConfig(
                targets=(TargetConfig("root", root, categories=("code",)),),
                standard="sw-dev-security-49",
            )).scan()
            payload = build_dashboard_payload(
                list(result.findings),
                standard="sw-dev-security-49",
                scanned_categories=("code",),
                source_analysis=result.source_analysis,
            )
        by_id = {row["official_id"]: row for row in payload["sw49"]["controls"]}
        self.assertEqual(by_id["C-03"]["status"], "NOT_APPLICABLE")
        self.assertEqual(by_id["C-04"]["status"], "NOT_APPLICABLE")

    def test_sw49_inventory_includes_manifests_keys_and_workflows(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text('{"dependencies":{"demo":"http://example.invalid/demo.tgz"}}', encoding="utf-8")
            private_key = "-----BEGIN " + "PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----"
            (root / "id_dsa").write_text(private_key, encoding="utf-8")
            (root / "Dockerfile.prod").write_text("FROM ubuntu:latest\n", encoding="utf-8")
            workflow = root / ".github" / "workflows"
            workflow.mkdir(parents=True)
            (workflow / "ci.yml").write_text("uses: actions/checkout@main\n", encoding="utf-8")
            result = SecurityScanner(ScannerConfig(
                targets=(TargetConfig("root", root, categories=("code", "secrets", "configuration", "dependencies", "prevention")),),
                standard="sw-dev-security-49",
            )).scan()
        paths = {entry[0] for entry in result.source_analysis.manifest.files}
        self.assertIn("package.json", paths)
        self.assertIn("id_dsa", paths)
        self.assertIn("Dockerfile.prod", paths)
        self.assertIn(".github/workflows/ci.yml", paths)
        rule_ids = {finding.rule_id for finding in result.findings}
        self.assertIn("config.private-key-like-file", rule_ids)
        self.assertIn("secret.private-key", rule_ids)
        self.assertIn("dependency.node-insecure-url", rule_ids)
        self.assertIn("dependency.docker-unpinned-base", rule_ids)
        self.assertIn("prevention.github-actions-unpinned", rule_ids)

    def test_clean_partial_controls_remain_review_required_not_passed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Main.java").write_text("class Main {}", encoding="utf-8")
            result = SecurityScanner(ScannerConfig(targets=(TargetConfig("root", root),), standard="sw-dev-security-49")).scan()
            payload = build_dashboard_payload(
                list(result.findings),
                standard="sw-dev-security-49",
                scanned_categories=("code", "secrets", "configuration", "dependencies", "prevention"),
                source_analysis=result.source_analysis,
            )
        counts = payload["sw49"]["status_counts"]
        self.assertEqual(counts["PASS"], 0)
        self.assertGreater(counts["NEEDS_REVIEW"], 0)
        self.assertEqual(counts.get("UNSUPPORTED", 0), 0)

    def test_cross_file_sarif_import_preserves_source_trace(self):
        document = load_sarif(SARIF / "c01_cross_file_positive.sarif")
        allowlist = {("codeql", "java/null-dereference"): {"rule_id": "code.null-pointer-dereference", "cwe_ids": ("CWE-476",), "verification_status": "confirmed", "evidence_kind": "dataflow"}}
        findings, warnings = import_sarif(document, FIXTURES, allowlist)
        self.assertFalse(warnings)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cwe_ids, ("CWE-476",))
        self.assertGreaterEqual(len(findings[0].trace), 2)
        self.assertEqual(findings[0].verification_status, "confirmed")

    def test_sarif_analyzer_name_is_case_insensitive(self):
        document = load_sarif(SARIF / "c01_cross_file_positive.sarif")
        document["runs"][0]["tool"]["driver"]["name"] = "CodeQL"
        allowlist = {("codeql", "java/null-dereference"): {"rule_id": "code.null-pointer-dereference"}}
        findings, warnings = import_sarif(document, FIXTURES, allowlist)
        self.assertFalse(warnings)
        self.assertEqual(len(findings), 1)

    def test_c01_sarif_without_trace_is_review_only(self):
        document = copy.deepcopy(load_sarif(SARIF / "c01_cross_file_positive.sarif"))
        document["runs"][0]["results"][0].pop("codeFlows")
        allowlist = {("codeql", "java/null-dereference"): {
            "rule_id": "code.null-pointer-dereference",
            "verification_status": "confirmed",
            "evidence_kind": "dataflow",
            "trace_required": True,
            "analyzer_versions": ("2.26.1",),
        }}
        findings, warnings = import_sarif(document, FIXTURES, allowlist)
        self.assertFalse(warnings)
        self.assertEqual(findings[0].verification_status, "needs_review")
        self.assertEqual(findings[0].evidence_kind, "candidate")

    def test_unapproved_analyzer_version_is_ignored(self):
        document = copy.deepcopy(load_sarif(SARIF / "c01_cross_file_positive.sarif"))
        document["runs"][0]["tool"]["driver"]["version"] = "2.25.0"
        allowlist = {("codeql", "java/null-dereference"): {
            "rule_id": "code.null-pointer-dereference",
            "analyzer_versions": ("2.26.1",),
        }}
        findings, warnings = import_sarif(document, FIXTURES, allowlist)
        self.assertFalse(findings)
        self.assertIn("sarif_analyzer_version_unmapped:2.25.0", warnings)

    def test_path_escape_is_ignored_without_importing_outside_target(self):
        document = load_sarif(SARIF / "path_escape.sarif")
        allowlist = {("codeql", "java/null-dereference"): {"rule_id": "code.null-pointer-dereference"}}
        findings, warnings = import_sarif(document, FIXTURES, allowlist)
        self.assertEqual(findings, ())
        self.assertIn("sarif_path_outside_target", warnings)

    def test_unknown_rule_warns_and_does_not_create_finding(self):
        findings, warnings = import_sarif(load_sarif(SARIF / "unknown_rule.sarif"), FIXTURES, {})
        self.assertEqual(findings, ())
        self.assertTrue(any(item.startswith("sarif_rule_unmapped:") for item in warnings))

    def test_invalid_sarif_documents_fail_closed_with_reason_codes(self):
        for filename, reason in (("malformed.sarif", "sarif_invalid_json"), ("wrong_version.sarif", "sarif_wrong_version")):
            with self.subTest(filename=filename):
                with self.assertRaises(SarifImportError) as caught:
                    load_sarif(SARIF / filename) if filename == "malformed.sarif" else import_sarif(load_sarif(SARIF / filename), FIXTURES)
                self.assertEqual(caught.exception.reason, reason)

    def test_oversized_sarif_is_rejected_before_json_parsing(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "large.sarif"
            path.write_bytes(b"{" + b" " * 32 + b"}")
            with self.assertRaises(SarifImportError) as caught:
                load_sarif(path, max_bytes=16)
            self.assertEqual(caught.exception.reason, "sarif_oversized")

    def test_digestless_positive_sarif_cannot_certify_negative_coverage(self):
        strategy = StrategyExecution("C-01", status="COMPLETE", negative_coverage_certified=False)
        summary = SourceAnalysisSummary(strategies=(strategy,))
        self.assertFalse(summary.coverage_complete)

    def test_kotlin_inapplicable_strategy_does_not_certify_java_coverage(self):
        kotlin = StrategyExecution("C-01", language="Kotlin", status="NOT_APPLICABLE")
        java = StrategyExecution("C-01", language="Java", status="COMPLETE", negative_coverage_certified=True)
        self.assertFalse(SourceAnalysisSummary(strategies=(kotlin, java)).coverage_complete)

    def test_invalid_analyzer_and_strategy_states_fail_closed(self):
        self.assertEqual(AnalyzerRun("fake", status="BOGUS").status, "FAILED")
        self.assertEqual(StrategyExecution("C-01", status="BOGUS").status, "NOT_RUN")

    def test_codeql_preflight_refuses_unverified_sandbox_before_missing_binary(self):
        run = preflight(None, sandbox=SandboxCapability(), license_attested=True, target=FIXTURES)
        self.assertEqual(run.profile_id, PROFILE_ID)
        self.assertEqual(run.status, "SKIPPED")
        self.assertEqual(run.failure_reason, "sandbox_capability_unverified")

    def test_codeql_missing_binary_is_missing_after_verified_capability(self):
        run = preflight(None, sandbox=SandboxCapability(status="VERIFIED"), license_attested=True, target=FIXTURES)
        self.assertEqual(run.status, "MISSING")
        self.assertEqual(run.failure_reason, "codeql_missing")

    def test_source_analyzer_timeout_must_be_positive(self):
        with self.assertRaises(ConfigError):
            config_from_dict({"targets": [{"path": str(FIXTURES)}], "source_analyzer_timeout": 0})

    def test_runtime_analyzer_and_pre_generated_sarif_are_mutually_exclusive(self):
        with self.assertRaises(ConfigError):
            config_from_dict({
                "targets": [{"path": str(FIXTURES)}],
                "source_analyzer": "codeql",
                "source_analyzer_sarif": str(SARIF / "c01_cross_file_positive.sarif"),
            })

    def test_cli_config_merge_preserves_source_analyzer_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scanner.json"
            path.write_text(json.dumps({
                "targets": [{"path": str(FIXTURES)}],
                "standard": "sw-dev-security-49",
                "source_analyzer_sarif": str(SARIF / "c01_cross_file_positive.sarif"),
                "source_analyzer_timeout": 33,
            }), encoding="utf-8")
            config = _build_scan_config(build_parser().parse_args(["scan", "--config", str(path)]))
        self.assertEqual(config.source_analyzer_sarif, SARIF / "c01_cross_file_positive.sarif")
        self.assertEqual(config.source_analyzer_timeout, 33)

    def test_all_49_runtime_contracts_are_canonical_and_fail_closed(self):
        contracts = sw49_contracts_payload()
        validate_sw49_contracts(contracts)
        self.assertEqual(len(contracts["controls"]), 49)
        self.assertTrue(all(row["required_strategies"] for row in contracts["controls"]))
        self.assertTrue(all(not row["pass_certified_profiles"] for row in contracts["controls"]))

    def test_local_null_dereference_is_detected_and_guard_is_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            positive = root / "Positive.java"
            negative = root / "Negative.java"
            positive.write_text("User user = null;\nuser.getName();\n", encoding="utf-8")
            negative.write_text("User user = null;\nif (user == null) return;\nuser.getName();\n", encoding="utf-8")
            vulnerable = SecurityScanner(ScannerConfig(
                targets=(TargetConfig("positive", positive),),
                standard="sw-dev-security-49",
            )).scan()
            guarded = SecurityScanner(ScannerConfig(
                targets=(TargetConfig("negative", negative),),
                standard="sw-dev-security-49",
            )).scan()
        self.assertIn("code.null-pointer-dereference", {item.rule_id for item in vulnerable.findings})
        self.assertNotIn("code.null-pointer-dereference", {item.rule_id for item in guarded.findings})
        c01 = next(row for row in sw49_payload(list(vulnerable.findings), source_analysis=vulnerable.source_analysis)["controls"] if row["official_id"] == "C-01")
        self.assertEqual(c01["status"], "VULNERABLE")

    def test_pre_generated_cross_file_sarif_reaches_sw49_report(self):
        result = SecurityScanner(ScannerConfig(
            targets=(TargetConfig("fixtures", FIXTURES),),
            standard="sw-dev-security-49",
            source_analyzer_sarif=SARIF / "c01_cross_file_positive.sarif",
        )).scan()
        imported = [item for item in result.findings if item.analyzer == "codeql"]
        self.assertEqual(len(imported), 1)
        self.assertGreaterEqual(len(imported[0].trace), 2)
        c01 = next(row for row in sw49_payload(list(result.findings), source_analysis=result.source_analysis)["controls"] if row["official_id"] == "C-01")
        self.assertEqual(c01["status"], "VULNERABLE")

    def test_diff_scoped_dashboard_judges_controls_from_all_findings(self):
        finding = Finding(
            rule_id="code.null-pointer-dereference",
            category="code",
            severity="medium",
            title="Null dereference",
            path=FIXTURES / "c01_cross_file" / "Consumer.java",
        )
        summary = SourceAnalysisSummary(all_findings=(finding,), report_findings=())
        payload = build_dashboard_payload(
            [],
            standard="sw-dev-security-49",
            scanned_categories=("code",),
            source_analysis=summary,
        )
        c01 = next(row for row in payload["sw49"]["controls"] if row["official_id"] == "C-01")
        self.assertEqual(c01["status"], "VULNERABLE")

    def test_report_serialization_does_not_disclose_all_findings(self):
        hidden_path = Path("/secret/unchanged.java")
        hidden = Finding("code.null-pointer-dereference", "code", "medium", "hidden", hidden_path)
        summary = SourceAnalysisSummary(all_findings=(hidden,), report_findings=())
        payload = render_json([], standard="sw-dev-security-49", scanned_categories=("code",), source_analysis=summary)
        self.assertNotIn(str(hidden_path), payload)
        self.assertNotIn('"all_findings"', payload)
        self.assertIn('"all_finding_count": 1', payload)

    def test_single_file_and_multi_target_manifests_preserve_exact_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = root / "one" / "One.java"
            second = root / "two" / "Two.java"
            first.parent.mkdir(); second.parent.mkdir()
            first.write_text("class One {}", encoding="utf-8")
            second.write_text("class Two {}", encoding="utf-8")
            single = SecurityScanner(ScannerConfig(targets=(TargetConfig("one", first),), standard="sw-dev-security-49")).scan()
            multiple = SecurityScanner(ScannerConfig(targets=(TargetConfig("one", first), TargetConfig("two", second)), standard="sw-dev-security-49")).scan()
        self.assertEqual(single.source_analysis.manifest.root.resolve(), first.resolve())
        self.assertEqual(single.source_analysis.manifest.files[0][0], "One.java")
        self.assertEqual({row[0] for row in multiple.source_analysis.manifest.files}, {"one/One.java", "two/Two.java"})

    def test_server_and_direct_html_keep_sw49_ledger(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "Null.java"
            path.write_text("User user = null;\nuser.getName();\n", encoding="utf-8")
            payload = scan_directory_payload(str(root), discover_projects=False, standard="sw-dev-security-49")
            result = SecurityScanner(ScannerConfig(targets=(TargetConfig("root", root),), standard="sw-dev-security-49")).scan()
            html = render_report(
                list(result.findings),
                report_format="html",
                standard="sw-dev-security-49",
                scanned_categories=("code",),
                source_analysis=result.source_analysis,
            )
        c01 = next(row for row in payload["sw49"]["controls"] if row["official_id"] == "C-01")
        self.assertEqual(c01["status"], "VULNERABLE")
        self.assertTrue(payload["source_analysis"]["strategies"])
        self.assertIn('"official_id": "C-01"', html)

    def test_release_json_serializes_slots_and_provenance(self):
        finding = Finding(
            "code.null-pointer-dereference", "code", "medium", "Null", FIXTURES / "c01_cross_file" / "Consumer.java",
            analyzer="codeql", analyzer_version="2.26.1", analyzer_rule_id="java/null-dereference",
            cwe_ids=("CWE-476",), evidence_kind="dataflow", trace=({"path": "Consumer.java", "line": 4},),
        )
        payload = json.loads(_findings_json([finding], SourceAnalysisSummary(all_findings=(finding,), report_findings=(finding,))))
        self.assertEqual(payload["findings"][0]["cwe_ids"], ["CWE-476"])
        self.assertEqual(payload["findings"][0]["analyzer"], "codeql")
        self.assertNotIn("all_findings", payload["source_analysis"])

    def test_positive_review_evidence_is_not_hidden_by_partial_coverage(self):
        finding = Finding(
            rule_id="secret.sensitive-comment",
            category="secrets",
            severity="medium",
            title="Sensitive comment",
            path=FIXTURES / "sensitive_comment.py",
            verification_status="needs_review",
        )
        summary = SourceAnalysisSummary(all_findings=(finding,))
        control = next(row for row in sw49_payload([finding], source_analysis=summary)["controls"] if row["official_id"] == "S-13")
        self.assertEqual(control["status"], "NEEDS_REVIEW")


if __name__ == "__main__":
    unittest.main()
