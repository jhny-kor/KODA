from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "platforms/shared/python"))
from security_scanner.cli import main

APP = "cpe:2.3:a:acme:widget:1.2:*:*:*:*:*:*:*"
OS = "cpe:2.3:o:acme:server:8:*:*:*:*:*:*:*"


class OfflineCpeCliTests(unittest.TestCase):
    def run_cli(self, args):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err), patch("urllib.request.urlopen", side_effect=AssertionError("network forbidden")):
            code = main(["cpe-scan", *args])
        return code, json.loads(out.getvalue()) if out.getvalue() else None, err.getvalue()

    def setUp(self):
        # Explicit local-file development fixtures; Linux production defaults
        # are exercised independently by test_managed_data_current_only.
        local_profile = patch("security_scanner.data_release.sys", SimpleNamespace(platform="darwin"))
        local_profile.start()
        self.addCleanup(local_profile.stop)
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.nvd = self.root / "nvd.json"
        self.record = {"id": "CVE-2026-12345", "configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*", "vulnerable": True, "versionEndExcluding": "2"}]}]}]}
        self.nvd.write_text(json.dumps({"vulnerabilities": [{"cve": self.record}]}))

    def test_scan_outputs_evidence_provenance_and_no_match_scope(self):
        args = ["--nvd-data", str(self.nvd), "--cpe", APP]
        code, report, error = self.run_cli(args)
        self.assertEqual(code, 1, error)
        self.assertEqual(report["findings"][0]["cve"], self.record["id"])
        self.assertEqual(len(report["coverage"]["sources"][0]["sha256"]), 64)
        code, report, error = self.run_cli(["--nvd-data", str(self.nvd), "--cpe", APP.replace("1.2", "2.0")])
        self.assertEqual(code, 0, error)
        self.assertEqual(report["findings"], [])
        self.assertIn("supplied CPE", report["coverage"]["scope"])

    def test_nested_sbom_and_output_file(self):
        sbom = self.root / "bom.json"
        sbom.write_text(json.dumps({"bomFormat": "CycloneDX", "components": [{"name": "outer", "components": [{"name": "inner", "cpe": APP}]}]}))
        output = self.root / "result.json"
        code, stdout, error = self.run_cli(["--sbom", str(sbom), "--nvd-data", str(self.nvd), "--output", str(output)])
        self.assertEqual(code, 1, error)
        self.assertIsNone(stdout)
        self.assertEqual(json.loads(output.read_text())["coverage"]["inputCpes"], 1)

    def test_spdx_generated_by_koda_uses_offline_cpe_inventory(self):
        from security_scanner.sbom import spdx_from_cyclonedx
        sbom = self.root / "bom.spdx.json"
        sbom.write_text(json.dumps(spdx_from_cyclonedx({
            "bomFormat": "CycloneDX", "components": [{"name": "widget", "version": "1.2", "cpe": APP}]})))
        code, report, error = self.run_cli(["--sbom", str(sbom), "--nvd-data", str(self.nvd)])
        self.assertEqual(code, 1, error)
        self.assertEqual(report["coverage"]["inputCpes"], 1)
        self.assertEqual(report["findings"][0]["cve"], self.record["id"])

    def test_missing_invalid_legacy_and_uncovered_data_never_pass(self):
        for args in (["--nvd-data", str(self.nvd)],
                     ["--nvd-data", str(self.nvd), "--cpe", "bad"],
                     ["--nvd-data", str(self.root / "missing"), "--cpe", APP],
                     ["--nvd-data", str(self.nvd), "--cpe", APP.replace("widget", "different")],
                     ["--nvd-data", str(self.nvd), "--cpe", APP.replace("1.2", "1.2rc1")]):
            code, report, _ = self.run_cli(args)
            self.assertEqual(code, 2)
            self.assertNotEqual(report["coverage"]["status"], "completed")
        self.nvd.write_text(json.dumps({"vulnerabilities": {self.record["id"]: {"id": self.record["id"], "cpe": [APP]}}}))
        code, report, _ = self.run_cli(["--nvd-data", str(self.nvd), "--cpe", APP])
        self.assertEqual(code, 2)
        self.assertEqual(report["coverage"]["sources"][0]["legacyDetailsOnly"], 1)

    def test_missing_environment_is_unknown_and_provided_environment_matches(self):
        self.record["configurations"][0]["operator"] = "AND"
        self.record["configurations"][0]["nodes"].append({"cpeMatch": [{"criteria": OS, "vulnerable": False}]})
        self.nvd.write_text(json.dumps({"vulnerabilities": [{"cve": self.record}]}))
        code, report, _ = self.run_cli(["--nvd-data", str(self.nvd), "--cpe", APP])
        self.assertEqual(code, 2)
        self.assertEqual(report["coverage"]["unknownCves"], 1)
        code, report, _ = self.run_cli(["--nvd-data", str(self.nvd), "--cpe", APP, "--cpe", OS])
        # A vulnerable app match is still emitted; the OS itself has no indexed
        # vulnerability condition, so whole-inventory coverage remains partial.
        self.assertEqual(code, 2)
        self.assertEqual(len(report["findings"]), 1)

    def test_deep_record_cannot_hide_behind_a_normal_record_for_same_product(self):
        deep = {"cpeMatch": [{"criteria": APP, "vulnerable": True}]}
        for _ in range(30):
            deep = {"nodes": [deep]}
        self.nvd.write_text(json.dumps({"vulnerabilities": [{"cve": self.record}, {"cve": {"id": "CVE-2026-54321", "configurations": [deep]}}]}))
        code, report, _ = self.run_cli(["--nvd-data", str(self.nvd), "--cpe", APP.replace("1.2", "2.0")])
        self.assertEqual(code, 2)
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["coverage"]["unmatchedProducts"], 0)
        self.assertEqual(report["coverage"]["unknownCves"], 1)
        self.assertEqual(report["coverage"]["indexIncompleteCves"], 1)
        self.assertIn("complexity", report["coverage"]["unresolved"][0]["reason"])


if __name__ == "__main__":
    unittest.main()
