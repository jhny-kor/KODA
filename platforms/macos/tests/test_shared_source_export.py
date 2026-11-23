"""Exercise the native export path against the same CLI bundled for Windows and Mac."""
import csv
import json
import os
from pathlib import Path
import platform
import plistlib
import shlex
import subprocess
import sys
import tempfile
import unittest
import zipfile

MAC = Path(__file__).resolve().parents[1]
ENGINE = MAC.parent / "shared/python"
SWIFT = MAC / "app/KODA/KODA/BundledJavaArchiveScanner.swift"


class SharedSourceExportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workspace = tempfile.TemporaryDirectory(prefix="koda desktop export ")
        cls.root = Path(cls.workspace.name)
        contents = cls.root / "KODA.app/Contents"
        cls.binary = contents / "MacOS/KODA"
        cls.binary.parent.mkdir(parents=True)
        (contents / "Info.plist").write_bytes(plistlib.dumps(
            {"CFBundleExecutable": "KODA", "CFBundleIdentifier": "koda.test.source-export", "CFBundlePackageType": "APPL"}
        ))
        harness = cls.root / "Harness.swift"
        harness.write_text("""
import Foundation
enum AppLanguage { case ko, en }
@main struct Harness {
    static func main() throws {
        let args = CommandLine.arguments
        let url: (String) -> URL = { URL(fileURLWithPath: $0) }
        let result = try BundledJavaArchiveScanner.exportSourceReport(
            targets: [url(args[1])], destination: url(args[2]),
            format: SharedSourceReportFormat(rawValue: args[3])!, discover: false,
            sarif: args.count > 5 ? url(args[5]) : nil,
            baseline: args.count > 4 && !args[4].isEmpty ? url(args[4]) : nil, failOn: "high"
        )
        print(result.gateFailed ? "gate-failed" : "gate-passed")
    }
}
""")
        subprocess.run(["swiftc", "-parse-as-library", str(SWIFT), str(harness), "-o", str(cls.binary)], check=True)
        architecture = "arm64" if platform.machine() == "arm64" else "amd64"
        helper_app = contents / f"Helpers/koda-java-scan-{architecture}.app"
        helper_app.parent.mkdir()
        if os.environ.get("KODA_TEST_FROZEN_HELPER"):
            helper_app.symlink_to(Path(os.environ["KODA_TEST_FROZEN_HELPER"]).resolve(), target_is_directory=True)
        else:
            helper = helper_app / "Contents/MacOS/koda-java-scan"
            helper.parent.mkdir(parents=True)
            helper.write_text("#!/bin/sh\n" + f"export PYTHONPATH={shlex.quote(str(ENGINE))}\n"
                              + f"exec {shlex.quote(sys.executable)} -m security_scanner \"$@\"\n")
            helper.chmod(0o755)
        cls.target = cls.root / "local project"
        cls.target.mkdir()
        (cls.target / "example.py").write_text('api_key = "AKIAIOSFODNN7EXAMPLE"\n')
        (cls.target / "requirements.txt").write_text("requests==2.32.0\n")

    @classmethod
    def tearDownClass(cls):
        cls.workspace.cleanup()

    def export(self, fmt, name, *extra):
        output = self.root / name
        run = subprocess.run([str(self.binary), str(self.target), str(output), fmt, *extra],
                             capture_output=True, text=True, timeout=30)
        self.assertEqual(run.returncode, 0, run.stderr)
        return output, run.stdout.strip()

    def test_new_only_gate_and_all_export_formats(self):
        baseline, status = self.export("json", "baseline.json")
        self.assertEqual(status, "gate-failed")
        self.assertIn("secret.aws-access-key", [f["rule_id"] for f in json.loads(baseline.read_text())["findings"]])
        result, status = self.export("sarif", "source.sarif", str(baseline))
        self.assertEqual(status, "gate-passed")
        self.assertEqual(json.loads(result.read_text())["version"], "2.1.0")
        result, _ = self.export("spdx", "source.spdx.json")
        self.assertEqual(json.loads(result.read_text())["spdxVersion"], "SPDX-2.3")
        result, _ = self.export("nis-sbom", "source.csv")
        with result.open() as stream:
            self.assertIn("requests", [r["Component Name"] for r in csv.DictReader(stream)])
        result, _ = self.export("hwpx", "source.hwpx")
        with zipfile.ZipFile(result) as archive:
            self.assertIn("Contents/section0.xml", archive.namelist())

    def test_imported_sarif_provenance(self):
        external = self.root / "external.sarif"
        external.write_text(json.dumps({"version": "2.1.0", "runs": [
            {"tool": {"driver": {"name": "fixture"}}, "results": []}]}))
        result, _ = self.export("json", "import.json", "", str(external))
        payload = json.loads(result.read_text())
        self.assertEqual(payload["source_analysis"]["analyzer_runs"][0]["output_origin"], "pre_generated")


if __name__ == "__main__":
    unittest.main()
