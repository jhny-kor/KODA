from __future__ import annotations

import csv
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SHARED_PYTHON = ROOT / "platforms" / "shared" / "python"
if str(SHARED_PYTHON) not in sys.path:
    sys.path.insert(0, str(SHARED_PYTHON))

from security_scanner.grype_adapter import GrypeResult, run_grype, run_grype_purls
from security_scanner.java_archives import scan_archives
from security_scanner.java_vulnerability_scan import JavaScanOptions, run_java_scan
from security_scanner.syft_adapter import run_syft


def _write_jar(path: Path, files: dict[str, str | bytes]) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for name, content in files.items():
            archive.writestr(name, content)


class JavaScanRuntimeTests(unittest.TestCase):
    def test_vulnerability_gates_fail_when_grype_comparison_is_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            jar = root / "demo.jar"
            _write_jar(jar, {"META-INF/maven/org.example/demo/pom.properties": "groupId=org.example\nartifactId=demo\nversion=1.2.3\n"})
            kev = root / "kev.json"
            kev.write_text(json.dumps({"vulnerabilities": []}), encoding="utf-8")
            for gate in ({"fail_on": "high"}, {"fail_on_kev": True}):
                for disabled in (False, True):
                    with self.subTest(gate=gate, disabled=disabled), patch.dict(os.environ, {"KODA_GRYPE_BIN": ""}):
                        result = run_java_scan(JavaScanOptions(
                            target=jar, output_dir=root / "reports", builtin_only=True,
                            cisa_kev=kev, no_grype=disabled, **gate,
                        ))
                        self.assertEqual(result.exit_code, 2)
                        self.assertTrue(any("requires Grype" in warning for warning in result.warnings))
                        self.assertTrue((root / "reports/server-sbom.cdx.json").is_file())

    def test_completed_clean_grype_comparison_passes_severity_gate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            jar = root / "demo.jar"
            _write_jar(jar, {"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\n"})
            with patch("security_scanner.java_vulnerability_scan.run_grype", return_value=GrypeResult((), "test", {}, "", False)):
                result = run_java_scan(JavaScanOptions(
                    target=jar, output_dir=root / "reports", builtin_only=True,
                    grype_bin=root / "grype", fail_on="high",
                ))
            self.assertEqual(result.exit_code, 0)

    def test_java_scan_combines_repeated_target_roots_into_one_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "api"
            second = root / "worker"
            first.mkdir()
            second.mkdir()
            _write_jar(first / "api.jar", {"META-INF/maven/org.example/api/pom.properties": "groupId=org.example\nartifactId=api\nversion=1.0.0\n"})
            _write_jar(second / "worker.jar", {"META-INF/maven/org.example/worker/pom.properties": "groupId=org.example\nartifactId=worker\nversion=2.0.0\n"})
            output = root / "reports"

            result = run_java_scan(
                JavaScanOptions(
                    target=first,
                    targets=(first, second, first),
                    output_dir=output,
                    builtin_only=True,
                    no_grype=True,
                )
            )

            self.assertEqual(result.exit_code, 0)
            self.assertEqual(result.archive_count, 2)
            self.assertEqual({component.name for component in result.components}, {"api", "worker"})
            payload = json.loads((output / "server-vulnerabilities.json").read_text(encoding="utf-8"))
            metadata = json.loads((output / "scan-metadata.json").read_text(encoding="utf-8"))
            self.assertEqual(len(payload["archives"]), 2)
            self.assertEqual(len(payload["components"]), 2)
            self.assertEqual(len(metadata["targets"]), 2)
            self.assertIn(str(first.resolve()), payload["target"])
            self.assertIn(str(second.resolve()), payload["target"])

    def test_scan_archives_accepts_a_single_jar_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            jar = root / "demo-1.2.3.jar"
            _write_jar(jar, {"META-INF/maven/org.example/demo/pom.properties": "groupId=org.example\nartifactId=demo\nversion=1.2.3\n"})

            result = scan_archives(jar)

            self.assertEqual(len(result.artifacts), 1)
            self.assertEqual(result.artifacts[0].location.outer_path, jar.resolve())

    def test_java_scan_writes_an_sbom_for_a_single_jar_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            jar = root / "demo-1.2.3.jar"
            output = root / "reports"
            _write_jar(jar, {"META-INF/maven/org.example/demo/pom.properties": "groupId=org.example\nartifactId=demo\nversion=1.2.3\n"})

            result = run_java_scan(JavaScanOptions(target=jar, output_dir=output, builtin_only=True, no_grype=True))

            self.assertEqual(result.exit_code, 0)
            self.assertTrue((output / "server-sbom.cdx.json").is_file())
            self.assertEqual(json.loads((output / "server-sbom.cdx.json").read_text(encoding="utf-8"))["specVersion"], "1.6")

    def test_java_scan_can_write_nis_sbom(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            jar = root / "demo-1.2.3.jar"
            output = root / "reports"
            _write_jar(jar, {"META-INF/maven/org.example/demo/pom.properties": "groupId=org.example\nartifactId=demo\nversion=1.2.3\n"})

            result = run_java_scan(JavaScanOptions(target=jar, output_dir=output, builtin_only=True, no_grype=True, sbom_format="nis-1.0"))

            self.assertEqual(result.exit_code, 0)
            nis_path = output / "server-sbom.nis.csv"
            raw_nis = nis_path.read_bytes()
            self.assertTrue(raw_nis.startswith(b"\xef\xbb\xbf"))
            self.assertIn(b"\r\n", raw_nis)
            self.assertNotIn(b"\r\r\n", raw_nis)
            rows = list(csv.DictReader(io.StringIO(nis_path.read_text(encoding="utf-8-sig"))))
            self.assertEqual(rows[0]["SBOM Standard"], "NIS 1.0")
            self.assertEqual(rows[0]["SBOM Type"], "Deployed")
            self.assertEqual(rows[0]["Component Name"], "demo")
            self.assertEqual(rows[0]["Component Supplier Name"], "org.example")
            self.assertRegex(rows[0]["Component Hash"], r"^alg : SHA-256\ncontent : [0-9a-f]{64}$")

    def test_default_scan_limits_entries_but_explicit_budget_allows_large_archive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            nested = root / "nested.jar"
            _write_jar(nested, {"META-INF/maven/org.example/demo/pom.properties": "groupId=org.example\nartifactId=demo\nversion=1.2.3\n"})
            with zipfile.ZipFile(root / "large.war", "w") as archive:
                for index in range(10_001):
                    archive.writestr(f"WEB-INF/classes/{index}.txt", b"")
                archive.writestr("WEB-INF/lib/nested.jar", nested.read_bytes())

            result = scan_archives(root)
            self.assertEqual(len(result.artifacts), 2)
            self.assertTrue(any("limit exceeded" in warning for warning in result.warnings))

            expanded_budget = scan_archives(root, max_entries=10_004)
            self.assertEqual(len(expanded_budget.artifacts), 3)
            self.assertFalse(any("limit exceeded" in warning for warning in expanded_budget.warnings))

    def test_external_tool_runners_request_utf8_decoding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "tool"
            binary.write_text("placeholder", encoding="utf-8")
            binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
            with patch("security_scanner.syft_adapter._run") as syft_run:
                syft_run.side_effect = [
                    subprocess.CompletedProcess([str(binary)], 0, "syft 1.0.0", ""),
                    subprocess.CompletedProcess([str(binary)], 0, json.dumps({"bomFormat": "CycloneDX", "components": []}), ""),
                ]
                run_syft(root, binary, 1)
            with patch("security_scanner.grype_adapter.subprocess.run") as grype_run:
                grype_run.side_effect = [
                    subprocess.CompletedProcess([str(binary)], 0, "grype 1.0.0", ""),
                    subprocess.CompletedProcess([str(binary)], 0, json.dumps({"database": {}}), ""),
                    subprocess.CompletedProcess([str(binary)], 0, json.dumps({"matches": []}), ""),
                ]
                run_grype(root / "sbom.json", binary, 1)

            self.assertEqual(len(syft_run.call_args_list), 2)
            for invocation in grype_run.call_args_list:
                self.assertEqual(invocation.kwargs["encoding"], "utf-8")
                self.assertEqual(invocation.kwargs["errors"], "replace")

    def test_syft_uses_a_file_source_for_a_single_archive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "syft"
            jar = root / "demo.jar"
            binary.write_text("placeholder", encoding="utf-8")
            binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
            _write_jar(jar, {"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\n"})
            with patch("security_scanner.syft_adapter._run") as syft_run:
                syft_run.side_effect = [
                    subprocess.CompletedProcess([str(binary)], 0, "syft 1.0.0", ""),
                    subprocess.CompletedProcess([str(binary)], 0, json.dumps({"bomFormat": "CycloneDX", "components": []}), ""),
                ]

                run_syft(jar, binary, 1)

            self.assertEqual(syft_run.call_args_list[1].args[1][0], f"file:{jar}")

    def test_grype_candidate_scan_uses_purl_file_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "grype"
            binary.write_text("placeholder", encoding="utf-8")
            binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
            with patch("security_scanner.grype_adapter.subprocess.run") as grype_run:
                grype_run.return_value = subprocess.CompletedProcess([str(binary)], 0, json.dumps({"matches": []}), "")

                result = run_grype_purls(("pkg:maven/org.example/demo@1.2.3",), binary, 1)

            self.assertFalse(result.fatal)
            self.assertTrue(grype_run.call_args_list)
            self.assertTrue(grype_run.call_args_list[0].args[0][1].startswith("purl:"))


if __name__ == "__main__":
    unittest.main()
