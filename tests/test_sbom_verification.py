from __future__ import annotations

import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SHARED_PYTHON = ROOT / "platforms" / "shared" / "python"
if str(SHARED_PYTHON) not in sys.path:
    sys.path.insert(0, str(SHARED_PYTHON))

from security_scanner.java_archives import scan_archives
from security_scanner.java_inventory import inventory_components
from security_scanner.sbom_verification import (
    SBOM_COMPONENT_MISSING_ON_SERVER,
    SERVER_COMPONENT_MISSING_IN_SBOM,
    VERSION_MISMATCH,
    SbomVerificationOptions,
    run_sbom_verification,
)


def _write_jar(path: Path, group: str, name: str, version: str, marker: str = "") -> None:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(
            f"META-INF/maven/{group}/{name}/pom.properties",
            f"groupId={group}\nartifactId={name}\nversion={version}\nmarker={marker}\n",
        )


def _sbom_component(component: object, *, version: str | None = None, sha256: str | None = None) -> dict[str, object]:
    payload = component.payload()
    return {
        "type": "library",
        "group": payload["group"],
        "name": payload["name"],
        "version": version if version is not None else payload["version"],
        "purl": payload["purl"],
        "hashes": [{"alg": "SHA-256", "content": sha256 or payload["sha256"]}],
        "properties": [{"name": "koda:location", "value": payload["locations"][0]}],
    }


class SbomVerificationTests(unittest.TestCase):
    def test_archive_limit_fails_verification(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            jar = root / "oversized.jar"
            _write_jar(jar, "org.example", "demo", "1.0", "x" * 1024)
            sbom = root / "sbom.json"
            sbom.write_text(json.dumps({"bomFormat": "CycloneDX", "components": []}), encoding="utf-8")
            from unittest.mock import patch
            with patch("security_scanner.java_archives.MAX_SINGLE_ARCHIVE_BYTES", 100):
                result = run_sbom_verification(SbomVerificationOptions(target=jar, sbom=sbom, output_dir=root / "report"))
            self.assertEqual(result.exit_code, 2)
            self.assertTrue(result.warnings)

    def test_current_sbom_compares_internal_version_and_hash_both_ways(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "app"
            target.mkdir()
            jar = target / "demo-1.2.4.jar"
            _write_jar(jar, "org.example", "demo", "1.2.3")
            component = inventory_components(scan_archives(target))[0]
            sbom = root / "server-sbom.cdx.json"
            sbom.write_text(
                json.dumps(
                    {
                        "bomFormat": "CycloneDX",
                        "specVersion": "1.5",
                        "components": [_sbom_component(component, version="1.2.3")],
                    }
                ),
                encoding="utf-8",
            )

            result = run_sbom_verification(SbomVerificationOptions(target=target, sbom=sbom, output_dir=root / "report"))

            statuses = {item.status for item in result.results}
            self.assertIn("FILENAME_VERSION_MISMATCH", statuses)
            self.assertEqual(result.summary["server_component_missing_in_sbom"], 0)
            self.assertTrue((root / "report" / "sbom-verification.json").exists())
            self.assertTrue((root / "report" / "current-inventory.json").exists())

    def test_version_mismatch_and_server_missing_are_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "app"
            target.mkdir()
            _write_jar(target / "demo-1.2.3.jar", "org.example", "demo", "1.2.3")
            _write_jar(target / "untracked-1.0.0.jar", "org.example", "untracked", "1.0.0")
            components = inventory_components(scan_archives(target))
            demo = next(item for item in components if item.name == "demo")
            sbom = root / "sbom.json"
            sbom.write_text(
                json.dumps(
                    {
                        "bomFormat": "CycloneDX",
                        "components": [
                            _sbom_component(demo, version="9.9.9"),
                            {
                                "type": "library",
                                "group": "org.example",
                                "name": "removed",
                                "version": "2.0.0",
                                "purl": "pkg:maven/org.example/removed@2.0.0",
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )

            result = run_sbom_verification(SbomVerificationOptions(target=target, sbom=sbom, output_dir=root / "report"))
            by_name = {item.component_name: item.status for item in result.results}
            self.assertEqual(by_name["demo"], VERSION_MISMATCH)
            self.assertEqual(by_name["removed"], SBOM_COMPONENT_MISSING_ON_SERVER)
            self.assertEqual(by_name["untracked"], SERVER_COMPONENT_MISSING_IN_SBOM)

    def test_baseline_detects_version_and_content_changes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "app"
            target.mkdir()
            _write_jar(target / "demo-2.0.0.jar", "org.example", "demo", "2.0.0")
            current = inventory_components(scan_archives(target))[0]
            baseline = root / "baseline.json"
            baseline.write_text(
                json.dumps(
                    {
                        "bomFormat": "CycloneDX",
                        "components": [_sbom_component(current, version="1.0.0", sha256="0" * 64)],
                    }
                ),
                encoding="utf-8",
            )

            result = run_sbom_verification(
                SbomVerificationOptions(target=target, baseline_sbom=baseline, output_dir=root / "report")
            )

            changes = {item.status for item in result.baseline_changes}
            self.assertIn("BASELINE_VERSION_CHANGED", changes)
            self.assertIn("BASELINE_CONTENT_CHANGED", changes)
            self.assertEqual(result.summary["server_component_missing_in_sbom"], 0)
            self.assertIn("upgrade", next(item.details for item in result.baseline_changes if item.status == "BASELINE_VERSION_CHANGED"))

    def test_hash_algorithm_names_are_normalized(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "app"
            target.mkdir()
            _write_jar(target / "demo-1.0.0.jar", "org.example", "demo", "1.0.0")
            component = inventory_components(scan_archives(target))[0]
            sbom = root / "sbom.json"
            sbom.write_text(
                json.dumps({"bomFormat": "CycloneDX", "components": [{**_sbom_component(component), "hashes": [{"alg": "sha256", "content": component.sha256}]}]}),
                encoding="utf-8",
            )
            result = run_sbom_verification(SbomVerificationOptions(target=target, sbom=sbom, output_dir=root / "report"))
            self.assertEqual(result.results[0].status, "MATCHED")

    def test_strict_hash_and_same_purl_content_conflict_are_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "app"
            target.mkdir()
            _write_jar(target / "demo-a.jar", "org.example", "demo", "1.0.0", "a")
            _write_jar(target / "demo-b.jar", "org.example", "demo", "1.0.0", "b")
            first = inventory_components(scan_archives(target))[0]
            sbom = root / "sbom.json"
            sbom.write_text(json.dumps({"bomFormat": "CycloneDX", "components": [{**_sbom_component(first), "hashes": []}]}), encoding="utf-8")

            result = run_sbom_verification(SbomVerificationOptions(target=target, sbom=sbom, output_dir=root / "report", strict_hash=True))

            self.assertEqual(result.results[0].status, "CONTENT_MISMATCH")
            self.assertIn("SAME_PURL_DIFFERENT_CONTENT", {item.status for item in result.results})
            self.assertEqual(result.exit_code, 0)


if __name__ == "__main__":
    unittest.main()
