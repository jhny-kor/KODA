from __future__ import annotations

import base64
import copy
from contextlib import redirect_stderr
import io
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
from types import SimpleNamespace
import urllib.request
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "platforms/shared/python"))
from security_scanner.cli import main
from security_scanner.java_vulnerability_scan import JavaScanOptions, run_java_scan
from security_scanner.models import DependencyComponent
from security_scanner.reporting import build_dashboard_payload, render_html_pair_zip_from_payload
from security_scanner.sbom import spdx_from_cyclonedx
from security_scanner.server import create_dashboard_server
from security_scanner.spdx_input import to_cyclonedx


def source_bom():
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": "urn:uuid:demo",
            "metadata": {"timestamp": "2026-10-19T10:11:12+00:00", "component": {"type": "application", "bom-ref": "root", "name": "product", "version": "1"}},
            "components": [{"type": "library", "bom-ref": "a", "name": "demo", "version": "1.2", "purl": "pkg:maven/org.example/demo@1.2",
                            "cpe": "cpe:2.3:a:acme:demo:1.2:*:*:*:*:*:*:*", "supplier": {"name": "Acme"},
                            "hashes": [{"alg": "SHA-256", "content": "a" * 64}], "licenses": [{"expression": "MIT OR Apache-2.0"}],
                            "properties": [{"name": "koda:location", "value": "/srv/demo.jar"}],
                            "components": [{"type": "library", "bom-ref": "b", "name": "nested", "version": "2"}]}],
            "dependencies": [{"ref": "root", "dependsOn": ["a"]}, {"ref": "a", "dependsOn": ["b"]}]}


class SpdxTests(unittest.TestCase):
    def setUp(self):
        # Explicit local-file development fixtures; Linux production defaults
        # are exercised independently by test_managed_data_current_only.
        local_profile = patch("security_scanner.data_release.sys", SimpleNamespace(platform="darwin"))
        local_profile.start()
        self.addCleanup(local_profile.stop)

    def test_required_fields_identity_hashes_licenses_and_schema(self):
        document = spdx_from_cyclonedx(source_bom())
        self.assertEqual(document["spdxVersion"], "SPDX-2.3")
        self.assertEqual(document["dataLicense"], "CC0-1.0")
        self.assertEqual(document["creationInfo"]["created"], "2026-10-19T10:11:12Z")
        package = next(item for item in document["packages"] if item["name"] == "demo")
        self.assertFalse(package["filesAnalyzed"])
        self.assertEqual(package["checksums"], [{"algorithm": "SHA256", "checksumValue": "a" * 64}])
        self.assertEqual(package["licenseDeclared"], "MIT OR Apache-2.0")
        self.assertEqual(package["licenseConcluded"], "NOASSERTION")
        self.assertEqual(package["copyrightText"], "NOASSERTION")
        self.assertEqual(package["downloadLocation"], "NOASSERTION")
        self.assertEqual(package["supplier"], "Organization: Acme")
        self.assertEqual({ref["referenceType"] for ref in package["externalRefs"]}, {"purl", "cpe23Type"})
        try:
            import jsonschema
        except ImportError:
            self.skipTest("Optional existing jsonschema unavailable; structural tests still run")
        schema = json.loads((Path(__file__).parent / "fixtures/spdx-2.3.schema.json").read_text())
        jsonschema.Draft7Validator(schema).validate(document)

    def test_relationships_are_resolvable_and_preserve_nesting_without_inference(self):
        document = spdx_from_cyclonedx(source_bom())
        ids = {item["name"]: item["SPDXID"] for item in document["packages"]}
        relationships = {(r["spdxElementId"], r["relationshipType"], r["relatedSpdxElement"]) for r in document["relationships"]}
        self.assertIn((ids["demo"], "CONTAINS", ids["nested"]), relationships)
        self.assertIn((ids["demo"], "DEPENDS_ON", ids["nested"]), relationships)
        self.assertIn((ids["product"], "DEPENDS_ON", ids["demo"]), relationships)
        flat = source_bom()
        flat.pop("dependencies")
        self.assertFalse(any(r["relationshipType"] == "DEPENDS_ON" for r in spdx_from_cyclonedx(flat)["relationships"]))

    def test_ambiguous_original_refs_preserve_evidence_without_guessing_edges(self):
        source = source_bom()
        source["components"].append({"name": "other", "bom-ref": "a", "version": "9"})
        document = spdx_from_cyclonedx(source)
        self.assertEqual(len({package["SPDXID"] for package in document["packages"]}), len(document["packages"]))
        evidence = json.loads(document["annotations"][0]["comment"])
        self.assertTrue(evidence["unresolvedRelationships"])
        again = spdx_from_cyclonedx(source)
        self.assertEqual([p["SPDXID"] for p in document["packages"]], [p["SPDXID"] for p in again["packages"]])
        self.assertNotEqual(document["documentNamespace"], again["documentNamespace"])

    def test_missing_unknown_custom_and_multiple_licenses(self):
        source = source_bom()
        value = source["components"][0]
        value["licenses"] = [{"license": {"name": "Unknown"}}]
        self.assertEqual(spdx_from_cyclonedx(source)["packages"][1]["licenseDeclared"], "NOASSERTION")
        value["licenses"] = [{"license": {"id": "MIT"}}, {"license": {"id": "Apache-2.0"}}]
        self.assertEqual(spdx_from_cyclonedx(source)["packages"][1]["licenseDeclared"], "NOASSERTION")
        value["licenses"] = [{"license": {"name": "Internal License", "text": {"encoding": "base64", "content": base64.b64encode(b"Exact local license notice").decode()}}}]
        document = spdx_from_cyclonedx(source)
        declared = document["packages"][1]["licenseDeclared"]
        self.assertTrue(declared.startswith("LicenseRef-KODA-"))
        self.assertEqual(document["hasExtractedLicensingInfos"][0]["extractedText"], "Exact local license notice")
        self.assertEqual(document["hasExtractedLicensingInfos"][0]["licenseId"], declared)

    def test_export_can_be_normalized_for_spdx_cpe_input(self):
        normalized = to_cyclonedx(spdx_from_cyclonedx(source_bom()))
        self.assertEqual(len(normalized["components"]), 3)
        component = next(value for value in normalized["components"] if value["name"] == "demo")
        self.assertEqual(component["purl"], source_bom()["components"][0]["purl"])
        self.assertEqual(component["cpe"], source_bom()["components"][0]["cpe"])
        self.assertEqual(component["hashes"], source_bom()["components"][0]["hashes"])

    def test_cli_dependency_scan_exports_spdx(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            (root / "requirements.txt").write_text("demo==1.2\n")
            output = root / "bom.spdx.json"
            with redirect_stderr(io.StringIO()):
                code = main(["scan", "--target", str(root), "--category", "dependencies", "--format", "spdx", "--output", str(output)])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(output.read_text())["packages"][0]["externalRefs"][0]["referenceLocator"], "pkg:pypi/demo@1.2")

    def test_java_spdx_keeps_hash_and_cyclonedx_for_analysis(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            jar, output = root / "demo.jar", root / "out"
            with zipfile.ZipFile(jar, "w") as archive:
                archive.writestr("META-INF/maven/org.example/demo/pom.properties", "groupId=org.example\nartifactId=demo\nversion=1.2\n")
            result = run_java_scan(JavaScanOptions(target=jar, output_dir=output, builtin_only=True, no_grype=True, sbom_format="spdx-2.3"))
            self.assertEqual(result.exit_code, 0)
            document = json.loads((output / "server-sbom.spdx.json").read_text())
            self.assertTrue((output / "server-sbom.cdx.json").is_file())
            self.assertEqual(document["packages"][0]["checksums"][0]["checksumValue"], result.components[0].sha256)
            self.assertIn("server-sbom.spdx.json", (output / "server-library-report.html").read_text())

    def test_dashboard_and_saved_html_zip_include_actual_spdx(self):
        component = DependencyComponent("demo", "PyPI", "1.2", Path("requirements.txt"), purl="pkg:pypi/demo@1.2")
        payload = build_dashboard_payload([], ("demo",), components=(component,))
        self.assertEqual(payload["spdx_sbom"]["spdxVersion"], "SPDX-2.3")
        payload["sbom"] = source_bom()
        with zipfile.ZipFile(io.BytesIO(render_html_pair_zip_from_payload(payload))) as archive:
            document = json.loads(archive.read("sbom.spdx.json"))
            self.assertEqual(len(document["packages"]), 3)
            self.assertIn("SPDX 2.3 JSON", archive.read("report.html").decode())
            self.assertTrue(any(p.get("checksums") for p in document["packages"]))

    def test_authenticated_dashboard_export_endpoint(self):
        server = create_dashboard_server("127.0.0.1", 0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_address[1]}"
        try:
            request = urllib.request.Request(base + "/api/export", method="POST", data=json.dumps({"format": "spdx", "payload": {"sbom": source_bom()}}).encode(),
                                             headers={"Content-Type": "application/json", "Origin": base, "X-KODA-Session": server.koda_session_token})
            with urllib.request.urlopen(request) as response:
                document = json.load(response)
                self.assertEqual(response.headers.get_content_type(), "application/spdx+json")
                self.assertIn(".spdx.json", response.headers["Content-Disposition"])
            self.assertEqual(document["spdxVersion"], "SPDX-2.3")
        finally:
            server.shutdown(); server.server_close(); thread.join()


if __name__ == "__main__":
    unittest.main()
