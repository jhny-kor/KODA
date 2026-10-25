from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest

from security_scanner.cli import main
from security_scanner import integrations
from security_scanner.standards import SECURITY_STANDARDS, SECURITY_STANDARD_IDS, resolve_standard_selection, standards_payload
from security_scanner.toolkit import security_template_files, render_security_toolkit_markdown


class RemovedDependencyTrackTests(unittest.TestCase):
    def test_removed_commands_are_rejected_and_absent_from_help(self):
        for command in ("upload-sbom", "dependency-track-command"):
            with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
                main([command])
            self.assertEqual(raised.exception.code, 2)
        output = io.StringIO()
        with redirect_stdout(output), self.assertRaises(SystemExit):
            main(["--help"])
        self.assertNotIn("upload-sbom", output.getvalue())
        self.assertNotIn("dependency-track", output.getvalue().lower())
        self.assertFalse(hasattr(integrations, "upload_sbom_to_dependency_track"))
        self.assertFalse(hasattr(integrations, "dependency_track_upload_command"))

    def test_removed_profile_is_rejected_without_silent_fallback(self):
        self.assertNotIn("owasp-dependency-track-baseline", SECURITY_STANDARD_IDS)
        self.assertNotIn("dependency-track", json.dumps(standards_payload()).lower())
        with self.assertRaisesRegex(ValueError, "Unsupported standard"):
            resolve_standard_selection("owasp-dependency-track-baseline")
        # Ordinary scanning and the separate dependency-check profile survive.
        self.assertEqual(resolve_standard_selection().standard, "local")
        self.assertIn("owasp-dependency-check-baseline", SECURITY_STANDARD_IDS)
        for standard in SECURITY_STANDARDS:
            for category in standard.categories:
                self.assertIsInstance(category.rule_ids, tuple, (standard.id, category.id))

    def test_dependency_manifest_retains_generic_sbom_and_vex_checks(self):
        from security_scanner.checks.prevention import check_project
        from security_scanner.models import TargetConfig
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "requirements.txt"
            manifest.write_text("demo==1.0\n")
            findings = check_project(root, [manifest], TargetConfig(name="fixture", path=root))
        rules = {finding.rule_id for finding in findings}
        self.assertIn("prevention.sbom-missing", rules)
        self.assertIn("prevention.vex-missing", rules)
        self.assertFalse(any("dependency-track" in rule for rule in rules))

    def test_generated_guardrails_keep_vex_zap_and_sbom_without_upload_service(self):
        templates = security_template_files("demo")
        self.assertIn("docs/security/VEX.md", templates)
        self.assertIn("docs/security/ZAP_BASELINE.md", templates)
        text = json.dumps(templates).lower() + render_security_toolkit_markdown("demo").lower()
        self.assertNotIn("dependency-track", text)
        self.assertNotIn("dependency_track", text)
        self.assertNotIn("upload-sbom", text)

    def test_shared_and_native_catalogs_do_not_publish_removed_feature(self):
        root = Path(__file__).resolve().parents[1]
        for path in (root / "platforms/macos/app/KODA/KODA").glob("*.swift"):
            self.assertNotIn("dependency-track", path.read_text().lower(), str(path))
        catalog = json.loads((root / "platforms/macos/app/KODA/KODA/rules_catalog.json").read_text())
        self.assertNotIn("dependency-track", json.dumps(catalog).lower())
