"""Check that staged Java assets match the actual app architecture."""

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


STAGE = Path(__file__).parents[1] / "scripts/stage-java-scan-app-bundle.command"


class JavaAssetPackagingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workspace = tempfile.TemporaryDirectory(prefix="koda-java-packaging-")
        cls.root = Path(cls.workspace.name)
        for architecture in ("arm64", "x86_64"):
            subprocess.run(["clang", "-arch", architecture, "-x", "c", "-",
                            "-o", str(cls.root / architecture)],
                           input="int main(void) { return 0; }", text=True, check=True)

    @classmethod
    def tearDownClass(cls):
        cls.workspace.cleanup()

    def stage(self, helper_architecture):
        workspace = tempfile.TemporaryDirectory(dir=self.root)
        self.addCleanup(workspace.cleanup)
        root = Path(workspace.name)
        app = root / "KODA.app"
        executable = app / "Contents/MacOS/KODA"
        executable.parent.mkdir(parents=True)
        shutil.copy2(self.root / "arm64", executable)
        assets = root / "assets"
        helper = assets / "helpers/arm64/koda-java-scan.app/Contents/MacOS/koda-java-scan"
        helper.parent.mkdir(parents=True)
        shutil.copy2(self.root / helper_architecture, helper)
        for name in ("syft", "grype"):
            tool = assets / "tools/arm64" / name
            tool.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(self.root / "arm64", tool)
        (assets / "resources/grype-db/incoming").mkdir(parents=True)
        (assets / "resources/vuln-data/nvd").mkdir(parents=True)
        (assets / "resources/vuln-data/known_exploited_vulnerabilities.json").write_text("{}")
        (assets / "asset-manifest.json").write_text("{}")
        (assets / "manifest.sha256").write_text("")
        result = subprocess.run(["bash", str(STAGE), "--app", str(app), "--assets", str(assets)],
                                capture_output=True, text=True, timeout=20)
        return result, app

    def test_matching_native_assets_are_staged(self):
        result, app = self.stage("arm64")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((app / "Contents/Helpers/koda-java-scan-arm64.app/Contents/MacOS/koda-java-scan").is_file())

    def test_mislabeled_helper_is_rejected_before_staging(self):
        result, app = self.stage("x86_64")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("wrong architecture", result.stderr)
        self.assertFalse((app / "Contents/Helpers").exists())


if __name__ == "__main__":
    unittest.main()
