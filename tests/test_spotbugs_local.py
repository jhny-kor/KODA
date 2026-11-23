import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from security_scanner.spotbugs_local import run_spotbugs


class SpotBugsLocalTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory(prefix="spotbugs with spaces ")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.target = self.root / "input.jar"
        self.tool = self.root / "spotbugs.jar"
        self.java = self.root / ("java.exe" if os.name == "nt" else "java")
        self.output = self.root / "result.sarif"
        for file in (self.target, self.tool, self.java):
            file.touch()
        self.java.chmod(0o700)

    def test_success_with_findings_keeps_report_and_does_not_use_jvm_injection_environment(self) -> None:
        def spotbugs(arguments, *, cwd, env, **kwargs):
            self.assertEqual(arguments[-1], str(self.target.resolve()))
            self.assertEqual(arguments[arguments.index("-sourcepath") + 1], str(self.root.resolve()))
            self.assertIn("-nested:false", arguments)
            self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
            self.assertNotIn("JAVA_TOOL_OPTIONS", env)
            self.assertNotIn("KODA_TEST_CREDENTIAL", env)
            report_path = Path(next(arg.removeprefix("-sarif=") for arg in arguments if arg.startswith("-sarif=")))
            self.assertEqual(report_path.parent, Path(cwd))
            report_path.write_text('{"version":"2.1.0"}', encoding="utf-8")
            return subprocess.CompletedProcess(arguments, 3)

        with (
            patch.dict(os.environ, {"JAVA_TOOL_OPTIONS": "-Duser.language=ja", "KODA_TEST_CREDENTIAL": "demo"}),
            patch("security_scanner.spotbugs_local.subprocess.run", side_effect=spotbugs),
        ):
            run_spotbugs(self.target, self.root, self.output, tool=self.tool, java=self.java)
        self.assertEqual(self.output.read_text(encoding="utf-8"), '{"version":"2.1.0"}')
        self.assertFalse(list(self.root.glob(".koda-spotbugs-*")))

    def test_timeout_preserves_previous_report(self) -> None:
        self.output.write_text("previous report", encoding="utf-8")
        with (
            patch("security_scanner.spotbugs_local.subprocess.run", side_effect=subprocess.TimeoutExpired("java", 120)),
            self.assertRaisesRegex(RuntimeError, "did not finish"),
        ):
            run_spotbugs(self.target, self.root, self.output, tool=self.tool, java=self.java)
        self.assertEqual(self.output.read_text(encoding="utf-8"), "previous report")
        self.assertFalse(list(self.root.glob(".koda-spotbugs-*")))

    def test_source_file_is_rejected_without_invoking_java(self) -> None:
        source = self.root / "Input.java"
        source.touch()
        with patch("security_scanner.spotbugs_local.subprocess.run") as run:
            with self.assertRaisesRegex(ValueError, "compiled classes"):
                run_spotbugs(source, self.root, self.output, tool=self.tool, java=self.java)
            run.assert_not_called()

    def test_network_target_is_rejected_before_path_resolution(self) -> None:
        for target in (Path(r"\\example.invalid\share\input.jar"), Path("//example.invalid/share/input.jar")):
            with (
                self.subTest(target=target),
                patch.object(type(target), "resolve", side_effect=AssertionError("filesystem probe")),
                self.assertRaisesRegex(ValueError, "local drive"),
            ):
                run_spotbugs(target, self.root, self.output, tool=self.tool, java=self.java)
