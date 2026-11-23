import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

from security_scanner.local_sast import prepare_local_sast
from security_scanner.semgrep_local import run_semgrep


class SemgrepLocalTests(TestCase):
    def test_network_rules_are_rejected_before_path_resolution(self):
        source = Path("project")
        rules = Path(r"\\example.invalid\share\rules.yml")
        with (
            patch.object(type(source), "resolve", side_effect=AssertionError("filesystem probe")),
            self.assertRaisesRegex(ValueError, "local drive"),
        ):
            prepare_local_sast(source, Path("work"), semgrep_rules=rules)

    def test_network_target_is_rejected_before_path_resolution(self):
        target = Path(r"\\example.invalid\share\source")
        with (
            patch.object(type(target), "resolve", side_effect=AssertionError("filesystem probe")),
            self.assertRaisesRegex(ValueError, "local drive"),
        ):
            run_semgrep(target, Path("rules.yml"), Path("output.sarif"), executable=Path("semgrep"))

    def test_isolates_state_and_only_publishes_valid_sarif(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "my project"
            target.mkdir()
            rules = root / "local.yml"
            rules.write_text("rules: []", encoding="utf-8")
            executable = root / "semgrep.exe"
            executable.touch(mode=0o700)
            output = root / "output.sarif"
            document = {"version": "2.1.0", "runs": [{"results": []}]}
            with patch.dict(os.environ, {"SEMGREP_APP_TOKEN": "test-only", "HTTPS_PROXY": "test-only"}), patch(
                "security_scanner.semgrep_local.subprocess.Popen"
            ) as start:
                process = start.return_value.__enter__.return_value
                def run_tool(timeout):
                    args = start.call_args.args[0]
                    environment = start.call_args.kwargs["env"]
                    copied_rules = Path(args[args.index("--config") + 1])
                    self.assertNotEqual(copied_rules, rules.resolve())
                    self.assertEqual(copied_rules.read_text(encoding="utf-8"), "rules: []")
                    self.assertEqual(Path(environment["SEMGREP_SETTINGS_FILE"]).parent, copied_rules.parent)
                    self.assertNotIn("SEMGREP_APP_TOKEN", environment)
                    self.assertNotIn("HTTPS_PROXY", environment)
                    for flag in ("--oss-only", "--metrics=off", "--disable-version-check"):
                        self.assertIn(flag, args)
                    self.assertEqual(args[-2:], ["--", "."])
                    self.assertEqual(start.call_args.kwargs["cwd"], target.resolve())
                    staged = Path(args[args.index("--output") + 1])
                    staged.write_text(json.dumps(document), encoding="utf-8")
                    return 0
                process.wait.side_effect = run_tool
                run_semgrep(target, rules, output, executable=executable)
                self.assertEqual(json.loads(output.read_bytes()), document)
                original = output.read_bytes()
                document["version"] = "1.0.0"
                with self.assertRaisesRegex(RuntimeError, "importable SARIF"):
                    run_semgrep(target, rules, output, executable=executable)
                self.assertEqual(output.read_bytes(), original)
