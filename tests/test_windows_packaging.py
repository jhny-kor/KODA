from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "platforms" / "windows" / "scripts"

SOURCE_ONLY_BOOT = r'''
import importlib.abc
import re
import runpy
import sys
from pathlib import Path

scripts = Path(sys.argv[1])
build = (scripts / "build-koda-windows-installer.ps1").read_text(encoding="utf-8")
block = re.search(r'\$SourceOnlyExcludedModules = @\((.*?)\n\)', build, re.S).group(1)
excluded = set(re.findall(r'"([^"]+)"', block))
class ExcludedModuleFinder(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path, target=None):
        if fullname in excluded:
            raise ModuleNotFoundError(f"SourceOnly excluded {fullname}", name=fullname)
sys.meta_path.insert(0, ExcludedModuleFinder())
sys.path.insert(0, str(scripts.parents[2] / "platforms" / "shared" / "python"))
sys.argv = [str(scripts / "koda-desktop.py"), "--smoke-test"]
runpy.run_path(sys.argv[0], run_name="__main__")
'''


class WindowsPackagingTests(unittest.TestCase):
    def test_source_only_desktop_starts_and_serves_dashboard_with_packaged_modules(self):
        environment = os.environ.copy()
        environment["KODA_SOURCE_ONLY"] = "1"
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        result = subprocess.run(
            [sys.executable, "-c", SOURCE_ONLY_BOOT, str(SCRIPTS)],
            env=environment, capture_output=True, text=True, timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_installer_runs_gui_smoke_and_rejects_nonzero_exit(self):
        script = (SCRIPTS / "build-koda-windows-installer.ps1").read_text(encoding="utf-8")
        self.assertRegex(script, r'(?s)Start-Process\s+.*?-FilePath \$GuiExecutable.*?-ArgumentList "--smoke-test"')
        self.assertIn("$guiSmokeProcess.ExitCode -ne 0", script)


if __name__ == "__main__":
    unittest.main()
