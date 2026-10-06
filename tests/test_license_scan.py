from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SHARED_PYTHON = ROOT / "platforms" / "shared" / "python"
if str(SHARED_PYTHON) not in sys.path:
    sys.path.insert(0, str(SHARED_PYTHON))

from security_scanner.checks.configuration import _check_license
from security_scanner.models import TargetConfig


class LicenseScanTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.target = TargetConfig(name="x", path=self.dir)

    def _write(self, name: str, content: str) -> Path:
        p = self.dir / name
        p.write_text(content, encoding="utf-8")
        return p

    def test_package_json_agpl_is_strong_copyleft(self):
        p = self._write("package.json", '{"name":"x","license":"AGPL-3.0"}')
        self.assertEqual([f.rule_id for f in _check_license(p, self.target)], ["license.strong-copyleft"])

    def test_package_json_mit_is_clean(self):
        p = self._write("package.json", '{"name":"x","license":"MIT"}')
        self.assertEqual(_check_license(p, self.target), [])

    def test_license_file_lgpl_is_weak_copyleft(self):
        p = self._write("LICENSE", "GNU LESSER GENERAL PUBLIC LICENSE Version 2.1")
        self.assertEqual([f.rule_id for f in _check_license(p, self.target)], ["license.weak-copyleft"])

    def test_pyproject_gpl3(self):
        p = self._write("pyproject.toml", 'license = "GPL-3.0-or-later"')
        self.assertEqual([f.rule_id for f in _check_license(p, self.target)], ["license.strong-copyleft"])


if __name__ == "__main__":
    unittest.main()
