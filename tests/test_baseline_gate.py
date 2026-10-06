from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SHARED_PYTHON = ROOT / "platforms" / "shared" / "python"
if str(SHARED_PYTHON) not in sys.path:
    sys.path.insert(0, str(SHARED_PYTHON))

from security_scanner import cli
from security_scanner.models import Finding


def _f(rule_id: str, path: str, line: int | None) -> Finding:
    return Finding(rule_id=rule_id, category="code", severity="high", title=rule_id,
                   path=Path(path), target="t", line=line, evidence="e")


class NewFindingsGateTests(unittest.TestCase):
    def _baseline(self, items: list[dict]) -> Path:
        fd = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
        json.dump({"findings": items}, fd)
        fd.close()
        return Path(fd.name)

    def test_findings_in_baseline_are_filtered_out(self):
        findings = [_f("code.sqli", "a.py", 10), _f("code.xss", "b.py", 5)]
        baseline = self._baseline([
            {"rule_id": "code.sqli", "target": "t", "path": "a.py", "line": 10},
        ])
        new = cli._new_findings(findings, baseline)
        self.assertEqual([f.rule_id for f in new], ["code.xss"])

    def test_none_line_matches_baseline_null(self):
        findings = [_f("code.secret", "c.py", None)]
        baseline = self._baseline([{"rule_id": "code.secret", "target": "t", "path": "c.py", "line": None}])
        self.assertEqual(cli._new_findings(findings, baseline), [])

    def test_missing_baseline_file_suppresses_nothing(self):
        findings = [_f("code.sqli", "a.py", 1)]
        new = cli._new_findings(findings, Path("/nonexistent/baseline.json"))
        self.assertEqual(len(new), 1)


if __name__ == "__main__":
    unittest.main()
