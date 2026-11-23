from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "platforms/shared/python"))
from security_scanner.desktop_projects import project_action, record_score
from security_scanner.server import scan_directory_payload


class DesktopProjectTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        environment = patch.dict(os.environ, LOCALAPPDATA=str(self.root / "app-data"))
        environment.start()
        self.addCleanup(environment.stop)
        self.project = self.root / "src"
        self.project.mkdir()
        self.file = self.root / "sample.py"
        self.file.write_text("print('sample')\n")

    def test_profile_persists_file_and_folder_skips_missing_target_and_deletes(self):
        paths = [str(self.file), str(self.project)]
        save = {"action": "save", "paths": paths}
        project_action(save)
        result = project_action(save)
        self.assertEqual(len(result["profiles"]), 1)
        profile_id = result["profiles"][0]["id"]
        self.file.unlink()
        loaded = project_action({"action": "load", "id": profile_id})
        self.assertEqual(loaded, {"paths": paths[1:], "missing": 1})
        project_action({"action": "delete", "id": profile_id})
        self.assertEqual(project_action({"action": "list"})["profiles"], [])

    def test_multi_target_scan_preserves_report_scores_and_sarif_state(self):
        sarif = self.root / "external.sarif"
        sarif.write_text(json.dumps({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "External"}}, "results": []}]}))
        for expected in ("SUCCESS", "FAILED"):
            report = scan_directory_payload(str(self.file), additional_paths=(str(self.project),),
                                            allow_file=True, source_analyzer_sarif=sarif)
            self.assertEqual(report["summary"]["target_count"], 2)
            self.assertEqual(report["source_analysis"]["analyzer_runs"][0]["status"], expected)
            record_score(report, [str(self.file), str(self.project)])
            sarif.write_text("not json")
        history = project_action({"action": "list"})["history"]
        self.assertEqual(len(history), 2)
        self.assertEqual(history[0]["score"], report["summary"]["risk_score"])
        self.assertEqual(history[0]["severity"], report["summary"]["by_severity"])
        self.assertEqual(history[0]["count"], report["summary"]["displayed_finding_count"])
        self.assertEqual(project_action({"action": "clear-history"})["history"], [])
