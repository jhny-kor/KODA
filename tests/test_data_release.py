import os
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from security_scanner.data_release import grype_cache_dir, pinned_release, release_metadata, vulnerability_paths


class DataReleaseTest(unittest.TestCase):
    def setUp(self):
        proof = patch("security_scanner.approved_release.verify_approved_release")
        proof.start(); self.addCleanup(proof.stop)

    def test_scan_keeps_old_release_when_current_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("one", "two"):
                release = root / "releases" / name
                release.mkdir(parents=True)
                (release / "metadata.env").write_text(f"BUNDLE_VERSION={name}\n")
            (root / "current").symlink_to("releases/one")
            (root / ".release.lock").write_text("")
            (root / ".managed.json").write_text(json.dumps({"format":"koda-managed-vulnerability-data-v1","state":"active","currentVersion":"one"}))
            with patch.dict(os.environ, KODA_VULN_DATA_ROOT=str(root)):
                with pinned_release():
                    (root / "next").symlink_to("releases/two")
                    (root / "next").replace(root / "current")
                    (root / ".managed.json").write_text(json.dumps({"format":"koda-managed-vulnerability-data-v1","state":"active","currentVersion":"two"}))
                    self.assertEqual(release_metadata()["BUNDLE_VERSION"], "one")
                    self.assertEqual(grype_cache_dir(), root.resolve() / "releases/one/grype-db")
                with pinned_release():
                    self.assertEqual(release_metadata()["BUNDLE_VERSION"], "two")
            self.assertIsNone(grype_cache_dir())

    def test_configured_missing_release_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, KODA_VULN_DATA_ROOT=directory):
            with pinned_release():
                self.assertIsNone(grype_cache_dir())
                self.assertEqual(vulnerability_paths(), (None, None))
                self.assertEqual(release_metadata()["status"], "unavailable")


if __name__ == "__main__":
    unittest.main()
