import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from security_scanner.data_release import grype_cache_dir, pinned_release, release_metadata


class DataReleaseTest(unittest.TestCase):
    def test_scan_keeps_old_release_when_current_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("one", "two"):
                release = root / "releases" / name
                release.mkdir(parents=True)
                (release / "metadata.env").write_text(f"BUNDLE_VERSION={name}\n")
            (root / "current").symlink_to("releases/one")
            with patch.dict(os.environ, KODA_VULN_DATA_ROOT=str(root)):
                with pinned_release():
                    (root / "next").symlink_to("releases/two")
                    (root / "next").replace(root / "current")
                    self.assertEqual(release_metadata()["BUNDLE_VERSION"], "one")
                    self.assertEqual(grype_cache_dir(), root.resolve() / "releases/one/grype-db")
                with pinned_release():
                    self.assertEqual(release_metadata()["BUNDLE_VERSION"], "two")
            self.assertIsNone(grype_cache_dir())

    def test_configured_missing_release_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, KODA_VULN_DATA_ROOT=directory):
            with self.assertRaises(FileNotFoundError), pinned_release():
                self.fail("missing data must not fall back to bundled DB")


if __name__ == "__main__":
    unittest.main()
