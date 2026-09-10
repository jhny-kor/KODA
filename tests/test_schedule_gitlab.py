import io
import hashlib
import tarfile
import tempfile
import unittest
import urllib.error
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import patch

from security_scanner.schedule_gitlab import GitLabCollector


class _Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def _archive():
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for name, content in (("repo-main/app/a.py", b"print(1)"),
                              ("repo-main/secret.txt", b"secret")):
            info = tarfile.TarInfo(name)
            info.size = len(content)
            info.mtime = 1700000000
            archive.addfile(info, io.BytesIO(content))
    return output.getvalue()


class GitLabCollectorTests(unittest.TestCase):
    def test_gitlab_status_classifies_transient_and_permanent_failures(self):
        from security_scanner.schedule_transport import _retryable_remote_error
        with tempfile.TemporaryDirectory() as directory:
            collector = GitLabCollector(SimpleNamespace(base_url="http://localhost", token="test"),
                                        {"schedule_run_id": "r", "lease_token": "l"}, cache_dir=Path(directory))
            for code, retry in ((403, False), (404, False), (429, True), (503, True)):
                error = urllib.error.HTTPError("http://localhost", code, "error", {}, None)
                with patch("security_scanner.schedule_gitlab._OPENER.open", side_effect=error):
                    with self.assertRaises(Exception) as caught:
                        collector.list_files({"max_bytes": 1024, "max_files": 10, "timeout_seconds": 30})
                self.assertEqual(_retryable_remote_error(caught.exception), retry)

    def test_lists_selected_directory_and_extracts_only_manifest_file(self):
        with tempfile.TemporaryDirectory() as directory:
            client = type("Client", (), {"base_url": "http://portal", "token": "x" * 32})()
            job = {"schedule_run_id": "run-1", "lease_token": "lease-1"}
            collector = GitLabCollector(client, job, cache_dir=Path(directory))
            with patch("security_scanner.schedule_gitlab._OPENER.open", return_value=_Response(_archive())):
                files = collector.list_files({
                    "source_kind": "gitlab", "source_gitlab_mapping_id": "map-1",
                    "source_gitlab_ref": "main", "source_gitlab_directory": "app",
                    "max_bytes": 1024, "max_files": 10, "timeout_seconds": 30,
                })
            self.assertEqual([item.relative_path for item in files], ["a.py"])
            self.assertEqual(collector.hashes["a.py"], hashlib.sha256(b"print(1)").hexdigest())
            target = Path(directory) / "files" / "a.py"
            digest = collector.fetch({"max_bytes": 1024}, files[0], target)
            self.assertEqual(target.read_bytes(), b"print(1)")
            self.assertEqual(len(digest), 64)

    def test_archive_size_limit_removes_partial_file(self):
        with tempfile.TemporaryDirectory() as directory:
            client = type("Client", (), {"base_url": "http://portal", "token": "x" * 32})()
            collector = GitLabCollector(client, {"schedule_run_id": "r", "lease_token": "l"}, cache_dir=Path(directory))
            with patch("security_scanner.schedule_gitlab._OPENER.open", return_value=_Response(_archive())):
                with self.assertRaises(Exception):
                    collector.list_files({"source_gitlab_mapping_id": "m", "source_gitlab_ref": "main",
                                          "max_bytes": 1, "max_files": 10, "timeout_seconds": 30})
            self.assertFalse((Path(directory) / "gitlab-source.tar.gz").exists())


if __name__ == "__main__":
    unittest.main()
