import hashlib
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from security_scanner.schedule_transport import (
    OpenSSHCollector, RemoteFile, RemoteLimitError, RemotePermanentError, RemoteTransportError,
    _retryable_remote_error,
)


def child_popen(payload: bytes, *, exit_code: int = 0):
    def factory(_command, **kwargs):
        code = "import sys;sys.stdout.buffer.write(%r);sys.stdout.flush();sys.exit(%d)" % (payload, exit_code)
        return __import__("subprocess").Popen([sys.executable, "-c", code], **kwargs)
    return factory


def script_popen(script: str):
    def factory(_command, **kwargs):
        return __import__("subprocess").Popen([sys.executable, "-c", script], **kwargs)
    return factory


def local_remote_shell(command, **kwargs):
    return subprocess.Popen(["/bin/sh", "-c", command[-1]], **kwargs)


def target(**extra):
    value = {
        "host": "example.test", "username": "readonly", "port": 22,
        "ssh_key_ref": "/keys/id_ed25519", "known_hosts_file": "/keys/known_hosts",
        "remote_directory": "/srv/app", "timeout_seconds": 5,
        "max_files": 200_000, "max_bytes": 1024,
    }
    value.update(extra)
    return value


class ScheduleTransportTests(unittest.TestCase):
    def test_manifest_is_streamed_and_bounded(self):
        payload = b"a.txt\t1\t1.0\n" + b"x" * 5000
        collector = OpenSSHCollector(popen=child_popen(payload))
        with self.assertRaises(RemoteLimitError):
            collector.list_files(target(manifest_max_bytes=4096))

    def test_manifest_file_count_limit(self):
        payload = b"a\t1\t1\n" + b"b\t1\t1\n"
        collector = OpenSSHCollector(popen=child_popen(payload))
        with self.assertRaises(RemoteLimitError):
            collector.list_files(target(max_files=1))

    def test_transfer_stops_and_removes_partial_file_on_overflow(self):
        collector = OpenSSHCollector(popen=child_popen(b"0123456789"))
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "copy"
            with self.assertRaises(RemoteLimitError):
                collector.fetch(target(), RemoteFile("a.txt", 4, 1), destination)
            self.assertFalse(destination.exists())

    def test_disconnect_and_permanent_errors_are_classified(self):
        collector = OpenSSHCollector(popen=child_popen(b"", exit_code=7))
        with self.assertRaises(RemoteTransportError):
            collector.fetch(target(), RemoteFile("a.txt", 0, 1), Path(tempfile.gettempdir()) / "koda-nope")
        self.assertFalse(_retryable_remote_error(RuntimeError("Permission denied")))
        self.assertTrue(_retryable_remote_error(RuntimeError("Connection reset")))

    def test_remote_path_and_account_are_rejected_before_process_start(self):
        def unexpected_process(*args, **kwargs):
            self.fail("invalid settings reached SSH")

        collector = OpenSSHCollector(popen=unexpected_process)
        with self.assertRaises(ValueError):
            collector.list_files(target(username="bad;id"))
        with self.assertRaises(ValueError):
            collector.list_files(target(remote_directory="/srv/../app"))
        with self.assertRaises(RemoteTransportError):
            collector.fetch(target(), RemoteFile("../secret", 0, 1), Path("/tmp/nope"))

    def test_stderr_flood_does_not_deadlock_manifest(self):
        script = "import sys;sys.stderr.write('x'*300000);sys.stderr.flush();sys.stdout.write('a.txt\\t1\\t1\\n')"
        files = OpenSSHCollector(popen=script_popen(script)).list_files(target())
        self.assertEqual([item.relative_path for item in files], ["a.txt"])

    def test_slow_stream_is_stopped_by_deadline(self):
        script = "import sys,time;[ (sys.stdout.write('x'),sys.stdout.flush(),time.sleep(.2)) for _ in range(10) ]"
        started = time.monotonic()
        with self.assertRaises(TimeoutError):
            OpenSSHCollector(popen=script_popen(script)).fetch(
                target(timeout_seconds=1), RemoteFile("a.txt", 10, 1), Path(tempfile.gettempdir()) / "koda-slow")
        self.assertLess(time.monotonic() - started, 2.5)

    def test_remote_helper_lists_and_fetches_literal_paths_and_prunes_excludes(self):
        collector = OpenSSHCollector(popen=local_remote_shell)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve() / "checkout [one]'s"
            source = root / "src" / "파일 one's.py"
            source.parent.mkdir(parents=True)
            source.write_bytes(b"print('sample')\n")
            for name in ("build", "vendor-1"):
                ignored = root / name
                ignored.mkdir()
                (ignored / "unsupported\tname").touch()
            settings = target(remote_directory=str(root) + "/./", exclude_paths=["build", "vendor-*"])
            files = collector.list_files(settings)
            self.assertEqual([item.relative_path for item in files], ["src/파일 one's.py"])
            self.assertEqual(files[0].mtime, source.stat().st_mtime)
            destination = root.parent / "copy"
            digest = collector.fetch(settings, files[0], destination)
            self.assertEqual(destination.read_bytes(), source.read_bytes())
            self.assertEqual(digest, hashlib.sha256(source.read_bytes()).hexdigest())

    def test_remote_helper_skips_links_and_accepts_only_regular_fetches(self):
        collector = OpenSSHCollector(popen=local_remote_shell)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve() / "checkout"
            source = root / "src" / "data.txt"
            source.parent.mkdir(parents=True)
            source.write_text("sample", encoding="utf-8")
            (root / "alias.txt").symlink_to(source)
            (root / "alias-dir").symlink_to(source.parent, target_is_directory=True)
            os.mkfifo(root / "pipe")
            settings = target(remote_directory=str(root))
            self.assertEqual([item.relative_path for item in collector.list_files(settings)], ["src/data.txt"])
            destination = root.parent / "copy"
            for name in ("alias.txt", "alias-dir/data.txt", "src", "pipe"):
                with self.subTest(name=name):
                    with self.assertRaises(RemotePermanentError):
                        collector.fetch(settings, RemoteFile(name, 0, 0), destination)
                    self.assertFalse(destination.exists())

    def test_remote_helper_rejects_a_link_in_the_configured_root(self):
        collector = OpenSSHCollector(popen=local_remote_shell)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source = root / "checkout" / "src"
            source.mkdir(parents=True)
            (root / "alias").symlink_to(source.parent, target_is_directory=True)
            for path in (root / "alias", root / "alias" / "src"):
                with self.subTest(path=path):
                    settings = target(remote_directory=str(path))
                    with self.assertRaises(RemotePermanentError):
                        collector.list_files(settings)

    def test_remote_helper_reports_missing_python(self):
        with tempfile.TemporaryDirectory() as directory:
            def no_python(command, **kwargs):
                return local_remote_shell(command, env={**os.environ, "PATH": directory}, **kwargs)

            collector = OpenSSHCollector(popen=no_python)
            with self.assertRaisesRegex(RemotePermanentError, "requires Python 3.7 or later"):
                collector.list_files(target())

    def test_transfer_rate_is_enforced(self):
        started = time.monotonic()
        destination = Path(tempfile.gettempdir()) / "koda-rate"
        try:
            digest = OpenSSHCollector(popen=child_popen(b"x" * 100)).fetch(
                target(transfer_rate_bytes_per_sec=1000), RemoteFile("a.txt", 100, 1), destination)
            self.assertEqual(len(digest), 64)
            self.assertGreaterEqual(time.monotonic() - started, .08)
        finally:
            destination.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
