from __future__ import annotations

import selectors
import subprocess
import sys
import time
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "platforms" / "shared" / "python"))

from security_scanner import syft_adapter


class WindowsSocketOnlySelector(selectors.SelectSelector):
    def select(self, timeout=None):
        raise OSError(10038, "An operation was attempted on something that is not a socket")


class SyftProcessTests(unittest.TestCase):
    def run_child(self, source: str, timeout: float = 3.0):
        processes = []
        popen = subprocess.Popen

        def capture(*args, **kwargs):
            process = popen(*args, **kwargs)
            processes.append(process)
            return process

        with patch.object(syft_adapter.subprocess, "Popen", side_effect=capture):
            result = syft_adapter._run(Path(sys.executable), ("-c", source), timeout, {})
        self.assertEqual(len(processes), 1)
        self.assertIsNotNone(processes[0].poll(), "external process must be reaped")
        return result

    def test_process_pipes_work_under_windows_socket_only_selector_contract(self):
        with patch.object(selectors, "DefaultSelector", WindowsSocketOnlySelector):
            result = self.run_child("import os; os.write(1, b'stdout\\n'); os.write(2, b'stderr\\n')")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "stdout\n")
        self.assertEqual(result.stderr, "stderr\n")

    def test_both_streams_larger_than_pipe_capacity_are_drained_and_decoded(self):
        result = self.run_child(
            "import os; os.write(1, ('한글' * 40000).encode()); "
            "os.write(2, ('오류' * 40000).encode()); raise SystemExit(7)"
        )
        self.assertEqual(result.returncode, 7)
        self.assertEqual(result.stdout, "한글" * 40000)
        self.assertEqual(result.stderr, "오류" * 40000)

    def test_stdout_and_stderr_limits_stop_and_reap_the_process(self):
        for descriptor, limit_name in ((1, "MAX_SYFT_STDOUT_BYTES"), (2, "MAX_SYFT_STDERR_BYTES")):
            with self.subTest(descriptor=descriptor), patch.object(syft_adapter, limit_name, 1024):
                result = self.run_child(f"import os, time; os.write({descriptor}, b'x' * 2048); time.sleep(20)", 0.5)
                self.assertEqual(result.returncode, 125)
                self.assertIn("byte limit exceeded", result.stderr)

    def test_exact_output_limit_is_allowed(self):
        with patch.object(syft_adapter, "MAX_SYFT_STDOUT_BYTES", 1024):
            result = self.run_child("import os; os.write(1, b'x' * 1024)")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "x" * 1024)

    def test_timeout_includes_wait_after_both_output_pipes_close(self):
        started = time.monotonic()
        result = self.run_child("import os, time; os.close(1); os.close(2); time.sleep(2)", 0.1)
        self.assertEqual(result.returncode, 124)
        self.assertLess(time.monotonic() - started, 1.5)

    def test_timeout_stops_process_with_open_output_pipes(self):
        result = self.run_child("import time; time.sleep(20)", 0.1)
        self.assertEqual(result.returncode, 124)


if __name__ == "__main__":
    unittest.main()
