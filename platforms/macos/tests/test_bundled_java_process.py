"""Exercise the production Java process runner with real, bounded child processes."""

import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
import unittest


SOURCE = Path(__file__).parents[1] / "app/KODA/KODA/BundledJavaArchiveScanner.swift"


class BundledJavaProcessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workspace = tempfile.TemporaryDirectory(prefix="koda-java-process-tests-")
        cls.root = Path(cls.workspace.name)
        # Appending an extension in the same file exposes the actual private runner;
        # no substitute process implementation is tested.
        harness = cls.root / "JavaProcessHarness.swift"
        source = SOURCE.read_text()
        harness.write_text(source + r'''
enum AppLanguage: String { case ko, en }
extension BundledJavaArchiveScanner {
    static func testRun() throws -> [String: Any] {
        let result = try run(executable: URL(fileURLWithPath: CommandLine.arguments[1]),
                             arguments: Array(CommandLine.arguments.dropFirst(3)),
                             environment: [:], timeout: Double(CommandLine.arguments[2])!)
        return ["exit": result.exitCode, "stdout": result.stdout, "stderr": result.stderr]
    }
}
@main struct Harness {
    static func main() throws {
        let value: [String: Any]
        do { value = try BundledJavaArchiveScanner.testRun() }
        catch { value = ["error": error.localizedDescription] }
        print(String(data: try JSONSerialization.data(withJSONObject: value), encoding: .utf8)!)
    }
}
''')
        cls.binary = cls.root / "java-process-harness"
        subprocess.run(["swiftc", "-parse-as-library", str(harness), "-o", str(cls.binary)], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.workspace.cleanup()

    def run_child(self, program, timeout=6, child_timeout=5):
        process = subprocess.Popen([str(self.binary), "/usr/bin/python3", str(child_timeout), "-c", program],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, start_new_session=True)
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate()
            self.fail("production Java runner did not complete within its bound")
        self.assertEqual(process.returncode, 0, stderr)
        return json.loads(stdout)

    def test_large_stdout_and_stderr_are_drained(self):
        result = self.run_child("import os; "
                                "[(os.write(1,b'o'*65536),os.write(2,b'e'*65536)) for _ in range(16)]")
        self.assertEqual(result["exit"], 0)
        self.assertEqual(result["stdout"], "o" * 1048576)
        self.assertEqual(result["stderr"], "e" * 1048576)

    def test_failure_exit_code_and_diagnostics_are_preserved(self):
        result = self.run_child("import sys; print('partial'); print('failed',file=sys.stderr); sys.exit(7)")
        self.assertEqual(result, {"exit": 7, "stdout": "partial\n", "stderr": "failed\n"})

    def test_timeout_terminates_an_unresponsive_child(self):
        marker = self.root / "child.pid"
        started = time.monotonic()
        try:
            result = self.run_child("import os,signal,time; "
                                    "signal.signal(signal.SIGTERM,signal.SIG_IGN); "
                                    f"open({str(marker)!r},'w').write(str(os.getpid())); time.sleep(30)",
                                    child_timeout=0.25)
            self.assertIn("timed out", result.get("error", "").lower())
            self.assertLess(time.monotonic() - started, 5)
            with self.assertRaises(ProcessLookupError):
                os.kill(int(marker.read_text()), 0)
        finally:
            if marker.exists():
                try:
                    os.kill(int(marker.read_text()), signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def test_missing_executable_reports_failure(self):
        result = subprocess.run([str(self.binary), str(self.root / "missing-executable"), "5"],
                                check=True, capture_output=True, text=True, timeout=5)
        self.assertTrue(json.loads(result.stdout)["error"])


if __name__ == "__main__":
    unittest.main()
