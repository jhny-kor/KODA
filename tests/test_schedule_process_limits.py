import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import time
import unittest


class ScheduleProcessLimitsTests(unittest.TestCase):
    def test_worker_or_analyzer_death_stops_entire_analysis_group(self):
        analyzer = """
import json, os, subprocess, sys, time
from security_scanner.process_limits import bind_parent_lifetime
bind_parent_lifetime(int(sys.argv[1]))
child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])
print(json.dumps({'analyzer': os.getpid(), 'tool': child.pid}), flush=True)
time.sleep(60)
"""
        parent_code = """
import os, subprocess, sys, time
subprocess.Popen([sys.executable, '-c', sys.argv[1], str(os.getpid())], start_new_session=True)
time.sleep(60)
"""
        for kill_worker in (True, False):
            with self.subTest(kill_worker=kill_worker):
                parent = subprocess.Popen([sys.executable, '-c', parent_code, analyzer], stdout=subprocess.PIPE, text=True)
                pids = {}
                try:
                    self.assertTrue(select.select([parent.stdout], [], [], 5)[0], 'analyzer ready')
                    pids = json.loads(parent.stdout.readline())
                    os.kill(parent.pid if kill_worker else pids['analyzer'], signal.SIGKILL)
                    if kill_worker:
                        parent.wait(timeout=5)
                    deadline = time.monotonic() + 5
                    while time.monotonic() < deadline:
                        running = []
                        for pid in pids.values():
                            if sys.platform == 'linux':
                                try:
                                    state = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[0]
                                except FileNotFoundError:
                                    state = ''
                            else:
                                state = subprocess.run(['ps', '-o', 'stat=', '-p', str(pid)], capture_output=True, text=True).stdout.strip()
                            if state and not state.startswith('Z'):
                                running.append(pid)
                        if not running:
                            break
                        time.sleep(.05)
                    self.assertEqual(running, [])
                finally:
                    if parent.poll() is None:
                        parent.kill()
                    parent.wait(timeout=5)
                    if pids:
                        try:
                            os.killpg(pids['analyzer'], signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                    parent.stdout.close()

    @unittest.skipUnless(sys.platform == 'linux', 'Linux deployment limits')
    def test_cpu_and_memory_limits_in_isolated_process(self):
        code = """
import json, os, resource
from security_scanner.process_limits import apply_limits
actual = apply_limits({'cpus': 1, 'memory_bytes': 512 * 1024**2})
assert len(os.sched_getaffinity(0)) == 1
assert resource.getrlimit(resource.RLIMIT_AS)[0] == 512 * 1024**2
try:
    x = bytearray(600 * 1024**2)
except MemoryError:
    print(json.dumps(actual))
else:
    raise AssertionError('allocation exceeded configured memory')
"""
        result = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout)['enforced'])
