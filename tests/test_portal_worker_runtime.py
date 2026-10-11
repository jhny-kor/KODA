"""Behavioral regression contracts for portal workspaces and isolated workers."""
from concurrent.futures import ThreadPoolExecutor
import json
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid
import zipfile
from pathlib import Path
from unittest.mock import Mock, patch

from security_scanner.linux_portal import _run_scan
from security_scanner.portal_store import PortalStore


class PortalWorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.store = PortalStore(self.root / 'portal.sqlite3')
        self.actor = str(uuid.uuid4())
        self.store.bootstrap(self.actor)
        self.project = self.store.create_project('workspace')
        self.store.set_membership(self.project, self.actor, 'admin')
        (self.root / 'inputs').mkdir()

    def run_input(self, archive=True):
        source = self.root / 'inputs' / (uuid.uuid4().hex + ('.zip' if archive else '.py'))
        if archive:
            with zipfile.ZipFile(source, 'w') as output:
                output.writestr('sample.py', 'print(1)\n')
        else:
            source.write_text('print(1)\n')
        input_id = self.store.add_input(self.project, source.name, source)
        return self.store.create_scan(self.actor, self.project, input_id, 'local', 'all', 'source')

    def test_archive_workspace_is_removed_after_success_and_failure(self):
        for failed in (False, True):
            run = self.run_input()
            def analyze(target, **options):
                self.assertTrue((Path(target) / 'sample.py').is_file())
                self.assertEqual(len(list((self.root / 'work').glob('koda-portal-*'))), 1)
                if failed:
                    raise RuntimeError('fixture analyzer failure')
                return {'findings_by_language': {'ko': []}}
            with patch('security_scanner.server.scan_directory_payload', side_effect=analyze):
                _run_scan(self.store, run['run_id'])
            self.assertEqual(list((self.root / 'work').glob('koda-portal-*')), [])
            self.assertEqual(self.store.run(run['run_id'])['status'], 'failed' if failed else 'completed')

    def test_plain_file_does_not_create_extraction_workspace(self):
        run = self.run_input(archive=False)
        def analyze(target, **options):
            self.assertFalse((self.root / 'work').exists())
            return {'findings_by_language': {'ko': []}}
        with patch('security_scanner.server.scan_directory_payload', side_effect=analyze):
            _run_scan(self.store, run['run_id'])
        self.assertEqual(self.store.run(run['run_id'])['status'], 'completed')

    def test_recovery_removes_orphan_but_preserves_live_lock_and_symlink(self):
        from security_scanner.portal_workspace import extraction_workspace, cleanup_workspaces
        root = self.root / 'work'
        root.mkdir()
        orphan = root / 'koda-portal-legacy123'
        orphan.mkdir()
        (orphan / 'source.txt').write_text('orphan')
        outside = self.root / 'outside'
        outside.mkdir()
        (outside / 'preserve.txt').write_text('preserve')
        (root / 'koda-portal-link').symlink_to(outside, target_is_directory=True)
        with extraction_workspace(root, str(uuid.uuid4())) as active:
            cleanup_workspaces(root)
            self.assertTrue(Path(active).is_dir())
            self.assertFalse(orphan.exists())
            self.assertTrue((outside / 'preserve.txt').exists())
        self.assertEqual([p for p in root.iterdir() if not p.is_symlink()], [])


class PortalSupervisorTests(unittest.TestCase):
    setUp = PortalWorkspaceTests.setUp
    run_input = PortalWorkspaceTests.run_input

    def wait_for(self, predicate):
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(.05)
        self.fail('isolated analyzer did not reach expected state')

    def sleeper(self, run_id):
        # This fixture creates a real extraction workspace and a grandchild.
        # The supervisor must terminate the process group before cleanup.
        source = '''import json, os, subprocess, sys, time
from pathlib import Path
from security_scanner.process_limits import bind_parent_lifetime
from security_scanner.portal_workspace import extraction_workspace
bind_parent_lifetime(int(sys.argv[3]))
with extraction_workspace(Path(sys.argv[1])/"work", sys.argv[2]) as root:
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    (root/"source.txt").write_text("fixture")
    (Path(sys.argv[1])/"child.json").write_text(json.dumps({"pid": os.getpid(), "child": child.pid}))
    time.sleep(60)
'''
        return [sys.executable, '-c', source, str(self.root), run_id, str(os.getpid())]

    def test_actual_child_scan_completes_and_keeps_results(self):
        from security_scanner.portal_worker import ScanSupervisor
        run = self.run_input()
        self.assertTrue(ScanSupervisor(self.store, timeout=20).execute(run['run_id']))
        result = self.store.run(run['run_id'])
        self.assertEqual(result['status'], 'completed', result.get('error'))
        self.assertIsInstance(result['result'], dict)
        self.assertEqual(list((self.root / 'work').glob('koda-portal-*')), [])

    def test_cancel_stops_real_process_group_and_cleans_work(self):
        from security_scanner.portal_worker import ScanSupervisor
        run = self.run_input()
        supervisor = ScanSupervisor(self.store, timeout=20, grace=.2, command_factory=self.sleeper)
        thread = threading.Thread(target=supervisor.execute, args=(run['run_id'],))
        thread.start()
        try:
            self.wait_for(lambda: (self.root / 'child.json').exists())
            self.store.request_cancel(run['run_id'], actor=self.actor)
            thread.join(timeout=4)
            self.assertFalse(thread.is_alive())
            self.assertEqual(self.store.run(run['run_id'])['status'], 'cancelled')
            self.assertEqual(list((self.root / 'work').glob('koda-portal-*')), [])
            child = json.loads((self.root / 'child.json').read_text())['child']
            status = subprocess.run(['ps', '-o', 'stat=', '-p', str(child)], capture_output=True, text=True).stdout.strip()
            self.assertTrue(not status or status.startswith('Z'), status)
        finally:
            supervisor.stop_event.set()
            thread.join(timeout=4)

    def test_timeout_records_failure_and_removes_workspace(self):
        from security_scanner.portal_worker import ScanSupervisor
        run = self.run_input()
        ScanSupervisor(self.store, timeout=.7, grace=.1, command_factory=self.sleeper).execute(run['run_id'])
        row = self.store.run(run['run_id'])
        self.assertEqual(row['status'], 'failed')
        self.assertEqual(row['error'], 'timeout')
        self.assertEqual(list((self.root / 'work').glob('koda-portal-*')), [])

    def test_preparation_failure_records_terminal_failure(self):
        from security_scanner.portal_worker import ScanSupervisor
        run = self.run_input()
        def broken_command(run_id):
            raise OSError('fixture command unavailable')
        self.assertTrue(ScanSupervisor(self.store, command_factory=broken_command).execute(run['run_id']))
        row = self.store.run(run['run_id'])
        self.assertEqual(row['status'], 'failed')
        self.assertIn('fixture command unavailable', row['error'])

    def test_cleanup_failure_stops_the_execution_owner(self):
        from security_scanner.portal_worker import ScanSupervisor
        run = self.run_input()
        with patch('security_scanner.portal_worker.cleanup_workspaces', return_value=['fixture permission error']):
            with self.assertRaisesRegex(OSError, 'workspace cleanup incomplete'):
                ScanSupervisor(self.store, timeout=10).execute(run['run_id'])
        self.assertEqual(self.store.run_status(run['run_id'])['status'], 'completed')
        self.assertIn('scan.workspace_cleanup_failed', {row['action'] for row in self.store.audit_events(None)})

    def test_termination_permission_race_requires_exited_leader_and_absent_group(self):
        from security_scanner.portal_worker import terminate_group
        process = Mock(pid=12345)
        process.poll.return_value = 0
        with patch('security_scanner.portal_worker.os.killpg', side_effect=[
            PermissionError('fixture termination race'), ProcessLookupError(), ProcessLookupError(),
        ]) as kill:
            terminate_group(process, grace=.1)
        self.assertEqual([call.args for call in kill.call_args_list], [
            (process.pid, signal.SIGTERM), (process.pid, 0), (process.pid, signal.SIGKILL),
        ])
        self.assertEqual(process.wait.call_count, 2)

    def test_termination_permission_error_is_not_ignored_for_live_or_existing_group(self):
        from security_scanner.portal_worker import terminate_group
        for returncode in (None, 0):
            with self.subTest(returncode=returncode):
                process = Mock(pid=12345)
                process.poll.return_value = returncode
                with patch('security_scanner.portal_worker.os.killpg', side_effect=[
                    PermissionError('fixture live group'), None,
                ]):
                    with self.assertRaises(PermissionError):
                        terminate_group(process, grace=.1)
                process.wait.assert_not_called()

    def test_unconfirmed_termination_stops_owner_and_preserves_workspace_for_recovery(self):
        from security_scanner.portal_worker import ScanSupervisor
        run = self.run_input()
        process = Mock(pid=12345, returncode=0)
        process.poll.return_value = 0
        supervisor = ScanSupervisor(self.store)
        with patch('security_scanner.portal_worker.subprocess.Popen', return_value=process), \
                patch('security_scanner.portal_worker.os.killpg', side_effect=PermissionError('fixture live group')), \
                patch('security_scanner.portal_worker.cleanup_workspaces') as cleanup:
            with self.assertRaisesRegex(OSError, 'analyzer termination incomplete'):
                supervisor.execute(run['run_id'])
            cleanup.assert_not_called()
        self.assertTrue(supervisor.stop_event.is_set())
        row = self.store.run(run['run_id'])
        self.assertEqual(row['status'], 'running')
        self.assertIn('termination failed', row['error'])
        self.assertTrue(Path(self.store.input(run['input_id'])['path']).exists())
        self.assertIn('scan.termination_failed', {row['action'] for row in self.store.audit_events(None)})
        next_run = self.run_input()
        self.assertFalse(supervisor.execute(next_run['run_id']))
        self.assertEqual(self.store.run_status(next_run['run_id'])['status'], 'queued')

    def test_shutdown_requeues_and_preserves_original_for_restart(self):
        from security_scanner.portal_worker import ScanSupervisor
        run = self.run_input()
        event = threading.Event()
        supervisor = ScanSupervisor(self.store, event, timeout=20, grace=.1, command_factory=self.sleeper)
        thread = threading.Thread(target=supervisor.execute, args=(run['run_id'],))
        thread.start()
        self.wait_for(lambda: (self.root / 'child.json').exists())
        event.set()
        thread.join(timeout=4)
        self.assertFalse(thread.is_alive())
        self.assertEqual(self.store.run(run['run_id'])['status'], 'queued')
        self.assertTrue(Path(self.store.input(run['input_id'])['path']).exists())

    def test_external_web_availability_uses_fresh_worker_heartbeat(self):
        from security_scanner.portal_worker import ExternalWorkerProxy, write_heartbeat
        proxy = ExternalWorkerProxy(self.store)
        self.assertFalse(proxy.available)
        write_heartbeat(self.store, 'scan')
        self.assertTrue(proxy.available)
        write_heartbeat(self.store, 'scan', ready=False)
        self.assertFalse(proxy.available)

    def test_healthcheck_does_not_open_or_migrate_database(self):
        from security_scanner import portal_worker
        portal_worker.write_heartbeat(self.store, 'scan')
        with patch.object(portal_worker.PortalStore, '__init__', side_effect=AssertionError('healthcheck opened database')):
            self.assertEqual(portal_worker.main(['--db', self.store.path, '--healthcheck']), 0)

    def test_delivery_requests_survive_reopening_and_do_not_repeat_acknowledged_work(self):
        from security_scanner.portal_worker import enqueue_delivery, next_publication, process_publication
        run = self.run_input()
        self.store.mark_run_running(run['run_id'])
        self.store.complete_run(run['run_id'], result={'findings': []})
        with self.store._db() as db:
            db.execute("INSERT INTO tracker_deliveries(run_id,status,attempts,created_at,updated_at) VALUES(?,'failed',1,'now','now')", (run['run_id'],))
        job = enqueue_delivery(self.store, 'tracker', run['run_id'], retry=True)
        self.assertEqual(job, enqueue_delivery(self.store, 'tracker', run['run_id'], retry=True))
        other = PortalStore(self.store.path)
        task = next_publication(other)
        self.assertEqual(task[:3], ('tracker', run['run_id'], True))
        with self.store._db() as db:
            db.execute("UPDATE tracker_deliveries SET status='completed' WHERE run_id=?", (run['run_id'],))
        with patch('security_scanner.linux_portal._run_delivery') as deliver:
            process_publication(other, task)
            deliver.assert_not_called()
        with other._db() as db:
            self.assertEqual(db.execute('SELECT status FROM portal_delivery_jobs WHERE job_id=?', (job['job_id'],)).fetchone()[0], 'completed')

    def test_failed_publication_response_keeps_durable_job_failed(self):
        from security_scanner.portal_worker import enqueue_delivery, next_publication, process_publication
        run = self.run_input()
        self.store.complete_run(run['run_id'], result={'findings': []})
        with self.store._db() as db:
            db.execute("INSERT INTO tracker_deliveries(run_id,status,attempts,created_at,updated_at) VALUES(?,'failed',1,'now','now')", (run['run_id'],))
        job = enqueue_delivery(self.store, 'tracker', run['run_id'], retry=True)
        with patch('security_scanner.linux_portal._run_delivery', return_value={'status': 'failed', 'error': 'remote unavailable'}):
            process_publication(self.store, next_publication(self.store))
        with self.store._db() as db:
            saved = db.execute('SELECT status,error FROM portal_delivery_jobs WHERE job_id=?', (job['job_id'],)).fetchone()
        self.assertEqual((saved['status'], saved['error']), ('failed', 'remote unavailable'))

    def test_delivery_role_runs_schedule_publications_outside_web(self):
        from security_scanner.linux_portal import _PortalWorker
        called = threading.Event()
        with patch('security_scanner.portal_worker.process_scheduled_publications', side_effect=lambda _: called.set()):
            worker = _PortalWorker(self.store, role='delivery', isolated=True)
            try:
                self.assertTrue(called.wait(3))
            finally:
                worker.close()
        self.assertFalse(worker.available)


class PortalExternalHttpTests(unittest.TestCase):
    def test_cpu_busy_analyzer_keeps_http_and_cancel_responsive(self):
        import test_linux_portal as fixtures
        from security_scanner.portal_worker import ScanSupervisor, write_heartbeat
        fixture = fixtures.LinuxPortalHttpTests()
        with patch.dict(os.environ, {'KODA_PORTAL_EXTERNAL_WORKER': '1'}):
            fixture.setUp()
        self.addCleanup(fixture.tearDown)
        store = fixture.server.portal_store
        project = store.create_project('busy worker', fixture.admin)
        source = Path(fixture.tmp.name) / 'inputs' / 'busy.py'
        source.write_text('print(1)\n')
        input_id = store.add_input(project, source.name, source, fixture.admin)
        run = store.create_scan(fixture.admin, project, input_id, 'local', 'all', 'source')
        write_heartbeat(store, 'scan')
        started = Path(fixture.tmp.name) / 'started'
        script = 'from pathlib import Path; import sys; Path(sys.argv[1]).write_text("ready")\nwhile True: pass'
        supervisor = ScanSupervisor(store, timeout=10, grace=.1,
                                    command_factory=lambda _: [sys.executable, '-c', script, str(started)])
        thread = threading.Thread(target=supervisor.execute, args=(run['run_id'],))
        thread.start()
        try:
            deadline = time.monotonic() + 5
            while not started.exists() and time.monotonic() < deadline:
                time.sleep(.01)
            self.assertTrue(started.exists())
            endpoints = ['/koda/', f'/koda/api/v1/runs/{run["run_id"]}/status'] * 6
            def fetch(endpoint):
                before = time.monotonic()
                status, _ = fixture.request(endpoint, headers=fixture.headers())
                return status, time.monotonic() - before
            with ThreadPoolExecutor(max_workers=4) as pool:
                results = list(pool.map(fetch, endpoints))
            self.assertTrue(all(status == 200 for status, _ in results))
            self.assertLess(max(elapsed for _, elapsed in results), 2)
            before = time.monotonic()
            status, _ = fixture.request(f'/koda/api/v1/runs/{run["run_id"]}/cancel',
                                        method='POST', payload={}, headers=fixture.headers())
            self.assertEqual(status, 200)
            thread.join(4)
            self.assertFalse(thread.is_alive())
            self.assertLess(time.monotonic() - before, 4)
            self.assertEqual(store.run_status(run['run_id'])['status'], 'cancelled')
        finally:
            supervisor.stop_event.set()
            thread.join(4)


if __name__ == '__main__':
    unittest.main()
