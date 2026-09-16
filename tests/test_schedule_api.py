import datetime as dt
import hashlib
import json
import os
import tempfile
import threading
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

from security_scanner.linux_portal import create_portal_server
from security_scanner.schedule_api import (
    API_PREFIX, DEFAULT_JSON_BYTES, MAX_RESPONSE_BYTES, ScheduleApiClient, ScheduleApiError,
    authorize, configured_json_bytes,
)
from security_scanner.schedule_api_worker import ApiScheduleRunner
from security_scanner.schedule_settings import save_settings
from security_scanner.schedule_transport import RemoteFile


class Collector:
    def __init__(self):
        self.fetched = 0
    def list_files(self, target, **kwargs):
        return [RemoteFile('app.py', 9, 1)]
    def fetch(self, target, item, destination, **kwargs):
        self.fetched += 1
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(b'print(1)\n')


class ScheduleApiTests(unittest.TestCase):
    def test_json_limit_defaults_to_the_bounded_500_mib_ceiling(self):
        with patch.dict(os.environ, {"KODA_JSON_MAX_BYTES": ""}):
            self.assertEqual(configured_json_bytes(), 500 * 1024 * 1024)
        with patch.dict(os.environ, {"KODA_JSON_MAX_BYTES": str(600 * 1024 * 1024)}):
            self.assertEqual(configured_json_bytes(), MAX_RESPONSE_BYTES)
        self.assertEqual(DEFAULT_JSON_BYTES, MAX_RESPONSE_BYTES)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.auth = patch.dict(os.environ, {'KODA_SCHEDULE_API_TOKEN': 'a' * 40})
        self.auth.start()
        self.server = create_portal_server('127.0.0.1', 0, db_path=self.root / 'portal.sqlite3', input_dir=self.root / 'inputs')
        self.store = self.server.portal_store
        self.admin = str(uuid.uuid4())
        self.store.bootstrap(self.admin)
        self.project = self.store.create_project('schedule-api')
        self.store.set_membership(self.project, self.admin, 'admin')
        self.target = self.store.save_schedule_target({'project_id': self.project, 'name': 'read-only', 'host': 'example.internal', 'username': 'scan', 'ssh_key_ref': '/run/koda/ssh/key', 'known_hosts_file': '/run/koda/ssh/known_hosts', 'remote_directory': '/srv/app', 'scan_scope': 'source', 'enabled': True, 'max_bytes': 1024}, self.admin)
        save_settings(self.store, {'enabled': True, 'min_free_bytes': 0, 'gap_seconds': 0}, self.admin)
        # An explicit queued day makes tests independent of local wall-clock hour.
        self.store.begin_schedule_run(self.target['target_id'], '2026-09-07', 'full', self.target['config_version'])
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.client = ScheduleApiClient(f'http://127.0.0.1:{self.server.server_address[1]}', 'a' * 40)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.auth.stop()
        self.tmp.cleanup()

    def next(self, owner='worker-one'):
        return self.client.next(owner)['job']

    def record(self):
        return {'result': {'findings': [], 'sbom': {'components': []}},
                'manifest': [{'relative_path': 'app.py', 'size': 9, 'mtime': 1, 'sha256': hashlib.sha256(b'print(1)\n').hexdigest()}],
                'counts': {'files_total': 1, 'changed_files': 1, 'changed_paths': ['app.py']}}

    def runner(self, collector=None):
        return ApiScheduleRunner(self.client, state_dir=self.root / 'private-state', worker_id='worker-one', collector=collector or Collector())

    def test_authentication_disabled_default_and_manual_priority(self):
        self.assertFalse(authorize({}))
        wrong = ScheduleApiClient(self.client.base_url, 'wrong' * 8)
        with self.assertRaises(ScheduleApiError) as error:
            wrong.state()
        self.assertEqual(error.exception.status, 401)
        save_settings(self.store, {'enabled': False})
        self.assertIsNone(self.next())
        save_settings(self.store, {'enabled': True})
        path = self.root / 'manual.py'
        path.write_text('print(1)')
        input_id = self.store.add_input(self.project, path.name, path)
        self.store.create_scan(self.admin, self.project, input_id, 'local', 'all', 'source')
        self.assertIsNone(self.next())

    def test_lease_cannot_change_manual_runs_or_bypass_cleanup(self):
        job = self.next()
        self.assertIsNone(self.next('worker-two'))
        self.assertNotIn('tracker_token_ref', json.dumps(job))
        with self.assertRaises(ScheduleApiError):
            self.client.request('POST', API_PREFIX + '/runs/update', {'run_id': 'manual', 'status': 'completed'})
        with self.assertRaises(ScheduleApiError):
            self.client.action('cleanup', job | {'lease_token': 'other'}, success=True, error='')
        with self.assertRaises(ScheduleApiError):
            self.client.action('cleanup', job, success=True, error='')
        self.assertEqual(self.store.schedule_run(job['schedule_run_id'])['cleanup_status'], 'pending')

    def test_persistence_cleanup_and_replay_are_idempotent(self):
        job = self.next()
        record = self.record()
        first = self.client.action('persist', job, **record)
        self.assertEqual(first, self.client.action('persist', job, **record))
        self.assertEqual(self.store.input(self.store.run(first['run_id'])['input_id'])['path'], '')
        with self.assertRaises(ScheduleApiError):
            self.client.action('persist', job, **(record | {'result': {'findings': ['different']}}))
        row = self.client.action('cleanup', job, success=True, error='')
        self.assertEqual(row['status'], 'completed')
        self.assertEqual(self.client.action('cleanup', job, success=True, error='')['status'], 'completed')
        self.assertEqual(self.client.action('persist', job, **record)['run_id'], first['run_id'])

    def test_real_analyzer_through_http_keeps_sources_only_in_worker(self):
        runner = self.runner()
        result = runner.run_once()
        self.assertEqual(result['status'], 'completed', result)
        self.assertFalse(list(runner.work_dir.iterdir()))
        self.assertFalse(runner.outbox.exists())
        self.assertEqual(list((self.root / 'inputs').iterdir()), [])
        self.assertIsInstance(self.store.run(result['run_id'])['result'], dict)
        self.assertEqual(len(self.store.baseline_schedule_files(self.target['target_id'])), 1)

    def test_result_outbox_replays_after_connection_failure_without_collection(self):
        runner = self.runner()
        request = self.client.request
        def offline(method, path, payload=None):
            if path.endswith('/persist'):
                raise ScheduleApiError(503, 'temporarily offline')
            return request(method, path, payload)
        with patch.object(self.client, 'request', side_effect=offline):
            with self.assertRaises(ScheduleApiError):
                runner.run_once()
        self.assertFalse(list(runner.work_dir.iterdir()))
        self.assertTrue(runner.outbox.exists())
        with patch.object(runner.collector, 'fetch', side_effect=AssertionError('must not recollect')):
            result = runner.run_once()
        self.assertEqual(result['status'], 'completed')
        self.assertFalse(runner.outbox.exists())

    def test_cleanup_failure_is_retried_next_tick_before_any_publication(self):
        runner = self.runner()
        original = runner._clean
        def fail_after_work():
            if runner.active.exists():
                raise OSError('cleanup denied')
            original()
        with patch.object(runner, '_clean', side_effect=fail_after_work):
            result = runner.run_once()
        self.assertEqual(result['status'], 'cleanup_failed')
        scheduled = self.store.list_schedule_runs()[0]
        self.assertEqual(scheduled['cleanup_status'], 'failed')
        with patch.object(runner.collector, 'fetch', side_effect=AssertionError('must not recollect')):
            result = runner.run_once()
        self.assertEqual(result['status'], 'completed')
        self.assertFalse(list(runner.work_dir.iterdir()))

    def test_timeout_and_cancel_cleanup_and_release_lease(self):
        runner = self.runner()
        with patch.object(runner, '_analyze', side_effect=TimeoutError('deadline')):
            result = runner.run_once()
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(result['cleanup_status'], 'completed')
        self.assertFalse(list(runner.work_dir.iterdir()))
        self.store.begin_schedule_run(self.target['target_id'], '2026-09-08', 'full', self.target['config_version'])
        def cancel(target, **kwargs):
            row = next(r for r in self.store.list_schedule_runs() if r['status'] == 'running')
            self.store.update_schedule_run(row['schedule_run_id'], status='cancelling')
            return [RemoteFile('app.py', 9, 1)]
        with patch.object(runner.collector, 'list_files', side_effect=cancel):
            result = runner.run_once()
        self.assertEqual(result['status'], 'cancelled')
        self.assertEqual(result['cleanup_status'], 'completed')
        self.assertFalse(list(runner.work_dir.iterdir()))

    def test_result_only_input_never_cleans_working_directory(self):
        job = self.next()
        result = self.client.action('persist', job, **self.record())
        with patch('security_scanner.portal_store.shutil.rmtree') as remove:
            self.assertTrue(self.store.cleanup_input_for_run(result['run_id']))
        remove.assert_not_called()

    def test_restart_before_result_requeues_same_job_after_source_cleanup(self):
        runner = self.runner()
        job = self.next()
        runner.active.write_text(json.dumps(job))
        abandoned = runner.work_dir / 'koda-schedule-abandoned'
        abandoned.mkdir()
        (abandoned / 'source').write_text('temporary')
        result = runner.run_once()
        self.assertEqual(result['status'], 'queued')
        self.assertFalse(list(runner.work_dir.iterdir()))
        self.assertEqual(self.next()['schedule_run_id'], job['schedule_run_id'])

    def test_cancel_between_analysis_and_persist_releases_lease(self):
        runner = self.runner()
        original = self.client.request
        cancelled = []
        def request(method, path, payload=None):
            if path.endswith('/persist') and not cancelled:
                cancelled.append(True)
                self.store.update_schedule_run(payload['schedule_run_id'], status='cancelling')
            return original(method, path, payload)
        with patch.object(self.client, 'request', side_effect=request):
            result = runner.run_once()
        self.assertEqual(result['status'], 'cancelled')
        self.assertEqual(result['cleanup_status'], 'completed')
        self.assertFalse(runner.outbox.exists())
        self.assertFalse(list(runner.work_dir.iterdir()))

    def test_rejected_result_does_not_block_next_target_forever(self):
        runner = self.runner()
        job = self.next()
        runner.active.write_text(json.dumps(job))
        runner.outbox.write_text(json.dumps({'job': job, **self.record()}))
        original = self.client.request
        def request(method, path, payload=None):
            if path.endswith('/persist'):
                raise ScheduleApiError(413, 'result too large')
            return original(method, path, payload)
        with patch.object(self.client, 'request', side_effect=request):
            result = runner.recover()
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(result['cleanup_status'], 'completed')
        self.assertFalse(runner.outbox.exists())

    def test_api_baseline_delta_and_policy_change_force_full(self):
        from security_scanner.schedule_api import _mode
        runner = self.runner()
        with patch.object(runner, '_analyze', return_value=self.record()['result']):
            first = runner.run_once()
            self.assertEqual(first['status'], 'completed')
            self.assertEqual(_mode(self.store, self.target, '2026-09-08'), 'changed')
            self.assertEqual(_mode(self.store, self.target, '2026-09-13'), 'full')
            self.store.begin_schedule_run(self.target['target_id'], '2026-09-08', 'changed', self.target['config_version'])
            second = runner.run_once()
        self.assertEqual(second['changed_files'], 0)
        self.assertEqual(runner.collector.fetched, 1)
        self.assertEqual(_mode(self.store, self.target | {'config_version': self.target['config_version'] + 1}, '2026-09-09'), 'full')
        policy = self.store.rule_policy(self.project)
        with patch.object(self.store, 'rule_policy', return_value=policy | {'hash': 'new-rule-policy'}):
            self.assertEqual(_mode(self.store, self.target, '2026-09-09'), 'full')

    def test_policy_edit_while_queued_recalculates_scan_mode(self):
        runner = self.runner()
        with patch.object(runner, '_analyze', return_value=self.record()['result']):
            runner.run_once()
        self.store.begin_schedule_run(self.target['target_id'], '2026-09-08', 'changed', self.target['config_version'])
        policy = self.store.rule_policy(self.project)
        with patch.object(self.store, 'rule_policy', return_value=policy | {'hash': 'changed-while-queued'}):
            job = self.next()
        self.assertEqual(job['mode'], 'full')
