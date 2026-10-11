"""Regression coverage for the shared manual/scheduled scan execution slot."""
import contextlib
import tempfile
import threading
import time
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from security_scanner.linux_portal import _PortalWorker
from security_scanner.portal_store import PortalStore
from security_scanner.schedule_api import _ensure, _next
from security_scanner.schedule_settings import save_settings


class ScanSerializationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.store = PortalStore(self.root / 'portal.sqlite3')
        self.other = PortalStore(self.store.path)
        self.admin = str(uuid.uuid4())
        self.store.bootstrap(self.admin)
        self.project = self.store.create_project('serialization')
        self.store.set_membership(self.project, self.admin, 'admin')
        self.target = self.store.save_schedule_target({
            'project_id': self.project, 'name': 'server', 'host': 'server.internal',
            'username': 'scan', 'ssh_key_ref': '/run/koda/ssh/key',
            'known_hosts_file': '/run/koda/ssh/known_hosts',
            'remote_directory': '/srv/app', 'scan_scope': 'source', 'enabled': True,
        }, self.admin)
        _ensure(self.store)
        save_settings(self.store, {'enabled': True, 'min_free_bytes': 0, 'gap_seconds': 0})

    def manual(self, subject=None):
        subject = subject or self.admin
        path = self.root / 'inputs' / (uuid.uuid4().hex + '.py')
        path.parent.mkdir(exist_ok=True)
        path.write_text('print(1)\n')
        input_id = self.store.add_input(self.project, path.name, path)
        return self.store.create_scan(subject, self.project, input_id, 'local', 'all', 'source')

    def scheduled(self):
        return self.store.begin_schedule_run(self.target['target_id'], '2026-09-07', 'full', self.target['config_version'])

    def finish_schedule(self, row):
        self.store.update_schedule_run(row['schedule_run_id'], status='completed', stage='completed', cleanup_status='completed')
        with self.store._db() as db:
            db.execute('DELETE FROM schedule_api_lease WHERE schedule_run_id=?', (row['schedule_run_id'],))

    def race(self, left, right):
        barrier = threading.Barrier(2)
        def enter(fn):
            barrier.wait(timeout=3)
            return fn()
        with ThreadPoolExecutor(max_workers=2) as executor:
            a, b = executor.submit(enter, left), executor.submit(enter, right)
            return a.result(timeout=5), b.result(timeout=5)

    def wait_for(self, predicate):
        deadline = time.monotonic() + 4
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(.02)
        self.fail('Worker did not reach the expected durable state')

    def test_distinct_stores_cannot_start_two_manual_scans(self):
        first, second = self.manual(), self.manual()
        outcomes = self.race(
            lambda: self.store.mark_run_running(first['run_id']),
            lambda: self.other.mark_run_running(second['run_id']),
        )
        self.assertEqual(sum(outcomes), 1)
        winner, loser = (first, second) if outcomes[0] else (second, first)
        self.assertEqual(self.store.run(loser['run_id'])['status'], 'queued')
        self.store.complete_run(winner['run_id'], result={'findings': []})
        self.assertTrue(self.other.mark_run_running(loser['run_id']))

    def test_manual_claim_wins_over_schedule_when_manual_is_queued(self):
        scheduled, manual = self.scheduled(), self.manual()
        outcomes = self.race(
            lambda: self.store.mark_run_running(manual['run_id']),
            lambda: self.other.claim_schedule_run(scheduled['schedule_run_id']),
        )
        self.assertEqual(outcomes, (True, False))
        self.assertEqual(self.store.schedule_run(scheduled['schedule_run_id'])['status'], 'queued')

    def test_active_schedule_blocks_manual_until_cleanup(self):
        scheduled = self.scheduled()
        self.assertTrue(self.store.claim_schedule_run(scheduled['schedule_run_id']))
        manual = self.manual()
        self.assertFalse(self.other.mark_run_running(manual['run_id']))
        self.store.update_schedule_run(scheduled['schedule_run_id'], status='cancelling')
        self.assertFalse(self.other.mark_run_running(manual['run_id']))
        self.finish_schedule(scheduled)
        self.assertTrue(self.other.mark_run_running(manual['run_id']))

    def test_schedule_lease_holds_slot_even_if_schedule_status_is_terminal(self):
        scheduled = self.scheduled()
        self.assertIsNotNone(_next(self.store, 'collector')['job'])
        self.store.update_schedule_run(scheduled['schedule_run_id'], status='failed')
        manual = self.manual()
        self.assertFalse(self.other.mark_run_running(manual['run_id']))
        self.finish_schedule(scheduled)
        self.assertTrue(self.other.mark_run_running(manual['run_id']))

    def test_api_rechecks_manual_work_when_acquiring_schedule_lease(self):
        scheduled = self.scheduled()
        # Reproduce a second process accepting a manual request after the API's
        # initial manual-priority check, but before its lease transaction.
        original = self.store.has_active_manual_work
        added = []
        def arriving_manual():
            prior = original()
            added.append(self.manual())
            self.assertTrue(self.other.mark_run_running(added[-1]['run_id']))
            return prior
        with patch.object(self.store, 'has_active_manual_work', side_effect=arriving_manual):
            self.assertIsNone(_next(self.store, 'collector')['job'])
        self.assertEqual(self.store.schedule_run(scheduled['schedule_run_id'])['status'], 'queued')

    def test_cancelled_queue_releases_priority_but_running_cancel_retains_slot(self):
        queued = self.manual()
        self.store.request_cancel(queued['run_id'])
        scheduled = self.scheduled()
        self.assertTrue(self.other.claim_schedule_run(scheduled['schedule_run_id']))
        self.finish_schedule(scheduled)
        running, waiting = self.manual(), self.manual()
        self.assertTrue(self.store.mark_run_running(running['run_id']))
        self.store.request_cancel(running['run_id'])
        self.assertFalse(self.other.mark_run_running(waiting['run_id']))
        self.store.complete_run(running['run_id'])
        self.assertTrue(self.other.mark_run_running(waiting['run_id']))

    def test_only_linked_legacy_scheduled_child_can_use_owned_slot(self):
        scheduled = self.scheduled()
        self.assertTrue(self.store.claim_schedule_run(scheduled['schedule_run_id']))
        path = self.root / 'scheduled.py'
        path.write_text('print(1)\n')
        input_id = self.store.add_input(self.project, path.name, path)
        snapshot = {'source_type': 'scheduled_server', 'schedule_run_id': scheduled['schedule_run_id']}
        child = self.store.create_scheduled_scan(self.project, input_id, 'local', 'all', 'source', snapshot)
        self.manual()  # A later manual request cannot interrupt its scheduled owner.
        # Creation links the parent automatically; explicitly remove that link
        # to verify that a snapshot alone cannot grant ownership of the slot.
        self.store.update_schedule_run(scheduled['schedule_run_id'], run_id=None)
        self.assertFalse(self.other.mark_run_running(child['run_id']))
        self.store.update_schedule_run(scheduled['schedule_run_id'], run_id=child['run_id'])
        self.assertTrue(self.other.mark_run_running(child['run_id']))

    @contextlib.contextmanager
    def lightweight_scan(self, callback):
        # Keep the real _run_scan claim, cancellation and completion transitions.
        # Replace only scanning/extraction and release metadata for a tiny input.
        with patch('security_scanner.data_release.pinned_release', side_effect=contextlib.nullcontext), \
             patch('security_scanner.data_release.release_metadata', return_value={}), \
             patch('security_scanner.archive_input.prepare_input_target', side_effect=lambda source, *_args, **_kwargs: source), \
             patch('security_scanner.server.scan_directory_payload', side_effect=callback):
            yield

    def test_worker_processes_users_fifo_with_no_overlapping_scan(self):
        user = str(uuid.uuid4())
        self.store.ensure_subject(user, 'second user')
        self.store.set_subject(user, status='enabled')
        self.store.set_membership(self.project, user, 'admin')
        entered, release = threading.Event(), threading.Event()
        seen = []
        def scan(_path, **kwargs):
            with self.store._db() as db:
                rows = db.execute("SELECT requested_by FROM scan_runs WHERE status='running'").fetchall()
            seen.append([row[0] for row in rows])
            if len(seen) == 1:
                entered.set()
                release.wait(timeout=3)
            return {'findings_by_language': {'ko': []}}
        first = self.manual()
        with self.lightweight_scan(scan):
            worker = _PortalWorker(self.store)
            try:
                self.assertTrue(entered.wait(timeout=3))
                second = self.manual(user)
                third = self.manual()
                # DB polling must discover another user's job even without an
                # in-memory enqueue notification from the accepting process.
                release.set()
                self.wait_for(lambda: self.store.run(third['run_id'])['status'] == 'completed')
                self.assertEqual(self.store.run(first['run_id'])['status'], 'completed')
                self.assertEqual(self.store.run(second['run_id'])['status'], 'completed')
                self.assertEqual(seen, [[self.admin], [user], [self.admin]])
            finally:
                release.set()
                worker.close()

    def test_worker_retains_manual_queue_and_resumes_after_schedule_cleanup(self):
        scheduled = self.scheduled()
        self.assertIsNotNone(_next(self.store, 'collector')['job'])
        manual = self.manual()
        entered = threading.Event()
        def scan(_path, **kwargs):
            entered.set()
            return {'findings_by_language': {'ko': []}}
        with self.lightweight_scan(scan):
            worker = _PortalWorker(self.store)
            try:
                self.assertFalse(entered.wait(timeout=.3))
                self.assertEqual(self.store.run(manual['run_id'])['status'], 'queued')
                self.finish_schedule(scheduled)
                self.wait_for(lambda: self.store.run(manual['run_id'])['status'] == 'completed')
                self.assertTrue(entered.is_set())
            finally:
                worker.close()

    def test_secondary_worker_does_not_recover_primary_active_scan(self):
        entered, release = threading.Event(), threading.Event()
        seen = []
        def scan(_path, **kwargs):
            seen.append(1)
            entered.set()
            release.wait(timeout=3)
            return {'findings_by_language': {'ko': []}}
        manual = self.manual()
        with self.lightweight_scan(scan):
            first = _PortalWorker(self.store)
            second = None
            try:
                self.assertTrue(entered.wait(timeout=3))
                second = _PortalWorker(self.other)
                self.assertEqual(self.store.run(manual['run_id'])['status'], 'running')
                time.sleep(.1)
                self.assertEqual(len(seen), 1)
            finally:
                release.set()
                if second:
                    second.close()
                first.close()

    def test_secondary_worker_takes_over_durable_queue_after_primary_close(self):
        entered, release = threading.Event(), threading.Event()
        seen = []

        def scan(_path, **kwargs):
            seen.append(1)
            if len(seen) == 1:
                entered.set()
                release.wait(timeout=3)
            return {'findings_by_language': {'ko': []}}

        first_run = self.manual()
        with self.lightweight_scan(scan):
            first = _PortalWorker(self.store)
            second = None
            closing = None
            try:
                self.assertTrue(entered.wait(timeout=3))
                second_run = self.manual()
                second = _PortalWorker(self.other)
                closing = threading.Thread(target=first.close)
                closing.start()
                self.wait_for(first.stop_event.is_set)
                release.set()
                closing.join(timeout=3)
                self.assertFalse(closing.is_alive())
                self.assertFalse(first.available)
                self.wait_for(lambda: self.store.run(second_run['run_id'])['status'] == 'completed')
                self.assertEqual(self.store.run(first_run['run_id'])['status'], 'completed')
                self.assertEqual(len(seen), 2)
            finally:
                release.set()
                if closing:
                    closing.join(timeout=3)
                if second:
                    second.close()
                first.close()
