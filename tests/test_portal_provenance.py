"""User-visible account IDs and input/run attribution survive source cleanup."""
import base64
import datetime as dt
import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
import uuid
from pathlib import Path

from security_scanner.linux_portal import create_portal_server
from security_scanner.portal_store import PortalStore
from security_scanner.portal_views import project_page, runs_page


class PortalProvenanceTests(unittest.TestCase):
    def test_uploader_and_executor_are_distinct_and_survive_cleanup(self):
        with tempfile.TemporaryDirectory() as root:
            store = PortalStore(Path(root) / 'db.sqlite3')
            uploader, executor = str(uuid.uuid4()), str(uuid.uuid4())
            store.bootstrap(executor)
            store.ensure_subject(executor, 'scan.operator')
            store.ensure_subject(uploader, 'upload.operator')
            project = store.create_project('sample')
            source = Path(root) / 'sample.py'
            source.write_text('print(1)')
            input_id = store.add_input(project, source.name, source, uploader)
            run = store.create_scan(executor, project, input_id, 'local', 'all', 'source')
            store.complete_run(run['run_id'], result={'findings': []})
            source.unlink(missing_ok=True)
            inputs, runs = store.list_inputs(project), store.list_runs(project)
            self.assertEqual(inputs[0]['registered_by_id'], 'upload.operator')
            self.assertEqual(inputs[0]['runs'], [{'run_id': run['run_id'], 'round_number': 1}])
            self.assertEqual(runs[0]['requested_by_id'], 'scan.operator')
            html = project_page(store.project(project), inputs, runs, can_upload=True, can_scan=True, admin=True)
            self.assertIn('등록자 ID', html)
            self.assertIn('upload.operator', html)
            self.assertIn('원본 삭제됨', html)
            self.assertIn('scan.operator', runs_page([(store.project(project), runs)], admin=True))
            # Upgrade an old DB: retained audit events supply the original actor.
            with store._db() as db:
                db.execute('ALTER TABLE inputs DROP COLUMN registered_by')
            migrated = PortalStore(store.path)
            self.assertEqual(migrated.list_inputs(project)[0]['registered_by_id'], 'upload.operator')

    def test_admin_sees_other_users_audit_and_username_not_uuid(self):
        with tempfile.TemporaryDirectory() as root:
            server = create_portal_server('127.0.0.1', 0, db_path=Path(root)/'db', input_dir=Path(root)/'inputs')
            admin, other = str(uuid.uuid4()), str(uuid.uuid4())
            store = server.portal_store
            store.bootstrap(admin)
            store.ensure_subject(other, 'other.user')
            store.record_audit(other, 'sample.other.user.activity', {})
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                def get(path, actor=admin, username='admin.user'):
                    headers = {'X-KODA-Identity-ID': actor,
                               'X-KODA-Identity-Expires': (dt.datetime.now(dt.timezone.utc)+dt.timedelta(minutes=5)).isoformat(),
                               'X-KODA-Identity-Display': base64.urlsafe_b64encode(username.encode()).decode().rstrip('=')}
                    request = urllib.request.Request(f'http://127.0.0.1:{server.server_port}'+path, headers=headers)
                    with urllib.request.urlopen(request) as response:
                        return response.read().decode()
                self.assertEqual(json.loads(get('/koda/api/v1/me'))['username'], 'admin.user')
                html = get('/koda/admin/audit')
                self.assertIn('모든 사용자의 KODA 활동', html)
                self.assertIn('other.user', html)
                self.assertIn('sample.other.user.activity', html)
                with self.assertRaises(urllib.error.HTTPError) as caught:
                    get('/koda/admin/audit', other, 'other.user')
                self.assertEqual(caught.exception.code, 403)
                caught.exception.close()
            finally:
                server.shutdown(); server.server_close(); thread.join()


if __name__ == '__main__':
    unittest.main()
