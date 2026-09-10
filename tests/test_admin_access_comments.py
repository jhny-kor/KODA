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


class AdminAccessCommentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.admin = str(uuid.uuid4())
        self.server = create_portal_server(
            "127.0.0.1", 0,
            db_path=Path(self.tmp.name) / "portal.sqlite3",
            input_dir=Path(self.tmp.name) / "inputs",
        )
        self.server.portal_store.bootstrap(self.admin)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.tmp.cleanup()

    def headers(self, subject=None, display="admin"):
        encoded = base64.urlsafe_b64encode(display.encode()).rstrip(b"=").decode()
        return {
            "X-KODA-Identity-ID": subject or self.admin,
            "X-KODA-Identity-Expires": (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5)).isoformat(),
            "X-KODA-Identity-Display": encoded,
        }

    def request(self, path, *, method="GET", payload=None, headers=None):
        body = json.dumps(payload).encode() if payload is not None else None
        request = urllib.request.Request(self.base + path, data=body, method=method, headers=headers or {})
        if payload is not None:
            request.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                raw = response.read()
                if not raw:
                    return response.status, None
                try:
                    return response.status, json.loads(raw)
                except json.JSONDecodeError:
                    return response.status, raw.decode()
        except urllib.error.HTTPError as error:
            raw = error.read()
            try:
                return error.code, json.loads(raw)
            except json.JSONDecodeError:
                return error.code, raw.decode()

    def test_subjects_page_has_bulk_picker_and_revoke_controls_without_uuid_columns(self):
        project = self.server.portal_store.create_project("access comments", self.admin)
        viewer = str(uuid.uuid4())
        self.server.portal_store.ensure_subject(viewer, "viewer")
        self.server.portal_store.set_subject(viewer, status="enabled", actor=self.admin)
        self.server.portal_store.set_membership(project, viewer, "viewer", self.admin)

        status, page = self.request("/koda/admin/subjects", headers=self.headers())
        self.assertEqual(status, 200)
        self.assertNotIn("<th>UUID</th>", page)
        self.assertIn("name='subject_ids'", page)
        self.assertIn("data-remove-membership-project=", page)
        self.assertIn("접근을 해제하시겠습니까?", page)
        self.assertIn("for(const subjectId of subjectIds)", page)
        self.assertIn("f.getAll('subject_ids')", page)
        self.assertIn("await json('/koda/api/v1/admin/memberships'", page)
        self.assertIn("alert(x.message)", page)
        self.assertIn("id='membership-select-all'", page)
        self.assertIn("id='membership-selection-count'", page)
        self.assertIn("data-sort-key='project_name'", page)
        self.assertIn("data-sort-key='display'", page)
        self.assertIn("aria-sort='none'", page)
        self.assertIn("localeCompare", page)
        self.assertIn("position:absolute", page)
        self.assertIn("event.key==='Escape'", page)

    def test_revoke_membership_uses_existing_endpoint_and_requires_admin(self):
        project = self.server.portal_store.create_project("revoke comments", self.admin)
        viewer = str(uuid.uuid4())
        self.server.portal_store.ensure_subject(viewer, "viewer")
        self.server.portal_store.set_subject(viewer, status="enabled", actor=self.admin)
        self.server.portal_store.set_membership(project, viewer, "viewer", self.admin)
        payload = {"project_id": project, "subject_id": viewer, "role": ""}

        self.assertEqual(self.request("/koda/api/v1/admin/memberships", method="POST", payload=payload, headers=self.headers(viewer, "viewer"))[0], 403)
        self.assertEqual(self.request("/koda/api/v1/admin/memberships", method="POST", payload=payload, headers=self.headers())[0], 200)
        self.assertNotIn(viewer, {membership["subject_id"] for membership in self.server.portal_store.list_memberships(project)})
        self.assertIn("membership.removed", {event["action"] for event in self.server.portal_store.audit_events(None)})

    def test_server_connection_crud_requires_admin(self):
        store = self.server.portal_store
        project = store.create_project("connection test", self.admin)
        viewer = str(uuid.uuid4())
        store.ensure_subject(viewer, "viewer")
        store.set_subject(viewer, status="enabled", actor=self.admin)
        endpoint = "/koda/api/v1/admin/server-connections"
        config = dict(name="test", host="sample.invalid", username="reader", port=22,
                      ssh_key_ref="/run/koda/ssh/key", known_hosts_file="/run/koda/ssh/known", project_ids=[project])
        self.assertEqual(self.request(endpoint, method="POST", payload=config, headers=self.headers(viewer, "viewer"))[0], 403)
        self.assertEqual(self.request(endpoint, method="POST", payload=config, headers=self.headers())[0], 200)
        connection = store.list_server_connections()[0]
        self.assertEqual(self.request(endpoint, headers=self.headers(viewer, "viewer"))[0], 403)
        self.assertEqual(self.request(endpoint, headers=self.headers())[0], 200)
        endpoint += "/" + connection["connection_id"]
        self.assertEqual(self.request(endpoint, method="DELETE", headers=self.headers(viewer, "viewer"))[0], 403)
        self.assertEqual(self.request(endpoint, method="DELETE", headers=self.headers())[0], 200)
        self.assertEqual(store.list_server_connections(), [])


if __name__ == "__main__":
    unittest.main()
