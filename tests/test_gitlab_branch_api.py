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
from unittest.mock import patch

from security_scanner.linux_portal import create_portal_server
from security_scanner.portal_integrations import create_gitlab_branch


class GitLabBranchApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.admin = str(uuid.uuid4())
        self.server = create_portal_server("127.0.0.1", 0, db_path=Path(self.tmp.name) / "portal.sqlite3")
        store = self.server.portal_store
        store.bootstrap(self.admin)
        project = store.create_project("demo")
        store.set_membership(project, self.admin, "admin")
        self.mapping = store.set_gitlab_repositories(project, [{
            "gitlab_project_id": 42, "path_with_namespace": "group/demo", "name": "demo",
            "default_branch": "main", "tracker_service_id": "service", "tracker_environment_id": "env",
            "tracker_token_ref": "token",
        }], self.admin)[0]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.tmp.cleanup()

    def headers(self, subject=None):
        return {
            "X-KODA-Identity-ID": subject or self.admin,
            "X-KODA-Identity-Expires": (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5)).isoformat(),
            "X-KODA-Identity-Display": base64.urlsafe_b64encode(b"admin").rstrip(b"=").decode(),
        }

    def request(self, path, payload, subject=None):
        request = urllib.request.Request(self.base + path, data=json.dumps(payload).encode(), method="POST", headers=self.headers(subject))
        request.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def test_create_branch_uses_mapping_project_and_is_admin_only(self):
        with patch("security_scanner.portal_integrations._gitlab_write_json", return_value={"name": "release/2026"}) as call:
            self.assertEqual(create_gitlab_branch(42, "release/2026", "main", Path(self.tmp.name)), {"name": "release/2026"})
        call.assert_called_once_with(
            "/projects/42/repository/branches", settings_dir=Path(self.tmp.name), method="POST",
            payload={"branch": "release/2026", "ref": "main"},
        )
        path = f"/koda/api/v1/admin/gitlab/mappings/{self.mapping['mapping_id']}/branches"
        with patch("security_scanner.linux_portal.create_gitlab_branch", return_value={"name": "release/2026"}) as create:
            status, body = self.request(path, {"branch": "release/2026", "ref": "main"})
        self.assertEqual((status, body), (201, {"name": "release/2026"}))
        create.assert_called_once_with(42, "release/2026", "main", Path(self.tmp.name) / "integrations")
        outsider = str(uuid.uuid4())
        self.server.portal_store.ensure_subject(outsider, "viewer")
        self.server.portal_store.set_subject(outsider, status="enabled", actor=self.admin)
        self.assertEqual(self.request(path, {"branch": "x", "ref": "main"}, outsider)[0], 403)

    def test_branch_names_reject_ref_injection_and_gitlab_duplicate_is_not_overwritten(self):
        for name in ("../bad", "bad name", "bad~name", "bad.lock"):
            with self.assertRaises(ValueError):
                create_gitlab_branch(42, name, "main", Path(self.tmp.name))
        from security_scanner.portal_integrations import IntegrationError
        with patch("security_scanner.portal_integrations._gitlab_write_json", side_effect=IntegrationError("duplicate", status=400)):
            with self.assertRaises(IntegrationError):
                create_gitlab_branch(42, "release/existing", "main", Path(self.tmp.name))


if __name__ == "__main__":
    unittest.main()
