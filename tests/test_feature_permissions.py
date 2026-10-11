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
from security_scanner.portal_store import PortalStore

TEST_GATEWAY_PROOF = "test-gateway-proof-0123456789abcdef0123456789abcdef"


class FeaturePermissionStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "portal.sqlite3"
        self.store = PortalStore(self.path)
        self.admin = str(uuid.uuid4())
        self.store.bootstrap(self.admin)
        self.project = self.store.create_project("feature-permissions")
        self.store.set_membership(self.project, self.admin, "admin")

    def tearDown(self):
        self.tmp.cleanup()

    def _subject(self, role="viewer"):
        subject = str(uuid.uuid4())
        self.store.ensure_subject(subject, subject)
        self.store.set_subject(subject, status="enabled", actor=self.admin)
        self.store.set_membership(self.project, subject, role, self.admin)
        return subject

    def _policy(self, **role_updates):
        policy = self.store.role_policy()
        roles = {role: list(perms) for role, perms in policy["roles"].items()}
        roles.update(role_updates)
        self.store.set_role_policy(roles, policy["version"], self.admin)

    def test_new_write_permissions_are_explicit_and_project_scoped(self):
        subject = self._subject()
        other_project = self.store.create_project("other", self.admin)
        self.assertFalse(self.store.can(subject, self.project, "project.delete"))
        self.assertFalse(self.store.can(subject, other_project, "runs.export"))

        self._policy(viewer=["dashboard.view", "runs.view", "runs.export", "project.delete"])
        self.assertTrue(self.store.can(subject, self.project, "runs.export"))
        self.assertTrue(self.store.can(subject, self.project, "project.delete"))
        self.assertFalse(self.store.can(subject, other_project, "project.delete"))

    def test_global_project_create_requires_any_assigned_role(self):
        subject = self._subject()
        self.assertFalse(self.store.can_global(subject, "project.create"))
        self._policy(viewer=["dashboard.view", "runs.view", "project.create"])
        self.assertTrue(self.store.can_global(subject, "project.create"))
        created = self.store.create_project("created-by-viewer", subject)
        membership = self.store.list_memberships(created)
        self.assertEqual([(row["subject_id"], row["role"]) for row in membership], [(subject, "admin")])

    def test_export_migration_is_one_time_and_does_not_restore_revocation(self):
        policy = self.store.role_policy()
        roles = {role: list(perms) for role, perms in policy["roles"].items()}
        roles["viewer"] = ["dashboard.view", "runs.view", "runs.export", "project.delete"]
        self.store.set_role_policy(roles, policy["version"], self.admin)
        with self.store._db() as db:
            db.execute("DELETE FROM portal_migrations WHERE migration_id='runs.export.v1'")
        reopened = PortalStore(self.path)
        self.assertIn("runs.export", reopened.role_policy()["roles"]["viewer"])
        policy = reopened.role_policy()
        roles = {role: list(perms) for role, perms in policy["roles"].items()}
        roles["viewer"].remove("runs.export")
        reopened.set_role_policy(roles, policy["version"], self.admin)
        reopened_again = PortalStore(self.path)
        self.assertNotIn("runs.export", reopened_again.role_policy()["roles"]["viewer"])


class FeaturePermissionHttpTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.admin = str(uuid.uuid4())
        self.server = create_portal_server("127.0.0.1", 0, db_path=Path(self.tmp.name) / "portal.sqlite3", input_dir=Path(self.tmp.name) / "inputs", gateway_proof=TEST_GATEWAY_PROOF)
        # These are permission/query fixtures, with explicit synthetic results.
        # Publication processing is invoked directly in its dedicated test.
        self.server.portal_worker.close()
        self.store = self.server.portal_store
        self.store.bootstrap(self.admin)
        self.project = self.store.create_project("HTTP features")
        self.store.set_membership(self.project, self.admin, "admin")
        source = Path(self.tmp.name) / "input.py"
        source.write_text("print('feature')\n", encoding="utf-8")
        input_id = self.store.add_input(self.project, source.name, source)
        self.run = self.store.create_scan(self.admin, self.project, input_id, "local", "all")
        self.store.complete_run(self.run["run_id"], result={"findings": [], "sbom": {"components": []}})
        source2 = Path(self.tmp.name) / "input2.py"
        source2.write_text("print('feature2')\n", encoding="utf-8")
        input2_id = self.store.add_input(self.project, source2.name, source2)
        self.run2 = self.store.create_scan(self.admin, self.project, input2_id, "local", "all")
        self.store.complete_run(self.run2["run_id"], result={"findings": [], "sbom": {"components": []}})
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.tmp.cleanup()

    def headers(self, subject=None, display="admin"):
        return {
            "X-KODA-Gateway-Proof": TEST_GATEWAY_PROOF,
            "X-KODA-Identity-ID": subject or self.admin,
            "X-KODA-Identity-Expires": (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5)).isoformat(),
            "X-KODA-Identity-Display": base64.urlsafe_b64encode(display.encode()).rstrip(b"=").decode(),
        }

    def request(self, path, *, method="GET", payload=None, headers=None):
        body = json.dumps(payload).encode() if payload is not None else None
        request = urllib.request.Request(self.base + path, data=body, method=method, headers=headers or {})
        if payload is not None:
            request.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                raw = response.read()
                return response.status, json.loads(raw) if response.headers.get_content_type() == "application/json" else raw.decode()
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            try:
                value = json.loads(raw)
            except ValueError:
                value = raw.decode()
            return exc.code, value

    def test_result_exports_are_denied_without_runs_export(self):
        subject = str(uuid.uuid4())
        self.store.ensure_subject(subject, "viewer")
        self.store.set_subject(subject, status="enabled", actor=self.admin)
        self.store.set_membership(self.project, subject, "viewer", self.admin)
        policy = self.store.role_policy()
        roles = {role: list(perms) for role, perms in policy["roles"].items()}
        roles["viewer"] = ["dashboard.view", "runs.view", "compare.view", "projects.view"]
        self.store.set_role_policy(roles, policy["version"], self.admin)
        run_id = self.run["run_id"]
        self.assertEqual(self.request(f"/koda/api/v1/runs/{run_id}/report?format=json", headers=self.headers(subject))[0], 403)
        self.assertEqual(self.request(f"/koda/api/v1/runs/{run_id}/sbom?format=cyclonedx", headers=self.headers(subject))[0], 403)
        other_id = self.run2["run_id"]
        self.assertEqual(self.request(f"/koda/compare?left={run_id}&right={other_id}", headers=self.headers(subject))[0], 200)
        page = self.request(f"/koda/compare?left={run_id}&right={other_id}", headers=self.headers(subject))[1]
        self.assertNotIn("format=csv", page)

    def test_delivery_retries_require_their_feature_permissions(self):
        self.server.portal_worker.close()
        subject = str(uuid.uuid4())
        self.store.ensure_subject(subject, "publisher")
        self.store.set_subject(subject, status="enabled", actor=self.admin)
        self.store.set_membership(self.project, subject, "viewer", self.admin)
        policy = self.store.role_policy()
        roles = {role: list(perms) for role, perms in policy["roles"].items()}
        roles["viewer"] = ["dashboard.view", "runs.view", "runs.tracker.publish", "runs.gitlab.result.publish", "runs.gitlab.issues.publish"]
        self.store.set_role_policy(roles, policy["version"], self.admin)
        target = Path(self.tmp.name) / "publish.txt"
        target.write_text("publish", encoding="utf-8")
        input_id = self.store.add_input(self.project, target.name, target, self.admin)
        mapping = self.store.set_gitlab_repositories(self.project, [{
            "gitlab_project_id": 42, "path_with_namespace": "group/permissions", "name": "permissions",
            "default_branch": "main", "tracker_service_id": "permissions", "tracker_environment_id": "test",
            "tracker_token_ref": "permissions.token",
        }], self.admin)[0]
        run = self.store.create_scan(self.admin, self.project, input_id, "local", "all", source_snapshot={
            "gitlab_mapping_id": mapping["mapping_id"], "gitlab_project_id": 42, "gitlab_path_with_namespace": "group/permissions",
        })
        run_id = run["run_id"]
        self.store.complete_run(run_id, result={"findings": [{"rule_id": "code.permissions", "category": "code", "verification_status": "confirmed"}]})
        self.store.claim_tracker_delivery(run_id)
        self.store.finish_tracker_delivery(run_id, "failed", error="offline")
        self.store.claim_gitlab_result(run_id, allow_tracker_failure=True)
        self.store.finish_gitlab_result(run_id, "failed", error="offline")
        self.store.claim_gitlab_issue_delivery(run_id)
        self.store.prepare_gitlab_issue_items(run_id, 42, [{"finding_index": 0, "finding_key": "permissions"}])
        self.store.finish_gitlab_issue_item(run_id, "permissions", "failed", error="offline")
        self.store.finish_gitlab_issue_delivery(run_id)
        queued = []
        with patch("security_scanner.linux_portal._run_delivery", return_value={"status": "completed"}) as delivery:
            for endpoint, kind in (("tracker/retry", "tracker"), ("gitlab/result/retry", "gitlab_result"), ("gitlab/issues/retry", "issues")):
                status, result = self.request(f"/koda/api/v1/runs/{run_id}/{endpoint}", method="POST", payload={}, headers=self.headers(subject, "publisher"))
                self.assertEqual((status, result["status"], result["kind"]), (202, "queued", kind))
                queued.append(result["job_id"])
            delivery.assert_not_called()
            from security_scanner.portal_worker import next_publication, process_publication
            for _ in range(3):
                process_publication(self.store, next_publication(self.store))
            self.assertEqual(delivery.call_count, 3)
        with self.store._db() as db:
            statuses = [db.execute("SELECT status FROM portal_delivery_jobs WHERE job_id=?", (job_id,)).fetchone()[0] for job_id in queued]
        self.assertEqual(statuses, ["completed"] * 3)


if __name__ == "__main__":
    unittest.main()
