import tempfile
import uuid
import json
import unittest
from html.parser import HTMLParser
from pathlib import Path

from security_scanner.portal_store import PortalStore, SCOPED_SCAN_PERMISSIONS


class ProjectDeletionAndScheduleLabelTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = PortalStore(self.root / "portal.sqlite")
        self.admin = str(uuid.uuid4())
        self.viewer = str(uuid.uuid4())
        self.store.bootstrap(self.admin)
        self.store.ensure_subject(self.viewer, "viewer")
        self.store.set_subject(self.viewer, status="enabled", actor=self.admin)

    def tearDown(self):
        self.tmp.cleanup()

    def _project(self, name):
        return self.store.create_project(name, self.admin)

    def _target(self, project, target_id, host="scan.example"):
        return self.store.save_schedule_target({
            "target_id": target_id, "project_id": project, "name": target_id,
            "source_kind": "server", "host": host, "port": 22,
            "username": "reader", "ssh_key_ref": "/run/koda/key",
            "known_hosts_file": "/run/koda/known_hosts", "remote_directory": "/srv/app",
        })

    def test_delete_project_requires_admin_and_preserves_shared_input_until_last_owner(self):
        first, second = self._project("first"), self._project("second")
        source = self.root / "shared.bin"
        source.write_bytes(b"source")
        self.store.add_input(first, "shared.bin", source, self.admin)
        self.store.add_input(second, "shared.bin", source, self.admin)
        with self.assertRaises(PermissionError):
            self.store.delete_project(first, self.viewer)
        deleted = self.store.delete_project(first, self.admin)
        self.assertEqual(deleted["cleanup_errors"], [])
        self.assertTrue(source.exists())
        self.store.delete_project(second, self.admin)
        self.assertFalse(source.exists())
        self.assertTrue(any(e["action"] == "project.deleted" and e["project_id"] == first for e in self.store.audit_events(None)))

    def test_delete_project_cascades_memberships_results_and_schedules_only_for_target(self):
        project, other = self._project("cascade"), self._project("preserved")
        for pid in (project, other):
            self.store.set_membership(pid, self.viewer, "viewer", self.admin)
        source = self.root / "cascade.txt"
        source.write_text("sample")
        input_id = self.store.add_input(project, source.name, source, self.admin)
        run = self.store.create_scan(self.admin, project, input_id, "local", "all", "source")
        self.store.complete_run(run["run_id"], result={"findings": [{"title": "sample"}]})
        target = self._target(project, "cascade-target")
        scheduled = self.store.begin_schedule_run(target["target_id"], "2026-09-21", "full", 1)
        self.store.update_schedule_run(scheduled["schedule_run_id"], status="completed")
        self.store.delete_project(project, self.admin)
        with self.store._db() as db:
            for table in ("projects", "memberships", "inputs", "scan_runs", "schedule_targets", "rule_policies", "role_policies", "project_server_connections", "gitlab_repositories"):
                self.assertEqual(db.execute(f"SELECT count(*) FROM {table} WHERE project_id=?", (project,)).fetchone()[0], 0, table)
            self.assertEqual(db.execute("SELECT count(*) FROM analysis_revisions WHERE run_id=?", (run["run_id"],)).fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT count(*) FROM schedule_runs WHERE target_id=?", (target["target_id"],)).fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT count(*) FROM memberships WHERE project_id=? AND subject_id=?", (other, self.viewer)).fetchone()[0], 1)
        self.assertIsNotNone(self.store.subject(self.viewer))
        self.assertIsNotNone(self.store.project(other))

    def test_project_delete_is_only_on_admin_detail_page(self):
        from security_scanner.portal_views import projects_page, project_page
        class DeleteControls(HTMLParser):
            def __init__(self, html):
                super().__init__()
                self.projects = []
                self.feed(html)

            def handle_starttag(self, tag, attrs):
                attrs = dict(attrs)
                if "data-delete-project" in attrs:
                    self.projects.append(attrs["data-delete-project"])

        project = self.store.project(self._project("detail-delete"))
        self.assertEqual(DeleteControls(projects_page([project], admin=True)).projects, [])
        self.assertNotIn("프로젝트 삭제", projects_page([project], admin=True))
        detail = project_page(project, [], [], can_upload=True, can_scan=True, admin=True)
        self.assertEqual(DeleteControls(detail).projects, [project["project_id"]])
        self.assertIn("연결된 사용자 정보", detail)
        self.assertIn("공용 사용자 계정과 다른 프로젝트 정보는 유지", detail)
        self.assertEqual(DeleteControls(project_page(project, [], [], can_upload=False, can_scan=False, admin=False)).projects, [])

    def test_delete_project_blocks_active_run_and_schedule_api_lease(self):
        project = self._project("active")
        target = self._target(project, "active-target")
        run = self.store.begin_schedule_run(target["target_id"], "2026-09-21", "full", 1)
        self.store.update_schedule_run(run["schedule_run_id"], status="running")
        with self.assertRaises(ValueError):
            self.store.delete_project(project, self.admin)
        self.store.update_schedule_run(run["schedule_run_id"], status="failed")
        with self.store._db() as db:
            db.execute("CREATE TABLE schedule_api_lease(slot INTEGER PRIMARY KEY,worker_id TEXT,lease_token TEXT,schedule_run_id TEXT,context_json TEXT)")
            db.execute("INSERT INTO schedule_api_lease VALUES(1,'worker','token',?,'{}')", (run["schedule_run_id"],))
        with self.assertRaises(ValueError):
            self.store.delete_project(project, self.admin)

    def test_begin_schedule_run_is_idempotent_and_round_counts_by_date_and_server(self):
        project = self._project("rounds")
        first = self._target(project, "target-a")
        second = self._target(project, "target-b")
        one = self.store.begin_schedule_run(first["target_id"], "2026-09-21", "full", 1)
        again = self.store.begin_schedule_run(first["target_id"], "2026-09-21", "full", 1)
        self.assertEqual(one["schedule_run_id"], again["schedule_run_id"])
        two = self.store.begin_schedule_run(second["target_id"], "2026-09-21", "full", 1)
        self.assertIn("· 1회차", one["round_label"])
        self.assertIn("· 2회차", two["round_label"])
        # Re-reading the first run after another target is queued must not
        # renumber it or produce duplicate daily round labels.
        self.assertIn("· 1회차", self.store.schedule_run(one["schedule_run_id"])["round_label"])
        rows = {row["schedule_run_id"]: row for row in self.store.list_schedule_runs()}
        self.assertEqual(rows[one["schedule_run_id"]]["scheduled_round"], 1)
        self.assertEqual(rows[two["schedule_run_id"]]["scheduled_round"], 2)
        tomorrow = self.store.begin_schedule_run(first["target_id"], "2026-09-22", "full", 1)
        self.assertIn("· 1회차", tomorrow["round_label"])

    def test_scoped_scan_permissions_are_independent_and_legacy_scan_create_migrates(self):
        project = self._project("permissions")
        # Simulate a pre-scoped database row and verify startup migration.
        with self.store._db() as db:
            db.execute("INSERT INTO role_policies VALUES(?,?,?,?,?)", ("legacy-project", 1, '{"viewer":["scan.create"]}', "legacy", self.store._now()))
        reopened = PortalStore(self.root / "portal.sqlite")
        with reopened._db() as db:
            migrated = db.execute("SELECT roles_json FROM role_policies WHERE project_id=? ORDER BY version DESC LIMIT 1", ("legacy-project",)).fetchone()
        self.assertEqual(set(json.loads(migrated[0])["viewer"]), set(SCOPED_SCAN_PERMISSIONS))
        policy = self.store.role_policy()
        self.store.set_role_policy({"viewer": ["scan.create"]}, policy["version"], self.admin)
        scoped = self.store.role_policy()["roles"]["viewer"]
        self.assertEqual(set(scoped), set(SCOPED_SCAN_PERMISSIONS))
        self.store.set_membership(project, self.viewer, "viewer", self.admin)
        self.store.set_role_policy({"viewer": ["scan.library.create", "dashboard.view", "projects.view"]}, self.store.role_policy()["version"], self.admin)
        self.assertTrue(self.store.can(self.viewer, project, "scan.library.create"))
        self.assertFalse(self.store.can(self.viewer, project, "scan.source.create"))
        source = self.root / "source.bin"
        source.write_bytes(b"source")
        input_id = self.store.add_input(project, "source.bin", source, self.admin)
        with self.assertRaises(PermissionError):
            self.store.create_scan(self.viewer, project, input_id, "local", "all", "source")
        with self.assertRaises(PermissionError):
            self.store.create_scan(self.viewer, project, input_id, "local", "all", "all")
        self.assertEqual(self.store.create_scan(self.viewer, project, input_id, "local", "all", "library")["snapshot"]["scan_scope"], "library")

    def test_daily_round_is_consistent_in_project_list_and_run_detail(self):
        from security_scanner.portal_views import project_page, run_page

        project = self._project("display-rounds")
        source = self.root / "display.txt"
        source.write_text("sample")
        input_id = self.store.add_input(project, source.name, source, self.admin)
        manual = self.store.create_scan(self.admin, project, input_id, "local", "all", "source")
        self.store.complete_run(manual["run_id"], result={"findings": []})
        source.write_text("scheduled sample")
        input_id = self.store.add_input(project, source.name, source, self.admin)
        target = self._target(project, "display-target")
        scheduled = self.store.begin_schedule_run(target["target_id"], "2026-09-21", "full", 1)
        run = self.store.create_scheduled_scan(project, input_id, "local", "all", "source", {
            "source_type": "scheduled_server", "schedule_target_id": target["target_id"],
            "schedule_run_id": scheduled["schedule_run_id"], "scheduled_for": "2026-09-21",
        })
        scheduled = self.store.schedule_run(scheduled["schedule_run_id"])
        self.assertEqual(run["round_number"], 2)
        self.assertEqual(scheduled["scheduled_round"], 1)
        runs = self.store.list_runs(project)
        self.assertEqual(runs[0]["round_label"], scheduled["round_label"])
        html = project_page(self.store.project(project), [], runs, can_upload=True, can_scan=True, admin=True)
        self.assertIn(scheduled["round_label"], html)
        self.assertIn(scheduled["round_label"], run_page(run, admin=True, schedule_run=scheduled))

    def test_server_result_branch_rounds_increment_without_source_kind_metadata(self):
        project = self._project("server-results")
        mapping = self.store.set_gitlab_repositories(project, [{
            "gitlab_project_id": 55, "path_with_namespace": "security/results",
            "default_branch": "main", "name": "results",
            "tracker_service_id": "svc", "tracker_environment_id": "env",
            "tracker_token_ref": "results.token",
        }])[0]
        target = self._target(project, "server-branch-target")
        branches = []
        for index in range(2):
            scheduled = self.store.begin_schedule_run(target["target_id"], f"2026-09-21T0{index}:00", "full", 1)
            source = self.root / f"input-{index}.txt"
            source.write_text("sample")
            input_id = self.store.add_input(project, source.name, source, self.admin)
            run = self.store.create_scheduled_scan(project, input_id, "local", "all", "source", {
                "source_type": "scheduled_server", "schedule_target_id": target["target_id"],
                "schedule_run_id": scheduled["schedule_run_id"], "scheduled_for": scheduled["scheduled_for"],
                "remote_server": "app.example:22", "remote_directory": f"/srv/app-{index}",
                "gitlab_mapping_id": mapping["mapping_id"],
            })
            self.assertEqual(run["snapshot"]["gitlab_result_version"], index + 1)
            branches.append(run["snapshot"]["gitlab_result_branch"])
        self.assertNotEqual(*branches)


if __name__ == "__main__":
    unittest.main()
