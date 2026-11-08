import json
import sqlite3
import tempfile
import unittest
import uuid
from pathlib import Path

from security_scanner.portal_store import PortalStore


class ManualGitLabStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.store = PortalStore(self.root / "portal.sqlite3")
        self.admin = str(uuid.uuid4())
        self.store.bootstrap(self.admin)
        self.project = self.store.create_project("manual GitLab")
        self.mapping_value = {
            "gitlab_project_id": 42, "path_with_namespace": "group/repo", "name": "repo",
            "default_branch": "main", "tracker_service_id": "service",
            "tracker_environment_id": "environment", "tracker_token_ref": "repo.token",
        }
        self.mapping = self.store.set_gitlab_repositories(self.project, [self.mapping_value], self.admin)[0]
        self.manifest = {"src/main.py": "a" * 64}
        self.file_scope = {
            "requested_mode": "changed", "effective_mode": "full", "reason": "first_scan",
            "files_total": 1, "files_scanned": 1, "scanner_fingerprint": "test-scanner",
        }

    def new_scan(self, *, mapping=None, project=None, ref_name="main", ref_type="branch", source_extra=None, mode=None):
        mapping = mapping or self.mapping
        project = project or self.project
        target = self.root / (uuid.uuid4().hex + ".tar.gz")
        target.write_bytes(b"archive")
        input_id = self.store.add_input(project, target.name, target)
        source = {
            "gitlab_mapping_id": mapping["mapping_id"], "gitlab_project_id": mapping["gitlab_project_id"],
            "gitlab_path_with_namespace": mapping["path_with_namespace"],
            "gitlab_ref_type": ref_type, "gitlab_ref_name": ref_name, "gitlab_commit_sha": "b" * 40,
        }
        source.update(source_extra or {})
        return self.store.create_scan(self.admin, project, input_id, "local", "all", "source", source_snapshot=source, gitlab_scan_mode=mode)

    def staged_scan(self, **kwargs):
        scan = self.new_scan(**kwargs)
        self.assertTrue(self.store.mark_run_running(scan["run_id"]))
        self.store.save_manual_gitlab_scope(scan["run_id"], self.manifest, self.file_scope)
        return self.store.run(scan["run_id"])

    def completed_scan(self, **kwargs):
        scan = self.staged_scan(**kwargs)
        self.store.complete_run(scan["run_id"], result={"findings": []})
        return self.store.run(scan["run_id"])

    def test_new_database_has_no_repository_scan_mode(self):
        with sqlite3.connect(self.store.path) as db:
            columns = {row[1] for row in db.execute("PRAGMA table_info(gitlab_repositories)")}
        self.assertNotIn("manual_scan_mode", columns)

    def test_legacy_repository_setting_is_ignored(self):
        with sqlite3.connect(self.store.path) as db:
            db.execute("ALTER TABLE gitlab_repositories ADD COLUMN manual_scan_mode TEXT NOT NULL DEFAULT 'changed'")
        self.store = PortalStore(self.store.path)
        self.assertEqual(self.new_scan()["snapshot"]["requested_scan_mode"], "full")
        self.assertEqual(self.new_scan(mode="changed")["snapshot"]["requested_scan_mode"], "changed")

    def test_invalid_run_mode_is_rejected(self):
        for mode in ("", "incremental", "FULL", [], True):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.new_scan(mode=mode)
        self.store.remove_gitlab_repository(self.mapping["mapping_id"], self.admin)
        with self.assertRaises(ValueError):
            self.new_scan(mode="changed")

    def test_mode_is_selected_per_run_and_snapshot_cannot_be_overridden(self):
        scan = self.new_scan(mode="changed")
        self.assertEqual(scan["snapshot"]["requested_scan_mode"], "changed")
        self.assertEqual(scan["snapshot"]["source_type"], "manual_gitlab")
        self.store.set_gitlab_repositories(self.project, [self.mapping_value], self.admin)
        self.assertEqual(self.store.run(scan["run_id"])["snapshot"]["requested_scan_mode"], "changed")
        self.assertEqual(self.new_scan()["snapshot"]["requested_scan_mode"], "full")
        with self.assertRaises(ValueError):
            self.new_scan(source_extra={"requested_scan_mode": "changed"})

    def test_scan_rejects_wrong_project_or_gitlab_identity(self):
        other = self.store.create_project("other")
        with self.assertRaises(ValueError):
            self.new_scan(project=other)
        with self.assertRaises(ValueError):
            self.new_scan(source_extra={"gitlab_project_id": 99})

    def test_scope_and_manifest_are_immutable_and_visible_in_revision_and_lists(self):
        scan = self.staged_scan()
        self.assertEqual(scan["snapshot"]["file_scope"], self.file_scope)
        self.store.save_manual_gitlab_scope(scan["run_id"], self.manifest, self.file_scope)
        with self.assertRaises(ValueError):
            self.store.save_manual_gitlab_scope(scan["run_id"], self.manifest, {"effective_mode": "changed"})
        with self.assertRaises(ValueError):
            self.store.save_manual_gitlab_scope(scan["run_id"], {"src/main.py": "c" * 64}, self.file_scope)
        with sqlite3.connect(self.store.path) as db:
            revision = json.loads(db.execute("SELECT snapshot_json FROM analysis_revisions WHERE run_id=?", (scan["run_id"],)).fetchone()[0])
        self.assertEqual(revision["file_scope"], self.file_scope)
        for item in (self.store.list_runs(self.project)[0], self.store.paginate_runs([self.project], source="manual")["items"][0]):
            self.assertEqual(item["file_scope"], {key: value for key, value in self.file_scope.items() if key != "scanner_fingerprint"})
            self.assertEqual(item["source"], "manual_gitlab")
        self.store.complete_run(scan["run_id"], result={"findings": []})
        with self.assertRaises(ValueError):
            self.store.save_manual_gitlab_scope(scan["run_id"], self.manifest, self.file_scope)

    def test_list_scope_omits_paths_and_fingerprint_but_detail_preserves_evidence(self):
        self.file_scope.update(selected_paths=["src/main.py"], deleted_paths=["src/removed.py"])
        scan = self.staged_scan()
        self.assertEqual(self.store.run(scan["run_id"])["snapshot"]["file_scope"], self.file_scope)
        self.assertEqual(self.store.run_summary(scan["run_id"])["snapshot"]["file_scope"], self.file_scope)
        compact = {key: value for key, value in self.file_scope.items()
                   if key not in {"selected_paths", "deleted_paths", "scanner_fingerprint"}}
        for item in (self.store.list_runs(self.project)[0], self.store.paginate_runs([self.project])["items"][0]):
            self.assertEqual(item["file_scope"], compact)
        self.assertEqual(self.store.run_summary(scan["run_id"], cached_only=True)["snapshot"]["file_scope"], compact)

    def test_scope_requires_running_scan_and_valid_manifest(self):
        scan = self.new_scan()
        with self.assertRaises(ValueError):
            self.store.save_manual_gitlab_scope(scan["run_id"], self.manifest, self.file_scope)
        self.assertTrue(self.store.mark_run_running(scan["run_id"]))
        for manifest in ({"../escape": "a" * 64}, {"/absolute": "a" * 64}, {"main.py": "invalid"}):
            with self.subTest(manifest=manifest), self.assertRaises(ValueError):
                self.store.save_manual_gitlab_scope(scan["run_id"], manifest, self.file_scope)
        self.store.request_cancel(scan["run_id"], self.admin)
        with self.assertRaises(ValueError):
            self.store.save_manual_gitlab_scope(scan["run_id"], self.manifest, self.file_scope)

    def test_baseline_excludes_failed_cancelled_unstaged_and_deleted_runs(self):
        baseline = self.completed_scan()
        failed = self.staged_scan()
        self.store.complete_run(failed["run_id"], error="scan failed")
        cancelled = self.staged_scan()
        self.store.request_cancel(cancelled["run_id"], self.admin)
        self.store.complete_run(cancelled["run_id"], result={"findings": []})
        unstaged = self.new_scan()
        self.store.complete_run(unstaged["run_id"], result={"findings": []})
        current = self.new_scan()
        selected = self.store.baseline_manual_gitlab_run(current)
        self.assertEqual(selected["run_id"], baseline["run_id"])
        self.assertEqual(selected["manifest"], self.manifest)
        self.store.delete_run(baseline["run_id"], self.admin)
        self.assertIsNone(self.store.baseline_manual_gitlab_run(current))

    def test_baseline_selects_latest_identity_match_and_leaves_policy_decision_to_caller(self):
        self.completed_scan()
        latest = self.completed_scan()
        self.completed_scan(ref_name="release")
        self.completed_scan(ref_type="tag")
        second_mapping = self.store.set_gitlab_repositories(self.project, [{**self.mapping_value, "gitlab_project_id": 43}], self.admin)[0]
        self.completed_scan(mapping=second_mapping)
        policy = self.store.rule_policy(self.project)
        self.store.set_rule_policy(self.project, ["example.rule"], policy["version"], self.admin)
        current = self.new_scan()
        selected = self.store.baseline_manual_gitlab_run(current)
        self.assertEqual(selected["run_id"], latest["run_id"])
        self.assertNotEqual(selected["snapshot"]["rule_policy_hash"], current["snapshot"]["rule_policy_hash"])

    def test_delta_baseline_requires_a_remaining_successful_full_scan(self):
        full = self.completed_scan()
        self.file_scope["effective_mode"] = "changed"
        latest = self.completed_scan()
        current = self.new_scan()
        selected = self.store.baseline_manual_gitlab_run(current)
        self.assertEqual(selected["run_id"], latest["run_id"])
        self.assertEqual(selected["full_scan_run_id"], full["run_id"])
        self.store.delete_run(full["run_id"], self.admin)
        self.assertIsNone(self.store.baseline_manual_gitlab_run(current))

    def test_baseline_isolated_from_other_koda_project_and_scheduled_source(self):
        manual = self.completed_scan()
        scheduled = self.completed_scan()
        with sqlite3.connect(self.store.path) as db:
            snapshot = scheduled["snapshot"]
            snapshot["source_type"] = "scheduled_server"
            db.execute("UPDATE scan_runs SET snapshot_json=? WHERE run_id=?", (json.dumps(snapshot), scheduled["run_id"]))
        current = self.new_scan()
        self.assertEqual(self.store.baseline_manual_gitlab_run(current)["run_id"], manual["run_id"])
        other = self.store.create_project("new owner")
        remapped = self.store.set_gitlab_repositories(other, [self.mapping_value], self.admin)[0]
        self.assertIsNone(self.store.baseline_manual_gitlab_run(self.new_scan(mapping=remapped, project=other)))

    def test_baseline_isolated_by_gitlab_server_even_with_same_project_id(self):
        legacy = self.completed_scan()
        first_server = self.completed_scan(source_extra={"gitlab_instance_url": "https://gitlab.first.test"})
        self.completed_scan(source_extra={"gitlab_instance_url": "https://gitlab.second.test"})
        current = self.new_scan(source_extra={"gitlab_instance_url": "https://gitlab.first.test"})
        self.assertEqual(self.store.baseline_manual_gitlab_run(current)["run_id"], first_server["run_id"])
        self.assertEqual(self.store.baseline_manual_gitlab_run(self.new_scan())["run_id"], legacy["run_id"])
        unknown = self.new_scan(source_extra={"gitlab_instance_url": "https://gitlab.third.test"})
        self.assertIsNone(self.store.baseline_manual_gitlab_run(unknown))

    def test_completed_partial_or_failed_analysis_stage_cannot_be_baseline(self):
        baseline = self.completed_scan()
        for result in (
            {"analysis_overall": "partial"},
            {"analysis_stages": {"source": {"status": "failed"}}},
            {"analysis_stages": {"library": {"status": "failed"}}},
            {"analysis_stages": {"quality": {"status": "failed"}}},
        ):
            with self.subTest(result=result):
                partial = self.staged_scan()
                self.store.complete_run(partial["run_id"], result={"findings": [], **result})
                self.assertEqual(self.store.run(partial["run_id"])["status"], "completed")
                current = self.new_scan()
                self.assertEqual(self.store.baseline_manual_gitlab_run(current)["run_id"], baseline["run_id"])
                self.store.complete_run(current["run_id"], error="not executed")

    def test_manifest_reader_returns_separate_evidence_and_hides_deleted_runs(self):
        scan = self.new_scan()
        self.assertIsNone(self.store.manual_gitlab_manifest(scan["run_id"]))
        self.assertTrue(self.store.mark_run_running(scan["run_id"]))
        self.store.save_manual_gitlab_scope(scan["run_id"], self.manifest, self.file_scope)
        manifest = self.store.manual_gitlab_manifest(scan["run_id"])
        self.assertEqual(manifest, self.manifest)
        manifest["src/main.py"] = "f" * 64
        self.assertEqual(self.store.manual_gitlab_manifest(scan["run_id"]), self.manifest)
        self.store.complete_run(scan["run_id"], result={"findings": []})
        self.store.delete_run(scan["run_id"], self.admin)
        self.assertIsNone(self.store.manual_gitlab_manifest(scan["run_id"]))


if __name__ == "__main__":
    unittest.main()
